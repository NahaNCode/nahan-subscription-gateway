package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Hostname               string   `json:"hostname"`
	Listen                 string   `json:"listen"`
	Upstreams              []string `json:"upstreams"`
	UpstreamServerName     string   `json:"upstreamServerName,omitempty"`
	CAFile                 string   `json:"caFile"`
	ClientCertFile         string   `json:"clientCertFile,omitempty"`
	ClientKeyFile          string   `json:"clientKeyFile,omitempty"`
	EdgeKeyFile            string   `json:"edgeKeyFile"`
	CertFile               string   `json:"certFile"`
	KeyFile                string   `json:"keyFile"`
	Challenge              string   `json:"challenge"`
	MaxResponseBytes       int64    `json:"maxResponseBytes,omitempty"`
	MaxConcurrent          int      `json:"maxConcurrent,omitempty"`
	UpstreamTimeoutSeconds int      `json:"upstreamTimeoutSeconds,omitempty"`
	CertificateSync        bool     `json:"certificateSync,omitempty"`
	CertificatePollSeconds int      `json:"certificatePollSeconds,omitempty"`
	HeartbeatSeconds       int      `json:"heartbeatSeconds,omitempty"`
	BehindProxy            bool     `json:"behindProxy,omitempty"`
	AppliedRevision        int64    `json:"appliedRevision,omitempty"`
}

func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("file exceeds limit")
	}
	return b, nil
}

func loadConfig(path string) (Config, error) {
	var c Config
	b, err := readLimited(path, 64<<10)
	if err != nil {
		return c, err
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return c, errors.New("trailing JSON")
	}
	return c, c.validate()
}

func validHostname(s string) bool {
	if len(s) < 1 || len(s) > 253 || s != strings.ToLower(s) || net.ParseIP(s) != nil {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}

func (c *Config) validate() error {
	if !validHostname(c.Hostname) {
		return errors.New("hostname must be a lowercase DNS name")
	}
	if _, port, err := net.SplitHostPort(c.Listen); err != nil {
		return errors.New("listen must be host:port")
	} else if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return errors.New("invalid listen port")
	}
	if len(c.Upstreams) < 1 || len(c.Upstreams) > 8 {
		return errors.New("one to eight upstreams required")
	}
	for _, raw := range c.Upstreams {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.Opaque != "" {
			return errors.New("upstreams must be HTTPS origins without credentials, paths, queries or fragments")
		}
		if p := u.Port(); p != "" {
			n, err := strconv.Atoi(p)
			if err != nil || n < 1 || n > 65535 {
				return errors.New("invalid upstream port")
			}
		}
	}
	if c.UpstreamServerName != "" && c.UpstreamServerName != "subscriptions.nahan.internal" {
		return errors.New("upstreamServerName may only be subscriptions.nahan.internal")
	}
	if c.CAFile == "" || c.EdgeKeyFile == "" || c.CertFile == "" || c.KeyFile == "" {
		return errors.New("CA, edge key and server certificate/key files required")
	}
	if (c.ClientCertFile == "") != (c.ClientKeyFile == "") {
		return errors.New("both client certificate and key required")
	}
	if !safeSegment(c.Challenge, 256) {
		return errors.New("challenge must be 1-256 URL-safe characters")
	}
	if c.MaxResponseBytes == 0 {
		c.MaxResponseBytes = 4 << 20
	}
	if c.MaxConcurrent == 0 {
		c.MaxConcurrent = 32
	}
	if c.UpstreamTimeoutSeconds == 0 {
		c.UpstreamTimeoutSeconds = 25
	}
	if c.CertificatePollSeconds == 0 {
		c.CertificatePollSeconds = 300
	}
	if c.HeartbeatSeconds == 0 {
		c.HeartbeatSeconds = 60
	}
	if c.CertificatePollSeconds < 30 || c.CertificatePollSeconds > 86400 || c.HeartbeatSeconds < 30 || c.HeartbeatSeconds > 3600 {
		return errors.New("invalid control intervals")
	}
	if c.CertificateSync && (c.CertFile != "/state/server.pem" || c.KeyFile != c.CertFile) {
		return errors.New("certificateSync requires certFile and keyFile /state/server.pem")
	}
	if c.BehindProxy && c.Listen != ":8080" {
		return errors.New("behindProxy requires listen :8080")
	}
	if c.MaxResponseBytes < 1 || c.MaxResponseBytes > 32<<20 || c.MaxConcurrent < 1 || c.MaxConcurrent > 256 || c.UpstreamTimeoutSeconds < 1 || c.UpstreamTimeoutSeconds > 30 {
		return errors.New("limits out of range")
	}
	return nil
}

func upstreamClient(c Config) (*httpClient, error) {
	pem, err := readLimited(c.CAFile, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("CA contains no certificates")
	}
	t := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: c.UpstreamServerName}
	if c.ClientCertFile != "" {
		cert, err := tls.LoadX509KeyPair(c.ClientCertFile, c.ClientKeyFile)
		if err != nil {
			return nil, errors.New("invalid upstream client certificate/key")
		}
		t.Certificates = []tls.Certificate{cert}
	}
	return newHTTPClient(t, time.Duration(c.UpstreamTimeoutSeconds)*time.Second, c.MaxConcurrent), nil
}
