package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

const certificatePath = "/api/subscription-edge/v1/certificate"
const heartbeatPath = "/api/subscription-edge/v1/heartbeat"

type certificateResponse struct {
	CertificatePEM string    `json:"certificatePem"`
	PrivateKeyPEM  string    `json:"privateKeyPem"`
	NotAfter       time.Time `json:"notAfter"`
}

func (g *Gateway) controlRequest(ctx context.Context, method, path string, payload []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(g.c.UpstreamTimeoutSeconds)*time.Second)
	defer cancel()
	for i, origin := range g.c.Upstreams {
		u, _ := url.Parse(origin)
		u.Path = path
		req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(payload))
		if err != nil {
			return nil, errors.New("control request invalid")
		}
		req.Header.Set("X-Nahan-Subscription-Edge-Key", g.edgeKey)
		req.Header.Set("X-Nahan-Subscription-Domain", g.c.Hostname)
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := g.client.Do(req)
		if err != nil {
			if method == http.MethodGet && ctx.Err() == nil {
				continue
			}
			return nil, errors.New("control unavailable")
		}
		if method == http.MethodGet && i+1 < len(g.c.Upstreams) && (resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 504) {
			resp.Body.Close()
			continue
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, (128<<10)+1))
		resp.Body.Close()
		if err != nil || len(b) > 128<<10 || resp.StatusCode != http.StatusOK {
			return nil, errors.New("control response rejected")
		}
		return b, nil
	}
	return nil, errors.New("control unavailable")
}

func validateCertificate(b []byte, hostname string, now time.Time) ([]byte, error) {
	var data certificateResponse
	if err := json.Unmarshal(b, &data); err != nil {
		return nil, errors.New("certificate JSON invalid")
	}
	pair, err := tls.X509KeyPair([]byte(data.CertificatePEM), []byte(data.PrivateKeyPEM))
	if err != nil {
		return nil, errors.New("certificate pair invalid")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.VerifyHostname(hostname) != nil || leaf.IsCA || now.Before(leaf.NotBefore) || !leaf.NotAfter.After(now.Add(5*time.Minute)) || !data.NotAfter.Equal(leaf.NotAfter) {
		return nil, errors.New("certificate identity or validity rejected")
	}
	return []byte(data.CertificatePEM + "\n" + data.PrivateKeyPEM + "\n"), nil
}

func atomicWrite(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".certificate-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (g *Gateway) syncCertificate(ctx context.Context) error {
	if !g.c.CertificateSync {
		return errors.New("certificate sync not enabled")
	}
	b, err := g.controlRequest(ctx, http.MethodGet, certificatePath, nil)
	if err != nil {
		return err
	}
	pem, err := validateCertificate(b, g.c.Hostname, time.Now())
	if err != nil {
		return err
	}
	return atomicWrite(g.c.CertFile, pem)
}

func (g *Gateway) heartbeat(ctx context.Context) error {
	// Versioned proposal: backend approval is required before enabling production.
	payload := struct {
		SchemaVersion       int        `json:"schemaVersion"`
		Hostname            string     `json:"hostname"`
		AppliedRevision     int64      `json:"appliedRevision"`
		CertificateNotAfter *time.Time `json:"certificateNotAfter,omitempty"`
	}{SchemaVersion: 1, Hostname: g.c.Hostname, AppliedRevision: g.c.AppliedRevision}
	if cert, err := loadServerPair(g.c); err == nil {
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			payload.CertificateNotAfter = &leaf.NotAfter
		}
	}
	b, _ := json.Marshal(payload)
	response, err := g.controlRequest(ctx, http.MethodPost, heartbeatPath, b)
	if err != nil {
		return err
	}
	var desired struct {
		Hostname        string `json:"hostname"`
		DesiredRevision int64  `json:"desiredRevision"`
	}
	if json.Unmarshal(response, &desired) != nil || desired.Hostname != g.c.Hostname {
		return errors.New("heartbeat response invalid")
	}
	if desired.DesiredRevision > g.c.AppliedRevision {
		g.c.AppliedRevision = desired.DesiredRevision
	}
	return nil
}

func (g *Gateway) controlLoop(ctx context.Context) {
	certTick := time.NewTicker(time.Duration(g.c.CertificatePollSeconds) * time.Second)
	heartTick := time.NewTicker(time.Duration(g.c.HeartbeatSeconds) * time.Second)
	defer certTick.Stop()
	defer heartTick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-certTick.C:
			if g.c.CertificateSync {
				if err := g.syncCertificate(ctx); err != nil {
					log.Print("certificate sync failed")
				}
			}
		case <-heartTick.C:
			if err := g.heartbeat(ctx); err != nil {
				log.Print("heartbeat failed")
			}
		}
	}
}
