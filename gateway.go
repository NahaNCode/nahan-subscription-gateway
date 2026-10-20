package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type httpClient = http.Client

func newHTTPClient(t *tls.Config, timeout time.Duration, concurrent int) *http.Client {
	if timeout > 8*time.Second {
		timeout = 8 * time.Second
	}
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			Proxy: nil, TLSClientConfig: t, DisableCompression: true,
			DialContext:         (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: timeout,
			MaxResponseHeaderBytes: 32 << 10, MaxConnsPerHost: concurrent,
			MaxIdleConns: concurrent * 8, MaxIdleConnsPerHost: concurrent, IdleConnTimeout: 60 * time.Second,
		},
	}
}

type Gateway struct {
	c       Config
	client  *http.Client
	edgeKey string
	slots   chan struct{}
}

func newGateway(c Config) (*Gateway, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	b, err := readLimited(c.EdgeKeyFile, 4096)
	if err != nil {
		return nil, errors.New("cannot read edge key")
	}
	key := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	if len(key) < 16 || len(key) > 4096 {
		return nil, errors.New("edge key must contain 16-4096 visible ASCII characters")
	}
	for _, ch := range key {
		if ch < 33 || ch > 126 {
			return nil, errors.New("edge key must be visible ASCII")
		}
	}
	client, err := upstreamClient(c)
	if err != nil {
		return nil, err
	}
	return &Gateway{c: c, client: client, edgeKey: key, slots: make(chan struct{}, c.MaxConcurrent)}, nil
}

func safeSegment(s string, max int) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for _, ch := range s {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
			return false
		}
	}
	return true
}

func allowedPath(u *url.URL) bool {
	if u.RawPath != "" || u.EscapedPath() != u.Path || len(u.Path) > 2048 {
		return false
	}
	p := strings.Split(u.Path, "/")
	if len(p) >= 3 && (p[1] == "s" || p[1] == "link") && safeSegment(p[2], 512) {
		return len(p) == 3 || len(p) == 4 && (p[3] == "presentation" || p[1] == "s" && p[3] == "qr.png")
	}
	if len(p) >= 3 && p[1] == "subscription-assets" {
		for _, part := range p[2:] {
			if part == "." || part == ".." || len(part) > 128 || part == "" {
				return false
			}
			for _, ch := range part {
				if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_' || ch == '.') {
					return false
				}
			}
		}
		return true
	}
	return false
}

func cleanQuery(raw string) (string, bool) {
	if len(raw) > 128 {
		return "", false
	}
	q, err := url.ParseQuery(raw)
	if err != nil {
		return "", false
	}
	for k, v := range q {
		if len(v) != 1 {
			return "", false
		}
		switch k {
		case "format":
			if v[0] != "html" && v[0] != "base64" {
				return "", false
			}
		case "config":
			if v[0] == "" || len(v[0]) > 10 {
				return "", false
			}
			for _, ch := range v[0] {
				if ch < '0' || ch > '9' {
					return "", false
				}
			}
			if _, err := strconv.ParseUint(v[0], 10, 31); err != nil {
				return "", false
			}
		default:
			return "", false
		}
	}
	return q.Encode(), true
}

func cleanAssetQuery(raw string) (string, bool) {
	if len(raw) > 128 {
		return "", false
	}
	query, err := url.ParseQuery(raw)
	if err != nil {
		return "", false
	}
	for key, values := range query {
		if key != "v" || len(values) != 1 || len(values[0]) == 0 || len(values[0]) > 64 {
			return "", false
		}
		for _, ch := range values[0] {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_' || ch == '.') {
				return "", false
			}
		}
	}
	return query.Encode(), true
}

func (g *Gateway) matchesHost(host string) bool {
	return host == g.c.Hostname || host == g.c.Hostname+":443"
}

func fail(w http.ResponseWriter, status int) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, http.StatusText(status), status)
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if !g.matchesHost(r.Host) || r.URL.IsAbs() || r.URL.Host != "" {
		fail(w, http.StatusMisdirectedRequest)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		fail(w, 405)
		return
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		fail(w, 400)
		return
	}
	if (r.URL.Path == "/healthz" || r.URL.Path == "/.well-known/nahan-subscription-check") && r.URL.RawPath == "" {
		if r.URL.RawQuery != "" {
			fail(w, 400)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == http.MethodGet {
			if r.URL.Path == "/healthz" {
				io.WriteString(w, "ok\n")
			} else {
				io.WriteString(w, g.c.Challenge+"\n")
			}
		}
		return
	}
	if !allowedPath(r.URL) {
		fail(w, 404)
		return
	}
	query, ok := cleanQuery(r.URL.RawQuery)
	if strings.HasPrefix(r.URL.Path, "/subscription-assets/") {
		query, ok = cleanAssetQuery(r.URL.RawQuery)
	}
	if !ok {
		fail(w, 400)
		return
	}
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	default:
		fail(w, 503)
		return
	}
	// One budget covers the whole ordered failover chain, including body reads.
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(g.c.UpstreamTimeoutSeconds)*time.Second)
	defer cancel()
	for i, origin := range g.c.Upstreams {
		u, _ := url.Parse(origin)
		u.Path, u.RawQuery = r.URL.Path, query
		req, err := http.NewRequestWithContext(ctx, r.Method, u.String(), nil)
		if err != nil {
			fail(w, 502)
			return
		}
		// A fresh header map avoids forwarding auth, cookies, proxy and hop headers.
		req.Header.Set("X-Nahan-Subscription-Edge-Key", g.edgeKey)
		req.Header.Set("X-Nahan-Subscription-Domain", g.c.Hostname)
		agent := r.Header.Get("User-Agent")
		if len(agent) > 512 {
			agent = agent[:512]
		}
		req.Header.Set("User-Agent", agent)
		if accept := r.Header.Get("Accept"); len(accept) <= 1024 {
			req.Header.Set("Accept", accept)
		}
		resp, err := g.client.Do(req)
		if err != nil {
			if resp != nil {
				resp.Body.Close()
			}
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if (resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 504) && i+1 < len(g.c.Upstreams) {
			resp.Body.Close()
			continue
		}
		if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
			resp.Body.Close()
			fail(w, 502)
			return
		}
		if resp.ContentLength > g.c.MaxResponseBytes {
			resp.Body.Close()
			fail(w, 502)
			return
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, g.c.MaxResponseBytes+1))
		resp.Body.Close()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if int64(len(body)) > g.c.MaxResponseBytes {
			fail(w, 502)
			return
		}
		for _, name := range []string{"Content-Type", "Content-Encoding", "Content-Disposition", "Subscription-Userinfo", "Profile-Update-Interval", "Profile-Web-Page-Url", "Retry-After", "Support-Url", "Content-Security-Policy", "X-Robots-Tag", "Vary"} {
			if value := resp.Header.Get(name); value != "" {
				w.Header().Set(name, value)
			}
		}
		// Subscriptions contain credentials; shared and browser caching is forbidden.
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == http.MethodHead && resp.ContentLength >= 0 {
			w.Header().Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
		} else {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		}
		w.WriteHeader(resp.StatusCode)
		if r.Method != http.MethodHead {
			w.Write(body)
		}
		return
	}
	fail(w, 502)
}
