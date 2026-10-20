package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func edgeRequest(method, target string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.URL.Scheme = ""
	r.URL.Host = ""
	return r
}

func fixture(t *testing.T, handler http.HandlerFunc) (*Gateway, *httptest.Server) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	directory := t.TempDir()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	os.WriteFile(filepath.Join(directory, "ca"), ca, 0600)
	os.WriteFile(filepath.Join(directory, "key"), []byte(strings.Repeat("a", 43)), 0600)
	c := Config{Hostname: "connect.example.com", Listen: ":8443", Upstreams: []string{server.URL}, CAFile: filepath.Join(directory, "ca"), EdgeKeyFile: filepath.Join(directory, "key"), CertFile: "/unused", KeyFile: "/unused", Challenge: "challenge"}
	g, err := newGateway(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.client.CloseIdleConnections)
	return g, server
}

func TestProxyBoundariesAndHeaders(t *testing.T) {
	calls := 0
	g, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("X-Forwarded-Host") != "" {
			t.Error("forwarded untrusted header")
		}
		if r.Header.Get("X-Nahan-Subscription-Edge-Key") != strings.Repeat("a", 43) || r.Header.Get("X-Nahan-Subscription-Domain") != "connect.example.com" {
			t.Error("missing gateway identity")
		}
		if r.UserAgent() != "v2rayNG" {
			t.Error("client negotiation lost")
		}
		w.Header().Set("Subscription-Userinfo", "total=123")
		w.Header().Set("Profile-Web-Page-Url", "https://connect.example.com/s/abcdefghijkl")
		w.Header().Set("Set-Cookie", "forbidden=yes")
		io.WriteString(w, "config")
	})
	r := edgeRequest("GET", "https://connect.example.com/s/abcdefghijkl?format=base64")
	r.Header.Set("User-Agent", "v2rayNG")
	r.Header.Set("Authorization", "secret")
	r.Header.Set("Cookie", "x=y")
	r.Header.Set("X-Forwarded-Host", "evil.example.com")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != "config" || w.Header().Get("Subscription-Userinfo") != "total=123" || w.Header().Get("Set-Cookie") != "" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("incorrect response %d", w.Code)
	}
	for _, path := range []string{"/admin", "/s/abcdefghijkl?url=https://evil.test", "/s/abcdefghijkl?format=base64&format=html", "/subscription-assets/../secret", "/s/abc%2fdef", "/api/subscription-edge/v1/certificate"} {
		w := httptest.NewRecorder()
		g.ServeHTTP(w, edgeRequest("GET", "https://connect.example.com"+path))
		if w.Code < 400 {
			t.Errorf("accepted %s", path)
		}
	}
	w = httptest.NewRecorder()
	g.ServeHTTP(w, edgeRequest("GET", "https://evil.example.com/s/abcdefghijkl"))
	if w.Code != 421 {
		t.Error("untrusted host")
	}
	if calls != 1 {
		t.Fatalf("unsafe upstream calls %d", calls)
	}
}

func TestFailoverAndTerminalResponses(t *testing.T) {
	calls := 0
	g, good := fixture(t, func(w http.ResponseWriter, r *http.Request) { calls++; io.WriteString(w, "ok") })
	bad := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer bad.Close()
	// Both synthetic servers share httptest's CA, and both verify normally.
	g.c.Upstreams = []string{bad.URL, good.URL}
	r := edgeRequest("GET", "https://connect.example.com/s/abcdefghijkl")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != 200 || calls != 1 {
		t.Fatal("fallback failed")
	}
	bad.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) })
	w = httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != 401 || calls != 1 {
		t.Fatal("authentication refusal retried")
	}
	g.c.MaxResponseBytes = 1
	g.c.Upstreams = []string{good.URL}
	w = httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != 502 {
		t.Fatal("oversized response accepted")
	}
}

func TestUntrustedTLSAndCancellation(t *testing.T) {
	g, server := fixture(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "unsafe") })
	g.client.Transport.(*http.Transport).TLSClientConfig.RootCAs = x509.NewCertPool()
	w := httptest.NewRecorder()
	g.ServeHTTP(w, edgeRequest("GET", "https://connect.example.com/s/abcdefghijkl"))
	if w.Code != 502 {
		t.Fatal("untrusted TLS accepted")
	}
	if g.client.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify {
		t.Fatal("TLS verification disabled")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := g.client.Get(server.URL); err == nil {
		t.Fatal("untrusted request succeeded")
	}
	if _, err := g.controlRequest(ctx, http.MethodGet, certificatePath, nil); err == nil {
		t.Fatal("cancel ignored")
	}
}

func TestHeartbeatFailoverAndRevocation(t *testing.T) {
	calls := 0
	g, good := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != heartbeatPath {
			t.Error("incorrect receipt")
		}
		io.WriteString(w, `{"hostname":"connect.example.com","desiredRevision":2}`)
	})
	bad := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer bad.Close()
	g.c.Upstreams = []string{bad.URL, good.URL}
	if err := g.heartbeat(context.Background()); err != nil || calls != 1 || g.c.AppliedRevision != 2 {
		t.Fatal("receipt failover failed")
	}
	bad.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) })
	if err := g.heartbeat(context.Background()); err == nil || calls != 1 {
		t.Fatal("revocation was retried")
	}
	bad.Close()
	if err := g.heartbeat(context.Background()); err != nil || calls != 2 {
		t.Fatal("network fallback failed")
	}
}

func TestCertificateValidation(t *testing.T) {
	_, server := fixture(t, func(http.ResponseWriter, *http.Request) {})
	cert := server.TLS.Certificates[0]
	_ = tls.VersionTLS12
	if _, err := validateCertificate([]byte(`{"certificatePem":"invalid","privateKeyPem":"invalid"}`), "connect.example.com", time.Now()); err == nil {
		t.Fatal("invalid certificate accepted")
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("fixture certificate missing")
	}
}
