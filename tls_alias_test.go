package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAliasTLSRequiresFreshAuthorizationAndCertificateName(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "origin.example.com"}, DNSNames: []string{"origin.example.com", "nnn.fg-t.ir"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "server.pem")
	data := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private})...)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	g := &Gateway{c: Config{Hostname: "origin.example.com", CertFile: path, KeyFile: path}}
	config, err := serverTLS(g.c, g.matchesHost)
	if err != nil {
		t.Fatal(err)
	}
	check := func(host string, want bool) {
		t.Helper()
		_, err := config.GetCertificate(&tls.ClientHelloInfo{ServerName: host})
		if (err == nil) != want {
			t.Fatalf("unexpected TLS admission for %q", host)
		}
	}
	check("origin.example.com", true)
	check("nnn.fg-t.ir", false)
	if err := g.setAliases([]string{"nnn.fg-t.ir", "not-in-certificate.test"}); err != nil {
		t.Fatal(err)
	}
	check("nnn.fg-t.ir", true)
	server := httptest.NewUnstartedServer(g)
	server.TLS = config
	server.StartTLS()
	defer server.Close()
	trusted := x509.NewCertPool()
	trusted.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: trusted, ServerName: "nnn.fg-t.ir", MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second * 5}
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/healthz", nil)
	req.Host = "nnn.fg-t.ir"
	response, err := client.Do(req)
	if err != nil {
		t.Fatal("verified alias TLS handshake failed", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatal("alias route rejected")
	}
	check("not-in-certificate.test", false)
	check("evil.test", false)
	check("nnn.fg-t.ir:443", false)
	check("", false)
	g.aliasesUntil = time.Now().Add(-time.Second)
	check("nnn.fg-t.ir", false)
	check("origin.example.com", true)
}
