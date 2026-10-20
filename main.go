package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func loadServerPair(c Config) (tls.Certificate, error) {
	if c.CertFile == c.KeyFile {
		b, err := readLimited(c.CertFile, 128<<10)
		if err != nil {
			return tls.Certificate{}, err
		}
		return tls.X509KeyPair(b, b)
	}
	return tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
}

func serverTLS(c Config) (*tls.Config, error) {
	if _, err := loadServerPair(c); err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName != c.Hostname {
			return nil, os.ErrPermission
		}
		cert, err := loadServerPair(c)
		if err != nil {
			return nil, err
		}
		return &cert, nil
	}}, nil
}

func main() {
	path := flag.String("config", "/etc/nahan/config.json", "configuration file")
	check := flag.Bool("check", false, "validate files and configuration without listening")
	command := flag.String("command", "serve", "serve or cert-sync")
	flag.Parse()
	// Never print configuration, URLs or errors that may contain subscription tokens.
	c, err := loadConfig(*path)
	if err != nil {
		log.Fatal("configuration invalid")
	}
	g, err := newGateway(c)
	if err != nil {
		log.Fatal("gateway initialization failed")
	}
	if *command == "health-check" {
		address := "http://127.0.0.1:8080/healthz"
		transport := &http.Transport{Proxy: nil}
		if !c.BehindProxy {
			pair, e := loadServerPair(c)
			if e != nil {
				os.Exit(1)
			}
			pool := x509.NewCertPool()
			for _, der := range pair.Certificate {
				cert, e := x509.ParseCertificate(der)
				if e != nil {
					os.Exit(1)
				}
				pool.AddCert(cert)
			}
			transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: c.Hostname, RootCAs: pool}
			address = "https://127.0.0.1:8443/healthz"
		}
		client := &http.Client{Transport: transport, Timeout: 4 * time.Second}
		defer client.CloseIdleConnections()
		req, _ := http.NewRequest("GET", address, nil)
		req.Host = c.Hostname
		response, e := client.Do(req)
		if e != nil {
			os.Exit(1)
		}
		defer response.Body.Close()
		body, e := io.ReadAll(io.LimitReader(response.Body, 16))
		if e != nil || response.StatusCode != 200 || strings.TrimSpace(string(body)) != "ok" {
			os.Exit(1)
		}
		return
	}
	if *command == "cert-sync" {
		if err := g.syncCertificate(context.Background()); err != nil {
			log.Fatal("certificate bootstrap failed")
		}
		log.Print("certificate synchronized")
		return
	}
	if *command != "serve" {
		log.Fatal("unknown command")
	}
	t, err := serverTLS(c)
	if err != nil {
		log.Fatal("server certificate/key invalid")
	}
	if *check {
		log.Print("configuration valid")
		return
	}
	srv := &http.Server{Addr: c.Listen, Handler: g, TLSConfig: t,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 35 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0),
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go g.controlLoop(ctx)
	go func() {
		<-ctx.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()
	log.Print("gateway starting")
	if c.BehindProxy {
		err = srv.ListenAndServe()
	} else {
		err = srv.ListenAndServeTLS("", "")
	}
	if err != nil && err != http.ErrServerClosed {
		log.Fatal("gateway stopped unexpectedly")
	}
	log.Print("gateway stopped")
}
