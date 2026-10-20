package main

import (
	"testing"
	"time"
)

func TestManagedHostAliases(t *testing.T) {
	g := &Gateway{c: Config{Hostname: "origin.example.com"}}
	if g.matchesHost("nnn.fg-t.ir") {
		t.Fatal("unregistered host admitted")
	}
	if err := g.setAliases([]string{"nnn.fg-t.ir"}); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"nnn.fg-t.ir", "nnn.fg-t.ir:443", "origin.example.com"} {
		if !g.matchesHost(host) {
			t.Fatalf("registered host rejected: %s", host)
		}
	}
	for _, host := range []string{"evil.example.com", "nnn.fg-t.ir:80", "nnn.fg-t.ir.evil", "NNN.fg-t.ir"} {
		if g.matchesHost(host) {
			t.Fatal("unexpected host admitted")
		}
	}
	for _, host := range []string{"*.fg-t.ir", "127.0.0.1", "nnn.fg-t.ir:443", "bad\n.example.com"} {
		if g.setAliases([]string{host}) == nil {
			t.Fatal("invalid alias accepted")
		}
	}
	g.aliasesUntil = time.Now().Add(-time.Second)
	if g.matchesHost("nnn.fg-t.ir") {
		t.Fatal("expired authorization admitted")
	}
	if err := g.setAliases(nil); err != nil {
		t.Fatal(err)
	}
	if g.matchesHost("nnn.fg-t.ir") {
		t.Fatal("removed alias admitted")
	}
}
