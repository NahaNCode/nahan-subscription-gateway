package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEmergencyClaimsAreBoundedAndPrivate(t *testing.T) {
	calls := 0
	g, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method == http.MethodPost {
			b, _ := io.ReadAll(r.Body)
			if string(b) != `{"requestId":"11111111-1111-4111-8111-111111111111"}` || r.Header.Get("Content-Type") != "application/json" {
				t.Error("claim payload lost")
			}
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("private headers forwarded")
		}
		io.WriteString(w, `{"visible":true}`)
	})
	request := func(method, path, origin, body string) int {
		r := edgeRequest(method, "https://connect.example.com"+path)
		r.Body = io.NopCloser(strings.NewReader(body))
		r.ContentLength = int64(len(body))
		r.Header.Set("Origin", origin)
		r.Header.Set("Cookie", "private")
		r.Header.Set("Authorization", "private")
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		return w.Code
	}
	body := `{"requestId":"11111111-1111-4111-8111-111111111111"}`
	for _, prefix := range []string{"/s/", "/link/"} {
		path := prefix + "abcdefghijkl/emergency"
		if request("GET", path, "", "") != 200 || request("POST", path, "https://connect.example.com", body) != 200 {
			t.Fatal("emergency route unavailable")
		}
	}
	before := calls
	for _, tc := range []struct {
		method, path, origin, body string
		status                     int
	}{
		{"POST", "/s/abcdefghijkl/emergency", "https://evil.example", body, 403},
		{"POST", "/s/abcdefghijkl/emergency", "https://connect.example.com", `{"requestId":"invalid"}`, 422},
		{"POST", "/s/abcdefghijkl/emergency", "https://connect.example.com", `{"requestId":"11111111-1111-4111-8111-111111111111","volumeMb":999}`, 422},
		{"POST", "/s/abcdefghijkl/emergency", "https://connect.example.com", strings.Repeat("x", 1025), 413},
		{"POST", "/s/abcdefghijkl/presentation", "https://connect.example.com", body, 405},
		{"DELETE", "/s/abcdefghijkl/emergency", "https://connect.example.com", body, 405},
	} {
		if code := request(tc.method, tc.path, tc.origin, tc.body); code != tc.status {
			t.Errorf("got %d want %d", code, tc.status)
		}
	}
	if calls != before {
		t.Fatal("unsafe upstream mutation")
	}
}
