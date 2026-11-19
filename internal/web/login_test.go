package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetLogin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		issuer     string
		wantAction string
	}{
		{
			name:       "basic",
			issuer:     "https://idp.example.com",
			wantAction: "/login",
		},
		{
			name:       "with path",
			issuer:     "https://idp.example.com/path",
			wantAction: "/path/login",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := newTestServer(t, testServerOptions{issuer: tt.issuer})

			req := httptest.NewRequest(http.MethodGet, "/login", nil)
			rec := httptest.NewRecorder()
			server.Routes().ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("got status %d, want status %d", rec.Code, http.StatusOK)
			}

			if rec.Header().Get("Content-Type") != "text/html; charset=utf-8" {
				t.Errorf(
					"got Content-Type %q, want Content-Type %q",
					rec.Header().Get("Content-Type"),
					"text/html; charset=utf-8",
				)
			}

			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Errorf(
					"got Cache-Control %q, want Cache-Control %q",
					rec.Header().Get("Cache-Control"),
					"no-store",
				)
			}

			if rec.Header().Get("X-Frame-Options") != "DENY" {
				t.Errorf(
					"got X-Frame-Options %q, want X-Frame-Options %q",
					rec.Header().Get("X-Frame-Options"),
					"DENY",
				)
			}

			body := rec.Body.String()

			if !strings.Contains(body, "<form action=\""+tt.wantAction+"\"") {
				t.Fatalf(
					"got body %q, want body to contain action %q",
					body,
					tt.wantAction,
				)
			}
		})
	}
}

func TestGetLoginBehindPrefixStrippingProxy(t *testing.T) {
	t.Parallel()

	webServer := newTestServer(t, testServerOptions{issuer: "http://localhost:8080/tenant"})

	req := httptest.NewRequest(
		http.MethodGet,
		"/tenant/login",
		nil,
	)
	rec := httptest.NewRecorder()
	http.StripPrefix("/tenant", webServer.Routes()).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want status %d", rec.Code, http.StatusOK)
	}
}
