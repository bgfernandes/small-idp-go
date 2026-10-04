package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bgfernandes/small-idp-go/internal/jwk"
)

func TestNewServer(t *testing.T) {
	t.Parallel()

	key, err := jwk.Generate()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	log := slog.New(slog.DiscardHandler)

	tests := []struct {
		name    string
		issuer  string
		key     *jwk.Key
		log     *slog.Logger
		wantErr bool
	}{
		{name: "valid root issuer", issuer: "http://localhost:8080", key: key, log: log, wantErr: false},
		{name: "valid https issuer", issuer: "https://idp.example.com", key: key, log: log, wantErr: false},
		{name: "valid issuer with path", issuer: "https://idp.example.com/tenant", key: key, log: log, wantErr: false},
		{name: "empty string issuer", issuer: "", key: key, log: log, wantErr: true},
		{name: "unparseable issuer", issuer: "://bad", key: key, log: log, wantErr: true},
		{name: "no scheme issuer", issuer: "idp.example.com", key: key, log: log, wantErr: true},
		{name: "wrong scheme issuer", issuer: "ftp://idp.example.com", key: key, log: log, wantErr: true},
		{name: "no host issuer", issuer: "http://", key: key, log: log, wantErr: true},
		{name: "issuer with query", issuer: "http://idp.example.com?x=1", key: key, log: log, wantErr: true},
		{name: "issuer with fragment", issuer: "http://idp.example.com#x=1", key: key, log: log, wantErr: true},
		{name: "issuer with trailing slash", issuer: "http://idp.example.com/", key: key, log: log, wantErr: true},
		{name: "issuer with path and trailing slash", issuer: "http://idp.example.com/tenant/", key: key, log: log, wantErr: true},
		{name: "issuer with trailing ?", issuer: "http://idp.example.com?", key: key, log: log, wantErr: true},
		{name: "issuer with trailing #", issuer: "http://idp.example.com#", key: key, log: log, wantErr: true},
		{name: "nil key", issuer: "http://idp.example.com", key: nil, log: log, wantErr: true},
		{name: "nil logger", issuer: "http://idp.example.com", key: key, log: nil, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewServer(tt.issuer, tt.key, tt.log)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewServer(%q) = %v, wantErr %t", tt.issuer, err, tt.wantErr)
			}
		})
	}
}

func newTestServer(t *testing.T) (*Server, *jwk.Key) {
	t.Helper()

	return newTestServerWithIssuer(t, "http://localhost:8080")
}

func newTestServerWithIssuer(t *testing.T, issuer string) (*Server, *jwk.Key) {
	t.Helper()

	key, err := jwk.Generate()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	log := slog.New(slog.DiscardHandler)

	apiServer, err := NewServer(issuer, key, log)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	return apiServer, key
}

func TestJWKSRoute(t *testing.T) {
	t.Parallel()

	apiServer, key := newTestServer(t)

	t.Run("happy path", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodGet, "/jwks", nil)
		rec := httptest.NewRecorder()
		apiServer.Routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("got code %d, want %d", rec.Code, http.StatusOK)
		}

		if rec.Header().Get("Content-Type") != "application/json" {
			t.Errorf("got Content-Type %q, want %q", rec.Header().Get("Content-Type"), "application/json")
		}

		var set jwk.Set
		if err := json.NewDecoder(rec.Body).Decode(&set); err != nil {
			t.Fatalf("failed to decode response body: %v", err)
		}

		if len(set.Keys) != 1 {
			t.Fatalf("got %d keys, want 1", len(set.Keys))
		}

		if set.Keys[0].KID != key.KID() {
			t.Errorf("got KID %q, want %q", set.Keys[0].KID, key.KID())
		}
	})

	t.Run("wrong method", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodPost, "/jwks", nil)
		rec := httptest.NewRecorder()
		apiServer.Routes().ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("got code %d, want %d", rec.Code, http.StatusMethodNotAllowed)
		}
	})
}

func TestWriteJSON(t *testing.T) {
	t.Parallel()

	apiServer, _ := newTestServer(t)

	tests := []struct {
		name            string
		code            int
		body            any
		wantCode        int
		wantContentType string
		wantBody        string
	}{
		{name: "ok", code: http.StatusOK, body: "some string", wantCode: http.StatusOK, wantContentType: "application/json", wantBody: `"some string"`},
		{name: "created", code: http.StatusCreated, body: "some string", wantCode: http.StatusCreated, wantContentType: "application/json", wantBody: `"some string"`},
		{name: "internal server error", code: http.StatusInternalServerError, body: "some string", wantCode: http.StatusInternalServerError, wantContentType: "application/json", wantBody: `"some string"`},
		{name: "marshal error", code: http.StatusOK, body: make(chan int), wantCode: http.StatusInternalServerError, wantContentType: "text/plain; charset=utf-8", wantBody: "Internal Server Error\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()

			apiServer.writeJSON(rec, tt.code, tt.body)
			if rec.Code != tt.wantCode {
				t.Errorf("writeJSON(%d, %v) got code %d, want %d", tt.code, tt.body, rec.Code, tt.wantCode)
			}

			if rec.Header().Get("Content-Type") != tt.wantContentType {
				t.Errorf("writeJSON(%d, %v) got Content-Type %q, want %q", tt.code, tt.body, rec.Header().Get("Content-Type"), tt.wantContentType)
			}

			if rec.Body.String() != tt.wantBody {
				t.Errorf("writeJSON(%d, %v) got body %q, want %q", tt.code, tt.body, rec.Body.String(), tt.wantBody)
			}
		})
	}
}
