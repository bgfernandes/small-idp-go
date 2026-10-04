package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bgfernandes/small-idp-go/internal/jwk"
)

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
