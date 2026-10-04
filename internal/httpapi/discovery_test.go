package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestOAuthMetadataBody(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		issuer string
		want   authorizationServerMetadata
	}{
		{
			name:   "root issuer",
			issuer: "http://localhost:8080",
			want: authorizationServerMetadata{
				Issuer:        "http://localhost:8080",
				TokenEndpoint: "http://localhost:8080/token",
				JWKSURI:       "http://localhost:8080/jwks",
				GrantTypesSupported: []string{
					grantTypeClientCredentials,
				},
				TokenEndpointAuthMethodsSupported: []string{
					tokenEndpointAuthMethodBasic,
					tokenEndpointAuthMethodPost,
				},
			},
		},
		{
			name:   "path issuer",
			issuer: "http://localhost:8080/tenant",
			want: authorizationServerMetadata{
				Issuer:        "http://localhost:8080/tenant",
				TokenEndpoint: "http://localhost:8080/tenant/token",
				JWKSURI:       "http://localhost:8080/tenant/jwks",
				GrantTypesSupported: []string{
					grantTypeClientCredentials,
				},
				TokenEndpointAuthMethodsSupported: []string{
					tokenEndpointAuthMethodBasic,
					tokenEndpointAuthMethodPost,
				},
			},
		},
		{
			name:   "deeper path issuer with https",
			issuer: "https://idp.example.com/a/b",
			want: authorizationServerMetadata{
				Issuer:        "https://idp.example.com/a/b",
				TokenEndpoint: "https://idp.example.com/a/b/token",
				JWKSURI:       "https://idp.example.com/a/b/jwks",
				GrantTypesSupported: []string{
					grantTypeClientCredentials,
				},
				TokenEndpointAuthMethodsSupported: []string{
					tokenEndpointAuthMethodBasic,
					tokenEndpointAuthMethodPost,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			apiServer, _ := newTestServerWithIssuer(t, tt.issuer)

			req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
			rec := httptest.NewRecorder()
			apiServer.Routes().ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("got status %d, want status %d", rec.Code, http.StatusOK)
			}

			if rec.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("got Content-Type %q, want Content-Type %q", rec.Header().Get("Content-Type"), "application/json")
			}

			var got authorizationServerMetadata
			err := json.NewDecoder(rec.Body).Decode(&got)
			if err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestOAuthMetadataExactKeys(t *testing.T) {
	t.Parallel()

	apiServer, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()
	apiServer.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want status %d", rec.Code, http.StatusOK)
	}

	var got map[string]json.RawMessage
	err := json.NewDecoder(rec.Body).Decode(&got)
	if err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(got) != 5 {
		t.Fatalf("got %d keys, want 5", len(got))
	}

	// assert the keys are exactly these five: issuer, token_endpoint, jwks_uri, grant_types_supported, token_endpoint_auth_methods_supported
	wantKeys := []string{
		"issuer",
		"token_endpoint",
		"jwks_uri",
		"grant_types_supported",
		"token_endpoint_auth_methods_supported",
	}
	for _, key := range wantKeys {
		if got[key] == nil {
			t.Fatalf("missing key %q", key)
		}
	}
}

func TestOAuthMetadataWrongMethod(t *testing.T) {
	t.Parallel()

	apiServer, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()
	apiServer.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("got code %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestOAuthMetadataBehindPrefixStrippingProxy(t *testing.T) {
	t.Parallel()

	apiServer, _ := newTestServerWithIssuer(t, "http://localhost:8080/tenant")

	req := httptest.NewRequest(http.MethodGet, "/tenant/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()
	http.StripPrefix("/tenant", apiServer.Routes()).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want status %d", rec.Code, http.StatusOK)
	}

	var got authorizationServerMetadata
	err := json.NewDecoder(rec.Body).Decode(&got)
	if err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if got.Issuer != "http://localhost:8080/tenant" {
		t.Errorf("got issuer %q, want %q", got.Issuer, "http://localhost:8080/tenant")
	}

	if got.TokenEndpoint != "http://localhost:8080/tenant/token" {
		t.Errorf("got token endpoint %q, want %q", got.TokenEndpoint, "http://localhost:8080/tenant/token")
	}

	if got.JWKSURI != "http://localhost:8080/tenant/jwks" {
		t.Errorf("got JWKS URI %q, want %q", got.JWKSURI, "http://localhost:8080/tenant/jwks")
	}

	// asserts that the JWKS URI is reachable
	req = httptest.NewRequest(http.MethodGet, got.JWKSURI, nil)
	rec = httptest.NewRecorder()
	http.StripPrefix("/tenant", apiServer.Routes()).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("got code %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestOAuthMetadataInsertedFormNotServed(t *testing.T) {
	t.Parallel()

	apiServer, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server/tenant", nil)
	rec := httptest.NewRecorder()
	apiServer.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("got code %d, want %d", rec.Code, http.StatusNotFound)
	}
}
