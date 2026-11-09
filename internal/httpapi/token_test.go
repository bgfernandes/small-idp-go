package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bgfernandes/small-idp-go/internal/client"
	"github.com/bgfernandes/small-idp-go/internal/jwk"
	"github.com/bgfernandes/small-idp-go/internal/jwt"
)

func TestTokenWrongMethod(t *testing.T) {
	t.Parallel()

	apiServer, _ := newTestServer(t, testServerOptions{})

	req := httptest.NewRequest(http.MethodGet, "/token", nil)
	rec := httptest.NewRecorder()
	apiServer.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("got code %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
	if rec.Header().Get("Allow") != "POST" {
		t.Errorf("got Allow header %q, want %q", rec.Header().Get("Allow"), "POST")
	}
}

func TestTokenErrorFormat(t *testing.T) {
	t.Parallel()

	apiServer, _ := newTestServer(t, testServerOptions{})

	req := httptest.NewRequest(http.MethodPost, "/token", nil)
	rec := httptest.NewRecorder()
	apiServer.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("got code %d, want %d", rec.Code, http.StatusBadRequest)
	}

	if rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("got Content-Type header %q, want %q", rec.Header().Get("Content-Type"), "application/json")
	}

	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("got Cache-Control header %q, want %q", rec.Header().Get("Cache-Control"), "no-store")
	}

	if rec.Header().Get("Pragma") != "no-cache" {
		t.Errorf("got Pragma header %q, want %q", rec.Header().Get("Pragma"), "no-cache")
	}

	var got map[string]json.RawMessage
	err := json.NewDecoder(rec.Body).Decode(&got)
	if err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(got) != 2 {
		t.Errorf("got %d keys, want 2", len(got))
	}

	if _, ok := got["error"]; !ok {
		t.Errorf("missing key error")
	}

	if _, ok := got["error_description"]; !ok {
		t.Errorf("missing key error_description")
	}
}

func assertTokenError(t *testing.T, rec *httptest.ResponseRecorder, wantStatus int, wantError tokenErrorResponse) {
	t.Helper()

	if rec.Code != wantStatus {
		t.Errorf("got code %d, want %d", rec.Code, wantStatus)
	}

	var got tokenErrorResponse
	err := json.NewDecoder(rec.Body).Decode(&got)
	if err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if got != wantError {
		t.Errorf("got error %+v, want %+v", got, wantError)
	}
}

func TestWriteTokenErrorServerError(t *testing.T) {
	t.Parallel()

	apiServer, _ := newTestServer(t, testServerOptions{})

	rec := httptest.NewRecorder()
	apiServer.writeTokenError(rec, errors.New("some error"))

	assertTokenError(t, rec, http.StatusInternalServerError, tokenErrorResponse{Error: "server_error", ErrorDescription: "internal server error"})
}

func TestTokenInvalidContentType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		contentType string
	}{
		{name: "<empty string>", contentType: ""},
		{name: "application/json", contentType: "application/json"},
		{name: "text/plain", contentType: "text/plain"},
		{name: "multipart/form-data", contentType: "multipart/form-data"},
		{name: "application/x-www-form-urlencoded; charset", contentType: "application/x-www-form-urlencoded; charset"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			apiServer, _ := newTestServer(t, testServerOptions{})

			req := httptest.NewRequest(http.MethodPost, "/token", nil)
			req.Header.Set("Content-Type", tt.contentType)

			rec := httptest.NewRecorder()
			apiServer.Routes().ServeHTTP(rec, req)

			assertTokenError(t, rec, http.StatusBadRequest, tokenErrorResponse{Error: "invalid_request", ErrorDescription: "invalid content-type"})
		})
	}
}

func TestTokenRequestBodyTooLarge(t *testing.T) {
	t.Parallel()

	apiServer, _ := newTestServer(t, testServerOptions{})

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(strings.Repeat("a", maxTokenRequestBytes+1)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

	rec := httptest.NewRecorder()
	apiServer.Routes().ServeHTTP(rec, req)

	assertTokenError(t, rec, http.StatusBadRequest, tokenErrorResponse{Error: "invalid_request", ErrorDescription: "request body too large"})
}

func TestTokenInvalidFormEncoding(t *testing.T) {
	t.Parallel()

	apiServer, _ := newTestServer(t, testServerOptions{})

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("grant_type=%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

	rec := httptest.NewRecorder()
	apiServer.Routes().ServeHTTP(rec, req)

	assertTokenError(t, rec, http.StatusBadRequest, tokenErrorResponse{Error: "invalid_request", ErrorDescription: "invalid form encoding"})
}

func TestTokenRepeatedParameters(t *testing.T) {
	t.Parallel()

	apiServer, _ := newTestServer(t, testServerOptions{})

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("client_secret=&client_secret=secret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

	rec := httptest.NewRecorder()
	apiServer.Routes().ServeHTTP(rec, req)

	assertTokenError(t, rec, http.StatusBadRequest, tokenErrorResponse{Error: "invalid_request", ErrorDescription: "parameter client_secret included more than once"})
}

func TestTokenMultipleAuthenticationMethods(t *testing.T) {
	t.Parallel()

	apiServer, _ := newTestServer(t, testServerOptions{})

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("grant_type=client_credentials&client_secret=secret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("Authorization", basicAuth("client", "secret"))

	rec := httptest.NewRecorder()
	apiServer.Routes().ServeHTTP(rec, req)

	assertTokenError(t, rec, http.StatusBadRequest, tokenErrorResponse{Error: "invalid_request", ErrorDescription: "only one authentication method is allowed"})
}

func TestTokenMissingClientID(t *testing.T) {
	t.Parallel()

	apiServer, _ := newTestServer(t, testServerOptions{})

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("grant_type=client_credentials&client_secret=secret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

	rec := httptest.NewRecorder()
	apiServer.Routes().ServeHTTP(rec, req)

	assertTokenError(t, rec, http.StatusBadRequest, tokenErrorResponse{Error: "invalid_client", ErrorDescription: "client_id is required"})
}

func TestTokenMissingClientSecret(t *testing.T) {
	t.Parallel()

	apiServer, _ := newTestServer(t, testServerOptions{})

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("grant_type=client_credentials&client_id=client"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

	rec := httptest.NewRecorder()
	apiServer.Routes().ServeHTTP(rec, req)

	assertTokenError(t, rec, http.StatusBadRequest, tokenErrorResponse{Error: "invalid_client", ErrorDescription: "client_secret is required"})
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
}

func TestTokenInvalidAuthHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		authHeader string
	}{
		{name: "missing client", authHeader: basicAuth("", "secret")},
		{name: "missing secret", authHeader: basicAuth("client", "")},
		{name: "invalid encoding", authHeader: basicAuth("client%zz", "secret")},
		{name: "invalid scheme", authHeader: "Bearer client:secret"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			apiServer, _ := newTestServer(t, testServerOptions{})

			req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("grant_type=client_credentials"))
			req.Header.Set("Authorization", tt.authHeader)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

			rec := httptest.NewRecorder()
			apiServer.Routes().ServeHTTP(rec, req)

			if rec.Header().Get("WWW-Authenticate") != basicChallenge {
				t.Errorf("got WWW-Authenticate header %q, want %q", rec.Header().Get("WWW-Authenticate"), basicChallenge)
			}

			assertTokenError(t, rec, http.StatusUnauthorized, tokenErrorResponse{Error: "invalid_client", ErrorDescription: "invalid authorization header"})
		})
	}
}

func TestTokenClientIDMismatch(t *testing.T) {
	t.Parallel()

	apiServer, _ := newTestServer(t, testServerOptions{})

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("grant_type=client_credentials&client_id=client"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.SetBasicAuth("other-client", "secret")

	rec := httptest.NewRecorder()
	apiServer.Routes().ServeHTTP(rec, req)

	assertTokenError(t, rec, http.StatusBadRequest, tokenErrorResponse{Error: "invalid_request", ErrorDescription: "client_id mismatch"})
}

func TestTokenInvalidClientCredentials(t *testing.T) {
	t.Parallel()

	apiServer, _ := newTestServer(t, testServerOptions{
		clientAuthenticator: &fakeClientAuthenticator{
			authenticate: func(ctx context.Context, clientID, clientSecret string) (client.Client, error) {
				if clientID != "client" || clientSecret != "secret" {
					return client.Client{}, client.ErrUnknownClientOrWrongSecret
				}
				return client.Client{ID: "client"}, nil
			},
		},
	})

	tests := []struct {
		name                string
		authHeader          string
		formClientID        string
		formClientSecret    string
		wantStatus          int
		wantWWWAuthenticate string
	}{
		{name: "basic with wrong client ID", authHeader: basicAuth("other-client", "secret"), wantStatus: http.StatusUnauthorized, wantWWWAuthenticate: basicChallenge},
		{name: "basic with wrong secret", authHeader: basicAuth("client", "other-secret"), wantStatus: http.StatusUnauthorized, wantWWWAuthenticate: basicChallenge},
		{name: "form with wrong client ID", formClientID: "other-client", formClientSecret: "secret", wantStatus: http.StatusBadRequest},
		{name: "form with wrong secret", formClientID: "client", formClientSecret: "other-secret", wantStatus: http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(
				url.Values{
					"grant_type":    {"client_credentials"},
					"client_id":     {tt.formClientID},
					"client_secret": {tt.formClientSecret},
				}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			rec := httptest.NewRecorder()
			apiServer.Routes().ServeHTTP(rec, req)

			if rec.Header().Get("WWW-Authenticate") != tt.wantWWWAuthenticate {
				t.Errorf("got WWW-Authenticate header %q, want %q", rec.Header().Get("WWW-Authenticate"), tt.wantWWWAuthenticate)
			}
			assertTokenError(t, rec, tt.wantStatus, tokenErrorResponse{Error: "invalid_client", ErrorDescription: "invalid client credentials"})
		})
	}
}

func TestTokenAuthenticatorError(t *testing.T) {
	t.Parallel()

	apiServer, _ := newTestServer(t, testServerOptions{
		clientAuthenticator: &fakeClientAuthenticator{
			authenticate: func(ctx context.Context, clientID, clientSecret string) (client.Client, error) {
				return client.Client{}, errors.New("authentication failed")
			},
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("grant_type=client_credentials&client_id=client&client_secret=secret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

	rec := httptest.NewRecorder()
	apiServer.Routes().ServeHTTP(rec, req)

	assertTokenError(t, rec, http.StatusInternalServerError, tokenErrorResponse{Error: "server_error", ErrorDescription: "internal server error"})
}

func TestTokenInvalidGrantType(t *testing.T) {
	t.Parallel()

	apiServer, _ := newTestServer(t, testServerOptions{
		clientAuthenticator: &fakeClientAuthenticator{
			authenticate: func(ctx context.Context, clientID, clientSecret string) (client.Client, error) {
				return client.Client{GrantTypes: []client.GrantType{"some_grant_type"}}, nil
			},
		},
	})

	tests := []struct {
		name            string
		grantType       string
		wantCode        string
		wantDescription string
	}{
		{name: "missing grant type", grantType: "", wantCode: "invalid_request", wantDescription: "grant_type is required"},
		{name: "unsupported grant type", grantType: "invalid", wantCode: "unsupported_grant_type", wantDescription: "unsupported grant_type"},
		{name: "unauthorized grant type", grantType: "client_credentials", wantCode: "unauthorized_client", wantDescription: "unauthorized grant_type"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(url.Values{
				"grant_type": {tt.grantType},
			}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
			req.Header.Set("Authorization", basicAuth("client", "secret"))

			rec := httptest.NewRecorder()
			apiServer.Routes().ServeHTTP(rec, req)

			assertTokenError(t, rec, http.StatusBadRequest, tokenErrorResponse{Error: tt.wantCode, ErrorDescription: tt.wantDescription})
		})
	}
}

func TestTokenInvalidScope(t *testing.T) {
	t.Parallel()

	apiServer, _ := newTestServer(t, testServerOptions{
		clientAuthenticator: &fakeClientAuthenticator{
			authenticate: func(ctx context.Context, clientID, clientSecret string) (client.Client, error) {
				return client.Client{
					GrantTypes: []client.GrantType{client.GrantTypeClientCredentials},
					Scopes:     []string{"scope1", "scope2"},
				}, nil
			},
		},
	})

	tests := []struct {
		name  string
		scope string
	}{
		{name: "unauthorized single scope", scope: "scope3"},
		{name: "unauthorized multiple scopes", scope: "scope3 scope4"},
		{name: "unauthorized multiple scopes with empty scope", scope: "scope1 "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(url.Values{
				"grant_type": {string(client.GrantTypeClientCredentials)},
				"scope":      {tt.scope},
			}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
			req.Header.Set("Authorization", basicAuth("client", "secret"))

			rec := httptest.NewRecorder()
			apiServer.Routes().ServeHTTP(rec, req)

			assertTokenError(t, rec, http.StatusBadRequest, tokenErrorResponse{Error: "invalid_scope", ErrorDescription: "unknown or malformed scope"})
		})
	}
}

func TestTokenInvalidResource(t *testing.T) {
	t.Parallel()

	apiServer, _ := newTestServer(t, testServerOptions{
		clientAuthenticator: &fakeClientAuthenticator{
			authenticate: func(ctx context.Context, clientID, clientSecret string) (client.Client, error) {
				return client.Client{
					Audiences:  []string{"resource1", "resource2"},
					GrantTypes: []client.GrantType{client.GrantTypeClientCredentials},
					Scopes:     []string{"scope1", "scope2"},
				}, nil
			},
		},
	})

	tests := []struct {
		name      string
		resources []string
	}{
		{name: "single unknown resource", resources: []string{"unknown1"}},
		{name: "multiple unknown resources", resources: []string{"unknown1", "unknown2"}},
		{name: "one known resource with an unknown resource", resources: []string{"resource1", "unknown2"}},
		{name: "one unknown resource with a known resource", resources: []string{"unknown1", "resource2"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(url.Values{
				"grant_type": {string(client.GrantTypeClientCredentials)},
				"resource":   tt.resources,
				"scope":      {"scope1"},
			}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
			req.Header.Set("Authorization", basicAuth("client", "secret"))

			rec := httptest.NewRecorder()
			apiServer.Routes().ServeHTTP(rec, req)

			assertTokenError(t, rec, http.StatusBadRequest, tokenErrorResponse{Error: "invalid_target", ErrorDescription: "unknown or malformed resource"})
		})
	}
}

func getPublicKeyFromJWKS(t *testing.T, apiServer *Server) (*ecdsa.PublicKey, string) {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/jwks", nil)
	rec := httptest.NewRecorder()
	apiServer.Routes().ServeHTTP(rec, req)

	var jwks jwk.Set
	err := json.NewDecoder(rec.Body).Decode(&jwks)
	if err != nil {
		t.Fatalf("failed to decode jwks: %v", err)
	}

	if len(jwks.Keys) == 0 {
		t.Fatalf("got 0 keys in jwks")
	}

	jwk := jwks.Keys[0]
	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		t.Fatalf("failed to decode x: %v", err)
	}
	y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		t.Fatalf("failed to decode y: %v", err)
	}

	pubKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append([]byte{0x04}, append(x, y...)...))
	if err != nil {
		t.Fatalf("failed to parse public key: %v", err)
	}

	return pubKey, jwk.KID
}

func verifyAndDecodeAccessToken(
	t *testing.T,
	accessToken string,
	publicKey *ecdsa.PublicKey,
) (header jwt.Header, claims jwt.AccessTokenClaims) {
	t.Helper()

	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		t.Fatalf("got %d parts in access token, want 3", len(parts))
	}

	// Verify the signature
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("failed to decode signature: %v", err)
	}

	if len(signature) != 64 {
		t.Fatalf("got %d bytes in signature, want 64", len(signature))
	}

	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	var r, s big.Int
	r.SetBytes(signature[0:32])
	s.SetBytes(signature[32:64])
	if !ecdsa.Verify(publicKey, digest[:], &r, &s) {
		t.Errorf("failed to verify signature")
	}

	// Decode and unmarshal the header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("failed to decode access token header: %v", err)
	}

	err = json.Unmarshal(headerBytes, &header)
	if err != nil {
		t.Fatalf("failed to unmarshal access token header: %v", err)
	}

	// Decode and unmarshal the claims
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode access token claims: %v", err)
	}

	err = json.Unmarshal(claimsBytes, &claims)
	if err != nil {
		t.Fatalf("failed to unmarshal access token claims: %v", err)
	}

	return header, claims
}

func TestTokenClientCredentialsSuccess(t *testing.T) {
	t.Parallel()

	c := client.Client{
		ID:         "client",
		Audiences:  []string{"resource1", "resource2"},
		GrantTypes: []client.GrantType{client.GrantTypeClientCredentials},
		Scopes:     []string{"scope1", "scope2"},
	}
	now := time.Now()
	accessTokenLifetime := 10 * time.Minute

	apiServer, _ := newTestServer(t, testServerOptions{
		accessTokenLifetime: accessTokenLifetime,
		clientAuthenticator: &fakeClientAuthenticator{
			authenticate: func(ctx context.Context, clientID, clientSecret string) (client.Client, error) {
				if clientID != "client" || clientSecret != "secret" {
					return client.Client{}, client.ErrUnknownClientOrWrongSecret
				}
				return c, nil
			},
		},
		now: func() time.Time {
			return now
		},
	})

	publicKey, kid := getPublicKeyFromJWKS(t, apiServer)

	tests := []struct {
		name       string
		authHeader string
		body       string
		wantAud    []string
		wantScope  string
	}{
		{
			name: "body credentials",
			body: url.Values{
				"grant_type":    {"client_credentials"},
				"resource":      {"resource1", "resource2"},
				"scope":         {"scope1 scope2"},
				"client_id":     {"client"},
				"client_secret": {"secret"},
			}.Encode(),
			wantAud:   []string{"resource1", "resource2"},
			wantScope: "scope1 scope2",
		},
		{
			name:       "header credentials",
			authHeader: basicAuth("client", "secret"),
			body: url.Values{
				"grant_type": {"client_credentials"},
				"resource":   {"resource1", "resource2"},
				"scope":      {"scope1 scope2"},
			}.Encode(),
			wantAud:   []string{"resource1", "resource2"},
			wantScope: "scope1 scope2",
		},
		{
			name:       "client_id in body and header, same value",
			authHeader: basicAuth("client", "secret"),
			body: url.Values{
				"grant_type": {"client_credentials"},
				"resource":   {"resource1", "resource2"},
				"scope":      {"scope1 scope2"},
				"client_id":  {"client"},
			}.Encode(),
			wantAud:   []string{"resource1", "resource2"},
			wantScope: "scope1 scope2",
		},
		{
			name:       "default scope and resources",
			authHeader: basicAuth("client", "secret"),
			body: url.Values{
				"grant_type": {"client_credentials"},
				"client_id":  {"client"},
			}.Encode(),
			wantAud:   []string{"resource1", "resource2"},
			wantScope: "scope1 scope2",
		},
		{
			name:       "duplicate scope",
			authHeader: basicAuth("client", "secret"),
			body: url.Values{
				"grant_type": {"client_credentials"},
				"client_id":  {"client"},
				"scope":      {"scope1 scope1"},
			}.Encode(),
			wantAud:   []string{"resource1", "resource2"},
			wantScope: "scope1",
		},
		{
			name:       "scope order",
			authHeader: basicAuth("client", "secret"),
			body: url.Values{
				"grant_type": {"client_credentials"},
				"client_id":  {"client"},
				"scope":      {"scope2 scope1"},
			}.Encode(),
			wantAud:   []string{"resource1", "resource2"},
			wantScope: "scope2 scope1",
		},
		{
			name:       "resource with an empty value",
			authHeader: basicAuth("client", "secret"),
			body: url.Values{
				"grant_type": {"client_credentials"},
				"client_id":  {"client"},
				"resource":   {""},
			}.Encode(),
			wantAud:   []string{"resource1", "resource2"},
			wantScope: "scope1 scope2",
		},
		{
			name:       "resource with an empty value along with a valid value",
			authHeader: basicAuth("client", "secret"),
			body: url.Values{
				"grant_type": {"client_credentials"},
				"client_id":  {"client"},
				"resource":   {"", "resource1"},
			}.Encode(),
			wantAud:   []string{"resource1"},
			wantScope: "scope1 scope2",
		},
		{
			name:       "duplicate resource",
			authHeader: basicAuth("client", "secret"),
			body: url.Values{
				"grant_type": {"client_credentials"},
				"client_id":  {"client"},
				"resource":   {"resource1", "resource1"},
			}.Encode(),
			wantAud:   []string{"resource1"},
			wantScope: "scope1 scope2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			rec := httptest.NewRecorder()
			apiServer.Routes().ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("got code %d, want %d", rec.Code, http.StatusOK)
			}

			if rec.Header().Get("Content-Type") != "application/json" {
				t.Errorf("got Content-Type header %q, want %q", rec.Header().Get("Content-Type"), "application/json")
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("got Cache-Control header %q, want %q", rec.Header().Get("Cache-Control"), "no-store")
			}
			if rec.Header().Get("Pragma") != "no-cache" {
				t.Errorf("got Pragma header %q, want %q", rec.Header().Get("Pragma"), "no-cache")
			}

			var got tokenResponse
			err := json.NewDecoder(rec.Body).Decode(&got)
			if err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			if got.TokenType != "Bearer" {
				t.Errorf("got token type %q, want %q", got.TokenType, "Bearer")
			}
			if got.ExpiresIn != int(accessTokenLifetime.Seconds()) {
				t.Errorf("got expires in %d, want %d", got.ExpiresIn, int(accessTokenLifetime.Seconds()))
			}
			if got.Scope != tt.wantScope {
				t.Errorf("got scope %q, want %q", got.Scope, tt.wantScope)
			}

			header, claims := verifyAndDecodeAccessToken(t, got.AccessToken, publicKey)

			// Verify the header
			if header.Typ != jwt.HeaderTypeAccessToken {
				t.Errorf("got header type %q, want %q", header.Typ, jwt.HeaderTypeAccessToken)
			}
			if header.KID != kid {
				t.Errorf("got header KID %q, want %q", header.KID, kid)
			}
			if header.Alg != "ES256" {
				t.Errorf("got header algorithm %q, want %q", header.Alg, "ES256")
			}

			// Verify the claims
			if claims.Iss != apiServer.issuer {
				t.Errorf("got claims issuer %q, want %q", claims.Iss, apiServer.issuer)
			}
			if claims.Sub != c.ID {
				t.Errorf("got claims subject %q, want %q", claims.Sub, c.ID)
			}
			if !slices.Equal(claims.Aud, tt.wantAud) {
				t.Errorf("got claims audience %q, want %q", claims.Aud, tt.wantAud)
			}
			if claims.Exp != now.Add(accessTokenLifetime).Unix() {
				t.Errorf("got claims expiration time %d, want %d", claims.Exp, now.Add(accessTokenLifetime).Unix())
			}
			if claims.Iat != now.Unix() {
				t.Errorf("got claims issued at %d, want %d", claims.Iat, now.Unix())
			}
			if claims.Jti == "" {
				t.Errorf("got claims JTI empty")
			}
			if claims.ClientID != c.ID {
				t.Errorf("got claims client ID %q, want %q", claims.ClientID, c.ID)
			}
			if claims.Scope != tt.wantScope {
				t.Errorf("got claims scope %q, want %q", claims.Scope, tt.wantScope)
			}
		})
	}
}

func TestTokenClientCredentialsExactKeys(t *testing.T) {
	t.Parallel()

	c := client.Client{
		ID:         "client",
		Audiences:  []string{"resource1", "resource2"},
		GrantTypes: []client.GrantType{client.GrantTypeClientCredentials},
		Scopes:     []string{"scope1", "scope2"},
	}

	apiServer, _ := newTestServer(t, testServerOptions{
		clientAuthenticator: &fakeClientAuthenticator{
			authenticate: func(ctx context.Context, clientID, clientSecret string) (client.Client, error) {
				return c, nil
			},
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(url.Values{
		"grant_type": {"client_credentials"},
		"resource":   {"resource1", "resource2"},
		"scope":      {"scope1 scope2"},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("Authorization", basicAuth("client", "secret"))

	rec := httptest.NewRecorder()
	apiServer.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("got code %d, want %d", rec.Code, http.StatusOK)
	}

	var got map[string]json.RawMessage
	err := json.NewDecoder(rec.Body).Decode(&got)
	if err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(got) != 4 {
		t.Errorf("got %d keys, want 4", len(got))
	}

	wantResponseKeys := []string{
		"access_token",
		"token_type",
		"expires_in",
		"scope",
	}
	for _, key := range wantResponseKeys {
		if _, ok := got[key]; !ok {
			t.Errorf("missing key %q", key)
		}
	}

	var accessToken string
	err = json.Unmarshal(got["access_token"], &accessToken)
	if err != nil {
		t.Fatalf("failed to unmarshal access token: %v", err)
	}

	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		t.Fatalf("got %d parts in access token, want 3", len(parts))
	}

	// Decode and unmarshal the header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("failed to decode access token header: %v", err)
	}

	var header map[string]json.RawMessage
	err = json.Unmarshal(headerBytes, &header)
	if err != nil {
		t.Fatalf("failed to unmarshal access token header: %v", err)
	}

	if len(header) != 3 {
		t.Errorf("got %d keys in header, want 3", len(header))
	}

	wantHeaderKeys := []string{
		"typ",
		"alg",
		"kid",
	}
	for _, key := range wantHeaderKeys {
		if _, ok := header[key]; !ok {
			t.Errorf("missing key %q", key)
		}
	}

	// Decode and unmarshal the claims
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode access token claims: %v", err)
	}

	var claims map[string]json.RawMessage
	err = json.Unmarshal(claimsBytes, &claims)
	if err != nil {
		t.Fatalf("failed to unmarshal access token claims: %v", err)
	}

	if len(claims) != 8 {
		t.Errorf("got %d keys in claims, want 8", len(claims))
	}

	wantClaimsKeys := []string{
		"iss", "sub", "aud", "exp", "iat", "jti", "client_id", "scope",
	}
	for _, key := range wantClaimsKeys {
		if _, ok := claims[key]; !ok {
			t.Errorf("missing key %q", key)
		}
	}
}

func TestTokenClientCredentialsBasicEncoding(t *testing.T) {
	t.Parallel()

	c := client.Client{
		ID:         "client",
		Audiences:  []string{"resource1", "resource2"},
		GrantTypes: []client.GrantType{client.GrantTypeClientCredentials},
		Scopes:     []string{"scope1", "scope2"},
	}

	var gotClientID, gotClientSecret string
	apiServer, _ := newTestServer(t, testServerOptions{
		clientAuthenticator: &fakeClientAuthenticator{
			authenticate: func(ctx context.Context, clientID, clientSecret string) (client.Client, error) {
				gotClientID = clientID
				gotClientSecret = clientSecret
				return c, nil
			},
		},
	})

	const wantClientID = "client% :"
	const wantClientSecret = "secret%zz"

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(url.Values{
		"grant_type": {"client_credentials"},
		"resource":   {"resource1", "resource2"},
		"scope":      {"scope1 scope2"},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("Authorization", basicAuth(
		url.QueryEscape(wantClientID),
		url.QueryEscape(wantClientSecret),
	))

	rec := httptest.NewRecorder()
	apiServer.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("got code %d, want %d", rec.Code, http.StatusOK)
	}

	if gotClientID != wantClientID {
		t.Errorf("got client ID %q, want %q", gotClientID, wantClientID)
	}
	if gotClientSecret != wantClientSecret {
		t.Errorf("got client secret %q, want %q", gotClientSecret, wantClientSecret)
	}
}

func TestTokenClientCredentialsClientWithNoScope(t *testing.T) {
	t.Parallel()

	c := client.Client{
		ID:         "client",
		Audiences:  []string{"resource1", "resource2"},
		GrantTypes: []client.GrantType{client.GrantTypeClientCredentials},
		Scopes:     []string{},
	}

	apiServer, _ := newTestServer(t, testServerOptions{
		clientAuthenticator: &fakeClientAuthenticator{
			authenticate: func(ctx context.Context, clientID, clientSecret string) (client.Client, error) {
				return c, nil
			},
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(url.Values{
		"grant_type": {"client_credentials"},
		"resource":   {"resource1", "resource2"},
		"scope":      {""}, // empty scope in the request should be ignored
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("Authorization", basicAuth("client", "secret"))

	rec := httptest.NewRecorder()
	apiServer.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("got code %d, want %d", rec.Code, http.StatusOK)
	}

	var got map[string]json.RawMessage
	err := json.NewDecoder(rec.Body).Decode(&got)
	if err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if _, ok := got["scope"]; ok {
		t.Errorf("got scope key, want none")
	}

	var accessToken string
	err = json.Unmarshal(got["access_token"], &accessToken)
	if err != nil {
		t.Fatalf("failed to unmarshal access token: %v", err)
	}

	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		t.Fatalf("got %d parts in access token, want 3", len(parts))
	}

	// Decode and unmarshal the claims
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode access token claims: %v", err)
	}

	var claims map[string]json.RawMessage
	err = json.Unmarshal(claimsBytes, &claims)
	if err != nil {
		t.Fatalf("failed to unmarshal access token claims: %v", err)
	}

	if _, ok := claims["scope"]; ok {
		t.Errorf("got scope key in claims, want none")
	}
}
