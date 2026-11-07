package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/bgfernandes/small-idp-go/internal/client"
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
