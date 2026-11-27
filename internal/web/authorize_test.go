package web

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/bgfernandes/small-idp-go/internal/client"
)

func assertRedirectWithError(
	t *testing.T,
	rec *httptest.ResponseRecorder,
	wantRedirectURL string,
	wantError authorizeError,
	wantState string,
) {
	t.Helper()

	if rec.Code != http.StatusFound {
		t.Errorf("got code %d, want %d", rec.Code, http.StatusFound)
	}

	if !strings.HasPrefix(rec.Header().Get("Location"), wantRedirectURL) {
		t.Errorf(
			"got redirect URL %q, want starting with %q",
			rec.Header().Get("Location"),
			wantRedirectURL,
		)
	}

	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("failed to parse location: %v", err)
	}

	wantU, err := url.Parse(wantRedirectURL)
	if err != nil {
		t.Fatalf("failed to parse want redirect URL: %v", err)
	}

	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		t.Fatalf("failed to parse query: %v", err)
	}

	u.RawQuery = ""
	wantU.RawQuery = ""
	if u.String() != wantU.String() {
		t.Errorf("got redirect URL %q, want %q", u.String(), wantU.String())
	}

	queryError, ok := query["error"]
	if !ok {
		t.Fatalf("missing error parameter in location")
	}
	if len(queryError) != 1 {
		t.Fatalf("duplicate error parameter in location")
	}
	if queryError[0] != wantError.code {
		t.Errorf("got error %q, want %q", queryError[0], wantError.code)
	}

	queryErrorDescription, ok := query["error_description"]
	if !ok {
		t.Fatalf("missing error_description parameter in location")
	}
	if len(queryErrorDescription) != 1 {
		t.Fatalf("duplicate error_description parameter in location")
	}
	if queryErrorDescription[0] != wantError.description {
		t.Errorf(
			"got error_description %q, want %q",
			queryErrorDescription[0],
			wantError.description,
		)
	}

	queryState, ok := query["state"]
	if !ok && wantState != "" {
		t.Fatalf("missing state parameter in location, want %q", wantState)
	}
	if ok && wantState == "" {
		t.Fatalf("got state parameter %v, want empty", queryState)
	}
	if ok && len(queryState) != 1 {
		t.Fatalf("duplicate state parameter in location")
	}
	if ok && queryState[0] != wantState {
		t.Errorf("got state %q, want %q", queryState[0], wantState)
	}
}

func TestRedirectWithErrorServerError(t *testing.T) {
	t.Parallel()

	webServer := newTestServer(t, testServerOptions{})

	req := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	rec := httptest.NewRecorder()
	webServer.redirectWithError(
		rec,
		req,
		"https://example.com",
		"state",
		errors.New("some error"),
	)

	assertRedirectWithError(
		t,
		rec,
		"https://example.com",
		authorizeError{code: "server_error", description: "internal server error"},
		"state",
	)
}

func TestAuthorizeWrongMethod(t *testing.T) {
	t.Parallel()

	webServer := newTestServer(t, testServerOptions{})

	req := httptest.NewRequest(http.MethodPost, "/authorize", nil)
	rec := httptest.NewRecorder()
	webServer.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("got code %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
	if rec.Header().Get("Allow") != "GET, HEAD" {
		t.Errorf("got Allow header %q, want %q", rec.Header().Get("Allow"), "GET, HEAD")
	}
}

func TestAuthorizeMalformedQuery(t *testing.T) {
	t.Parallel()

	webServer := newTestServer(t, testServerOptions{})

	req := httptest.NewRequest(http.MethodGet, "/authorize?client_id=%zz", nil)
	rec := httptest.NewRecorder()
	webServer.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("got code %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if rec.Body.String() != "invalid query\n" {
		t.Errorf("got body %q, want %q", rec.Body.String(), "invalid query\n")
	}
}

func TestAuthorizeNonRedirectionErrors(t *testing.T) {
	t.Parallel()

	webServer := newTestServer(
		t,
		testServerOptions{clientGetter: &fakeClientGetter{
			get: func(ctx context.Context, id string) (client.Client, error) {
				if id == "correct-client-id" {
					return client.Client{
						ID: "correct-client-id",
						RedirectionURIs: []string{
							"https://example.com/a",
							"https://example.com/a/b",
						},
					}, nil
				}
				if id == "db-error-client-id" {
					return client.Client{}, errors.New("database error")
				}
				return client.Client{}, client.ErrNotFound
			},
		}},
	)

	tests := []struct {
		name        string
		query       url.Values
		wantStatus  int
		wantMessage string
	}{
		{
			name: "missing client id",
			query: url.Values{
				"response_type": {"code"},
				"redirect_uri":  {"https://example.com/a"},
				"scope":         {"openid profile email"},
			},
			wantStatus:  http.StatusBadRequest,
			wantMessage: "missing client identifier\n",
		},
		{
			name: "duplicate client id",
			query: url.Values{
				"client_id":     {"correct-client-id", "correct-client-id"},
				"response_type": {"code"},
				"redirect_uri":  {"https://example.com/a"},
				"scope":         {"openid profile email"},
			},
			wantStatus:  http.StatusBadRequest,
			wantMessage: "duplicate client identifier\n",
		},
		{
			name: "empty client id",
			query: url.Values{
				"client_id":     {""},
				"response_type": {"code"},
				"redirect_uri":  {"https://example.com/a"},
				"scope":         {"openid profile email"},
			},
			wantStatus:  http.StatusBadRequest,
			wantMessage: "missing client identifier\n",
		},
		{
			name: "client id not found",
			query: url.Values{
				"client_id":     {"not-found-client-id"},
				"response_type": {"code"},
				"redirect_uri":  {"https://example.com/a"},
				"scope":         {"openid profile email"},
			},
			wantStatus:  http.StatusBadRequest,
			wantMessage: "missing or invalid client identifier\n",
		},
		{
			name: "database error getting client",
			query: url.Values{
				"client_id":     {"db-error-client-id"},
				"response_type": {"code"},
				"redirect_uri":  {"https://example.com/a"},
				"scope":         {"openid profile email"},
			},
			wantStatus:  http.StatusInternalServerError,
			wantMessage: "internal server error\n",
		},
		{
			name: "missing redirect uri",
			query: url.Values{
				"client_id":     {"correct-client-id"},
				"response_type": {"code"},
				"scope":         {"openid profile email"},
			},
			wantStatus:  http.StatusBadRequest,
			wantMessage: "missing or invalid redirection URI\n",
		},
		{
			name: "duplicate redirect uri",
			query: url.Values{
				"client_id":     {"correct-client-id"},
				"response_type": {"code"},
				"redirect_uri":  {"https://example.com/a", "https://example.com/a"},
				"scope":         {"openid profile email"},
			},
			wantStatus:  http.StatusBadRequest,
			wantMessage: "missing or invalid redirection URI\n",
		},
		{
			name: "empty redirect uri",
			query: url.Values{
				"client_id":     {"correct-client-id"},
				"response_type": {"code"},
				"redirect_uri":  {""},
				"scope":         {"openid profile email"},
			},
			wantStatus:  http.StatusBadRequest,
			wantMessage: "missing or invalid redirection URI\n",
		},
		{
			name: "invalid redirect uri",
			query: url.Values{
				"client_id":     {"correct-client-id"},
				"response_type": {"code"},
				"redirect_uri":  {"https://example.com/invalid"},
			},
			wantStatus:  http.StatusBadRequest,
			wantMessage: "missing or invalid redirection URI\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "/authorize", nil)
			req.URL.RawQuery = tt.query.Encode()
			rec := httptest.NewRecorder()
			webServer.Routes().ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("got code %d, want %d", rec.Code, tt.wantStatus)
			}
			body := rec.Body.String()
			if body != tt.wantMessage {
				t.Errorf("got body %q, want %q", body, tt.wantMessage)
			}
		})
	}
}

func TestAuthorizeRedirectedErrors(t *testing.T) {
	t.Parallel()

	webServer := newTestServer(
		t,
		testServerOptions{clientGetter: &fakeClientGetter{
			get: func(ctx context.Context, id string) (client.Client, error) {
				if id == "correct-client-id" {
					return client.Client{
						ID: "correct-client-id",
						GrantTypes: []client.GrantType{
							client.GrantTypeAuthorizationCode,
							client.GrantTypeClientCredentials,
						},
						RedirectionURIs: []string{
							"https://example.com/a",
							"https://example.com/a/b",
							"https://example.com/a?query=b%20c",
						},
						Scopes: []string{"openid", "profile", "email"},
					}, nil
				}
				if id == "unauthorized-client-id" {
					return client.Client{
						ID: "unauthorized-client-id",
						GrantTypes: []client.GrantType{
							client.GrantTypeClientCredentials,
						},
						RedirectionURIs: []string{
							"https://example.com/a",
							"https://example.com/a/b",
							"https://example.com/a?query=b%20c",
						},
						Scopes: []string{"openid", "profile", "email"},
					}, nil
				}
				return client.Client{}, client.ErrNotFound
			},
		}},
	)

	tests := []struct {
		name            string
		query           url.Values
		wantRedirectURL string
		wantError       authorizeError
		wantState       string
	}{
		{
			name: "duplicate state",
			query: url.Values{
				"client_id":     {"correct-client-id"},
				"response_type": {"code"},
				"redirect_uri":  {"https://example.com/a"},
				"scope":         {"openid profile email"},
				"state":         {"state1", "state2"},
			},
			wantRedirectURL: "https://example.com/a",
			wantError: authorizeError{
				code:        "invalid_request",
				description: "duplicate state parameter",
			},
			wantState: "",
		},
		{
			name: "unauthorized client",
			query: url.Values{
				"client_id":     {"unauthorized-client-id"},
				"response_type": {"code"},
				"redirect_uri":  {"https://example.com/a"},
				"scope":         {"openid profile email"},
				"state":         {"some-state"},
			},
			wantRedirectURL: "https://example.com/a",
			wantError: authorizeError{
				code:        "unauthorized_client",
				description: "client is not authorized to request an authorization code",
			},
			wantState: "some-state",
		},
		{
			name: "unauthorized client with no state",
			query: url.Values{
				"client_id":     {"unauthorized-client-id"},
				"response_type": {"code"},
				"redirect_uri":  {"https://example.com/a"},
				"scope":         {"openid profile email"},
			},
			wantRedirectURL: "https://example.com/a",
			wantError: authorizeError{
				code:        "unauthorized_client",
				description: "client is not authorized to request an authorization code",
			},
			wantState: "",
		},
		{
			name: "unauthorized client with empty state",
			query: url.Values{
				"client_id":     {"unauthorized-client-id"},
				"response_type": {"code"},
				"redirect_uri":  {"https://example.com/a"},
				"scope":         {"openid profile email"},
				"state":         {""},
			},
			wantRedirectURL: "https://example.com/a",
			wantError: authorizeError{
				code:        "unauthorized_client",
				description: "client is not authorized to request an authorization code",
			},
			wantState: "",
		},
		{
			name: "unauthorized client with redirect URI with query params",
			query: url.Values{
				"client_id":     {"unauthorized-client-id"},
				"response_type": {"code"},
				"redirect_uri":  {"https://example.com/a?query=b%20c"},
				"scope":         {"openid profile email"},
				"state":         {"some-state"},
			},
			wantRedirectURL: "https://example.com/a?query=b%20c",
			wantError: authorizeError{
				code:        "unauthorized_client",
				description: "client is not authorized to request an authorization code",
			},
			wantState: "some-state",
		},
		{
			name: "missing response type",
			query: url.Values{
				"client_id":    {"correct-client-id"},
				"redirect_uri": {"https://example.com/a"},
				"scope":        {"openid profile email"},
				"state":        {"some-state"},
			},
			wantRedirectURL: "https://example.com/a",
			wantError: authorizeError{
				code:        "invalid_request",
				description: "response_type is required",
			},
			wantState: "some-state",
		},
		{
			name: "duplicate response type",
			query: url.Values{
				"client_id":     {"correct-client-id"},
				"response_type": {"code", "code"},
				"redirect_uri":  {"https://example.com/a"},
				"scope":         {"openid profile email"},
				"state":         {"some-state"},
			},
			wantRedirectURL: "https://example.com/a",
			wantError: authorizeError{
				code:        "invalid_request",
				description: "duplicate response_type parameter",
			},
			wantState: "some-state",
		},
		{
			name: "empty response type",
			query: url.Values{
				"client_id":     {"correct-client-id"},
				"response_type": {""},
				"redirect_uri":  {"https://example.com/a"},
				"scope":         {"openid profile email"},
				"state":         {"some-state"},
			},
			wantRedirectURL: "https://example.com/a",
			wantError: authorizeError{
				code:        "invalid_request",
				description: "response_type is required",
			},
			wantState: "some-state",
		},
		{
			name: "unsupported response type",
			query: url.Values{
				"client_id":     {"correct-client-id"},
				"response_type": {"invalid"},
				"redirect_uri":  {"https://example.com/a"},
				"scope":         {"openid profile email"},
				"state":         {"some-state"},
			},
			wantRedirectURL: "https://example.com/a",
			wantError: authorizeError{
				code:        "unsupported_response_type",
				description: "response_type must be 'code'",
			},
			wantState: "some-state",
		},
		{
			name: "repeated scope parameter",
			query: url.Values{
				"client_id":     {"correct-client-id"},
				"response_type": {"code"},
				"redirect_uri":  {"https://example.com/a"},
				"scope":         {"openid", "profile"},
				"state":         {"some-state"},
			},
			wantRedirectURL: "https://example.com/a",
			wantError: authorizeError{
				code:        "invalid_request",
				description: "duplicate scope parameter",
			},
			wantState: "some-state",
		},
		{
			name: "unsupported scope",
			query: url.Values{
				"client_id":     {"correct-client-id"},
				"response_type": {"code"},
				"redirect_uri":  {"https://example.com/a"},
				"scope":         {"unsupported-scope"},
				"state":         {"some-state"},
			},
			wantRedirectURL: "https://example.com/a",
			wantError: authorizeError{
				code:        "invalid_scope",
				description: "unknown or malformed scope",
			},
			wantState: "some-state",
		},
		{
			name: "missing code challenge",
			query: url.Values{
				"client_id":     {"correct-client-id"},
				"response_type": {"code"},
				"redirect_uri":  {"https://example.com/a"},
				"scope":         {"openid profile email"},
				"state":         {"some-state"},
			},
			wantRedirectURL: "https://example.com/a",
			wantError: authorizeError{
				code:        "invalid_request",
				description: "code_challenge is required",
			},
			wantState: "some-state",
		},
		{
			name: "empty code challenge",
			query: url.Values{
				"client_id":      {"correct-client-id"},
				"code_challenge": {""},
				"response_type":  {"code"},
				"redirect_uri":   {"https://example.com/a"},
				"scope":          {"openid profile email"},
				"state":          {"some-state"},
			},
			wantRedirectURL: "https://example.com/a",
			wantError: authorizeError{
				code:        "invalid_request",
				description: "code_challenge is required",
			},
			wantState: "some-state",
		},
		{
			name: "duplicate code challenge",
			query: url.Values{
				"client_id":      {"correct-client-id"},
				"code_challenge": {"code1", "code2"},
				"response_type":  {"code"},
				"redirect_uri":   {"https://example.com/a"},
				"scope":          {"openid profile email"},
				"state":          {"some-state"},
			},
			wantRedirectURL: "https://example.com/a",
			wantError: authorizeError{
				code:        "invalid_request",
				description: "duplicate code_challenge parameter",
			},
			wantState: "some-state",
		},
		{
			name: "missing code_challenge_method",
			query: url.Values{
				"client_id":      {"correct-client-id"},
				"code_challenge": {"code1"},
				"response_type":  {"code"},
				"redirect_uri":   {"https://example.com/a"},
				"scope":          {"openid profile email"},
				"state":          {"some-state"},
			},
			wantRedirectURL: "https://example.com/a",
			wantError: authorizeError{
				code:        "invalid_request",
				description: "code_challenge_method must be S256",
			},
			wantState: "some-state",
		},
		{
			name: "empty code_challenge_method",
			query: url.Values{
				"client_id":             {"correct-client-id"},
				"code_challenge":        {"code1"},
				"code_challenge_method": {""},
				"response_type":         {"code"},
				"redirect_uri":          {"https://example.com/a"},
				"scope":                 {"openid profile email"},
				"state":                 {"some-state"},
			},
			wantRedirectURL: "https://example.com/a",
			wantError: authorizeError{
				code:        "invalid_request",
				description: "code_challenge_method must be S256",
			},
			wantState: "some-state",
		},
		{
			name: "duplicate code_challenge_method",
			query: url.Values{
				"client_id":             {"correct-client-id"},
				"code_challenge":        {"code1"},
				"code_challenge_method": {"method1", "method2"},
				"response_type":         {"code"},
				"redirect_uri":          {"https://example.com/a"},
				"scope":                 {"openid profile email"},
				"state":                 {"some-state"},
			},
			wantRedirectURL: "https://example.com/a",
			wantError: authorizeError{
				code:        "invalid_request",
				description: "duplicate code_challenge_method parameter",
			},
			wantState: "some-state",
		},
		{
			name: "plain code_challenge_method",
			query: url.Values{
				"client_id":             {"correct-client-id"},
				"code_challenge":        {"code1"},
				"code_challenge_method": {"plain"},
				"response_type":         {"code"},
				"redirect_uri":          {"https://example.com/a"},
				"scope":                 {"openid profile email"},
				"state":                 {"some-state"},
			},
			wantRedirectURL: "https://example.com/a",
			wantError: authorizeError{
				code:        "invalid_request",
				description: "code_challenge_method must be S256",
			},
			wantState: "some-state",
		},
		{
			name: "another code_challenge_method",
			query: url.Values{
				"client_id":             {"correct-client-id"},
				"code_challenge":        {"code1"},
				"code_challenge_method": {"another"},
				"response_type":         {"code"},
				"redirect_uri":          {"https://example.com/a"},
				"scope":                 {"openid profile email"},
				"state":                 {"some-state"},
			},
			wantRedirectURL: "https://example.com/a",
			wantError: authorizeError{
				code:        "invalid_request",
				description: "code_challenge_method must be S256",
			},
			wantState: "some-state",
		},
		{
			name: "non base64 code challenge",
			query: url.Values{
				"client_id":             {"correct-client-id"},
				"code_challenge":        {"code!!!"},
				"code_challenge_method": {"S256"},
				"response_type":         {"code"},
				"redirect_uri":          {"https://example.com/a"},
				"scope":                 {"openid profile email"},
				"state":                 {"some-state"},
			},
			wantRedirectURL: "https://example.com/a",
			wantError: authorizeError{
				code:        "invalid_request",
				description: "invalid code_challenge",
			},
			wantState: "some-state",
		},
		{
			name: "smaller than 32 bytes code challenge",
			query: url.Values{
				"client_id":             {"correct-client-id"},
				"code_challenge":        {base64.RawURLEncoding.EncodeToString(make([]byte, 31))},
				"code_challenge_method": {"S256"},
				"response_type":         {"code"},
				"redirect_uri":          {"https://example.com/a"},
				"scope":                 {"openid profile email"},
				"state":                 {"some-state"},
			},
			wantRedirectURL: "https://example.com/a",
			wantError: authorizeError{
				code:        "invalid_request",
				description: "invalid code_challenge",
			},
			wantState: "some-state",
		},
		{
			name: "larger than 32 bytes code challenge",
			query: url.Values{
				"client_id":             {"correct-client-id"},
				"code_challenge":        {base64.RawURLEncoding.EncodeToString(make([]byte, 33))},
				"code_challenge_method": {"S256"},
				"response_type":         {"code"},
				"redirect_uri":          {"https://example.com/a"},
				"scope":                 {"openid profile email"},
				"state":                 {"some-state"},
			},
			wantRedirectURL: "https://example.com/a",
			wantError: authorizeError{
				code:        "invalid_request",
				description: "invalid code_challenge",
			},
			wantState: "some-state",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "/authorize", nil)
			req.URL.RawQuery = tt.query.Encode()
			rec := httptest.NewRecorder()
			webServer.Routes().ServeHTTP(rec, req)

			assertRedirectWithError(
				t,
				rec,
				tt.wantRedirectURL,
				tt.wantError,
				tt.wantState,
			)
		})
	}
}
