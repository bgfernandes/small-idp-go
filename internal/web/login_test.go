package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/bgfernandes/small-idp-go/internal/user"
)

func assertHTMLTemplate(
	t *testing.T,
	rec *httptest.ResponseRecorder,
	wantStatus int,
	wantStrings []string,
	dontWantStrings []string,
) {
	t.Helper()

	if rec.Code != wantStatus {
		t.Errorf("got code %d, want %d", rec.Code, wantStatus)
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
	for _, wantString := range wantStrings {
		if !strings.Contains(body, wantString) {
			t.Errorf("got body %q, want body to contain %q", body, wantString)
		}
	}
	for _, dontWantString := range dontWantStrings {
		if strings.Contains(body, dontWantString) {
			t.Errorf("got body %q, want body to not contain %q", body, dontWantString)
		}
	}
}

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

			assertHTMLTemplate(
				t,
				rec,
				http.StatusOK,
				[]string{"<form action=\"" + tt.wantAction + "\"", "Login"},
				nil,
			)
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

	assertHTMLTemplate(
		t,
		rec,
		http.StatusOK,
		[]string{"<form action=\"/tenant/login\"", "Login"},
		nil,
	)
}

func TestPostLoginInvalidContentType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		contentType string
	}{
		{name: "<empty string>", contentType: ""},
		{name: "application/json", contentType: "application/json"},
		{name: "text/plain", contentType: "text/plain"},
		{name: "multipart/form-data", contentType: "multipart/form-data"},
		{
			name:        "application/x-www-form-urlencoded; charset",
			contentType: "application/x-www-form-urlencoded; charset",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			webServer := newTestServer(t, testServerOptions{})

			req := httptest.NewRequest(http.MethodPost, "/login", nil)
			req.Header.Set("Content-Type", tt.contentType)

			rec := httptest.NewRecorder()
			webServer.Routes().ServeHTTP(rec, req)

			assertHTMLTemplate(
				t,
				rec,
				http.StatusBadRequest,
				[]string{"<form action=\"/login\"", "Invalid content type."},
				nil,
			)
		})
	}
}

func TestPostLoginRequestBodyTooLarge(t *testing.T) {
	t.Parallel()

	webServer := newTestServer(t, testServerOptions{})

	req := httptest.NewRequest(
		http.MethodPost,
		"/login",
		strings.NewReader(strings.Repeat("a", maxLoginRequestBytes+1)),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

	rec := httptest.NewRecorder()
	webServer.Routes().ServeHTTP(rec, req)

	assertHTMLTemplate(
		t,
		rec,
		http.StatusBadRequest,
		[]string{"<form action=\"/login\"", "Request body too large."},
		nil,
	)
}

func TestPostLoginInvalidFormEncoding(t *testing.T) {
	t.Parallel()

	webServer := newTestServer(t, testServerOptions{})

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("email=%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

	rec := httptest.NewRecorder()
	webServer.Routes().ServeHTTP(rec, req)

	assertHTMLTemplate(
		t,
		rec,
		http.StatusBadRequest,
		[]string{"<form action=\"/login\"", "Invalid form encoding."},
		nil,
	)
}

func TestPostLoginUserStoreError(t *testing.T) {
	t.Parallel()

	webServer := newTestServer(t, testServerOptions{
		userAuthenticator: &fakeUserAuthenticator{
			authenticate: func(ctx context.Context, email, password string) (user.User, error) {
				return user.User{}, errors.New("database error")
			},
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(
		url.Values{
			"email":    {"user@example.com"},
			"password": {"some-password"},
		}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

	rec := httptest.NewRecorder()
	webServer.Routes().ServeHTTP(rec, req)

	assertHTMLTemplate(
		t,
		rec,
		http.StatusInternalServerError,
		[]string{"<form action=\"/login\"", "Internal Server Error."},
		[]string{"some-password", "database error"},
	)
}

func TestPostLogin(t *testing.T) {
	t.Parallel()

	webServer := newTestServer(t, testServerOptions{
		userAuthenticator: &fakeUserAuthenticator{
			authenticate: func(ctx context.Context, email, password string) (user.User, error) {
				if email != "user@example.com" || password != "correct-password" {
					return user.User{}, user.ErrUnknownUserOrWrongPassword
				}
				return user.User{Email: "user@example.com"}, nil
			},
		},
	})

	tests := []struct {
		name        string
		email       string
		password    string
		wantStrings []string
	}{
		{
			name:        "unknown email",
			email:       "unknown@example.com",
			password:    "correct-password",
			wantStrings: []string{"<form action=\"/login\"", "Unknown user or wrong password."},
		},
		{
			name:        "wrong password",
			email:       "user@example.com",
			password:    "other-password",
			wantStrings: []string{"<form action=\"/login\"", "Unknown user or wrong password."},
		},
		{
			name:        "unknown email and wrong password",
			email:       "unknown@example.com",
			password:    "other-password",
			wantStrings: []string{"<form action=\"/login\"", "Unknown user or wrong password."},
		},
		{
			name:        "no email",
			password:    "correct-password",
			wantStrings: []string{"<form action=\"/login\"", "Unknown user or wrong password."},
		},
		{
			name:        "no password",
			email:       "user@example.com",
			wantStrings: []string{"<form action=\"/login\"", "Unknown user or wrong password."},
		},
		{
			name:        "empty form",
			wantStrings: []string{"<form action=\"/login\"", "Unknown user or wrong password."},
		},
		{
			name:        "correct email and password",
			email:       "user@example.com",
			password:    "correct-password",
			wantStrings: []string{"You are logged in as user@example.com."},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(
				url.Values{
					"email":    {tt.email},
					"password": {tt.password},
				}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

			rec := httptest.NewRecorder()
			webServer.Routes().ServeHTTP(rec, req)

			var dontWantStrings []string
			if tt.password != "" {
				dontWantStrings = append(dontWantStrings, tt.password)
			}

			assertHTMLTemplate(
				t,
				rec,
				http.StatusOK,
				tt.wantStrings,
				dontWantStrings,
			)
		})
	}
}
