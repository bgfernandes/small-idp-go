package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bgfernandes/small-idp-go/internal/client"
	"github.com/bgfernandes/small-idp-go/internal/jwk"
)

type fakeClientAuthenticator struct {
	authenticate func(ctx context.Context, clientID, clientSecret string) (client.Client, error)
}

func (f *fakeClientAuthenticator) Authenticate(ctx context.Context, clientID, clientSecret string) (client.Client, error) {
	return f.authenticate(ctx, clientID, clientSecret)
}

func TestNewServerIssuerValidation(t *testing.T) {
	t.Parallel()

	clientAuthenticator := &fakeClientAuthenticator{}

	key, err := jwk.Generate()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	log := slog.New(slog.DiscardHandler)

	tests := []struct {
		name    string
		issuer  string
		wantErr bool
	}{
		{name: "valid root issuer", issuer: "http://localhost:8080", wantErr: false},
		{name: "valid https issuer", issuer: "https://idp.example.com", wantErr: false},
		{name: "valid issuer with path", issuer: "https://idp.example.com/tenant", wantErr: false},
		{name: "empty string issuer", issuer: "", wantErr: true},
		{name: "unparseable issuer", issuer: "://bad", wantErr: true},
		{name: "no scheme issuer", issuer: "idp.example.com", wantErr: true},
		{name: "wrong scheme issuer", issuer: "ftp://idp.example.com", wantErr: true},
		{name: "no host issuer", issuer: "http://", wantErr: true},
		{name: "issuer with query", issuer: "http://idp.example.com?x=1", wantErr: true},
		{name: "issuer with fragment", issuer: "http://idp.example.com#x=1", wantErr: true},
		{name: "issuer with trailing slash", issuer: "http://idp.example.com/", wantErr: true},
		{name: "issuer with path and trailing slash", issuer: "http://idp.example.com/tenant/", wantErr: true},
		{name: "issuer with trailing ?", issuer: "http://idp.example.com?", wantErr: true},
		{name: "issuer with trailing #", issuer: "http://idp.example.com#", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewServer(Config{
				ClientAuthenticator: clientAuthenticator,
				Issuer:              tt.issuer,
				Key:                 key,
				Log:                 log,
				Now:                 time.Now,
			})
			if (err != nil) != tt.wantErr {
				t.Errorf("NewServer(%q) = %v, wantErr %t", tt.issuer, err, tt.wantErr)
			}
		})
	}
}

func TestNewServerRequiredDependencies(t *testing.T) {
	t.Parallel()

	clientAuthenticator := &fakeClientAuthenticator{}

	key, err := jwk.Generate()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	log := slog.New(slog.DiscardHandler)

	tests := []struct {
		name                string
		clientAuthenticator ClientAuthenticator
		key                 *jwk.Key
		log                 *slog.Logger
		now                 func() time.Time
	}{
		{name: "nil key", clientAuthenticator: clientAuthenticator, key: nil, log: log, now: time.Now},
		{name: "nil logger", clientAuthenticator: clientAuthenticator, key: key, log: nil, now: time.Now},
		{name: "nil clientAuthenticator", clientAuthenticator: nil, key: key, log: log, now: time.Now},
		{name: "nil now function", clientAuthenticator: clientAuthenticator, key: key, log: log, now: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewServer(Config{
				ClientAuthenticator: tt.clientAuthenticator,
				Issuer:              "http://localhost:8080",
				Key:                 tt.key,
				Log:                 tt.log,
				Now:                 tt.now,
			})
			if err == nil {
				t.Errorf("got nil error, want error for %+v", tt)
			}
		})
	}
}

type testServerOptions struct {
	clientAuthenticator ClientAuthenticator
	issuer              string
	now                 func() time.Time
}

func newTestServer(t *testing.T, opts testServerOptions) (*Server, *jwk.Key) {
	t.Helper()

	if opts.clientAuthenticator == nil {
		opts.clientAuthenticator = &fakeClientAuthenticator{}
	}
	if opts.issuer == "" {
		opts.issuer = "http://localhost:8080"
	}
	if opts.now == nil {
		opts.now = time.Now
	}

	key, err := jwk.Generate()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	log := slog.New(slog.DiscardHandler)

	apiServer, err := NewServer(
		Config{
			ClientAuthenticator: opts.clientAuthenticator,
			Issuer:              opts.issuer,
			Key:                 key,
			Log:                 log,
			Now:                 opts.now,
		},
	)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	return apiServer, key
}

func TestWriteJSON(t *testing.T) {
	t.Parallel()

	apiServer, _ := newTestServer(t, testServerOptions{})

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
