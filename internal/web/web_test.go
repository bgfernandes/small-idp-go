package web

import (
	"context"
	"log/slog"
	"testing"

	"github.com/bgfernandes/small-idp-go/internal/issuer"
	"github.com/bgfernandes/small-idp-go/internal/user"
)

type fakeUserAuthenticator struct {
	authenticate func(ctx context.Context, email, password string) (user.User, error)
}

func (f *fakeUserAuthenticator) Authenticate(
	ctx context.Context,
	email, password string,
) (user.User, error) {
	return f.authenticate(ctx, email, password)
}

func TestNewServerRequiredDependencies(t *testing.T) {
	t.Parallel()

	userAuthenticator := &fakeUserAuthenticator{}

	validIssuer, err := issuer.Parse("http://localhost:8080")
	if err != nil {
		t.Fatalf("failed to parse issuer: %v", err)
	}

	log := slog.New(slog.DiscardHandler)

	tests := []struct {
		name              string
		issuer            issuer.Issuer
		log               *slog.Logger
		userAuthenticator UserAuthenticator
		wantErr           bool
	}{
		{
			name:              "zero issuer",
			issuer:            issuer.Issuer{},
			log:               log,
			userAuthenticator: userAuthenticator,
			wantErr:           true,
		},
		{
			name:              "nil logger",
			issuer:            validIssuer,
			log:               nil,
			userAuthenticator: userAuthenticator,
			wantErr:           true,
		},
		{
			name:              "nil userAuthenticator",
			issuer:            validIssuer,
			log:               log,
			userAuthenticator: nil,
			wantErr:           true,
		},
		{
			name:              "valid config",
			issuer:            validIssuer,
			log:               log,
			userAuthenticator: userAuthenticator,
			wantErr:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewServer(Config{
				Issuer:            tt.issuer,
				Log:               tt.log,
				UserAuthenticator: tt.userAuthenticator,
			})
			if (err != nil) != tt.wantErr {
				t.Errorf("got error %v, want error %t", err, tt.wantErr)
			}
		})
	}
}

type testServerOptions struct {
	issuer            string
	userAuthenticator UserAuthenticator
}

func newTestServer(t *testing.T, opts testServerOptions) *Server {
	t.Helper()

	if opts.issuer == "" {
		opts.issuer = "http://localhost:8080"
	}

	if opts.userAuthenticator == nil {
		opts.userAuthenticator = &fakeUserAuthenticator{}
	}

	i, err := issuer.Parse(opts.issuer)
	if err != nil {
		t.Fatalf("failed to parse issuer: %v", err)
	}

	log := slog.New(slog.DiscardHandler)

	if opts.userAuthenticator == nil {
		opts.userAuthenticator = &fakeUserAuthenticator{}
	}

	webServer, err := NewServer(
		Config{
			Issuer:            i,
			Log:               log,
			UserAuthenticator: opts.userAuthenticator,
		},
	)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	return webServer
}
