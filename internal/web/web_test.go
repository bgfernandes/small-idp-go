package web

import (
	"context"
	"log/slog"
	"testing"

	"github.com/bgfernandes/small-idp-go/internal/client"
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

type fakeClientGetter struct {
	get func(ctx context.Context, clientID string) (client.Client, error)
}

func (f *fakeClientGetter) Get(
	ctx context.Context,
	clientID string,
) (client.Client, error) {
	return f.get(ctx, clientID)
}

func TestNewServerRequiredDependencies(t *testing.T) {
	t.Parallel()

	clientGetter := &fakeClientGetter{}
	userAuthenticator := &fakeUserAuthenticator{}

	validIssuer, err := issuer.Parse("http://localhost:8080")
	if err != nil {
		t.Fatalf("failed to parse issuer: %v", err)
	}

	log := slog.New(slog.DiscardHandler)

	tests := []struct {
		name              string
		clientGetter      ClientGetter
		issuer            issuer.Issuer
		log               *slog.Logger
		userAuthenticator UserAuthenticator
		wantErr           bool
	}{
		{
			name:              "nil clientGetter",
			clientGetter:      nil,
			issuer:            validIssuer,
			log:               log,
			userAuthenticator: userAuthenticator,
			wantErr:           true,
		},
		{
			name:              "zero issuer",
			clientGetter:      clientGetter,
			issuer:            issuer.Issuer{},
			log:               log,
			userAuthenticator: userAuthenticator,
			wantErr:           true,
		},
		{
			name:              "nil logger",
			clientGetter:      clientGetter,
			issuer:            validIssuer,
			log:               nil,
			userAuthenticator: userAuthenticator,
			wantErr:           true,
		},
		{
			name:              "nil userAuthenticator",
			clientGetter:      clientGetter,
			issuer:            validIssuer,
			log:               log,
			userAuthenticator: nil,
			wantErr:           true,
		},
		{
			name:              "valid config",
			clientGetter:      clientGetter,
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
				ClientGetter:      tt.clientGetter,
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
	clientGetter      ClientGetter
	issuer            string
	userAuthenticator UserAuthenticator
}

func newTestServer(t *testing.T, opts testServerOptions) *Server {
	t.Helper()

	if opts.clientGetter == nil {
		opts.clientGetter = &fakeClientGetter{}
	}

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
			ClientGetter:      opts.clientGetter,
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
