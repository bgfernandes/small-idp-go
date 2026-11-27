// Package httpapi implements the HTTP API for the small IDP.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/bgfernandes/small-idp-go/internal/client"
	"github.com/bgfernandes/small-idp-go/internal/issuer"
	"github.com/bgfernandes/small-idp-go/internal/jwk"
)

// ClientAuthenticator is an interface for authenticating clients.
type ClientAuthenticator interface {
	Authenticate(ctx context.Context, clientID, clientSecret string) (client.Client, error)
}

// Server is the HTTP server for the small IDP.
type Server struct {
	accessTokenLifetime time.Duration
	clientAuthenticator ClientAuthenticator
	issuer              issuer.Issuer
	key                 *jwk.Key
	log                 *slog.Logger
	now                 func() time.Time
}

// Config is the configuration for a server instance of the small IDP, every field is required.
type Config struct {
	AccessTokenLifetime time.Duration
	ClientAuthenticator ClientAuthenticator
	Issuer              issuer.Issuer
	Key                 *jwk.Key
	Log                 *slog.Logger
	Now                 func() time.Time
}

// NewServer creates a new HTTP server for the small IDP.
func NewServer(
	config Config,
) (*Server, error) {
	if config.AccessTokenLifetime <= 0 {
		return nil, errors.New("Config.AccessTokenLifetime must be greater than 0")
	}

	if config.ClientAuthenticator == nil {
		return nil, errors.New("Config.ClientAuthenticator is required")
	}

	if config.Issuer.IsZero() {
		return nil, errors.New("Config.Issuer must be a non-zero value")
	}

	if config.Key == nil {
		return nil, errors.New("Config.Key is required")
	}

	if config.Log == nil {
		return nil, errors.New("Config.Log is required")
	}

	if config.Now == nil {
		return nil, errors.New("Config.Now is required")
	}

	return &Server{
		accessTokenLifetime: config.AccessTokenLifetime,
		clientAuthenticator: config.ClientAuthenticator,
		issuer:              config.Issuer,
		key:                 config.Key,
		log:                 config.Log,
		now:                 config.Now,
	}, nil
}

// Routes returns the HTTP routes for the small IDP.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	s.AddRoutes(mux)
	return mux
}

// AddRoutes adds the HTTP routes for the small IDP to the given mux.
func (s *Server) AddRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.handleOAuthAuthorizationServer)
	mux.HandleFunc("GET /jwks", s.handleJWKS)
	mux.HandleFunc("POST /token", s.handleToken)
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	jsonBody, err := json.Marshal(v)
	if err != nil {
		s.log.Error("marshal JSON", slog.String("type", fmt.Sprintf("%T", v)), slog.Any("err", err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, err = w.Write(jsonBody)
	if err != nil {
		s.log.Warn("write JSON", slog.String("type", fmt.Sprintf("%T", v)), slog.Any("err", err))
	}
}
