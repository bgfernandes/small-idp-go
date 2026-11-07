// Package httpapi implements the HTTP API for the small IDP.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bgfernandes/small-idp-go/internal/client"
	"github.com/bgfernandes/small-idp-go/internal/jwk"
)

// ClientAuthenticator is an interface for authenticating clients.
type ClientAuthenticator interface {
	Authenticate(ctx context.Context, clientID, clientSecret string) (client.Client, error)
}

// Server is the HTTP server for the small IDP.
type Server struct {
	clientAuthenticator ClientAuthenticator
	issuer              string
	jwksURI             string
	key                 *jwk.Key
	log                 *slog.Logger
	now                 func() time.Time
	tokenEndpoint       string
}

// Config is the configuration for a server instance of the small IDP, every field is required.
type Config struct {
	ClientAuthenticator ClientAuthenticator
	Issuer              string
	Key                 *jwk.Key
	Log                 *slog.Logger
	Now                 func() time.Time
}

// NewServer creates a new HTTP server for the small IDP.
func NewServer(
	config Config,
) (*Server, error) {
	if config.ClientAuthenticator == nil {
		return nil, errors.New("Config.ClientAuthenticator is required")
	}

	// Validate issuer per RFC 8414 §2, accepting plain HTTP for now
	issuerURL, err := url.Parse(config.Issuer)
	if err != nil {
		return nil, fmt.Errorf("invalid Config.Issuer: %w", err)
	}
	if issuerURL.Scheme != "http" && issuerURL.Scheme != "https" {
		return nil, errors.New("Config.Issuer must use HTTP or HTTPS scheme")
	}
	if issuerURL.Host == "" {
		return nil, errors.New("Config.Issuer must have a host")
	}
	// Do not allow query params or fragments as per RFC 8414 §2
	if strings.ContainsAny(config.Issuer, "?#") {
		return nil, errors.New("Config.Issuer must not have query params or fragments")
	}
	// Do not allow trailing slash for consistency
	if strings.HasSuffix(config.Issuer, "/") {
		return nil, errors.New("Config.Issuer must not have a trailing slash")
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

	tokenEndpoint, err := url.JoinPath(config.Issuer, "token")
	if err != nil {
		return nil, fmt.Errorf("invalid token endpoint: %w", err)
	}

	jwksURI, err := url.JoinPath(config.Issuer, "jwks")
	if err != nil {
		return nil, fmt.Errorf("invalid JWKS URI: %w", err)
	}

	return &Server{
		clientAuthenticator: config.ClientAuthenticator,
		issuer:              config.Issuer,
		key:                 config.Key,
		log:                 config.Log,
		now:                 config.Now,
		tokenEndpoint:       tokenEndpoint,
		jwksURI:             jwksURI,
	}, nil
}

// Routes returns the HTTP routes for the small IDP.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.handleOAuthAuthorizationServer)
	mux.HandleFunc("GET /jwks", s.handleJWKS)
	mux.HandleFunc("POST /token", s.handleToken)
	return mux
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
