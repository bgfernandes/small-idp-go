// Package web implements the web interface for the small IDP.
package web

import (
	"context"
	"embed"
	"errors"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/bgfernandes/small-idp-go/internal/issuer"
	"github.com/bgfernandes/small-idp-go/internal/user"
)

//go:embed templates/*.html
var embedTemplates embed.FS
var templates = template.Must(template.ParseFS(embedTemplates, "templates/*.html"))

// UserAuthenticator is an interface for authenticating users.
type UserAuthenticator interface {
	Authenticate(ctx context.Context, email, password string) (user.User, error)
}

// Server is the web server for the small IDP.
type Server struct {
	issuer            issuer.Issuer
	log               *slog.Logger
	userAuthenticator UserAuthenticator
}

// Config is the configuration for a web server instance of the small IDP, every field is required.
type Config struct {
	Issuer            issuer.Issuer
	Log               *slog.Logger
	UserAuthenticator UserAuthenticator
}

// NewServer creates a new web server for the small IDP.
func NewServer(
	config Config,
) (*Server, error) {
	if config.Issuer.IsZero() {
		return nil, errors.New("Config.Issuer must be a non-zero value")
	}

	if config.Log == nil {
		return nil, errors.New("Config.Log is required")
	}

	if config.UserAuthenticator == nil {
		return nil, errors.New("Config.UserAuthenticator is required")
	}

	return &Server{
		issuer:            config.Issuer,
		log:               config.Log,
		userAuthenticator: config.UserAuthenticator,
	}, nil
}

// Routes returns the HTTP Web routes for the small IDP.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", s.handleGetLogin)
	return mux
}
