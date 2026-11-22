// Package web implements the web interface for the small IDP.
package web

import (
	"bytes"
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
	csrf              *http.CrossOriginProtection
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

	// Initialize the CSRF protection middleware. Cross-origin requests are currently detected with
	// the `Sec-Fetch-Site` header, available in all browsers since 2023, or by comparing the
	// hostname of the `Origin` header with the `Host` header.
	csrf := http.NewCrossOriginProtection()

	return &Server{
		csrf:              csrf,
		issuer:            config.Issuer,
		log:               config.Log,
		userAuthenticator: config.UserAuthenticator,
	}, nil
}

// Routes returns the HTTP Web routes for the small IDP.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	s.AddRoutes(mux)
	return mux
}

// AddRoutes adds the HTTP Web routes for the small IDP to the given mux.
func (s *Server) AddRoutes(mux *http.ServeMux) {
	// The GET, HEAD, and OPTIONS methods are considered safe methods and are always allowed by the
	// CSRF protection, but it's not harmful to just apply it to all routes in the web.Server by
	// convention.
	mux.Handle("GET /login", s.csrf.Handler(http.HandlerFunc(s.handleGetLogin)))
	mux.Handle("POST /login", s.csrf.Handler(http.HandlerFunc(s.handlePostLogin)))
}

func (s *Server) writeHTMLTemplate(w http.ResponseWriter, status int, name string, data any) {
	var buffer bytes.Buffer
	err := templates.ExecuteTemplate(
		&buffer,
		name,
		data,
	)
	if err != nil {
		s.log.Error(
			"execute HTML template",
			slog.String("template", name),
			slog.Any("err", err),
		)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.WriteHeader(status)

	_, err = buffer.WriteTo(w)
	if err != nil {
		s.log.Debug("write HTML template", slog.String("template", name), slog.Any("err", err))
	}
}
