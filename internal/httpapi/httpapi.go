// Package httpapi implements the HTTP API for the small IDP.
package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/bgfernandes/small-idp-go/internal/jwk"
)

// Server is the HTTP server for the small IDP.
type Server struct {
	issuer string
	key    *jwk.Key
	log    *slog.Logger
}

// NewServer creates a new HTTP server for the small IDP.
func NewServer(issuer string, key *jwk.Key, log *slog.Logger) (*Server, error) {
	// Validate issuer per RFC 8414 §2, accepting plain HTTP for now
	issuerURL, err := url.Parse(issuer)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer: %w", err)
	}
	if issuerURL.Scheme != "http" && issuerURL.Scheme != "https" {
		return nil, errors.New("issuer must use HTTP or HTTPS scheme")
	}
	if issuerURL.Host == "" {
		return nil, errors.New("issuer must have a host")
	}
	// Do not allow query params or fragments as per RFC 8414 §2
	if strings.ContainsAny(issuer, "?#") {
		return nil, errors.New("issuer must not have query params or fragments")
	}
	// Do not allow trailing slash for consistency
	if strings.HasSuffix(issuer, "/") {
		return nil, errors.New("issuer must not have a trailing slash")
	}

	if key == nil {
		return nil, errors.New("key is required")
	}

	if log == nil {
		return nil, errors.New("log is required")
	}

	return &Server{
		issuer: issuer,
		key:    key,
		log:    log,
	}, nil
}

// Routes returns the HTTP routes for the small IDP.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /jwks", s.handleJWKS)
	return mux
}

func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	// RFC 7517 §8.5.1 registers application/jwk-set+json as the media type for JWK Sets,
	// but application/json is commonly used and accepted by clients.
	s.writeJSON(w, http.StatusOK, jwk.Set{
		Keys: []jwk.PublicKey{s.key.Public()},
	})
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
