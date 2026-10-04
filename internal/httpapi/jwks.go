package httpapi

import (
	"net/http"

	"github.com/bgfernandes/small-idp-go/internal/jwk"
)

func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	// RFC 7517 §8.5.1 registers application/jwk-set+json as the media type for JWK Sets,
	// but application/json is commonly used and accepted by clients.
	s.writeJSON(w, http.StatusOK, jwk.Set{
		Keys: []jwk.PublicKey{s.key.Public()},
	})
}
