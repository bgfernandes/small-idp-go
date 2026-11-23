package httpapi

import (
	"net/http"

	"github.com/bgfernandes/small-idp-go/internal/client"
)

type authorizationServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported,omitempty"`
	SubjectTypesSupported             []string `json:"subject_types_supported,omitempty"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

const (
	tokenEndpointAuthMethodBasic = "client_secret_basic"
	tokenEndpointAuthMethodPost  = "client_secret_post"
)

func (s *Server) handleOAuthAuthorizationServer(w http.ResponseWriter, _ *http.Request) {
	grantTypesSupported := make([]string, len(client.SupportedGrantTypes))
	for i, grantType := range client.SupportedGrantTypes {
		grantTypesSupported[i] = string(grantType)
	}

	s.writeJSON(w, http.StatusOK, authorizationServerMetadata{
		AuthorizationEndpoint:  s.issuer.URL("authorize"),
		GrantTypesSupported:    grantTypesSupported,
		Issuer:                 s.issuer.String(),
		JWKSURI:                s.issuer.URL("jwks"),
		ResponseTypesSupported: []string{"code"},
		TokenEndpoint:          s.issuer.URL("token"),
		TokenEndpointAuthMethodsSupported: []string{
			tokenEndpointAuthMethodBasic,
			tokenEndpointAuthMethodPost,
		},
	})
}
