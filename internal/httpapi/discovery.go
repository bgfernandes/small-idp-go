package httpapi

import (
	"net/http"
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
	grantTypeClientCredentials   = "client_credentials"
	tokenEndpointAuthMethodBasic = "client_secret_basic"
	tokenEndpointAuthMethodPost  = "client_secret_post"
)

func (s *Server) handleOAuthAuthorizationServer(w http.ResponseWriter, _ *http.Request) {
	// Only fields that are needed for client_credentials grant type according to RFC 8414.
	// response_types_supported is REQUIRED according to RFC 8414 §2, but the server currently supports no response types,
	// and §3.2 says "Claims with zero elements MUST be omitted". The two rules contradict each other
	// for a server with no authorization endpoint, so we omit it for now.
	s.writeJSON(w, http.StatusOK, authorizationServerMetadata{
		Issuer:        s.issuer,
		TokenEndpoint: s.tokenEndpoint,
		JWKSURI:       s.jwksURI,
		GrantTypesSupported: []string{
			grantTypeClientCredentials,
		},
		TokenEndpointAuthMethodsSupported: []string{
			tokenEndpointAuthMethodBasic,
			tokenEndpointAuthMethodPost,
		},
	})
}
