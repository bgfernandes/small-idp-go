package httpapi

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/bgfernandes/small-idp-go/internal/client"
	"github.com/bgfernandes/small-idp-go/internal/jwt"
)

// oauthError is a custom error type for OAuth 2.0 errors.
// TODO: Extract it to another file when reused.
type oauthError struct {
	status            int
	code, description string
	wwwAuthenticate   string
}

func (e *oauthError) Error() string { return e.code + ": " + e.description }

type tokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

const maxTokenRequestBytes = 10 << 10 // 10 KiB

func (s *Server) writeTokenError(w http.ResponseWriter, err error) {
	if err == nil {
		panic("err is nil")
	}

	// RFC 6749 §5.1 requires Cache-Control and Pragma headers to be set in responses that contain tokens or sensitive information
	// This may not be the case for all error responses, but the example in RFC 6749 §5.2 has them, so we'll follow suit.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	oauthErr, ok := errors.AsType[*oauthError](err)
	if !ok {
		s.log.Error("internal server error", slog.Any("err", err))
		// RFC 6749 defines server_error only for the authorization endpoint, but it's common vendor behaviour to use it for the token endpoint as well
		oauthErr = &oauthError{status: http.StatusInternalServerError, code: "server_error", description: "internal server error"}
	}

	if oauthErr.wwwAuthenticate != "" {
		w.Header().Set("WWW-Authenticate", oauthErr.wwwAuthenticate)
	}

	s.writeJSON(w, oauthErr.status, tokenErrorResponse{Error: oauthErr.code, ErrorDescription: oauthErr.description})
}

// singleFormValue returns the form value for a given key while checking that it is included only once
// as per RFC 6749 §3.2 that says parameters "MUST NOT be included more than once".
func singleFormValue(form url.Values, key string) (string, error) {
	if len(form[key]) > 1 {
		return "", fmt.Errorf("parameter %s included more than once", key)
	}
	return form.Get(key), nil
}

const basicChallenge = `Basic realm="oauth2-token-endpoint"`

func invalidClientError(usesBasicAuth bool, description string) *oauthError {
	if usesBasicAuth {
		return &oauthError{status: http.StatusUnauthorized, code: "invalid_client", description: description, wwwAuthenticate: basicChallenge}
	}
	return &oauthError{status: http.StatusBadRequest, code: "invalid_client", description: description}
}

type credentials struct {
	clientID      string
	clientSecret  string
	usesBasicAuth bool
}

// parseCredentials parses the client credentials from the request and returns them.
// TODO: move this to another file when reused.
func parseCredentials(r *http.Request) (credentials, error) {
	usesBasicAuth := r.Header.Get("Authorization") != ""

	formClientSecret, err := singleFormValue(r.PostForm, "client_secret")
	if err != nil {
		return credentials{}, &oauthError{status: http.StatusBadRequest, code: "invalid_request", description: err.Error()}
	}

	// RFC 6749 §2.3 says clients MUST NOT use more than one authentication method in each request
	// For now we only support client_secret_basic, and client_secret_post, so we need to check that only one of them is present
	if formClientSecret != "" && usesBasicAuth {
		return credentials{}, &oauthError{status: http.StatusBadRequest, code: "invalid_request", description: "only one authentication method is allowed"}
	}

	formClientID, err := singleFormValue(r.PostForm, "client_id")
	if err != nil {
		return credentials{}, &oauthError{status: http.StatusBadRequest, code: "invalid_request", description: err.Error()}
	}

	if !usesBasicAuth {
		if formClientID == "" {
			return credentials{}, invalidClientError(usesBasicAuth, "client_id is required")
		}

		// TODO in the future when implementing public clients, allow missing client_secret in form
		if formClientSecret == "" {
			return credentials{}, invalidClientError(usesBasicAuth, "client_secret is required")
		}

		return credentials{
			clientID:      formClientID,
			clientSecret:  formClientSecret,
			usesBasicAuth: usesBasicAuth,
		}, nil
	}

	// If Authorization header is present, check if it conforms to RFC 7617
	basicClientID, basicClientSecret, ok := r.BasicAuth()
	if !ok {
		return credentials{}, invalidClientError(usesBasicAuth, "invalid authorization header")
	}

	if basicClientID == "" || basicClientSecret == "" {
		return credentials{}, invalidClientError(usesBasicAuth, "invalid authorization header")
	}

	// RFC 6749 §2.3.1 says both values are form-urlencoded before going into the Basic header
	basicClientID, err = url.QueryUnescape(basicClientID)
	if err != nil {
		return credentials{}, invalidClientError(usesBasicAuth, "invalid authorization header")
	}
	basicClientSecret, err = url.QueryUnescape(basicClientSecret)
	if err != nil {
		return credentials{}, invalidClientError(usesBasicAuth, "invalid authorization header")
	}

	// RFC 6749 §3.2.1 states a client MAY use client_id to identify itself, it says nothing about combining it with
	// basic auth, so if both are present, we check it matches the form value defensively
	if formClientID != "" && basicClientID != formClientID {
		return credentials{}, &oauthError{status: http.StatusBadRequest, code: "invalid_request", description: "client_id mismatch"}
	}

	return credentials{
		clientID:      basicClientID,
		clientSecret:  basicClientSecret,
		usesBasicAuth: usesBasicAuth,
	}, nil
}

// parseGrantType parses the grant type from the request, checks if it is supported by the client and returns the typed grant type.
func parseGrantType(r *http.Request, c client.Client) (client.GrantType, error) {
	rawValue, err := singleFormValue(r.PostForm, "grant_type")
	if err != nil {
		return "", &oauthError{status: http.StatusBadRequest, code: "invalid_request", description: err.Error()}
	}

	if rawValue == "" {
		return "", &oauthError{status: http.StatusBadRequest, code: "invalid_request", description: "grant_type is required"}
	}

	typedGrantType := client.GrantType(rawValue)

	if !slices.Contains(client.SupportedGrantTypes, typedGrantType) {
		return "", &oauthError{status: http.StatusBadRequest, code: "unsupported_grant_type", description: "unsupported grant_type"}
	}

	if !slices.Contains(c.GrantTypes, typedGrantType) {
		return "", &oauthError{status: http.StatusBadRequest, code: "unauthorized_client", description: "unauthorized grant_type"}
	}

	return typedGrantType, nil
}

// parseScope parses the scope from the request, checks if it is supported by the client, and returns it as a
// deduplicated space-separated string.
// This function does not re-validate the scopes, it assumes they were validated on creation by the client store.
func parseScope(r *http.Request, c client.Client) (string, error) {
	rawValue, err := singleFormValue(r.PostForm, "scope")
	if err != nil {
		return "", &oauthError{status: http.StatusBadRequest, code: "invalid_request", description: err.Error()}
	}

	// RFC 6749 §3.3 says that if missing, authorization server MUST either process the request using a pre-defined default
	// value or fail the request indicating an invalid scope. Here we will default to all the scopes supported by the client, which
	// is frequently used in practice.
	if rawValue == "" {
		return strings.Join(c.Scopes, " "), nil
	}

	scopes := strings.Split(rawValue, " ")
	seenScopes := map[string]bool{}
	dedupedScopes := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if !slices.Contains(c.Scopes, scope) {
			return "", &oauthError{status: http.StatusBadRequest, code: "invalid_scope", description: "unknown or malformed scope"}
		}

		if !seenScopes[scope] {
			seenScopes[scope] = true
			dedupedScopes = append(dedupedScopes, scope)
		}
	}

	return strings.Join(dedupedScopes, " "), nil
}

// parseResource parses the resource from the request, checks if it is supported by the client, and returns it as a
// deduplicated list of strings.
// This function does not re-validate the resources, it assumes they were validated on creation by the client store.
func parseResource(r *http.Request, c client.Client) ([]string, error) {
	rawValues := r.PostForm["resource"]

	scrubbedValues := slices.Clone(rawValues)

	// RFC 6749 §3.2 says that a parameter sent without a value is treated as omitted, so drop empty values before validating
	scrubbedValues = slices.DeleteFunc(scrubbedValues, func(value string) bool {
		return value == ""
	})

	// Per RFC 8707 §2.1, if an authorization request has no resource parameter, the authorization server MAY process the request with
	// no specific resource or by using a predefined default resource value, but it specifies nothing about the access token request.
	// RFC 9068 §3 says that when the request has no resource parameter, the server MUST use a default resource indicator for the token's aud claim.
	// The audiences list is used in this project as the default resource indicator, and also to validate the resource
	// parameter when it is sent, rejecting unknown values with invalid_target per RFC 8707 §2
	if len(scrubbedValues) == 0 {
		return c.Audiences, nil
	}

	seenResources := map[string]bool{}
	dedupedResources := make([]string, 0, len(scrubbedValues))
	for _, v := range scrubbedValues {
		if !slices.Contains(c.Audiences, v) {
			return nil, &oauthError{status: http.StatusBadRequest, code: "invalid_target", description: "unknown or malformed resource"}
		}

		if !seenResources[v] {
			seenResources[v] = true
			dedupedResources = append(dedupedResources, v)
		}
	}

	return dedupedResources, nil
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	// Body type must be application/x-www-form-urlencoded, according to RFC 6749 §4.4.2
	mimeType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mimeType != "application/x-www-form-urlencoded" {
		s.writeTokenError(w, &oauthError{status: http.StatusBadRequest, code: "invalid_request", description: "invalid content-type"})
		return
	}

	// Parse body with a MaxBytesReader to limit the size of the request body
	r.Body = http.MaxBytesReader(w, r.Body, maxTokenRequestBytes)
	if err := r.ParseForm(); err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			s.writeTokenError(w, &oauthError{status: http.StatusBadRequest, code: "invalid_request", description: "request body too large"})
			return
		}
		s.writeTokenError(w, &oauthError{status: http.StatusBadRequest, code: "invalid_request", description: "invalid form encoding"})
		return
	}

	creds, err := parseCredentials(r)
	if err != nil {
		s.writeTokenError(w, err)
		return
	}

	c, err := s.clientAuthenticator.Authenticate(r.Context(), creds.clientID, creds.clientSecret)
	if err != nil {
		if errors.Is(err, client.ErrUnknownClientOrWrongSecret) {
			s.writeTokenError(w, invalidClientError(creds.usesBasicAuth, "invalid client credentials"))
		} else {
			s.writeTokenError(w, err)
		}
		return
	}

	_, err = parseGrantType(r, c)
	if err != nil {
		s.writeTokenError(w, err)
		return
	}

	scope, err := parseScope(r, c)
	if err != nil {
		s.writeTokenError(w, err)
		return
	}

	resources, err := parseResource(r, c)
	if err != nil {
		s.writeTokenError(w, err)
		return
	}

	// TODO: currently this handler only supports client_credentials, in the future, branched off based on grant_type from here

	currentTime := s.now()
	// RFC 9068 §2.2 requires the following claims: iss, exp, aud, sub, client_id, iat, jti
	// §2.2.1 and §2.2.2 only apply for grants involving a resource owner, so for client credentials they do not apply
	// §2.2.3 states that the jwt AT SHOULD include the scope claim, and RFC 6749 §5.1 says it is optional if identical
	// to the scope requested by the client, but we always include it when it's not empty to simplify the implementation
	claims := jwt.AccessTokenClaims{
		Iss:      s.issuer,
		Sub:      c.ID,
		Aud:      resources,
		Exp:      currentTime.Add(s.accessTokenLifetime).Unix(),
		Iat:      currentTime.Unix(),
		Jti:      rand.Text(),
		ClientID: c.ID,
		Scope:    scope,
	}

	accessToken, err := jwt.New(s.key, jwt.HeaderTypeAccessToken, claims)
	if err != nil {
		s.writeTokenError(w, err)
		return
	}

	resp := tokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(s.accessTokenLifetime.Seconds()),
		Scope:       scope,
	}

	// RFC 6749 §5.1 requires Cache-Control and Pragma headers to be set in responses that contain tokens or sensitive information
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	s.writeJSON(w, http.StatusOK, resp)
}
