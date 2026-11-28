package web

import (
	"encoding/base64"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bgfernandes/small-idp-go/internal/client"
	"github.com/bgfernandes/small-idp-go/internal/scope"
)

type authorizeError struct {
	code, description string
}

func (e *authorizeError) Error() string { return e.code + ": " + e.description }

// redirectWithError redirects the user-agent to the client's redirection endpoint with the query
// component parameters as specified in RFC 6749 §4.1.2.1.
func (s *Server) redirectWithError(
	w http.ResponseWriter,
	r *http.Request,
	redirectURI, state string,
	err error,
) {
	authorizeErr, ok := errors.AsType[*authorizeError](err)
	if !ok {
		s.log.Error("internal server error", slog.Any("err", err))
		// RFC 6749 §4.1.2.1 defines server_error only for the authorization endpoint
		authorizeErr = &authorizeError{
			code:        "server_error",
			description: "internal server error",
		}
	}

	// At this point, redirectURI should be validated, but handle the error just in case.
	u, err := url.Parse(redirectURI)
	if err != nil {
		s.log.Error(
			"invalid redirection URI in redirectWithError",
			slog.Any("err", err),
			slog.String("redirectURI", redirectURI),
		)
		http.Error(w, "invalid redirection URI", http.StatusInternalServerError)
		return
	}

	if u.RawQuery != "" {
		u.RawQuery = u.RawQuery + "&"
	}
	uValues := url.Values{
		"error":             {authorizeErr.code},
		"error_description": {authorizeErr.description},
	}
	if state != "" {
		uValues.Add("state", state)
	}
	u.RawQuery = u.RawQuery + uValues.Encode()

	http.Redirect(w, r, u.String(), http.StatusFound)
}

func parseClientID(query url.Values) (string, error) {
	queryClientID, ok := query["client_id"]
	if !ok {
		return "", errors.New("missing client identifier")
	}
	// RFC 6749 §3.1 says that request parameters should not be duplicated
	if len(queryClientID) != 1 {
		return "", errors.New("duplicate client identifier")
	}
	if queryClientID[0] == "" {
		return "", errors.New("missing client identifier")
	}
	return queryClientID[0], nil
}

func parseAndValidateRedirectURI(query url.Values, c client.Client) (string, error) {
	// According to RFC 6749 §3.1.2.3, the redirect_uri is required only if the client has multiple
	// redirection URIs registered, or if only part of the redirection URI is registered, or if no
	// redirection URI was registered.
	// But, OIDC Core §3.1.2.1 makes redirect_uri REQUIRED, so we will always require it here.
	queryRedirectURI, ok := query["redirect_uri"]
	// RFC 6749 §3.1 says that request parameters should not be duplicated
	if !ok || len(queryRedirectURI) != 1 {
		return "", errors.New("missing or invalid redirection URI")
	}
	if !slices.Contains(c.RedirectionURIs, queryRedirectURI[0]) {
		return "", errors.New("missing or invalid redirection URI")
	}
	return queryRedirectURI[0], nil
}

func parseState(query url.Values) (string, error) {
	// According to RFC 6749 §4.1.1, state is an optional opaque string that should be returned to
	// the client even on errors.
	queryState, ok := query["state"]
	// RFC 6749 §3.1 says that request parameters should not be duplicated
	if ok && len(queryState) != 1 {
		return "", &authorizeError{
			code:        "invalid_request",
			description: "duplicate state parameter",
		}
	}
	if ok {
		return queryState[0], nil
	}
	return "", nil
}

func parseAndValidateResponseType(query url.Values) error {
	// According to RFC 6749 §4.1.1, response_type is required and must be "code"
	queryResponseType, ok := query["response_type"]
	if !ok {
		return &authorizeError{
			code:        "invalid_request",
			description: "response_type is required",
		}
	}
	// RFC 6749 §3.1 says that request parameters should not be duplicated
	if len(queryResponseType) != 1 {
		return &authorizeError{
			code:        "invalid_request",
			description: "duplicate response_type parameter",
		}
	}
	if queryResponseType[0] == "" {
		return &authorizeError{
			code:        "invalid_request",
			description: "response_type is required",
		}
	}
	if queryResponseType[0] != "code" {
		return &authorizeError{
			code:        "unsupported_response_type",
			description: "response_type must be 'code'",
		}
	}
	return nil
}

func parseAndValidateScope(query url.Values, c client.Client) ([]string, error) {
	// According to RFC 6749 §3.3, scope is optional, and if the client omits the scope parameter
	// the authorization server MUST either process the request using a pre-defined default value or
	// fail the request indicating an invalid scope. If a default is used, it should be documented.
	// OIDC Core §3.1.2.1 makes scope REQUIRED and it MUST contain openid.
	// Here, we will default to the client's full list of allowed scopes, including openid, which is
	// usual in practice.
	queryScope, ok := query["scope"]
	if !ok {
		return c.Scopes, nil
	}
	if len(queryScope) != 1 {
		return nil, &authorizeError{
			code:        "invalid_request",
			description: "duplicate scope parameter",
		}
	}

	scopes, err := scope.Parse(queryScope[0], c.Scopes)
	if err != nil {
		return nil, &authorizeError{
			code:        "invalid_scope",
			description: err.Error(),
		}
	}
	return scopes, nil
}

func parseAndValidateCodeChallenge(query url.Values) (string, error) {
	// RFC 7636 §4.4.1 says that if the server requires PKCE and the client does not send
	// code_challenge, it should respond with invalid_request
	queryCodeChallenge, ok := query["code_challenge"]
	if !ok {
		return "", &authorizeError{
			code:        "invalid_request",
			description: "code_challenge is required",
		}
	}
	if len(queryCodeChallenge) != 1 {
		return "", &authorizeError{
			code:        "invalid_request",
			description: "duplicate code_challenge parameter",
		}
	}
	if queryCodeChallenge[0] == "" {
		return "", &authorizeError{
			code:        "invalid_request",
			description: "code_challenge is required",
		}
	}

	// RFC 7636 §4.2 says plain SHOULD NOT be used when the client can do S256, the OAuth 2.0
	// Security BCP (RFC 9700) requires PKCE for public clients and recommends it for all, and the
	// OAuth 2.1 draft drops plain entirely.
	// RFC 7636 §4.4.1 says that if the server does not support the transform, it should also
	// respond with invalid_request
	queryCodeChallengeMethod, ok := query["code_challenge_method"]
	if !ok {
		return "", &authorizeError{
			code:        "invalid_request",
			description: "code_challenge_method must be S256",
		}
	}
	if len(queryCodeChallengeMethod) != 1 {
		return "", &authorizeError{
			code:        "invalid_request",
			description: "duplicate code_challenge_method parameter",
		}
	}
	if queryCodeChallengeMethod[0] == "" {
		return "", &authorizeError{
			code:        "invalid_request",
			description: "code_challenge_method must be S256",
		}
	}
	if queryCodeChallengeMethod[0] != "S256" {
		return "", &authorizeError{
			code:        "invalid_request",
			description: "code_challenge_method must be S256",
		}
	}

	// Check that the code challenge is a valid base64url encoded string of a sha256 hash
	decodedCodeChallenge, err := base64.RawURLEncoding.DecodeString(queryCodeChallenge[0])
	if err != nil {
		return "", &authorizeError{
			code:        "invalid_request",
			description: "invalid code_challenge",
		}
	}
	if len(decodedCodeChallenge) != 32 {
		return "", &authorizeError{
			code:        "invalid_request",
			description: "invalid code_challenge",
		}
	}

	return queryCodeChallenge[0], nil
}

func parseNonce(query url.Values) (string, error) {
	// According to OIDC Core §3.1.2.1, nonce is an optional opaque string used to associate a
	// Client session with an ID Token, and to mitigate replay attacks
	queryNonce, ok := query["nonce"]
	// RFC 6749 §3.1 says that request parameters should not be duplicated
	if ok && len(queryNonce) != 1 {
		return "", &authorizeError{
			code:        "invalid_request",
			description: "duplicate nonce parameter",
		}
	}
	if ok {
		return queryNonce[0], nil
	}
	return "", nil
}

var allowedPrompts = []string{"none", "login", "consent", "select_account"}

func parsePrompt(query url.Values) ([]string, error) {
	// According to OIDC Core §3.1.2.1, prompt is an optional space-separated list of values that
	// specifies whether the Authorization Server prompts the End-User for reauthentication and
	// consent.
	queryPrompt, ok := query["prompt"]
	if !ok {
		return nil, nil
	}
	if len(queryPrompt) != 1 {
		return nil, &authorizeError{
			code:        "invalid_request",
			description: "duplicate prompt parameter",
		}
	}
	if queryPrompt[0] == "" {
		return nil, nil
	}

	prompts := strings.Split(queryPrompt[0], " ")
	seenPrompts := map[string]bool{}
	recognizedPrompts := make([]string, 0, len(prompts))
	for _, prompt := range prompts {
		// According to OIDC Core §3.1.2.1, If an OP receives a prompt value outside the set
		// defined above that it does not understand, it MAY return an error or it MAY ignore it; in
		// practice, not returning errors for not-understood values will help facilitate phasing in
		// extensions using new prompt values.
		if slices.Contains(allowedPrompts, prompt) && !seenPrompts[prompt] {
			seenPrompts[prompt] = true
			recognizedPrompts = append(recognizedPrompts, prompt)
		}
	}

	// According to OIDC Core §3.1.2.1, if none is present, no other prompt values may be present.
	if slices.Contains(recognizedPrompts, "none") && len(recognizedPrompts) > 1 {
		return nil, &authorizeError{
			code:        "invalid_request",
			description: "none prompt cannot be combined with other prompt values",
		}
	}

	// This IDP does not support multiple sessions, so select_account is not supported.
	if slices.Contains(recognizedPrompts, "select_account") {
		return nil, &authorizeError{
			code:        "account_selection_required",
			description: "select_account prompt was requested but multiple sessions are not supported",
		}
	}

	return recognizedPrompts, nil
}

func parseMaxAge(query url.Values) (time.Duration, bool, error) {
	// According to OIDC Core §3.1.2.1, max_age is an optional integer value that specifies the
	// maximum allowed elapsed time in seconds since the last time the End-User was actively
	// authenticated by the OP.
	queryMaxAge, ok := query["max_age"]
	if !ok {
		return 0, false, nil
	}
	if len(queryMaxAge) != 1 {
		return 0, false, &authorizeError{
			code:        "invalid_request",
			description: "duplicate max_age parameter",
		}
	}
	if queryMaxAge[0] == "" {
		return 0, false, nil
	}

	maxAge, err := strconv.Atoi(queryMaxAge[0])
	if err != nil {
		return 0, false, &authorizeError{
			code:        "invalid_request",
			description: "invalid max_age parameter",
		}
	}

	if maxAge < 0 {
		return 0, false, &authorizeError{
			code:        "invalid_request",
			description: "max_age must be a non-negative integer",
		}
	}

	if maxAge > math.MaxInt64/int(time.Second) {
		return 0, false, &authorizeError{
			code:        "invalid_request",
			description: "max_age is too large",
		}
	}

	return time.Duration(maxAge) * time.Second, true, nil
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		http.Error(w, "invalid query", http.StatusBadRequest)
		return
	}

	// First, check and validate for issues that would cause the request to be rejected without
	// redirecting to the client's redirection endpoint. According to RFC 6749 §4.1.2.1, if the
	// request fails due to a missing, invalid, or mismatching redirection URI, or if the client
	// identifier is missing or invalid, the authorization server SHOULD inform the resource owner
	// of the error and MUST NOT automatically redirect the user-agent to the invalid redirection
	// URI.
	clientID, err := parseClientID(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	c, err := s.clientGetter.Get(r.Context(), clientID)
	if err != nil {
		if errors.Is(err, client.ErrNotFound) {
			http.Error(w, "missing or invalid client identifier", http.StatusBadRequest)
			return
		}
		s.log.Error("get client", slog.Any("err", err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	redirectURI, err := parseAndValidateRedirectURI(query, c)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// From this point on we can assume that the clientID and redirectURI are valid, and can
	// redirect back to the client on errors.

	state, err := parseState(query)
	if err != nil {
		s.redirectWithError(w, r, redirectURI, "", err)
		return
	}

	if !slices.Contains(c.GrantTypes, client.GrantTypeAuthorizationCode) {
		s.redirectWithError(w, r, redirectURI, state, &authorizeError{
			code:        "unauthorized_client",
			description: "client is not authorized to request an authorization code",
		})
		return
	}

	err = parseAndValidateResponseType(query)
	if err != nil {
		s.redirectWithError(w, r, redirectURI, state, err)
		return
	}

	scopes, err := parseAndValidateScope(query, c)
	if err != nil {
		s.redirectWithError(w, r, redirectURI, state, err)
		return
	}

	_, err = parseAndValidateCodeChallenge(query)
	if err != nil {
		s.redirectWithError(w, r, redirectURI, state, err)
		return
	}

	var nonce string
	var prompts []string
	var maxAge time.Duration
	var maxAgeRequired bool
	// Additional OIDC only parameters should only be honored if the request is OIDC
	if slices.Contains(scopes, "openid") {
		nonce, err = parseNonce(query)
		if err != nil {
			s.redirectWithError(w, r, redirectURI, state, err)
			return
		}

		prompts, err = parsePrompt(query)
		if err != nil {
			s.redirectWithError(w, r, redirectURI, state, err)
			return
		}

		maxAge, maxAgeRequired, err = parseMaxAge(query)
		if err != nil {
			s.redirectWithError(w, r, redirectURI, state, err)
			return
		}
	}

	// TODO: Remove this:
	_ = nonce
	_ = prompts
	_ = maxAge
	_ = maxAgeRequired

	// TODO: Check here if the user is authenticated

	// TODO: if the user is authenticated, redirect to a consent screen, and after consent, generate
	// and save the code along with client_id, redirect_uri, code_challenge, nonce, sub, auth_time,
	// granted scopes in a single-use, short TTL code store.

	// TODO: if the user is not authenticated, redirect to login, and after login, redirect back to
	// this endpoint with the same parameters, taking care to prevent open-redirection attacks

	// TODO remove this error response, because it is just a placeholder until the above is
	// implemented. RFC 6749 §4.1.2.1 defines error code temporarily_unavailable for a server that
	// cannot currently handle the request
	s.redirectWithError(w, r, redirectURI, state, &authorizeError{
		code:        "temporarily_unavailable",
		description: "server cannot currently handle the request",
	})
}
