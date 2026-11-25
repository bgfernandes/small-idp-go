package web

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"

	"github.com/bgfernandes/small-idp-go/internal/client"
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

	// TODO: Implement the rest of the function.
}
