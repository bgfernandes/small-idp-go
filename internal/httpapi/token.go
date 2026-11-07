package httpapi

import (
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"net/url"

	"github.com/bgfernandes/small-idp-go/internal/client"
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

// clientCredentials parses the client credentials from the request and returns them.
// TODO: move this to another file when reused.
func clientCredentials(r *http.Request) (credentials, error) {
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

	creds, err := clientCredentials(r)
	if err != nil {
		s.writeTokenError(w, err)
		return
	}

	_, err = s.clientAuthenticator.Authenticate(r.Context(), creds.clientID, creds.clientSecret)
	if err != nil {
		if errors.Is(err, client.ErrUnknownClientOrWrongSecret) {
			s.writeTokenError(w, invalidClientError(creds.usesBasicAuth, "invalid client credentials"))
		} else {
			s.writeTokenError(w, err)
		}
		return
	}

	// TODO check grant type, then client authorisation for that grant, then scope, then resource
	// TODO check grant_type against the allowed values for unsupported_grant_type, missing is invalid_request
	// TODO check grant_types against the client's allowed grant_types for unauthorized_client

	// TODO all the rest :)
	http.Error(w, "not implemented", http.StatusNotImplemented)
}
