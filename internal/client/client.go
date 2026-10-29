// Package client provides a client and store interface for an OIDC/OAuth2 client.
package client

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// GrantType is a type of grant type supported by a client.
type GrantType string

const (
	// GrantTypeClientCredentials is the grant type for client credentials.
	GrantTypeClientCredentials GrantType = "client_credentials"
)

// SupportedGrantTypes is a list of supported grant types.
var SupportedGrantTypes = []GrantType{
	GrantTypeClientCredentials,
}

// Client is a OIDC/OAuth2 client.
type Client struct {
	ID         string
	Name       string
	GrantTypes []GrantType
	Scopes     []string
	Audiences  []string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// CreateParams is the parameters for creating a client.
type CreateParams struct {
	Audiences  []string
	GrantTypes []GrantType
	Name       string
	Scopes     []string
}

// Store is a client store interface.
// TODO: Move this interface to httpapi and cmd/client packages
type Store interface {
	Get(ctx context.Context, clientID string) (Client, error)
	Create(ctx context.Context, params CreateParams) (Client, string, error)
	Authenticate(ctx context.Context, clientID, clientSecret string) (Client, error)
}

// ErrNotFound is returned when a client is not found.
var ErrNotFound = errors.New("client not found")

// ErrUnknownClientOrWrongSecret is returned when a client is not found or the secret is wrong as per per RFC 6749 §5.2.
var ErrUnknownClientOrWrongSecret = errors.New("unknown client or wrong secret")

// InvalidClientError is returned when a client is invalid.
type InvalidClientError struct {
	Field  string
	Reason string
}

func (e *InvalidClientError) Error() string {
	return fmt.Sprintf("invalid client field %s: %s", e.Field, e.Reason)
}
