package postgres

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/bgfernandes/small-idp-go/internal/client"
	"github.com/jackc/pgx/v5/pgconn"
)

// ClientStore is a store for clients.
type ClientStore struct {
	db *sql.DB
}

// NewClientStore creates a new ClientStore.
func NewClientStore(db *sql.DB) *ClientStore {
	return &ClientStore{db: db}
}

const clientColumns = "id, name, grant_types, scopes, audiences, created_at, updated_at, secret_hash, redirection_uris"

// scanClient scans a client from a database row. It returns the client and the secret hash.
func scanClient(row *sql.Row) (client.Client, string, error) {
	c := client.Client{}
	var secretHash sql.Null[string]
	err := row.Scan(
		&c.ID,
		&c.Name,
		&c.GrantTypes,
		&c.Scopes,
		&c.Audiences,
		&c.CreatedAt,
		&c.UpdatedAt,
		&secretHash,
		&c.RedirectionURIs,
	)
	if err != nil {
		return client.Client{}, "", fmt.Errorf("scan client: %w", err)
	}
	c.Public = !secretHash.Valid
	return c, secretHash.V, nil
}

// Get gets a client by its ID.
func (s *ClientStore) Get(ctx context.Context, clientID string) (client.Client, error) {
	query := `
		SELECT ` + clientColumns + `
		FROM clients
		WHERE id = $1
	`
	c, _, err := scanClient(s.db.QueryRowContext(ctx, query, clientID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return client.Client{}, client.ErrNotFound
		}
		return client.Client{}, fmt.Errorf("get client: %w", err)
	}

	return c, nil
}

func hasDuplicates[T cmp.Ordered](s []T) bool {
	cloned := slices.Clone(s)
	slices.Sort(cloned)
	cloned = slices.Compact(cloned)
	return len(s) != len(cloned)
}

func hashSecret(secret string) string {
	// No salt needed because the secret is high entropy, and there is next to no chance of a
	// collision
	secretHashBytes := sha256.Sum256([]byte(secret))
	secretHash := hex.EncodeToString(secretHashBytes[:])
	return secretHash
}

// Create creates and stores a new client.
func (s *ClientStore) Create(
	ctx context.Context,
	params client.CreateParams,
) (client.Client, string, error) {
	if params.Name == "" {
		return client.Client{}, "", &client.InvalidClientError{
			Field:  "Name",
			Reason: "name is required",
		}
	}

	if len(params.GrantTypes) == 0 {
		return client.Client{}, "", &client.InvalidClientError{
			Field:  "GrantTypes",
			Reason: "at least one grant type is required",
		}
	}
	for _, grantType := range params.GrantTypes {
		if !slices.Contains(client.SupportedGrantTypes, grantType) {
			return client.Client{}, "", &client.InvalidClientError{
				Field:  "GrantTypes",
				Reason: fmt.Sprintf("unsupported grant type: %s", grantType),
			}
		}
	}
	if hasDuplicates(params.GrantTypes) {
		return client.Client{}, "", &client.InvalidClientError{
			Field:  "GrantTypes",
			Reason: "grant types cannot have duplicates",
		}
	}
	// RFC 6749 §4.4 says client credentials grant type MUST only be used by confidential clients
	if slices.Contains(params.GrantTypes, client.GrantTypeClientCredentials) && params.Public {
		return client.Client{}, "", &client.InvalidClientError{
			Field:  "GrantTypes",
			Reason: "client_credentials grant type is not allowed for public clients",
		}
	}

	// RFC 6749 §3.3 makes scope optional
	if params.Scopes == nil {
		params.Scopes = []string{}
	}

	// RFC 6749 §3.3 defines scope-token as one or more printable ASCII characters excluding space,
	// double quote and backslash
	for _, scope := range params.Scopes {
		if scope == "" {
			return client.Client{}, "", &client.InvalidClientError{
				Field:  "Scopes",
				Reason: "scope cannot be empty",
			}
		}
		for i := range len(scope) {
			if scope[i] < 0x21 || scope[i] > 0x7E || scope[i] == 0x22 || scope[i] == 0x5C {
				return client.Client{}, "", &client.InvalidClientError{
					Field:  "Scopes",
					Reason: fmt.Sprintf("scope contains invalid characters: %s", scope),
				}
			}
		}
	}
	if hasDuplicates(params.Scopes) {
		return client.Client{}, "", &client.InvalidClientError{
			Field:  "Scopes",
			Reason: "scopes cannot have duplicates",
		}
	}

	// RFC 9068 §2.2 lists aud as required in a JWT access token, and RFC 9068 §3 says that when
	// the request has no
	// resource parameter, the server MUST use a default resource indicator for aud.
	// The audiences list is used in this project as the default resource indicator, and also to
	// validate the resource
	// parameter when it is sent, rejecting unknown values with invalid_target per RFC 8707 §2.2
	if len(params.Audiences) == 0 {
		return client.Client{}, "", &client.InvalidClientError{
			Field:  "Audiences",
			Reason: "at least one audience is required",
		}
	}
	if slices.Contains(params.Audiences, "") {
		return client.Client{}, "", &client.InvalidClientError{
			Field:  "Audiences",
			Reason: "audience cannot be empty",
		}
	}
	for _, audience := range params.Audiences {
		// RFC 8707 §2 gives the rule: an absolute URI with no fragment, and it should not have a
		// query
		u, err := url.Parse(audience)
		if err != nil {
			return client.Client{}, "", &client.InvalidClientError{
				Field:  "Audiences",
				Reason: fmt.Sprintf("invalid audience: %s", audience),
			}
		}
		if !u.IsAbs() {
			return client.Client{}, "", &client.InvalidClientError{
				Field:  "Audiences",
				Reason: fmt.Sprintf("audience must be an absolute URI: %s", audience),
			}
		}
		if u.Fragment != "" {
			return client.Client{}, "", &client.InvalidClientError{
				Field:  "Audiences",
				Reason: fmt.Sprintf("audience cannot have a fragment: %s", audience),
			}
		}
		if u.RawQuery != "" {
			return client.Client{}, "", &client.InvalidClientError{
				Field:  "Audiences",
				Reason: fmt.Sprintf("audience cannot have a query: %s", audience),
			}
		}
	}
	if hasDuplicates(params.Audiences) {
		return client.Client{}, "", &client.InvalidClientError{
			Field:  "Audiences",
			Reason: "audiences cannot have duplicates",
		}
	}

	if params.RedirectionURIs == nil {
		params.RedirectionURIs = []string{}
	}

	// RFC 6749 §3.1.2.2 requires redirection URI registration only for public clients or
	// confidential clients using the implicit grant type, but recommends it for all clients prior
	// to utilizing the authorization endpoint, so we will require it for all clients that will use
	// the authorization endpoint.
	if slices.Contains(params.GrantTypes, client.GrantTypeAuthorizationCode) &&
		len(params.RedirectionURIs) == 0 {
		return client.Client{}, "", &client.InvalidClientError{
			Field:  "RedirectionURIs",
			Reason: "redirection URIs are required for authorization code clients",
		}
	}
	for _, redirectionURI := range params.RedirectionURIs {
		if redirectionURI == "" {
			return client.Client{}, "", &client.InvalidClientError{
				Field:  "RedirectionURIs",
				Reason: "redirection URI cannot be empty",
			}
		}
		u, err := url.Parse(redirectionURI)
		if err != nil {
			return client.Client{}, "", &client.InvalidClientError{
				Field:  "RedirectionURIs",
				Reason: fmt.Sprintf("invalid redirection URI: %s", redirectionURI),
			}
		}
		// TODO: support custom schemes for native apps RFC 8252 §7.1
		if u.Scheme != "https" && u.Scheme != "http" {
			return client.Client{}, "", &client.InvalidClientError{
				Field: "RedirectionURIs",
				Reason: fmt.Sprintf(
					"redirection URI must be an https or http URI: %s",
					redirectionURI,
				),
			}
		}
		if u.Hostname() == "" {
			return client.Client{}, "", &client.InvalidClientError{
				Field:  "RedirectionURIs",
				Reason: fmt.Sprintf("redirection URI must have a host: %s", redirectionURI),
			}
		}
		if strings.Contains(redirectionURI, "#") {
			return client.Client{}, "", &client.InvalidClientError{
				Field:  "RedirectionURIs",
				Reason: fmt.Sprintf("redirection URI cannot have a fragment: %s", redirectionURI),
			}
		}
		// TODO: RFC 6749 §3.1.2.1 recommends TLS for redirection URIs, but RFC 8252 §7 allows it
		// for some native apps. For now, we will not require TLS for redirection URIs, but in the
		// future, we will add a config option to require TLS for non-native apps, that can be
		// turned on for production deployments.
	}
	if hasDuplicates(params.RedirectionURIs) {
		return client.Client{}, "", &client.InvalidClientError{
			Field:  "RedirectionURIs",
			Reason: "redirection URIs cannot have duplicates",
		}
	}

	clientID := rand.Text()
	var secret string

	var secretHash sql.Null[string]
	if !params.Public {
		secret = rand.Text()
		secretHash.Valid = true
		secretHash.V = hashSecret(secret)
	}

	query := `
		INSERT INTO clients (id, name, grant_types, scopes, audiences, secret_hash, redirection_uris)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING ` + clientColumns

	c, _, err := scanClient(s.db.QueryRowContext(ctx, query,
		clientID,
		params.Name,
		params.GrantTypes,
		params.Scopes,
		params.Audiences,
		secretHash,
		params.RedirectionURIs,
	))
	if err != nil {
		if pgError, ok := errors.AsType[*pgconn.PgError](err); ok {
			// 23505 is the SQLState code for unique_violation
			if pgError.Code == "23505" && pgError.ConstraintName == "clients_name_key" {
				return client.Client{}, "", &client.InvalidClientError{
					Field:  "Name",
					Reason: "name must be unique",
				}
			}
		}
		return client.Client{}, "", fmt.Errorf("insert client: %w", err)
	}
	return c, secret, nil
}

var fixedSecretHash = make([]byte, 64)

// Authenticate authenticates a client if both ID and secret match.
func (s *ClientStore) Authenticate(
	ctx context.Context,
	clientID, secret string,
) (client.Client, error) {
	calculatedSecretHash := hashSecret(secret)
	query := `
		SELECT ` + clientColumns + `
		FROM clients
		WHERE id = $1
	`
	c, secretHash, err := scanClient(s.db.QueryRowContext(ctx, query, clientID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// If no client is found, compare against a fixed 64 character string and discard the
			// result to keep similar time to mitigate against timing attacks. In this case, a
			// missed DB lookup against an index column would return faster than a hit, so this
			// mitigation won't help much in that case, it would matter much more if the comparison
			// was a much slower operation,
			// like a bcrypt comparison.
			subtle.ConstantTimeCompare([]byte(calculatedSecretHash), fixedSecretHash)

			return client.Client{}, client.ErrUnknownClientOrWrongSecret
		}
		return client.Client{}, fmt.Errorf("authenticate client: %w", err)
	}

	if c.Public {
		// If the client is public, apply similar timing mitigation as above.
		subtle.ConstantTimeCompare([]byte(calculatedSecretHash), fixedSecretHash)

		return client.Client{}, client.ErrUnknownClientOrWrongSecret
	}

	if subtle.ConstantTimeCompare([]byte(calculatedSecretHash), []byte(secretHash)) == 1 {
		return c, nil
	}
	return client.Client{}, client.ErrUnknownClientOrWrongSecret
}
