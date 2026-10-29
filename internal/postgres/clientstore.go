package postgres

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"slices"

	"github.com/bgfernandes/small-idp-go/internal/client"
)

// ClientStore is a store for clients.
type ClientStore struct {
	db *sql.DB
}

// NewClientStore creates a new ClientStore.
func NewClientStore(db *sql.DB) *ClientStore {
	return &ClientStore{db: db}
}

// Get gets a client by its ID.
func (s *ClientStore) Get(ctx context.Context, clientID string) (c client.Client, err error) {
	query := `
		SELECT id, name, grant_types, scopes, audiences, created_at, updated_at
		FROM clients
		WHERE id = $1
	`
	err = s.db.QueryRowContext(ctx, query, clientID).Scan(&c.ID, &c.Name, &c.GrantTypes, &c.Scopes, &c.Audiences, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return client.Client{}, client.ErrNotFound
		}
		return client.Client{}, fmt.Errorf("scan client: %w", err)
	}

	return c, nil
}

func hasDuplicates[T cmp.Ordered](s []T) bool {
	cloned := slices.Clone(s)
	slices.Sort(cloned)
	cloned = slices.Compact(cloned)
	return len(s) != len(cloned)
}

// Create creates and stores a new client.
func (s *ClientStore) Create(ctx context.Context, params client.CreateParams) (client.Client, string, error) {
	if params.Name == "" {
		return client.Client{}, "", &client.InvalidClientError{Field: "Name", Reason: "name is required"}
	}

	if len(params.GrantTypes) == 0 {
		return client.Client{}, "", &client.InvalidClientError{Field: "GrantTypes", Reason: "at least one grant type is required"}
	}
	for _, grantType := range params.GrantTypes {
		if !slices.Contains(client.SupportedGrantTypes, grantType) {
			return client.Client{}, "", &client.InvalidClientError{Field: "GrantTypes", Reason: fmt.Sprintf("unsupported grant type: %s", grantType)}
		}
	}
	if hasDuplicates(params.GrantTypes) {
		return client.Client{}, "", &client.InvalidClientError{Field: "GrantTypes", Reason: "grant types cannot have duplicates"}
	}

	// RFC 6749 §3.3 makes scope optional
	if params.Scopes == nil {
		params.Scopes = []string{}
	}

	// RFC 6749 §3.3 defines scope-token as one or more printable ASCII characters excluding space, double quote and backslash
	for _, scope := range params.Scopes {
		if scope == "" {
			return client.Client{}, "", &client.InvalidClientError{Field: "Scopes", Reason: "scope cannot be empty"}
		}
		for i := range len(scope) {
			if scope[i] < 0x21 || scope[i] > 0x7E || scope[i] == 0x22 || scope[i] == 0x5C {
				return client.Client{}, "", &client.InvalidClientError{Field: "Scopes", Reason: fmt.Sprintf("scope contains invalid characters: %s", scope)}
			}
		}
	}
	if hasDuplicates(params.Scopes) {
		return client.Client{}, "", &client.InvalidClientError{Field: "Scopes", Reason: "scopes cannot have duplicates"}
	}

	//  RFC 9068 §2.2 lists aud as required in a JWT access token, and RFC 9068 §3 says that when the request has no
	// resource parameter, the server MUST use a default resource indicator for aud.
	// The audiences list is used in this project as the default resource indicator, and also to validate the resource
	// parameter when it is sent, rejecting unknown values with invalid_target per RFC 8707 §2.2
	if len(params.Audiences) == 0 {
		return client.Client{}, "", &client.InvalidClientError{Field: "Audiences", Reason: "at least one audience is required"}
	}
	if slices.Contains(params.Audiences, "") {
		return client.Client{}, "", &client.InvalidClientError{Field: "Audiences", Reason: "audience cannot be empty"}
	}
	for _, audience := range params.Audiences {
		// RFC 8707 §2 gives the rule: an absolute URI with no fragment, and it should not have a query
		u, err := url.Parse(audience)
		if err != nil {
			return client.Client{}, "", &client.InvalidClientError{Field: "Audiences", Reason: fmt.Sprintf("invalid audience: %s", audience)}
		}
		if !u.IsAbs() {
			return client.Client{}, "", &client.InvalidClientError{Field: "Audiences", Reason: fmt.Sprintf("audience must be an absolute URI: %s", audience)}
		}
		if u.Fragment != "" {
			return client.Client{}, "", &client.InvalidClientError{Field: "Audiences", Reason: fmt.Sprintf("audience cannot have a fragment: %s", audience)}
		}
		if u.RawQuery != "" {
			return client.Client{}, "", &client.InvalidClientError{Field: "Audiences", Reason: fmt.Sprintf("audience cannot have a query: %s", audience)}
		}
	}
	if hasDuplicates(params.Audiences) {
		return client.Client{}, "", &client.InvalidClientError{Field: "Audiences", Reason: "audiences cannot have duplicates"}
	}

	c := client.Client{
		ID: rand.Text(),
	}
	secret := rand.Text()

	// No salt needed because the secret is high entropy, and there is next to no chance of a collision
	secretHashBytes := sha256.Sum256([]byte(secret))
	secretHash := hex.EncodeToString(secretHashBytes[:])

	query := `
		INSERT INTO clients (id, name, grant_types, scopes, audiences, client_secret_hash)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING name, grant_types, scopes, audiences, created_at, updated_at
	`

	err := s.db.QueryRowContext(ctx, query,
		c.ID,
		params.Name,
		params.GrantTypes,
		params.Scopes,
		params.Audiences,
		secretHash,
	).Scan(
		&c.Name,
		&c.GrantTypes,
		&c.Scopes,
		&c.Audiences,
		&c.CreatedAt,
		&c.UpdatedAt,
	)
	if err != nil {
		return client.Client{}, "", fmt.Errorf("insert client: %w", err)
	}
	return c, secret, nil
}
