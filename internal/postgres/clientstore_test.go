//go:build integration

package postgres_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"

	"github.com/bgfernandes/small-idp-go/internal/client"
	"github.com/bgfernandes/small-idp-go/internal/postgres"
	"github.com/bgfernandes/small-idp-go/internal/postgres/pgtest"
)

func TestClientStoreGetNonExistentClient(t *testing.T) {
	t.Parallel()

	db := pgtest.CreateTestDatabaseAndRunMigrations(t, testDatabasePrefix)

	store := postgres.NewClientStore(db)

	_, err := store.Get(t.Context(), "non-existent-client-id")
	if !errors.Is(err, client.ErrNotFound) {
		t.Fatalf("got error %v, want %v", err, client.ErrNotFound)
	}
}

func TestClientStoreCreateAndGetClient(t *testing.T) {
	t.Parallel()

	db := pgtest.CreateTestDatabaseAndRunMigrations(t, testDatabasePrefix)

	store := postgres.NewClientStore(db)

	c, secret, err := store.Create(t.Context(), client.CreateParams{
		Audiences:  []string{"https://example.com"},
		GrantTypes: []client.GrantType{client.GrantTypeClientCredentials},
		Name:       "test-client",
		Scopes:     []string{"openid"},
	})
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	if c.ID == "" {
		t.Fatalf("got client ID empty, want non-empty")
	}
	if secret == "" {
		t.Fatalf("got secret empty, want non-empty")
	}
	if c.CreatedAt.IsZero() {
		t.Fatalf("got client created at zero, want non-zero")
	}
	if c.UpdatedAt.IsZero() {
		t.Fatalf("got client updated at zero, want non-zero")
	}

	wantClient := client.Client{
		ID:         c.ID,
		CreatedAt:  c.CreatedAt,
		UpdatedAt:  c.UpdatedAt,
		Name:       "test-client",
		GrantTypes: []client.GrantType{client.GrantTypeClientCredentials},
		Scopes:     []string{"openid"},
		Audiences:  []string{"https://example.com"},
	}

	if !reflect.DeepEqual(c, wantClient) {
		t.Fatalf("got client %+v, want %+v", c, wantClient)
	}

	gotClient, err := store.Get(t.Context(), c.ID)
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}
	if !reflect.DeepEqual(gotClient, wantClient) {
		t.Fatalf("got client from get %+v, want %+v", gotClient, wantClient)
	}

	// check that the hash is the sha256 of the secret
	query := `
		SELECT secret_hash
		FROM clients
		WHERE id = $1
	`
	var hash string
	err = db.QueryRowContext(t.Context(), query, c.ID).Scan(&hash)
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}
	secretHashBytes := sha256.Sum256([]byte(secret))
	secretHash := hex.EncodeToString(secretHashBytes[:])
	if hash != secretHash {
		t.Fatalf("got hash %s, want %s", hash, secretHash)
	}
}

func TestClientStoreCreateInvalidParams(t *testing.T) {
	t.Parallel()

	db := pgtest.CreateTestDatabaseAndRunMigrations(t, testDatabasePrefix)

	store := postgres.NewClientStore(db)

	tests := []struct {
		name             string
		params           client.CreateParams
		wantInvalidError *client.InvalidClientError
	}{
		{
			name: "invalid client name",
			params: client.CreateParams{
				Audiences:  []string{"https://example.com"},
				GrantTypes: []client.GrantType{client.GrantTypeClientCredentials},
				Name:       "",
				Scopes:     []string{"openid"},
			},
			wantInvalidError: &client.InvalidClientError{
				Field:  "Name",
				Reason: "name is required",
			},
		},
		{
			name: "no grant types",
			params: client.CreateParams{
				Audiences: []string{"https://example.com"},
				Name:      "test-client",
				Scopes:    []string{"openid"},
			},
			wantInvalidError: &client.InvalidClientError{
				Field:  "GrantTypes",
				Reason: "at least one grant type is required",
			},
		},
		{
			name: "invalid grant type",
			params: client.CreateParams{
				Audiences:  []string{"https://example.com"},
				GrantTypes: []client.GrantType{"invalid"},
				Name:       "test-client",
				Scopes:     []string{"openid"},
			},
			wantInvalidError: &client.InvalidClientError{
				Field:  "GrantTypes",
				Reason: "unsupported grant type: invalid",
			},
		},
		{
			name: "duplicate grant types",
			params: client.CreateParams{
				Audiences:  []string{"https://example.com"},
				GrantTypes: []client.GrantType{client.GrantTypeClientCredentials, client.GrantTypeClientCredentials},
				Name:       "test-client",
				Scopes:     []string{"openid"},
			},
			wantInvalidError: &client.InvalidClientError{
				Field:  "GrantTypes",
				Reason: "grant types cannot have duplicates",
			},
		},
		{
			name: "empty scope",
			params: client.CreateParams{
				Audiences:  []string{"https://example.com"},
				GrantTypes: []client.GrantType{client.GrantTypeClientCredentials},
				Name:       "test-client",
				Scopes:     []string{""},
			},
			wantInvalidError: &client.InvalidClientError{
				Field:  "Scopes",
				Reason: "scope cannot be empty",
			},
		},
		{
			name: "invalid scope",
			params: client.CreateParams{
				Audiences:  []string{"https://example.com"},
				GrantTypes: []client.GrantType{client.GrantTypeClientCredentials},
				Name:       "test-client",
				Scopes:     []string{"invalid scope"},
			},
			wantInvalidError: &client.InvalidClientError{
				Field:  "Scopes",
				Reason: "scope contains invalid characters: invalid scope",
			},
		},
		{
			name: "duplicate scopes",
			params: client.CreateParams{
				Audiences:  []string{"https://example.com"},
				GrantTypes: []client.GrantType{client.GrantTypeClientCredentials},
				Name:       "test-client",
				Scopes:     []string{"openid", "openid"},
			},
			wantInvalidError: &client.InvalidClientError{
				Field:  "Scopes",
				Reason: "scopes cannot have duplicates",
			},
		},
		{
			name: "no audiences",
			params: client.CreateParams{
				GrantTypes: []client.GrantType{client.GrantTypeClientCredentials},
				Name:       "test-client",
				Scopes:     []string{"openid"},
			},
			wantInvalidError: &client.InvalidClientError{
				Field:  "Audiences",
				Reason: "at least one audience is required",
			},
		},
		{
			name: "empty audience",
			params: client.CreateParams{
				Audiences:  []string{""},
				GrantTypes: []client.GrantType{client.GrantTypeClientCredentials},
				Name:       "test-client",
				Scopes:     []string{"openid"},
			},
			wantInvalidError: &client.InvalidClientError{
				Field:  "Audiences",
				Reason: "audience cannot be empty",
			},
		},
		{
			name: "invalid audience",
			params: client.CreateParams{
				Audiences:  []string{":::invalidaudience"},
				GrantTypes: []client.GrantType{client.GrantTypeClientCredentials},
				Name:       "test-client",
				Scopes:     []string{"openid"},
			},
			wantInvalidError: &client.InvalidClientError{
				Field:  "Audiences",
				Reason: "invalid audience: :::invalidaudience",
			},
		},
		{
			name: "invalid audience URI",
			params: client.CreateParams{
				Audiences:  []string{"example.com/invalid-audience-uri"},
				GrantTypes: []client.GrantType{client.GrantTypeClientCredentials},
				Name:       "test-client",
				Scopes:     []string{"openid"},
			},
			wantInvalidError: &client.InvalidClientError{
				Field:  "Audiences",
				Reason: "audience must be an absolute URI: example.com/invalid-audience-uri",
			},
		},
		{
			name: "audience with fragment",
			params: client.CreateParams{
				Audiences:  []string{"https://example.com/audience#fragment"},
				GrantTypes: []client.GrantType{client.GrantTypeClientCredentials},
				Name:       "test-client",
				Scopes:     []string{"openid"},
			},
			wantInvalidError: &client.InvalidClientError{
				Field:  "Audiences",
				Reason: "audience cannot have a fragment: https://example.com/audience#fragment",
			},
		},
		{
			name: "audience with query",
			params: client.CreateParams{
				Audiences:  []string{"https://example.com/audience?query=value"},
				GrantTypes: []client.GrantType{client.GrantTypeClientCredentials},
				Name:       "test-client",
				Scopes:     []string{"openid"},
			},
			wantInvalidError: &client.InvalidClientError{
				Field:  "Audiences",
				Reason: "audience cannot have a query: https://example.com/audience?query=value",
			},
		},
		{
			name: "duplicate audiences",
			params: client.CreateParams{
				Audiences:  []string{"https://example.com", "https://example.com"},
				GrantTypes: []client.GrantType{client.GrantTypeClientCredentials},
				Name:       "test-client",
				Scopes:     []string{"openid"},
			},
			wantInvalidError: &client.InvalidClientError{
				Field:  "Audiences",
				Reason: "audiences cannot have duplicates",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, _, err := store.Create(t.Context(), tt.params)

			if err == nil {
				t.Fatalf("got error nil, want %v", tt.wantInvalidError)
			}
			var invalid *client.InvalidClientError
			if !errors.As(err, &invalid) {
				t.Fatalf("got error %T, want %T", err, tt.wantInvalidError)
			}
			if !reflect.DeepEqual(invalid, tt.wantInvalidError) {
				t.Fatalf("got invalid error %+v, want %+v", invalid, tt.wantInvalidError)
			}
		})
	}
}

func TestClientStoreCreateClientWithNoScopes(t *testing.T) {
	t.Parallel()

	db := pgtest.CreateTestDatabaseAndRunMigrations(t, testDatabasePrefix)

	store := postgres.NewClientStore(db)

	params := client.CreateParams{
		Audiences:  []string{"https://example.com"},
		GrantTypes: []client.GrantType{client.GrantTypeClientCredentials},
		Name:       "test-client",
	}

	c, secret, err := store.Create(t.Context(), params)
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	if secret == "" {
		t.Fatalf("got secret empty, want non-empty")
	}

	wantClient := client.Client{
		ID:         c.ID,
		CreatedAt:  c.CreatedAt,
		UpdatedAt:  c.UpdatedAt,
		Name:       "test-client",
		GrantTypes: []client.GrantType{client.GrantTypeClientCredentials},
		Scopes:     []string{},
		Audiences:  []string{"https://example.com"},
	}
	if !reflect.DeepEqual(c, wantClient) {
		t.Fatalf("got client %+v, want %+v", c, wantClient)
	}

	gotClient, err := store.Get(t.Context(), c.ID)
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}
	if !reflect.DeepEqual(gotClient, wantClient) {
		t.Fatalf("got client from get %+v, want %+v", gotClient, wantClient)
	}
}

func TestClientStoreTwoCreatesDifferentClients(t *testing.T) {
	t.Parallel()

	db := pgtest.CreateTestDatabaseAndRunMigrations(t, testDatabasePrefix)

	store := postgres.NewClientStore(db)

	client1, secret1, err := store.Create(t.Context(), client.CreateParams{
		Audiences:  []string{"https://example.com"},
		GrantTypes: []client.GrantType{client.GrantTypeClientCredentials},
		Name:       "test-client-1",
		Scopes:     []string{"openid"},
	})
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	client2, secret2, err := store.Create(t.Context(), client.CreateParams{
		Audiences:  []string{"https://example.com"},
		GrantTypes: []client.GrantType{client.GrantTypeClientCredentials},
		Name:       "test-client-2",
		Scopes:     []string{"openid"},
	})
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	if client1.ID == client2.ID {
		t.Fatalf("got client IDs equal, want different")
	}
	if secret1 == secret2 {
		t.Fatalf("got secrets equal, want different")
	}
}

func TestClientStoreCreateClientWithDuplicateName(t *testing.T) {
	t.Parallel()

	db := pgtest.CreateTestDatabaseAndRunMigrations(t, testDatabasePrefix)

	store := postgres.NewClientStore(db)

	params := client.CreateParams{
		Audiences:  []string{"https://example.com"},
		GrantTypes: []client.GrantType{client.GrantTypeClientCredentials},
		Name:       "test-client",
		Scopes:     []string{"openid"},
	}

	_, _, err := store.Create(t.Context(), params)
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	wantInvalidError := &client.InvalidClientError{Field: "Name", Reason: "name must be unique"}

	_, _, err = store.Create(t.Context(), params)
	invalid, ok := errors.AsType[*client.InvalidClientError](err)
	if !ok {
		t.Fatalf("got error %T, want %T", err, wantInvalidError)
	}
	if !reflect.DeepEqual(invalid, wantInvalidError) {
		t.Fatalf("got invalid error %+v, want %+v", invalid, wantInvalidError)
	}

	// name uniqueness is case insensitive
	params.Name = "Test-Client"
	_, _, err = store.Create(t.Context(), params)
	invalid, ok = errors.AsType[*client.InvalidClientError](err)
	if !ok {
		t.Fatalf("got error %T, want %T", err, wantInvalidError)
	}
	if !reflect.DeepEqual(invalid, wantInvalidError) {
		t.Fatalf("got invalid error %+v, want %+v", invalid, wantInvalidError)
	}
}
