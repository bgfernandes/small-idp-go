//go:build integration

package postgres_test

import (
	"crypto/sha256"
	"database/sql"
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
		Audiences:       []string{"https://example.com"},
		GrantTypes:      []client.GrantType{client.GrantTypeClientCredentials},
		Name:            "test-client",
		RedirectionURIs: []string{"http://localhost:3000/callback?with=query"},
		Scopes:          []string{"openid"},
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
		ID:              c.ID,
		Audiences:       []string{"https://example.com"},
		GrantTypes:      []client.GrantType{client.GrantTypeClientCredentials},
		Name:            "test-client",
		Public:          false,
		RedirectionURIs: []string{"http://localhost:3000/callback?with=query"},
		Scopes:          []string{"openid"},
		CreatedAt:       c.CreatedAt,
		UpdatedAt:       c.UpdatedAt,
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

func TestClientStoreCreateAndGetPublicClient(t *testing.T) {
	t.Parallel()

	db := pgtest.CreateTestDatabaseAndRunMigrations(t, testDatabasePrefix)

	store := postgres.NewClientStore(db)

	c, secret, err := store.Create(t.Context(), client.CreateParams{
		Audiences:       []string{"https://example.com"},
		GrantTypes:      []client.GrantType{client.GrantTypeAuthorizationCode},
		Name:            "test-public-client",
		Public:          true,
		RedirectionURIs: []string{"http://localhost:3000/callback?with=query"},
		Scopes:          []string{"openid"},
	})
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	if c.ID == "" {
		t.Fatalf("got client ID empty, want non-empty")
	}
	if secret != "" {
		t.Errorf("got secret %s, want empty", secret)
	}
	if c.CreatedAt.IsZero() {
		t.Errorf("got client created at zero, want non-zero")
	}
	if c.UpdatedAt.IsZero() {
		t.Errorf("got client updated at zero, want non-zero")
	}

	wantClient := client.Client{
		ID:              c.ID,
		Audiences:       []string{"https://example.com"},
		GrantTypes:      []client.GrantType{client.GrantTypeAuthorizationCode},
		Name:            "test-public-client",
		Public:          true,
		RedirectionURIs: []string{"http://localhost:3000/callback?with=query"},
		Scopes:          []string{"openid"},
		CreatedAt:       c.CreatedAt,
		UpdatedAt:       c.UpdatedAt,
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

	// check that the secret hash is null
	query := `
		SELECT secret_hash
		FROM clients
		WHERE id = $1
	`
	var hash sql.Null[string]
	err = db.QueryRowContext(t.Context(), query, c.ID).Scan(&hash)
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}
	if hash.Valid {
		t.Errorf("got secret hash %s, want null", hash.V)
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
				Audiences: []string{"https://example.com"},
				GrantTypes: []client.GrantType{
					client.GrantTypeClientCredentials,
					client.GrantTypeClientCredentials,
				},
				Name:   "test-client",
				Scopes: []string{"openid"},
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
		{
			name: "authorization code client with no redirection URIs",
			params: client.CreateParams{
				Audiences:  []string{"https://example.com"},
				GrantTypes: []client.GrantType{client.GrantTypeAuthorizationCode},
				Name:       "test-client",
				Scopes:     []string{"openid"},
			},
			wantInvalidError: &client.InvalidClientError{
				Field:  "RedirectionURIs",
				Reason: "redirection URIs are required for authorization code clients",
			},
		},
		{
			name: "empty redirection URI",
			params: client.CreateParams{
				Audiences:       []string{"https://example.com"},
				GrantTypes:      []client.GrantType{client.GrantTypeAuthorizationCode},
				Name:            "test-client",
				RedirectionURIs: []string{""},
				Scopes:          []string{"openid"},
			},
			wantInvalidError: &client.InvalidClientError{
				Field:  "RedirectionURIs",
				Reason: "redirection URI cannot be empty",
			},
		},
		{
			name: "invalid redirection URI",
			params: client.CreateParams{
				Audiences:       []string{"https://example.com"},
				GrantTypes:      []client.GrantType{client.GrantTypeAuthorizationCode},
				Name:            "test-client",
				RedirectionURIs: []string{":::invaliduri"},
				Scopes:          []string{"openid"},
			},
			wantInvalidError: &client.InvalidClientError{
				Field:  "RedirectionURIs",
				Reason: "invalid redirection URI: :::invaliduri",
			},
		},
		{
			name: "invalid redirection URI with no host",
			params: client.CreateParams{
				Audiences:       []string{"https://example.com"},
				GrantTypes:      []client.GrantType{client.GrantTypeAuthorizationCode},
				Name:            "test-client",
				RedirectionURIs: []string{"https://:8080/path"},
				Scopes:          []string{"openid"},
			},
			wantInvalidError: &client.InvalidClientError{
				Field:  "RedirectionURIs",
				Reason: "redirection URI must have a host: https://:8080/path",
			},
		},
		{
			name: "redirection URI with no scheme",
			params: client.CreateParams{
				Audiences:       []string{"https://example.com"},
				GrantTypes:      []client.GrantType{client.GrantTypeAuthorizationCode},
				Name:            "test-client",
				RedirectionURIs: []string{"invalid-uri.com/path"},
				Scopes:          []string{"openid"},
			},
			wantInvalidError: &client.InvalidClientError{
				Field:  "RedirectionURIs",
				Reason: "redirection URI must be an https or http URI: invalid-uri.com/path",
			},
		},
		{
			name: "redirection URI with fragment",
			params: client.CreateParams{
				Audiences:       []string{"https://example.com"},
				GrantTypes:      []client.GrantType{client.GrantTypeAuthorizationCode},
				Name:            "test-client",
				RedirectionURIs: []string{"https://example.com/path#fragment"},
				Scopes:          []string{"openid"},
			},
			wantInvalidError: &client.InvalidClientError{
				Field:  "RedirectionURIs",
				Reason: "redirection URI cannot have a fragment: https://example.com/path#fragment",
			},
		},
		{
			name: "public client with client credentials grant type",
			params: client.CreateParams{
				Audiences: []string{"https://example.com"},
				GrantTypes: []client.GrantType{
					client.GrantTypeClientCredentials,
					client.GrantTypeAuthorizationCode,
				},
				Name:            "test-client",
				Public:          true,
				RedirectionURIs: []string{"https://example.com/path"},
				Scopes:          []string{"openid"},
			},
			wantInvalidError: &client.InvalidClientError{
				Field:  "GrantTypes",
				Reason: "client_credentials grant type is not allowed for public clients",
			},
		},
		{
			name: "duplicate redirection URIs",
			params: client.CreateParams{
				Audiences:       []string{"https://example.com"},
				GrantTypes:      []client.GrantType{client.GrantTypeAuthorizationCode},
				Name:            "test-client",
				RedirectionURIs: []string{"https://example.com/path", "https://example.com/path"},
				Scopes:          []string{"openid"},
			},
			wantInvalidError: &client.InvalidClientError{
				Field:  "RedirectionURIs",
				Reason: "redirection URIs cannot have duplicates",
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
		ID:              c.ID,
		Audiences:       []string{"https://example.com"},
		GrantTypes:      []client.GrantType{client.GrantTypeClientCredentials},
		Name:            "test-client",
		Public:          false,
		RedirectionURIs: []string{},
		Scopes:          []string{},
		CreatedAt:       c.CreatedAt,
		UpdatedAt:       c.UpdatedAt,
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

func TestClientStoreAuthenticate(t *testing.T) {
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

	authenticatedClient, err := store.Authenticate(t.Context(), c.ID, secret)
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}
	if !reflect.DeepEqual(authenticatedClient, c) {
		t.Fatalf("got authenticated client %+v, want %+v", authenticatedClient, c)
	}

	gotClient, err := store.Get(t.Context(), c.ID)
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}
	if !reflect.DeepEqual(gotClient, authenticatedClient) {
		t.Fatalf("got client from get %+v, want %+v", gotClient, authenticatedClient)
	}
}

func TestClientStoreAuthenticateUnknownClientOrWrongSecret(t *testing.T) {
	t.Parallel()

	db := pgtest.CreateTestDatabaseAndRunMigrations(t, testDatabasePrefix)

	store := postgres.NewClientStore(db)

	clientA, _, err := store.Create(t.Context(), client.CreateParams{
		Audiences:  []string{"https://example.com"},
		GrantTypes: []client.GrantType{client.GrantTypeClientCredentials},
		Name:       "test-client-a",
		Scopes:     []string{"openid"},
	})
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	_, secretB, err := store.Create(t.Context(), client.CreateParams{
		Audiences:  []string{"https://example.com"},
		GrantTypes: []client.GrantType{client.GrantTypeClientCredentials},
		Name:       "test-client-b",
		Scopes:     []string{"openid"},
	})
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	publicClient, _, err := store.Create(t.Context(), client.CreateParams{
		Audiences:       []string{"https://example.com"},
		GrantTypes:      []client.GrantType{client.GrantTypeAuthorizationCode},
		Name:            "test-public-client",
		Public:          true,
		RedirectionURIs: []string{"http://localhost:3000/callback"},
		Scopes:          []string{"openid"},
	})
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	tests := []struct {
		name     string
		clientID string
		secret   string
	}{
		{
			name:     "unknown client",
			clientID: "unknown-client-id",
			secret:   "secret",
		},
		{
			name:     "wrong secret",
			clientID: clientA.ID,
			secret:   "wrong-secret",
		},
		{
			name:     "empty secret",
			clientID: clientA.ID,
			secret:   "",
		},
		{
			name:     "another client's secret",
			clientID: clientA.ID,
			secret:   secretB,
		},
		{
			name:     "public client",
			clientID: publicClient.ID,
			secret:   "secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := store.Authenticate(t.Context(), tt.clientID, tt.secret)
			if !errors.Is(err, client.ErrUnknownClientOrWrongSecret) {
				t.Fatalf("got error %v, want %v", err, client.ErrUnknownClientOrWrongSecret)
			}
		})
	}
}
