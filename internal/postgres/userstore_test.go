//go:build integration

package postgres_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/bgfernandes/small-idp-go/internal/postgres"
	"github.com/bgfernandes/small-idp-go/internal/postgres/pgtest"
	"github.com/bgfernandes/small-idp-go/internal/user"
	"golang.org/x/crypto/bcrypt"
)

func TestUserStoreGetNonExistentUser(t *testing.T) {
	t.Parallel()

	db := pgtest.CreateTestDatabaseAndRunMigrations(t, testDatabasePrefix)

	store := postgres.NewUserStore(db, bcrypt.MinCost)

	_, err := store.Get(t.Context(), "non-existent-user-id")
	if !errors.Is(err, user.ErrNotFound) {
		t.Fatalf("got error %v, want %v", err, user.ErrNotFound)
	}
}

func TestUserStoreCreateAndGetUser(t *testing.T) {
	t.Parallel()

	db := pgtest.CreateTestDatabaseAndRunMigrations(t, testDatabasePrefix)

	store := postgres.NewUserStore(db, bcrypt.MinCost)

	email, password := "test@example.com", "password"

	u, err := store.Create(t.Context(), user.CreateParams{
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	if u.ID == "" {
		t.Fatalf("got user ID empty, want non-empty")
	}
	if u.Email != email {
		t.Fatalf("got email %s, want %s", u.Email, email)
	}
	if u.CreatedAt.IsZero() {
		t.Fatalf("got user created at zero, want non-zero")
	}
	if u.UpdatedAt.IsZero() {
		t.Fatalf("got user updated at zero, want non-zero")
	}

	wantUser := user.User{
		ID:        u.ID,
		Email:     u.Email,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
	}

	gotUser, err := store.Get(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}
	if !reflect.DeepEqual(gotUser, wantUser) {
		t.Fatalf("got user from get %+v, want %+v", gotUser, wantUser)
	}

	// check that the password hash matches the password
	query := `
		SELECT password_hash
		FROM users
		WHERE id = $1
	`
	var passwordHash string
	err = db.QueryRowContext(t.Context(), query, u.ID).Scan(&passwordHash)
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}
}

func TestUserStoreCreateInvalidParams(t *testing.T) {
	t.Parallel()

	db := pgtest.CreateTestDatabaseAndRunMigrations(t, testDatabasePrefix)

	store := postgres.NewUserStore(db, bcrypt.MinCost)

	tests := []struct {
		name             string
		params           user.CreateParams
		wantInvalidError *user.InvalidUserError
	}{
		{
			name: "empty email",
			params: user.CreateParams{
				Email:    "",
				Password: "password",
			},
			wantInvalidError: &user.InvalidUserError{
				Field:  "Email",
				Reason: "email is required",
			},
		},
		{
			name: "email with no @",
			params: user.CreateParams{
				Email:    "testexample.com",
				Password: "password",
			},
			wantInvalidError: &user.InvalidUserError{
				Field:  "Email",
				Reason: "email must contain exactly one @",
			},
		},
		{
			name: "email with two @",
			params: user.CreateParams{
				Email:    "test@example.com@example.com",
				Password: "password",
			},
			wantInvalidError: &user.InvalidUserError{
				Field:  "Email",
				Reason: "email must contain exactly one @",
			},
		},
		{
			name: "email with whitespace",
			params: user.CreateParams{
				Email:    " test@example.com",
				Password: "password",
			},
			wantInvalidError: &user.InvalidUserError{
				Field:  "Email",
				Reason: "email must not contain whitespace",
			},
		},
		{
			name: "email with newline",
			params: user.CreateParams{
				Email:    "test@example.com\n",
				Password: "password",
			},
			wantInvalidError: &user.InvalidUserError{
				Field:  "Email",
				Reason: "email must not contain whitespace",
			},
		},
		{
			name: "email with tab",
			params: user.CreateParams{
				Email:    "test@example.com\t",
				Password: "password",
			},
			wantInvalidError: &user.InvalidUserError{
				Field:  "Email",
				Reason: "email must not contain whitespace",
			},
		},
		{
			name: "empty password",
			params: user.CreateParams{
				Email:    "test@example.com",
				Password: "",
			},
			wantInvalidError: &user.InvalidUserError{
				Field:  "Password",
				Reason: "password is required",
			},
		},
		{
			name: "password too long",
			params: user.CreateParams{
				Email:    "test@example.com",
				Password: strings.Repeat("a", 73),
			},
			wantInvalidError: &user.InvalidUserError{
				Field:  "Password",
				Reason: "password must be at most 72 bytes",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := store.Create(t.Context(), tt.params)

			if err == nil {
				t.Fatalf("got error nil, want %v", tt.wantInvalidError)
			}

			invalid, ok := errors.AsType[*user.InvalidUserError](err)
			if !ok {
				t.Fatalf("got error %T, want %T", err, tt.wantInvalidError)
			}

			if !reflect.DeepEqual(invalid, tt.wantInvalidError) {
				t.Fatalf("got invalid error %+v, want %+v", invalid, tt.wantInvalidError)
			}
		})
	}
}

func TestUserStoreTwoCreatesDifferentUsers(t *testing.T) {
	t.Parallel()

	db := pgtest.CreateTestDatabaseAndRunMigrations(t, testDatabasePrefix)

	store := postgres.NewUserStore(db, bcrypt.MinCost)

	user1, err := store.Create(t.Context(), user.CreateParams{
		Email:    "test@example.com",
		Password: "password",
	})
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	user2, err := store.Create(t.Context(), user.CreateParams{
		Email:    "test2@example.com",
		Password: "password2",
	})
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	if user1.ID == user2.ID {
		t.Fatalf("got user IDs equal, want different")
	}
}

func TestUserStoreCreateUserWithDuplicateEmail(t *testing.T) {
	t.Parallel()

	db := pgtest.CreateTestDatabaseAndRunMigrations(t, testDatabasePrefix)

	store := postgres.NewUserStore(db, bcrypt.MinCost)

	params := user.CreateParams{
		Email:    "test@example.com",
		Password: "password",
	}

	_, err := store.Create(t.Context(), params)
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	wantInvalidError := &user.InvalidUserError{Field: "Email", Reason: "email must be unique"}

	_, err = store.Create(t.Context(), params)
	invalid, ok := errors.AsType[*user.InvalidUserError](err)
	if !ok {
		t.Fatalf("got error %T, want %T", err, wantInvalidError)
	}
	if !reflect.DeepEqual(invalid, wantInvalidError) {
		t.Fatalf("got invalid error %+v, want %+v", invalid, wantInvalidError)
	}

	// email uniqueness is case insensitive
	params.Email = "TEST@example.com"
	_, err = store.Create(t.Context(), params)
	invalid, ok = errors.AsType[*user.InvalidUserError](err)
	if !ok {
		t.Fatalf("got error %T, want %T", err, wantInvalidError)
	}
	if !reflect.DeepEqual(invalid, wantInvalidError) {
		t.Fatalf("got invalid error %+v, want %+v", invalid, wantInvalidError)
	}
}

func TestUserStoreAuthenticate(t *testing.T) {
	t.Parallel()

	db := pgtest.CreateTestDatabaseAndRunMigrations(t, testDatabasePrefix)

	store := postgres.NewUserStore(db, bcrypt.MinCost)

	u, err := store.Create(t.Context(), user.CreateParams{
		Email:    "test@example.com",
		Password: "password",
	})
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	tests := []struct {
		name  string
		email string
	}{
		{
			name:  "case equal email",
			email: "test@example.com",
		},
		{
			name:  "case insensitive email",
			email: "TEST@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			authenticatedUser, err := store.Authenticate(t.Context(), tt.email, "password")
			if err != nil {
				t.Fatalf("got error %v, want nil", err)
			}
			if !reflect.DeepEqual(authenticatedUser, u) {
				t.Fatalf("got authenticated user %+v, want %+v", authenticatedUser, u)
			}

			gotUser, err := store.Get(t.Context(), u.ID)
			if err != nil {
				t.Fatalf("got error %v, want nil", err)
			}
			if !reflect.DeepEqual(gotUser, authenticatedUser) {
				t.Fatalf("got user from get %+v, want %+v", gotUser, authenticatedUser)
			}
		})
	}
}

func TestUserStoreAuthenticateUnknownUserOrWrongPassword(t *testing.T) {
	t.Parallel()

	db := pgtest.CreateTestDatabaseAndRunMigrations(t, testDatabasePrefix)

	store := postgres.NewUserStore(db, bcrypt.MinCost)

	userA, err := store.Create(t.Context(), user.CreateParams{
		Email:    "user-a@example.com",
		Password: "user-a-password",
	})
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	_, err = store.Create(t.Context(), user.CreateParams{
		Email:    "user-b@example.com",
		Password: "user-b-password",
	})
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	tests := []struct {
		name     string
		email    string
		password string
	}{
		{
			name:     "unknown user",
			email:    "unknown-user@example.com",
			password: "unknown-password",
		},
		{
			name:     "wrong password",
			email:    userA.Email,
			password: "wrong-password",
		},
		{
			name:     "empty password",
			email:    userA.Email,
			password: "",
		},
		{
			name:     "another user's password",
			email:    userA.Email,
			password: "user-b-password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := store.Authenticate(t.Context(), tt.email, tt.password)
			if !errors.Is(err, user.ErrUnknownUserOrWrongPassword) {
				t.Fatalf("got error %v, want %v", err, user.ErrUnknownUserOrWrongPassword)
			}
		})
	}
}

func TestUserStoreAuthenticateMalformedPasswordHash(t *testing.T) {
	t.Parallel()

	db := pgtest.CreateTestDatabaseAndRunMigrations(t, testDatabasePrefix)

	store := postgres.NewUserStore(db, bcrypt.MinCost)

	u, err := store.Create(t.Context(), user.CreateParams{
		Email:    "test@example.com",
		Password: "password",
	})
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	// update the password hash to a malformed one
	query := `
		UPDATE users
		SET password_hash = 'malformed-password-hash'
		WHERE id = $1
	`
	_, err = db.ExecContext(t.Context(), query, u.ID)
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}

	_, err = store.Authenticate(t.Context(), u.Email, "password")
	if err == nil {
		t.Fatalf("got error nil, want error")
	}
	if errors.Is(err, user.ErrUnknownUserOrWrongPassword) {
		t.Fatalf("got error %v, don't want %v", err, user.ErrUnknownUserOrWrongPassword)
	}
}
