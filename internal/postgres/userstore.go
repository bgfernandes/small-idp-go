package postgres

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/bgfernandes/small-idp-go/internal/user"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/bcrypt"
)

// UserStore is a store for users.
type UserStore struct {
	db               *sql.DB
	passwordHashCost int
}

// DefaultPasswordHashCost is the cost for the bcrypt password hash used in production when creating a new user,
// (in the future) re-hashing a user's password on login, or (in the future) doing a dummy comparison to mitigate timing
// attacks on password verification.
// For production, this value should be changed deliberately, and upward, as hardware gets faster. It is a constant here
// because it does not need to be tuned per deployment.
const DefaultPasswordHashCost = 12

// NewUserStore creates a new UserStore.
// passwordHashCost is the cost of the bcrypt password hash, and must be between bcrypt.MinCost and bcrypt.MaxCost, for tests it should be bcrypt.MinCost
// and for production it should be a fixed higher cost.
func NewUserStore(db *sql.DB, passwordHashCost int) *UserStore {
	if passwordHashCost < bcrypt.MinCost || passwordHashCost > bcrypt.MaxCost {
		panic("postgres: passwordHashCost must be between bcrypt.MinCost and bcrypt.MaxCost")
	}
	return &UserStore{db: db, passwordHashCost: passwordHashCost}
}

const userColumns = "id, email, password_hash, created_at, updated_at"

// scanUser scans a user from a database row.
func scanUser(row *sql.Row) (user.User, string, error) {
	u := user.User{}
	var passwordHash string
	err := row.Scan(
		&u.ID,
		&u.Email,
		&passwordHash,
		&u.CreatedAt,
		&u.UpdatedAt,
	)
	if err != nil {
		return user.User{}, "", fmt.Errorf("scan user: %w", err)
	}
	return u, passwordHash, nil
}

func (s *UserStore) hashPassword(password string) (string, error) {
	passwordHashBytes, err := bcrypt.GenerateFromPassword([]byte(password), s.passwordHashCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}

	return string(passwordHashBytes), nil
}

// Create creates a new user.
func (s *UserStore) Create(ctx context.Context, params user.CreateParams) (user.User, error) {
	// Validate email: non-empty, exactly one @, no whitespace
	if params.Email == "" {
		return user.User{}, &user.InvalidUserError{Field: "Email", Reason: "email is required"}
	}
	if strings.Count(params.Email, "@") != 1 {
		return user.User{}, &user.InvalidUserError{Field: "Email", Reason: "email must contain exactly one @"}
	}
	if strings.ContainsFunc(params.Email, unicode.IsSpace) {
		return user.User{}, &user.InvalidUserError{Field: "Email", Reason: "email must not contain whitespace"}
	}

	// Validate password: simple policy of non empty and at most 72 bytes for now
	if params.Password == "" {
		return user.User{}, &user.InvalidUserError{Field: "Password", Reason: "password is required"}
	}
	if len(params.Password) > 72 {
		return user.User{}, &user.InvalidUserError{Field: "Password", Reason: "password must be at most 72 bytes"}
	}

	passwordHash, err := s.hashPassword(params.Password)
	if err != nil {
		return user.User{}, fmt.Errorf("create user: %w", err)
	}

	query := `
	INSERT INTO users (id, email, password_hash)
	VALUES ($1, $2, $3)
	RETURNING ` + userColumns

	row := s.db.QueryRowContext(ctx, query,
		rand.Text(),
		params.Email,
		passwordHash,
	)

	u, _, err := scanUser(row)
	if err != nil {
		if pgError, ok := errors.AsType[*pgconn.PgError](err); ok {
			// 23505 is the SQLState code for unique_violation
			if pgError.Code == "23505" && pgError.ConstraintName == "users_email_key" {
				return user.User{}, &user.InvalidUserError{Field: "Email", Reason: "email must be unique"}
			}
		}
		return user.User{}, fmt.Errorf("insert user: %w", err)
	}
	return u, nil
}

// Get gets a user by its ID.
func (s *UserStore) Get(ctx context.Context, userID string) (user.User, error) {
	query := `
		SELECT ` + userColumns + `
		FROM users
		WHERE id = $1
	`
	u, _, err := scanUser(s.db.QueryRowContext(ctx, query, userID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return user.User{}, user.ErrNotFound
		}
		return user.User{}, fmt.Errorf("get user: %w", err)
	}

	return u, nil
}
