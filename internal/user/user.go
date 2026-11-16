// Package user provides a user type and auxiliary types
package user

import (
	"errors"
	"fmt"
	"time"
)

// User is a user of the OIDC/OAuth2 server.
type User struct {
	ID        string
	Email     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// CreateParams is the parameters for creating a user.
type CreateParams struct {
	Email    string
	Password string
}

// InvalidUserError is returned when a user is invalid.
type InvalidUserError struct {
	Field  string
	Reason string
}

func (e *InvalidUserError) Error() string {
	return fmt.Sprintf("invalid user field %s: %s", e.Field, e.Reason)
}

// ErrNotFound is returned when a user is not found.
var ErrNotFound = errors.New("user not found")
