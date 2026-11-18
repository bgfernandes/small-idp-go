// Package config provides the configuration for the small idp.
package config

import (
	"errors"
	"fmt"
	"time"

	"github.com/bgfernandes/small-idp-go/internal/issuer"
)

type Config struct {
	AccessTokenLifetime time.Duration
	Addr                string
	DatabaseURL         string
	Issuer              issuer.Issuer
}

var (
	ErrInvalidAccessTokenLifetime = errors.New("invalid SMALLIDP_ACCESS_TOKEN_LIFETIME")
	ErrInvalidIssuer              = errors.New("invalid SMALLIDP_ISSUER")
)

var defaultIssuer = issuer.MustParse("http://localhost:8080")

// Load loads the configuration from the environment or uses default values.
func Load(getenv func(string) string) (Config, error) {
	// Default values
	// RFC 8414 §2 requires HTTPS, but we're using HTTP for now
	cfg := Config{
		AccessTokenLifetime: 5 * time.Minute,
		Addr:                ":8080",
		DatabaseURL:         "postgresql://smallidp:smallidp@localhost:5432/smallidp",
		Issuer:              defaultIssuer,
	}

	if v := getenv("SMALLIDP_ACCESS_TOKEN_LIFETIME"); v != "" {
		lifetime, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("%w: %w", ErrInvalidAccessTokenLifetime, err)
		}

		if lifetime <= 0 {
			return Config{}, fmt.Errorf("%w: value is not positive", ErrInvalidAccessTokenLifetime)
		}

		cfg.AccessTokenLifetime = lifetime
	}

	if v := getenv("SMALLIDP_ADDR"); v != "" {
		cfg.Addr = v
	}

	if v := getenv("SMALLIDP_DATABASE_URL"); v != "" {
		cfg.DatabaseURL = v
	}

	if v := getenv("SMALLIDP_ISSUER"); v != "" {
		i, err := issuer.Parse(v)
		if err != nil {
			return Config{}, fmt.Errorf("%w: %w", ErrInvalidIssuer, err)
		}
		cfg.Issuer = i
	}

	return cfg, nil
}
