package config

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/bgfernandes/small-idp-go/internal/issuer"
)

func TestLoad(t *testing.T) {
	t.Parallel()

	defaultIssuer, err := issuer.Parse("http://localhost:8080")
	if err != nil {
		t.Fatalf("failed to parse default issuer: %v", err)
	}

	customIssuer, err := issuer.Parse("https://idp.example.com")
	if err != nil {
		t.Fatalf("failed to parse custom issuer: %v", err)
	}

	tests := []struct {
		name string
		env  map[string]string
		want Config
	}{
		{
			name: "default",
			env:  map[string]string{},
			want: Config{
				AccessTokenLifetime: 5 * time.Minute,
				Addr:                ":8080",
				DatabaseURL:         "postgresql://smallidp:smallidp@localhost:5432/smallidp",
				Issuer:              defaultIssuer,
			},
		},
		{
			name: "empty string",
			env: map[string]string{
				"SMALLIDP_ACCESS_TOKEN_LIFETIME": "",
				"SMALLIDP_ADDR":                  "",
				"SMALLIDP_DATABASE_URL":          "",
				"SMALLIDP_ISSUER":                "",
			},
			want: Config{
				AccessTokenLifetime: 5 * time.Minute,
				Addr:                ":8080",
				DatabaseURL:         "postgresql://smallidp:smallidp@localhost:5432/smallidp",
				Issuer:              defaultIssuer,
			},
		},

		{
			name: "custom values",
			env: map[string]string{
				"SMALLIDP_ACCESS_TOKEN_LIFETIME": "120s",
				"SMALLIDP_ADDR":                  ":8081",
				"SMALLIDP_DATABASE_URL":          "postgresql://someuser:somepassword@localhost:5432/somedb",
				"SMALLIDP_ISSUER":                "https://idp.example.com",
			},
			want: Config{
				AccessTokenLifetime: 120 * time.Second,
				Addr:                ":8081",
				DatabaseURL:         "postgresql://someuser:somepassword@localhost:5432/somedb",
				Issuer:              customIssuer,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := Load(func(key string) string {
				return tt.env[key]
			})
			if err != nil {
				t.Fatalf("failed to load config: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Load() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestLoadInvalidValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		env  map[string]string
		want error
	}{
		{name: "negative access token lifetime", env: map[string]string{
			"SMALLIDP_ACCESS_TOKEN_LIFETIME": "-1s",
			"SMALLIDP_ADDR":                  ":8081",
			"SMALLIDP_DATABASE_URL":          "postgresql://someuser:somepassword@localhost:5432/somedb",
			"SMALLIDP_ISSUER":                "https://idp.example.com",
		}, want: ErrInvalidAccessTokenLifetime},
		{name: "zero access token lifetime", env: map[string]string{
			"SMALLIDP_ACCESS_TOKEN_LIFETIME": "0s",
			"SMALLIDP_ADDR":                  ":8081",
			"SMALLIDP_DATABASE_URL":          "postgresql://someuser:somepassword@localhost:5432/somedb",
			"SMALLIDP_ISSUER":                "https://idp.example.com",
		}, want: ErrInvalidAccessTokenLifetime},
		{name: "string access token lifetime", env: map[string]string{
			"SMALLIDP_ACCESS_TOKEN_LIFETIME": "some string",
			"SMALLIDP_ADDR":                  ":8081",
			"SMALLIDP_DATABASE_URL":          "postgresql://someuser:somepassword@localhost:5432/somedb",
			"SMALLIDP_ISSUER":                "https://idp.example.com",
		}, want: ErrInvalidAccessTokenLifetime},
		{name: "invalid issuer", env: map[string]string{
			"SMALLIDP_ACCESS_TOKEN_LIFETIME": "120s",
			"SMALLIDP_ADDR":                  ":8081",
			"SMALLIDP_DATABASE_URL":          "postgresql://someuser:somepassword@localhost:5432/somedb",
			"SMALLIDP_ISSUER":                "invalid",
		}, want: ErrInvalidIssuer},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := Load(func(key string) string {
				return tt.env[key]
			})
			if !errors.Is(err, tt.want) {
				t.Errorf("got error %v, want %v error", err, tt.want)
			}
		})

	}
}
