package config

import (
	"testing"
)

func TestLoad(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		env  map[string]string
		want Config
	}{
		{
			name: "default",
			env:  map[string]string{},
			want: Config{
				Addr:        ":8080",
				DatabaseURL: "postgresql://smallidp:smallidp@localhost:5432/smallidp",
				Issuer:      "http://localhost:8080",
			},
		},
		{
			name: "empty string",
			env: map[string]string{
				"SMALLIDP_ADDR":         "",
				"SMALLIDP_DATABASE_URL": "",
				"SMALLIDP_ISSUER":       "",
			},
			want: Config{
				Addr:        ":8080",
				DatabaseURL: "postgresql://smallidp:smallidp@localhost:5432/smallidp",
				Issuer:      "http://localhost:8080",
			},
		},

		{
			name: "custom values",
			env: map[string]string{
				"SMALLIDP_ADDR":         ":8081",
				"SMALLIDP_DATABASE_URL": "postgresql://someuser:somepassword@localhost:5432/somedb",
				"SMALLIDP_ISSUER":       "https://idp.example.com",
			},
			want: Config{
				Addr:        ":8081",
				DatabaseURL: "postgresql://someuser:somepassword@localhost:5432/somedb",
				Issuer:      "https://idp.example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := Load(func(key string) string {
				return tt.env[key]
			})
			if got != tt.want {
				t.Errorf("Load() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
