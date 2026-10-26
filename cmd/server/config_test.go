package main

import (
	"testing"
)

func TestLoadConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		env  map[string]string
		want config
	}{
		{
			name: "default",
			env:  map[string]string{},
			want: config{
				addr:        ":8080",
				databaseURL: "postgresql://smallidp:smallidp@localhost:5432/smallidp",
				issuer:      "http://localhost:8080",
			},
		},
		{
			name: "empty string",
			env: map[string]string{
				"SMALLIDP_ADDR":         "",
				"SMALLIDP_DATABASE_URL": "",
				"SMALLIDP_ISSUER":       "",
			},
			want: config{
				addr:        ":8080",
				databaseURL: "postgresql://smallidp:smallidp@localhost:5432/smallidp",
				issuer:      "http://localhost:8080",
			},
		},

		{
			name: "custom values",
			env: map[string]string{
				"SMALLIDP_ADDR":         ":8081",
				"SMALLIDP_DATABASE_URL": "postgresql://someuser:somepassword@localhost:5432/somedb",
				"SMALLIDP_ISSUER":       "https://idp.example.com",
			},
			want: config{
				addr:        ":8081",
				databaseURL: "postgresql://someuser:somepassword@localhost:5432/somedb",
				issuer:      "https://idp.example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := loadConfig(func(key string) string {
				return tt.env[key]
			})
			if got != tt.want {
				t.Errorf("loadConfig() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
