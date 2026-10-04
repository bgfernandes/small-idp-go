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
		{name: "default", env: map[string]string{}, want: config{issuer: "http://localhost:8080", addr: ":8080"}},
		{name: "empty string", env: map[string]string{"SMALLIDP_ISSUER": "", "SMALLIDP_ADDR": ""}, want: config{issuer: "http://localhost:8080", addr: ":8080"}},
		{name: "custom issuer", env: map[string]string{"SMALLIDP_ISSUER": "https://idp.example.com"}, want: config{issuer: "https://idp.example.com", addr: ":8080"}},
		{name: "custom addr", env: map[string]string{"SMALLIDP_ADDR": ":8081"}, want: config{issuer: "http://localhost:8080", addr: ":8081"}},
		{name: "custom issuer and addr", env: map[string]string{"SMALLIDP_ISSUER": "https://idp.example.com", "SMALLIDP_ADDR": ":8081"}, want: config{issuer: "https://idp.example.com", addr: ":8081"}},
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
