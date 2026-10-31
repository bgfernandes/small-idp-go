// Package config provides the configuration for the small idp.
package config

type Config struct {
	Addr        string
	DatabaseURL string
	Issuer      string
}

// Load loads the configuration from the environment or uses default values.
func Load(getenv func(string) string) Config {
	// Default values
	// RFC 8414 §2 requires HTTPS, but we're using HTTP for now
	cfg := Config{
		Addr:        ":8080",
		DatabaseURL: "postgresql://smallidp:smallidp@localhost:5432/smallidp",
		Issuer:      "http://localhost:8080",
	}

	if v := getenv("SMALLIDP_ADDR"); v != "" {
		cfg.Addr = v
	}

	if v := getenv("SMALLIDP_DATABASE_URL"); v != "" {
		cfg.DatabaseURL = v
	}

	if v := getenv("SMALLIDP_ISSUER"); v != "" {
		cfg.Issuer = v
	}

	return cfg
}
