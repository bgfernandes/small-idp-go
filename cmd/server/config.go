package main

type config struct {
	addr        string
	databaseURL string
	issuer      string
}

// loadConfig loads the configuration from the environment or uses default values.
func loadConfig(getenv func(string) string) config {
	// Default values
	// RFC 8414 §2 requires HTTPS, but we're using HTTP for now
	cfg := config{
		addr:        ":8080",
		databaseURL: "postgresql://smallidp:smallidp@localhost:5432/smallidp",
		issuer:      "http://localhost:8080",
	}

	if v := getenv("SMALLIDP_ADDR"); v != "" {
		cfg.addr = v
	}

	if v := getenv("SMALLIDP_DATABASE_URL"); v != "" {
		cfg.databaseURL = v
	}

	if v := getenv("SMALLIDP_ISSUER"); v != "" {
		cfg.issuer = v
	}

	return cfg
}
