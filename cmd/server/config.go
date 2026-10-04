package main

type config struct {
	issuer string
	addr   string
}

func loadConfig(getenv func(string) string) config {
	// Default values
	// RFC 8414 §2 requires HTTPS, but we're using HTTP for now
	cfg := config{issuer: "http://localhost:8080", addr: ":8080"}

	if v := getenv("SMALLIDP_ISSUER"); v != "" {
		cfg.issuer = v
	}

	if v := getenv("SMALLIDP_ADDR"); v != "" {
		cfg.addr = v
	}

	return cfg
}
