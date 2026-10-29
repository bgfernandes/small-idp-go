//go:build integration

package postgres_test

import (
	"testing"

	"github.com/bgfernandes/small-idp-go/internal/postgres"
	"github.com/bgfernandes/small-idp-go/internal/postgres/pgtest"
)

func TestRunMigrations(t *testing.T) {
	testDatabaseURL := pgtest.CreateTestDatabase(t, testDatabasePrefix)

	db, err := postgres.Open(t.Context(), testDatabaseURL)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}()

	if err := postgres.RunMigrations(t.Context(), db); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}

	// check that the clients table was created
	var count int
	err = db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM clients").Scan(&count)
	if err != nil {
		t.Fatalf("QueryRow: %v", err)
	}
	if count != 0 {
		t.Fatalf("got %d clients, want 0", count)
	}

	// running migrations again should not error
	if err := postgres.RunMigrations(t.Context(), db); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
}

func TestOpenBadDatabaseURL(t *testing.T) {
	// a bad database URL should error
	db, err := postgres.Open(t.Context(), "postgresql://smallidp:smallidp@localhost:5432/nonexistent")
	if err == nil {
		t.Fatalf("Expected error, got nil")
	}
	if db != nil {
		t.Fatalf("Expected db to be nil, got %v", db)
	}
}

func TestOpenGoodDatabaseURL(t *testing.T) {
	testDatabaseURL := pgtest.CreateTestDatabase(t, testDatabasePrefix)

	db, err := postgres.Open(t.Context(), testDatabaseURL)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}()
}
