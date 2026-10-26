// Package pgtest provides test helpers for integration tests with PostgreSQL.
package pgtest

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bgfernandes/small-idp-go/internal/postgres"
)

const defaultComposeDatabaseURL = "postgresql://smallidp:smallidp@localhost:5432/smallidp"

func mainDatabaseURL() string {
	if v := os.Getenv("SMALLIDP_TEST_DATABASE_URL"); v != "" {
		return v
	}
	return defaultComposeDatabaseURL
}

// CreateTestDatabase creates a new test database and returns its URL.
func CreateTestDatabase(t *testing.T, prefix string) string {
	t.Helper()

	// generate a random database name
	testDatabaseName := prefix + strings.ToLower(rand.Text())

	db, err := postgres.Open(t.Context(), mainDatabaseURL())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}()

	// Create database cannot take a parameter, testDatabaseName is a fixed prefix plus a lowercased base32 string, so it's safe to concatenate it with the query here
	_, err = db.ExecContext(t.Context(), "CREATE DATABASE "+testDatabaseName)
	if err != nil {
		t.Fatalf("Exec create database: %v", err)
	}

	t.Cleanup(func() {
		t.Helper()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		db, err := postgres.Open(ctx, mainDatabaseURL())
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer func() {
			if err := db.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
		}()

		_, err = db.ExecContext(ctx, "DROP DATABASE IF EXISTS "+testDatabaseName+" WITH (FORCE)")
		if err != nil {
			t.Fatalf("Exec drop database: %v", err)
		}
	})

	u, err := url.Parse(mainDatabaseURL())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	u.Path = testDatabaseName
	return u.String()
}

// CreateTestDatabaseAndRunMigrations creates a new test database, runs the migrations, and returns the *sql.DB.
func CreateTestDatabaseAndRunMigrations(t *testing.T, prefix string) *sql.DB {
	t.Helper()

	db, err := postgres.Open(t.Context(), CreateTestDatabase(t, prefix))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if err := postgres.RunMigrations(t.Context(), db); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}

	t.Cleanup(func() {
		t.Helper()

		if err := db.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	})

	return db
}

// DropStaleTestDatabases drops all test databases with the given prefix.
func DropStaleTestDatabases(ctx context.Context, prefix string) (err error) {
	db, err := postgres.Open(ctx, mainDatabaseURL())
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer func() { err = errors.Join(err, db.Close()) }()

	// drop all databases that start with the prefix
	rows, err := db.QueryContext(ctx, "SELECT datname FROM pg_database WHERE STARTS_WITH(datname, $1)", prefix)
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}
	defer func() { err = errors.Join(err, rows.Close()) }()

	var databases []string

	for rows.Next() {
		var databaseName string
		err = rows.Scan(&databaseName)
		if err != nil {
			return fmt.Errorf("scan: %w", err)
		}
		databases = append(databases, databaseName)
	}

	if rows.Err() != nil {
		return fmt.Errorf("rows: %w", rows.Err())
	}

	for _, databaseName := range databases {
		_, err = db.ExecContext(ctx, "DROP DATABASE IF EXISTS "+databaseName+" WITH (FORCE)")
		if err != nil {
			return fmt.Errorf("exec drop database: %w", err)
		}
	}

	return nil
}
