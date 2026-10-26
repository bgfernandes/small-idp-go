// Package postgres provides a PostgreSQL client and migration utilities.
package postgres

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
)

//go:embed migrations/*.sql
var embedMigrations embed.FS

// RunMigrations runs the migrations for the given database.
// It uses a PostgreSQL session locker to ensure that only one instance of the app runs the migrations at a time.
// It also uses the embed.FS to load the migrations from the embed.FS.
func RunMigrations(ctx context.Context, db *sql.DB) error {
	fsys, err := fs.Sub(embedMigrations, "migrations")
	if err != nil {
		return fmt.Errorf("sub: %w", err)
	}

	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return fmt.Errorf("new locker: %w", err)
	}

	provider, err := goose.NewProvider(
		goose.DialectPostgres,
		db,
		fsys,
		goose.WithSessionLocker(locker),
	)
	if err != nil {
		return fmt.Errorf("new provider: %w", err)
	}
	// No defer provider.Close() because it would only close the database connection, that we want to keep open.

	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("up: %w", err)
	}

	return nil
}

// Open opens a new database connection using the pgx driver to the given database URL.
func Open(ctx context.Context, databaseURL string) (*sql.DB, error) {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	if err := db.PingContext(ctx); err != nil {
		cerr := db.Close()
		if cerr != nil {
			return nil, fmt.Errorf("ping database: %w; close database: %w", err, cerr)
		}
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return db, nil
}
