//go:build integration

package postgres_test

import (
	"context"
	"log"
	"testing"
	"time"

	"github.com/bgfernandes/small-idp-go/internal/postgres/pgtest"
)

const testDatabasePrefix = "smallidp_test_postgres_"

// TestMain will clean up stale databases that could have been left over from a previous test run
func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := pgtest.DropStaleTestDatabases(ctx, testDatabasePrefix); err != nil {
		log.Fatalf("DropStaleTestDatabases: %v", err)
	}

	m.Run()
}
