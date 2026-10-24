// Package testdb gives each test an isolated, migrated PostgreSQL schema.
package testdb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tntrock/secure-exchange/internal/db"
)

// New returns a pool whose search_path is a fresh random schema, migrated and dropped on cleanup.
// Skips the test when SX_TEST_DATABASE_URL is unset.
func New(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("SX_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("SX_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	schema := "t_" + hex.EncodeToString(b)

	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		admin.Close()
	})

	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := db.OpenConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close) // runs before the schema drop (LIFO)
	return pool
}
