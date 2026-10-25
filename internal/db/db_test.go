package db_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tntrock/secure-exchange/internal/db"
	"github.com/tntrock/secure-exchange/internal/db/testdb"
)

func TestMigrationsApply(t *testing.T) {
	pool := testdb.New(t)
	var n int
	if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM users").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("users count = %d, want 0", n)
	}
}

func TestAuditLogImmutable(t *testing.T) {
	pool := testdb.New(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO audit_log (at, actor_type, actor_id, ip, user_agent, action, target_type, target_id, result, prev_hash, hash)
		VALUES (now(), 'user', 'u1', '1.2.3.4', 'ua', 'login', 'user', 'u1', 'ok', '\x00', '\x01')`); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"UPDATE audit_log SET action = 'tampered'", "DELETE FROM audit_log"} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	var action string
	var n int
	if err := pool.QueryRow(ctx, "SELECT count(*), min(action) FROM audit_log").Scan(&n, &action); err != nil {
		t.Fatal(err)
	}
	if n != 1 || action != "login" {
		t.Fatalf("row changed: n=%d action=%q", n, action)
	}
}

func TestParallelTestDB(t *testing.T) {
	for i := 0; i < 6; i++ {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			pool := testdb.New(t)
			if _, err := pool.Exec(context.Background(), "SELECT 1 FROM users"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMigration0002Applies(t *testing.T) {
	pool := testdb.New(t)
	var n int
	if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM shares").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("shares count = %d, want 0", n)
	}
}

func TestMigration0003Applies(t *testing.T) {
	pool := testdb.New(t)
	for _, tbl := range []string{"file_previews", "preview_items", "render_jobs", "view_traces"} {
		var n int
		if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM "+tbl).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s: n=%d err=%v", tbl, n, err)
		}
	}
}

// serve and worker may start together against a fresh database.
func TestConcurrentOpen(t *testing.T) {
	url := os.Getenv("SX_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("SX_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	b := make([]byte, 8)
	rand.Read(b)
	schema := "t_" + hex.EncodeToString(b)
	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	var wg sync.WaitGroup
	errs := make([]error, 10)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cfg, _ := pgxpool.ParseConfig(url)
			cfg.ConnConfig.RuntimeParams["search_path"] = schema
			pool, err := db.OpenConfig(ctx, cfg)
			if err == nil {
				pool.Close()
			}
			errs[i] = err
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("open %d: %v", i, err)
		}
	}
}
