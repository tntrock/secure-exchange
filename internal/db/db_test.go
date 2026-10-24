package db_test

import (
	"context"
	"fmt"
	"testing"

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
