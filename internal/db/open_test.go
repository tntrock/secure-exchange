package db_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tntrock/secure-exchange/internal/db"
)

func TestOpenURL(t *testing.T) {
	raw := os.Getenv("SX_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("SX_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	b := make([]byte, 8)
	rand.Read(b)
	schema := "t_" + hex.EncodeToString(b)
	admin, err := pgxpool.New(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")

	withPath := func(s string) string {
		u, _ := url.Parse(raw)
		q := u.Query()
		q.Set("search_path", s)
		u.RawQuery = q.Encode()
		return u.String()
	}
	pool, err := db.Open(ctx, withPath(schema))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var n int
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM "+schema+".users").Scan(&n); err != nil || n != 0 {
		t.Fatalf("migrations not applied in %s: n=%d err=%v", schema, n, err)
	}

	// search_path naming a missing schema: current_schema() is NULL
	if _, err := db.Open(ctx, withPath(schema+"_missing")); err == nil || !strings.Contains(err.Error(), "migrate") {
		t.Fatalf("missing schema: %v", err)
	}
	// a conflicting table makes the first migration fail
	clash := schema + "_clash"
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+clash+"; CREATE TABLE "+clash+".users (x int)"); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+clash+" CASCADE")
	if _, err := db.Open(ctx, withPath(clash)); err == nil || !strings.Contains(err.Error(), "migrate") {
		t.Fatalf("conflicting table: %v", err)
	}
}

func TestOpenErrors(t *testing.T) {
	ctx := context.Background()
	if _, err := db.Open(ctx, "postgres://%zz"); err == nil || !strings.Contains(err.Error(), "parse url") {
		t.Fatalf("bad url: %v", err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close() // nothing listens here now
	if _, err := db.Open(ctx, "postgres://u:p@"+addr+"/x?connect_timeout=5"); err == nil || !strings.Contains(err.Error(), "ping") {
		t.Fatalf("unreachable: %v", err)
	}

	cfg, err := pgxpool.ParseConfig("postgres://u:p@" + addr + "/x")
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 0 // rejected by pgxpool
	if _, err := db.OpenConfig(ctx, cfg); err == nil || !strings.Contains(err.Error(), "connect") {
		t.Fatalf("invalid pool config: %v", err)
	}
}
