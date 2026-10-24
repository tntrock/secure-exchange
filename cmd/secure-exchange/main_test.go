package main

import (
	"context"
	"encoding/base64"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/db/testdb"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
)

func key(b byte) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string(rune(b)), 32)))
}

func TestRunUnknownCommand(t *testing.T) {
	if got := run([]string{"bogus"}); got != 2 {
		t.Fatalf("exit %d, want 2", got)
	}
}

func TestRunRotateKeys(t *testing.T) {
	ctx := context.Background()
	pool := testdb.New(t)
	k1, _ := sxcrypto.ParseKeyring("1:"+key(1), 1)
	us := auth.NewUsers(pool, k1)
	u, err := us.Create(ctx, "a@example.com", "A", "staff", "password-12345")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := us.BeginTOTP(ctx, u.ID); err != nil {
		t.Fatal(err)
	}

	// point the command at the same isolated schema
	dbURL, _ := url.Parse(testURL(t))
	q := dbURL.Query()
	q.Set("search_path", pool.Config().ConnConfig.RuntimeParams["search_path"])
	dbURL.RawQuery = q.Encode()
	t.Setenv("SX_DATABASE_URL", dbURL.String())
	t.Setenv("SX_BASE_URL", "https://sx.example.com")
	t.Setenv("SX_MASTER_KEYS", "1:"+key(1)+",2:"+key(2))
	t.Setenv("SX_ACTIVE_KEY_ID", "2")

	if got := run([]string{"rotate-keys"}); got != 0 {
		t.Fatalf("exit %d, want 0", got)
	}
	var sealed []byte
	if err := pool.QueryRow(ctx, `SELECT totp_secret_sealed FROM users WHERE id=$1`, u.ID).Scan(&sealed); err != nil || sealed[3] != 2 {
		t.Fatalf("totp not rotated: %v %v", sealed[:4], err)
	}
	ents, err := audit.New(pool).List(ctx, audit.Filter{Action: audit.ActKeyRotate})
	if err != nil || len(ents) != 1 || ents[0].Event.ActorType != "system" {
		t.Fatalf("audit: %v %+v", err, ents)
	}

	t.Setenv("SX_ACTIVE_KEY_ID", "9") // active key missing from keyring
	if got := run([]string{"rotate-keys"}); got != 1 {
		t.Fatalf("bad keyring exit %d, want 1", got)
	}
}

func testURL(t *testing.T) string {
	t.Helper()
	return os.Getenv("SX_TEST_DATABASE_URL")
}
