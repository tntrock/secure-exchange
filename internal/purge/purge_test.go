package purge

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tntrock/secure-exchange/internal/db/testdb"
	"github.com/tntrock/secure-exchange/internal/mail"
)

func count(t *testing.T, pool *pgxpool.Pool, table string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM "+table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestOnceDeletesOnlyExpired(t *testing.T) {
	pool := testdb.New(t)
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	const old, live = "now() - interval '48 hours'", "now() + interval '1 hour'"

	user := uuid.New()
	exec(`INSERT INTO users (id, email, role) VALUES ($1, 'a@x.test', 'staff')`, user)
	exec(`INSERT INTO sessions (token_hash, user_id, mfa_passed, ip, user_agent, expires_at) VALUES
		('\x01', $1, true, '', '', `+old+`), ('\x02', $1, true, '', '', `+live+`),
		('\x03', $1, true, '', '', now() - interval '1 hour')`, user) // expired but inside grace: kept

	shareOld, shareLive := uuid.New(), uuid.New()
	exec(`INSERT INTO shares (id, owner_id, token_hash, token_sealed, allow_download, watermark, expires_at) VALUES
		($1, $3, '\x0a', '\x', true, false, `+old+`), ($2, $3, '\x0b', '\x', true, false, `+live+`)`, shareOld, shareLive, user)
	exec(`INSERT INTO vendor_share_views (session_hash, share_id) VALUES ('\x01', $1), ('\x01', $2)`, shareOld, shareLive)

	rOld, rLive := uuid.New(), uuid.New()
	exec(`INSERT INTO share_recipients (id, share_id, email) VALUES ($1, $3, 'r1@x.test'), ($2, $3, 'r2@x.test')`, rOld, rLive, shareLive)
	exec(`INSERT INTO share_sessions (token_hash, recipient_id, ip, user_agent, expires_at) VALUES
		('\x01', $1, '', '', `+old+`), ('\x02', $2, '', '', `+live+`)`, rOld, rLive)
	exec(`INSERT INTO share_otps (id, recipient_id, code_hash, expires_at) VALUES
		($3, $1, '\x', `+old+`), ($4, $2, '\x', `+live+`)`, rOld, rLive, uuid.New(), uuid.New())

	reqID, upOld, upLive := uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO upload_requests (id, owner_id, token_hash, token_sealed, expires_at, max_files, max_total_bytes)
		VALUES ($1, $2, '\x0c', '\x', `+live+`, 1, 1)`, reqID, user)
	exec(`INSERT INTO request_uploaders (id, request_id, email) VALUES ($1, $3, 'u1@x.test'), ($2, $3, 'u2@x.test')`, upOld, upLive, reqID)
	exec(`INSERT INTO request_sessions (token_hash, uploader_id, ip, user_agent, expires_at) VALUES
		('\x01', $1, '', '', `+old+`), ('\x02', $2, '', '', `+live+`)`, upOld, upLive)
	exec(`INSERT INTO request_otps (id, uploader_id, code_hash, expires_at) VALUES
		($3, $1, '\x', `+old+`), ($4, $2, '\x', `+live+`)`, upOld, upLive, uuid.New(), uuid.New())

	// outbox: dead+old (gone), dead but young, still retrying, sent+old-created (left to the mailer)
	exec(`INSERT INTO mail_outbox (id, to_addr, body_sealed, attempts, created_at) VALUES
		($1, 'a', '\x', $4, now() - interval '31 days'),
		($2, 'b', '\x', $4, now() - interval '29 days'),
		($3, 'c', '\x', $4 - 1, now() - interval '31 days')`, uuid.New(), uuid.New(), uuid.New(), mail.MaxAttempts)
	exec(`INSERT INTO mail_outbox (id, to_addr, body_sealed, attempts, created_at, sent_at) VALUES
		($1, 'd', '\x', 0, now() - interval '31 days', now())`, uuid.New())

	got, err := Once(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{"sessions": 1, "share_sessions": 1, "request_sessions": 1,
		"share_otps": 1, "request_otps": 1, "mail_outbox": 1, "vendor_share_views": 1}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("deleted %s = %d, want %d", k, got[k], v)
		}
	}
	for table, n := range map[string]int{"sessions": 2, "share_sessions": 1, "request_sessions": 1,
		"share_otps": 1, "request_otps": 1, "mail_outbox": 3, "vendor_share_views": 1} {
		if c := count(t, pool, table); c != n {
			t.Errorf("%s left = %d, want %d", table, c, n)
		}
	}
	var gone bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM vendor_share_views WHERE share_id = $1)`, shareOld).Scan(&gone); err != nil || gone {
		t.Errorf("view of expired share kept (err %v)", err)
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	pool := testdb.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	Run(ctx, pool, slog.Default(), time.Hour)
}
