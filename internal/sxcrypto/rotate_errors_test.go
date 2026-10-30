package sxcrypto_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/db/testdb"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
)

func TestRotateErrors(t *testing.T) {
	k1 := ring(t, "1:"+b64key(1), 1)
	k12 := ring(t, "1:"+b64key(1)+",2:"+b64key(2), 2)
	exec := func(t *testing.T, pool *pgxpool.Pool, q string) {
		if _, err := pool.Exec(context.Background(), q); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name    string
		prep    func(t *testing.T, pool *pgxpool.Pool, owner uuid.UUID)
		ctx     func() (context.Context, func()) // nil = background
		wantErr string
	}{
		{name: "canceled", ctx: func() (context.Context, func()) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, cancel
		}, wantErr: "canceled"},
		{name: "unreadable wrapped dek", prep: func(t *testing.T, pool *pgxpool.Pool, owner uuid.UUID) {
			insertOldFile(t, pool, k1, owner)
			exec(t, pool, `UPDATE files SET wrapped_dek = 'x'`)
		}, wantErr: "files.wrapped_dek"},
		{name: "unreadable sealed value", prep: func(t *testing.T, pool *pgxpool.Pool, _ uuid.UUID) {
			exec(t, pool, `UPDATE users SET totp_secret_sealed = '\x0000000199'`)
		}, wantErr: "users.totp_secret_sealed"},
		{name: "shutdown after a pass", ctx: func() (context.Context, func()) {
			ctx, cancel := context.WithCancel(context.Background())
			sxcrypto.SetAfterPass(func(int) { cancel() })
			return ctx, func() { sxcrypto.SetAfterPass(nil); cancel() }
		}, wantErr: "canceled"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pool := testdb.New(t)
			u, err := auth.NewUsers(pool, k1).Create(context.Background(), "a@example.com", "A", "staff", "correct horse battery")
			if err != nil {
				t.Fatal(err)
			}
			if c.prep != nil {
				c.prep(t, pool, u.ID)
			}
			ctx := context.Background()
			if c.ctx != nil {
				var done func()
				ctx, done = c.ctx()
				defer done()
			}
			if _, err := sxcrypto.RotateAll(ctx, pool, k12); err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, c.wantErr)
			}
		})
	}
}
