package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSessionsLifecycle(t *testing.T) {
	us := newUsers(t)
	ss := NewSessions(us.pool)
	ctx := context.Background()
	u, err := us.Create(ctx, "s@x.com", "", "staff", "password-12345")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := ss.Create(ctx, u.ID, false, "1.2.3.4", "ua", time.Hour)
	if err != nil || len(tok) < 43 {
		t.Fatalf("%q %v", tok, err)
	}
	var raw int
	us.pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE token_hash=$1`, []byte(tok)).Scan(&raw)
	if raw != 0 {
		t.Fatal("raw token stored")
	}
	s, err := ss.Lookup(ctx, tok)
	if err != nil || s.UserID != u.ID || s.MFAPassed {
		t.Fatal(s, err)
	}
	if err := ss.MarkMFA(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if s, _ := ss.Lookup(ctx, tok); !s.MFAPassed {
		t.Fatal("mfa not marked")
	}
	if _, err := ss.Lookup(ctx, "bogus"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if err := ss.Revoke(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if _, err := ss.Lookup(ctx, tok); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}

	expired, _ := ss.Create(ctx, u.ID, true, "", "", -time.Second)
	if _, err := ss.Lookup(ctx, expired); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired session accepted", err)
	}

	a, _ := ss.Create(ctx, u.ID, true, "", "", time.Hour)
	b, _ := ss.Create(ctx, u.ID, true, "", "", time.Hour)
	if err := ss.RevokeAllForUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	for _, tk := range []string{a, b} {
		if _, err := ss.Lookup(ctx, tk); !errors.Is(err, ErrNotFound) {
			t.Fatal("not revoked", err)
		}
	}
}
