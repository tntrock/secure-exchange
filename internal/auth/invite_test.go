package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func newInviteUser(t *testing.T) (*Users, *User) {
	t.Helper()
	s := newUsers(t)
	u, err := s.Create(context.Background(), "i@x.com", "I", "staff", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	return s, u
}

func mkInvite(t *testing.T, s *Users, u *User) string {
	t.Helper()
	tx, err := s.pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	tok, exp, err := CreateInvite(context.Background(), tx, u.ID)
	if err != nil || tok == "" || exp.IsZero() {
		t.Fatalf("%q %v %v", tok, exp, err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestInviteNewestOnly(t *testing.T) {
	ctx := context.Background()
	s, u := newInviteUser(t)
	first := mkInvite(t, s, u)
	second := mkInvite(t, s, u)
	if _, err := InviteUser(ctx, s.pool, first); !errors.Is(err, ErrInviteGone) {
		t.Fatalf("first: %v", err)
	}
	if id, err := InviteUser(ctx, s.pool, second); err != nil || id != u.ID {
		t.Fatalf("second: %v %v", id, err)
	}
}

func TestInviteExpiredAndConsumed(t *testing.T) {
	ctx := context.Background()
	s, u := newInviteUser(t)
	tok := mkInvite(t, s, u)
	if _, err := s.pool.Exec(ctx, `UPDATE account_invites SET expires_at = now() - interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	if _, err := InviteUser(ctx, s.pool, tok); !errors.Is(err, ErrInviteGone) {
		t.Fatalf("expired: %v", err)
	}
	tok = mkInvite(t, s, u)
	tx, _ := s.pool.Begin(ctx)
	defer tx.Rollback(ctx)
	if err := ConsumeInvite(ctx, tx, tok); err != nil {
		t.Fatal(err)
	}
	if err := ConsumeInvite(ctx, tx, tok); !errors.Is(err, ErrInviteGone) {
		t.Fatalf("second consume: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := InviteUser(ctx, s.pool, tok); !errors.Is(err, ErrInviteGone) {
		t.Fatalf("consumed: %v", err)
	}
}

func TestValidPassword(t *testing.T) {
	for _, tc := range []struct{ pw, want string }{
		{strings.Repeat("a", 11), "too_short"},
		{strings.Repeat("密", 12), ""},
		{strings.Repeat("a", 257), "invalid"},
	} {
		if got := ValidPassword(tc.pw); got != tc.want {
			t.Errorf("%d bytes: %q, want %q", len(tc.pw), got, tc.want)
		}
	}
}

func TestTouchLogin(t *testing.T) {
	ctx := context.Background()
	s, u := newInviteUser(t)
	if u.LastLoginAt != nil {
		t.Fatal("fresh user has last login")
	}
	if err := s.TouchLogin(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if u, _ = s.ByID(ctx, u.ID); u.LastLoginAt == nil {
		t.Fatal("not set")
	}
}
