package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestUpsertExternalCreatesAndUpdates(t *testing.T) {
	us := newUsers(t)
	ctx := context.Background()
	u, prev, err := us.UpsertExternal(ctx, "ldap", "ab01", "a@x.test", "A", false)
	if err != nil || prev != "" || u.Role != "staff" || u.ExternalID != "ab01" || u.AuthSource != "ldap" {
		t.Fatal(u, prev, err)
	}
	u2, prev, err := us.UpsertExternal(ctx, "ldap", "ab01", "b@x.test", "B", true)
	if err != nil || prev != "staff" || u2.ID != u.ID || u2.Role != "admin" || u2.Email != "b@x.test" || u2.DisplayName != "B" {
		t.Fatal(u2, prev, err)
	}
	got, err := us.ByExternal(ctx, "ldap", "ab01")
	if err != nil || got.ID != u.ID {
		t.Fatal(got, err)
	}
	if _, err := us.ByExternal(ctx, "ldap", "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

func TestUpsertExternalEmailConflict(t *testing.T) {
	us := newUsers(t)
	ctx := context.Background()
	if _, _, err := us.UpsertExternal(ctx, "ldap", "01", "a@x.test", "A", false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := us.UpsertExternal(ctx, "ldap", "02", "A@x.test", "B", false); !errors.Is(err, ErrEmailTaken) {
		t.Fatal(err)
	}
}

func TestUpsertExternalDBError(t *testing.T) {
	us := newUsers(t)
	us.pool.Close()
	if _, _, err := us.UpsertExternal(context.Background(), "ldap", "01", "a@x.test", "A", false); err == nil || errors.Is(err, ErrEmailTaken) {
		t.Fatal(err)
	}
}

func TestByEmailLocalOnly(t *testing.T) {
	us := newUsers(t)
	ctx := context.Background()
	if _, _, err := us.UpsertExternal(ctx, "ldap", "01", "a@x.test", "L", false); err != nil {
		t.Fatal(err)
	}
	if _, err := us.ByEmail(ctx, "a@x.test"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	l, err := us.Create(ctx, "a@x.test", "", "staff", "password-12345")
	if err != nil {
		t.Fatal(err)
	}
	got, err := us.ByEmail(ctx, "A@x.test")
	if err != nil || got.ID != l.ID {
		t.Fatal(got, err)
	}
}

func TestUpsertExternalKeepsDisabled(t *testing.T) {
	us := newUsers(t)
	ctx := context.Background()
	if _, _, err := us.UpsertExternal(ctx, "ldap", "01", "a@x.test", "A", false); err != nil {
		t.Fatal(err)
	}
	us.pool.Exec(ctx, `UPDATE users SET disabled=true`)
	u, _, err := us.UpsertExternal(ctx, "ldap", "01", "a@x.test", "A", false)
	if err != nil || !u.Disabled {
		t.Fatal(u, err)
	}
}

func TestClaimCheck(t *testing.T) {
	us := newUsers(t)
	ss := NewSessions(us.pool)
	ctx := context.Background()
	u, _, _ := us.UpsertExternal(ctx, "ldap", "01", "a@x.test", "A", false)
	tok, err := ss.Create(ctx, u.ID, true, "1.2.3.4", "ua", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := ss.ClaimCheck(ctx, tok, 15*time.Minute); ok || err != nil {
		t.Fatal(ok, err)
	}
	us.pool.Exec(ctx, `UPDATE sessions SET checked_at = now() - interval '16 minutes'`)
	if s, _ := ss.Lookup(ctx, tok); time.Since(s.CheckedAt) < 15*time.Minute {
		t.Fatal("CheckedAt not loaded", s.CheckedAt)
	}
	if ok, err := ss.ClaimCheck(ctx, tok, 15*time.Minute); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if ok, _ := ss.ClaimCheck(ctx, tok, 15*time.Minute); ok {
		t.Fatal("second claim")
	}
	us.pool.Close()
	if _, err := ss.ClaimCheck(ctx, tok, time.Minute); err == nil {
		t.Fatal("want error")
	}
}
