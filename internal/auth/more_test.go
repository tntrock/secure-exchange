package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tntrock/secure-exchange/internal/sxcrypto"
)

func TestUserContext(t *testing.T) {
	if UserFrom(context.Background()) != nil {
		t.Fatal("empty context has a user")
	}
	u := &User{Email: "a@example.com"}
	if got := UserFrom(WithUser(context.Background(), u)); got != u {
		t.Fatalf("got %+v", got)
	}
}

func TestVerifyPasswordRejectsBadParams(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	p := strings.Split(h, "$")
	for name, enc := range map[string]string{
		"other version":   strings.Replace(h, "$v=19$", "$v=18$", 1),
		"version garbage": strings.Replace(h, "$v=19$", "$v=x$", 1),
		"params garbage":  strings.Join([]string{"", p[1], p[2], "m=x", p[4], p[5]}, "$"),
	} {
		if VerifyPassword(enc, "correct horse battery") {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestTOTPEdgeCases(t *testing.T) {
	us := newUsers(t)
	ctx := context.Background()
	if _, err := us.BeginTOTP(ctx, uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
	u, err := us.Create(ctx, "t@example.com", "T", "staff", "password-12345")
	if err != nil {
		t.Fatal(err)
	}
	if us.CheckTOTP(ctx, u.ID, "000000") {
		t.Fatal("check passed without a secret")
	}
	if _, err := us.BeginTOTP(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	// a keyring that cannot open the stored secret must fail closed
	k := make([]byte, 32)
	rand.Read(k)
	other, _ := sxcrypto.ParseKeyring("2:"+base64.StdEncoding.EncodeToString(k), 2)
	if NewUsers(us.pool, other).CheckTOTP(ctx, u.ID, "000000") {
		t.Fatal("check passed with an unreadable secret")
	}
	if secretFromURL("%zz") != "" {
		t.Fatal("bad URL yielded a secret")
	}
}

func TestCanceledContext(t *testing.T) {
	us := newUsers(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := us.Create(ctx, "c@example.com", "C", "staff", "password-12345"); err == nil {
		t.Fatal("Create succeeded on a canceled context")
	}
	if err := us.EnsureInitialAdmin(ctx, "c@example.com", "password-12345"); err == nil {
		t.Fatal("EnsureInitialAdmin succeeded on a canceled context")
	}
	if _, err := NewSessions(us.pool).Create(ctx, uuid.New(), true, "1.2.3.4", "ua", time.Hour); err == nil {
		t.Fatal("session Create succeeded on a canceled context")
	}
}
