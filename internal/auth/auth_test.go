package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/tntrock/secure-exchange/internal/db/testdb"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
)

func newUsers(t *testing.T) *Users {
	t.Helper()
	pool := testdb.New(t)
	k := make([]byte, 32)
	rand.Read(k)
	kr, err := sxcrypto.ParseKeyring("1:"+base64.StdEncoding.EncodeToString(k), 1)
	if err != nil {
		t.Fatal(err)
	}
	return NewUsers(pool, kr)
}

func TestPasswordHashVerify(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil || !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Fatalf("%q %v", h, err)
	}
	if !VerifyPassword(h, "correct horse battery") || VerifyPassword(h, "wrong horse battery!") || VerifyPassword("junk", "x") {
		t.Fatal("verify mismatch")
	}
}

func TestWeakPassword(t *testing.T) {
	if _, err := HashPassword("12345678901"); !errors.Is(err, ErrWeakPassword) {
		t.Fatal(err)
	}
}

func TestEmailCaseInsensitiveUnique(t *testing.T) {
	s := newUsers(t)
	ctx := context.Background()
	if _, err := s.Create(ctx, "A@x.com", "", "staff", "password-12345"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(ctx, "a@X.com", "", "staff", "password-12345"); !errors.Is(err, ErrEmailTaken) {
		t.Fatal(err)
	}
	if u, err := s.ByEmail(ctx, "a@x.COM"); err != nil || u.Email != "A@x.com" {
		t.Fatal(u, err)
	}
	if _, err := s.ByEmail(ctx, "nobody@x.com"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

func TestTOTPFlow(t *testing.T) {
	s := newUsers(t)
	ctx := context.Background()
	u, _ := s.Create(ctx, "t@x.com", "", "staff", "password-12345")
	url, err := s.BeginTOTP(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	secret := secretFromURL(url)
	var sealed []byte
	s.pool.QueryRow(ctx, `SELECT totp_secret_sealed FROM users WHERE id=$1`, u.ID).Scan(&sealed)
	if len(sealed) == 0 || strings.Contains(string(sealed), secret) {
		t.Fatal("secret not sealed")
	}
	if err := s.EnableTOTP(ctx, u.ID, "000000"); !errors.Is(err, ErrBadCode) {
		t.Fatal(err)
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	if err := s.EnableTOTP(ctx, u.ID, code); err != nil {
		t.Fatal(err)
	}
	if u2, _ := s.ByID(ctx, u.ID); !u2.TOTPEnabled {
		t.Fatal("not enabled")
	}
}

func TestTOTPNoReplay(t *testing.T) {
	s := newUsers(t)
	ctx := context.Background()
	u, _ := s.Create(ctx, "t@x.com", "", "staff", "password-12345")
	url, _ := s.BeginTOTP(ctx, u.ID)
	code, _ := totp.GenerateCode(secretFromURL(url), time.Now())
	if !s.CheckTOTP(ctx, u.ID, code) {
		t.Fatal("first use should pass")
	}
	if s.CheckTOTP(ctx, u.ID, code) {
		t.Fatal("replay accepted")
	}
}

func TestEnsureInitialAdminOnlyWhenEmpty(t *testing.T) {
	s := newUsers(t)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := s.EnsureInitialAdmin(ctx, "admin@x.com", "password-12345"); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	s.pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE role='admin'`).Scan(&n)
	if n != 1 {
		t.Fatal(n)
	}
	if err := s.EnsureInitialAdmin(ctx, "other@x.com", "password-12345"); err != nil {
		t.Fatal(err)
	}
	s.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n)
	if n != 1 {
		t.Fatal(n)
	}
}
