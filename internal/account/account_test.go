package account

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"

	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/db/testdb"
	"github.com/tntrock/secure-exchange/internal/mail"
	"github.com/tntrock/secure-exchange/internal/mail/mailtest"
	"github.com/tntrock/secure-exchange/internal/rules"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
	"github.com/tntrock/secure-exchange/internal/vendor"
)

const goodPW = "correct horse battery"

var ctx = context.Background()

type env struct {
	t        *testing.T
	svc      *Service
	users    *auth.Users
	sessions *auth.Sessions
	keys     *sxcrypto.Keyring
	rs       *rules.Service
	vendors  *vendor.Service
	admin    *auth.User
}

func setup(t *testing.T) *env {
	t.Helper()
	pool := testdb.New(t)
	keys, err := sxcrypto.ParseKeyring("1:"+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), 1)
	if err != nil {
		t.Fatal(err)
	}
	users, sessions := auth.NewUsers(pool, keys), auth.NewSessions(pool)
	rs := rules.New(pool, 1<<30)
	if err := rs.Seed(ctx, 30); err != nil {
		t.Fatal(err)
	}
	outbox := mail.NewOutbox(pool, keys, nil)
	e := &env{t: t, users: users, sessions: sessions, keys: keys, rs: rs,
		svc:     New(pool, users, sessions, outbox, rs, "https://sx.example"),
		vendors: vendor.NewService(pool, users, sessions, outbox, "https://sx.example", "staff", rs)}
	e.admin = e.local("boss@x.com", "admin")
	return e
}

// local creates a usable local account (password set).
func (e *env) local(email, role string) *auth.User {
	e.t.Helper()
	u, err := e.users.Create(ctx, email, "Name "+email, role, goodPW)
	if err != nil {
		e.t.Fatal(err)
	}
	return u
}

func (e *env) exec(sql string, args ...any) {
	e.t.Helper()
	if _, err := e.svc.pool.Exec(ctx, sql, args...); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) mails() []mail.Message { return mailtest.Messages(e.t, e.svc.pool, e.keys) }

var (
	activateRE = regexp.MustCompile(`https://sx\.example/activate/([A-Za-z0-9_-]{43})`)
	inviteRE   = regexp.MustCompile(`https://sx\.example/invite/([A-Za-z0-9_-]{43})`)
)

// lastToken returns the token of the newest mail matching re.
func (e *env) lastToken(re *regexp.Regexp) string {
	e.t.Helper()
	ms := e.mails()
	for i := len(ms) - 1; i >= 0; i-- {
		if m := re.FindStringSubmatch(ms[i].Body); m != nil {
			return m[1]
		}
	}
	e.t.Fatal("no invitation mail")
	return ""
}

func (e *env) invited(email, role string) (*Account, string) {
	e.t.Helper()
	a, err := e.svc.Create(ctx, e.admin, CreateInput{Email: email, DisplayName: "N", Role: role})
	if err != nil {
		e.t.Fatal(err)
	}
	return a, e.lastToken(activateRE)
}

func (e *env) get(id uuid.UUID) *Account {
	e.t.Helper()
	a, err := e.svc.get(ctx, id)
	if err != nil {
		e.t.Fatal(err)
	}
	return a
}

func (e *env) vendor(email string) uuid.UUID {
	e.t.Helper()
	v, err := e.vendors.Create(ctx, e.admin, vendor.CreateInput{Email: email, DisplayName: "V", ExpiresAt: time.Now().AddDate(0, 0, 30)})
	if err != nil {
		e.t.Fatal(err)
	}
	return v.ID
}

func code(t *testing.T, otpauth string) string {
	t.Helper()
	u, err := url.Parse(otpauth)
	if err != nil {
		t.Fatal(err)
	}
	c, err := totp.GenerateCode(u.Query().Get("secret"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCreateInvitesLocalStaff(t *testing.T) {
	e := setup(t)
	a, err := e.svc.Create(ctx, e.admin, CreateInput{Email: "New@x.com", DisplayName: "New", Role: "staff"})
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != "invited" || a.AuthSource != "local" || a.Role != "staff" {
		t.Fatalf("%+v", a)
	}
	ms := e.mails()
	if len(ms) != 1 || ms[0].To != "new@x.com" || !activateRE.MatchString(ms[0].Body) {
		t.Fatalf("mails %+v", ms)
	}
	if _, err := e.svc.Create(ctx, e.admin, CreateInput{Email: "NEW@x.com", Role: "staff"}); !errors.Is(err, ErrEmailTaken) {
		t.Fatalf("dup: %v", err)
	}
	e.vendor("v@x.com")
	if _, err := e.svc.Create(ctx, e.admin, CreateInput{Email: "V@x.com", Role: "staff"}); !errors.Is(err, ErrEmailTaken) {
		t.Fatalf("vendor dup: %v", err)
	}
	var ve *ValidationError
	for _, in := range []CreateInput{{Email: "a@x.com", Role: "vendor"}, {Email: "a@x.com", Role: ""}} {
		if _, err := e.svc.Create(ctx, e.admin, in); !errors.As(err, &ve) || ve.Field != "role" {
			t.Fatalf("role %q: %v", in.Role, err)
		}
	}
	for email, want := range map[string]string{"": "required", "  ": "required", "nope": "invalid"} {
		if _, err := e.svc.Create(ctx, e.admin, CreateInput{Email: email, Role: "staff"}); !errors.As(err, &ve) || ve.Field != "email" || ve.Code != want {
			t.Fatalf("email %q: %v", email, err)
		}
	}
	if _, err := e.svc.Create(ctx, e.admin, CreateInput{Email: "n@x.com", Role: "staff", DisplayName: string(make([]rune, 101))}); !errors.As(err, &ve) || ve.Field != "display_name" {
		t.Fatalf("name: %v", err)
	}
}

func TestList(t *testing.T) {
	e := setup(t)
	e.invited("inv@x.com", "staff")
	e.exec(`UPDATE users SET auth_source='ldap', password_hash=NULL WHERE id=$1`, e.local("l@x.com", "staff").ID)
	e.vendor("v@x.com")
	all, err := e.svc.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, a := range all {
		got[a.Email] = a.Status
	}
	want := map[string]string{"boss@x.com": "active", "inv@x.com": "invited", "l@x.com": "active", "v@x.com": "invited"}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q want %q", k, got[k], v)
		}
	}
	if all[0].CreatedAt == nil {
		t.Error("created_at")
	}
}

func TestActivateWithoutForcedTOTP(t *testing.T) {
	e := setup(t)
	a, tok := e.invited("n@x.com", "staff")
	email, req, u, err := e.svc.InviteInfo(ctx, tok)
	if err != nil || email != "n@x.com" || req || u != "" {
		t.Fatalf("%q %v %q %v", email, req, u, err)
	}
	var ve *ValidationError
	if _, err := e.svc.Activate(ctx, tok, "short", ""); !errors.As(err, &ve) || ve.Field != "password" || ve.Code != "too_short" {
		t.Fatalf("weak: %v", err)
	}
	id, err := e.svc.Activate(ctx, tok, goodPW, "")
	if err != nil || id != a.ID {
		t.Fatal(id, err)
	}
	u2, err := e.users.ByID(ctx, a.ID)
	if err != nil || u2.PasswordHash == "" || u2.TOTPEnabled {
		t.Fatalf("%+v %v", u2, err)
	}
	if !auth.VerifyPassword(u2.PasswordHash, goodPW) {
		t.Fatal("password does not verify")
	}
	if e.get(a.ID).Status != "active" {
		t.Fatal("not active")
	}
	if _, err := e.svc.Activate(ctx, tok, goodPW, ""); !errors.Is(err, ErrInviteGone) {
		t.Fatalf("reuse: %v", err)
	}
	if _, _, _, err := e.svc.InviteInfo(ctx, tok); !errors.Is(err, ErrInviteGone) {
		t.Fatalf("info reuse: %v", err)
	}
}

func TestActivateWithForcedTOTP(t *testing.T) {
	e := setup(t)
	e.exec(`UPDATE site_rules SET force_totp = true`)
	a, tok := e.invited("n@x.com", "admin")
	_, req, u1, err := e.svc.InviteInfo(ctx, tok)
	if err != nil || !req || u1 == "" {
		t.Fatal(req, u1, err)
	}
	if _, _, u2, _ := e.svc.InviteInfo(ctx, tok); u2 != u1 {
		t.Fatal("secret changed on reload")
	}
	if _, err := e.svc.Activate(ctx, tok, goodPW, ""); !errors.Is(err, ErrTOTPRequired) {
		t.Fatalf("empty: %v", err)
	}
	if _, err := e.svc.Activate(ctx, tok, goodPW, "000000"); !errors.Is(err, ErrBadCode) {
		t.Fatalf("wrong: %v", err)
	}
	if got, _ := e.users.ByID(ctx, a.ID); got.PasswordHash != "" || got.TOTPEnabled {
		t.Fatalf("changed: %+v", got)
	}
	if _, err := e.svc.Activate(ctx, tok, goodPW, code(t, u1)); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.users.ByID(ctx, a.ID); got.PasswordHash == "" || !got.TOTPEnabled {
		t.Fatalf("not enrolled: %+v", got)
	}
}

func TestActivateForcedWithoutInviteInfo(t *testing.T) {
	e := setup(t)
	e.exec(`UPDATE site_rules SET force_totp = true`)
	_, tok := e.invited("n@x.com", "staff")
	if _, err := e.svc.Activate(ctx, tok, goodPW, "123456"); !errors.Is(err, ErrBadCode) {
		t.Fatalf("no secret: %v", err)
	}
}

func TestActivateRefusesVendorToken(t *testing.T) {
	e := setup(t)
	e.vendor("v@x.com")
	tok := e.lastToken(inviteRE)
	if _, _, _, err := e.svc.InviteInfo(ctx, tok); !errors.Is(err, ErrInviteGone) {
		t.Fatalf("info: %v", err)
	}
	if _, err := e.svc.Activate(ctx, tok, goodPW, ""); !errors.Is(err, ErrInviteGone) {
		t.Fatalf("activate: %v", err)
	}
}

func TestReinviteVoidsOldLink(t *testing.T) {
	e := setup(t)
	e.exec(`UPDATE site_rules SET force_totp = true`)
	a, old := e.invited("n@x.com", "staff")
	_, _, oldURL, _ := e.svc.InviteInfo(ctx, old)
	time.Sleep(5 * time.Millisecond)
	if err := e.svc.Reinvite(ctx, e.admin, a.ID); err != nil {
		t.Fatal(err)
	}
	tok := e.lastToken(activateRE)
	if tok == old {
		t.Fatal("same token")
	}
	if _, _, _, err := e.svc.InviteInfo(ctx, old); !errors.Is(err, ErrInviteGone) {
		t.Fatalf("old: %v", err)
	}
	_, _, newURL, err := e.svc.InviteInfo(ctx, tok)
	if err != nil || newURL == oldURL {
		t.Fatalf("pending secret kept: %v", err)
	}
	if _, err := e.svc.Activate(ctx, tok, goodPW, code(t, newURL)); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Reinvite(ctx, e.admin, a.ID); !errors.Is(err, ErrState) {
		t.Fatalf("active: %v", err)
	}
	if err := e.svc.Reinvite(ctx, e.admin, e.vendor("v@x.com")); !errors.Is(err, ErrState) {
		t.Fatalf("vendor: %v", err)
	}
	if err := e.svc.Reinvite(ctx, e.admin, uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
}

func TestLastAdminGuard(t *testing.T) {
	e := setup(t) // e.admin is the only usable local admin
	if err := e.svc.SetDisabled(ctx, e.admin.ID, true); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("disable: %v", err)
	}
	if err := e.svc.SetRole(ctx, e.admin.ID, "staff"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demote: %v", err)
	}
	inv, _ := e.invited("inv@x.com", "admin") // no password: does not count
	if err := e.svc.SetDisabled(ctx, e.admin.ID, true); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("invited admin counted: %v", err)
	}
	e.exec(`UPDATE users SET auth_source='ldap' WHERE id=$1`, e.local("ext@x.com", "admin").ID) // external does not count
	if err := e.svc.SetDisabled(ctx, e.admin.ID, true); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("external admin counted: %v", err)
	}
	if err := e.svc.SetDisabled(ctx, inv.ID, true); err != nil { // not usable, so never guarded
		t.Fatal(err)
	}
	e.local("second@x.com", "admin")
	if err := e.svc.SetRole(ctx, e.admin.ID, "staff"); err != nil {
		t.Fatalf("demote with second admin: %v", err)
	}
	if err := e.svc.SetRole(ctx, e.admin.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.SetDisabled(ctx, e.admin.ID, true); err != nil {
		t.Fatalf("disable with second admin: %v", err)
	}
	if err := e.svc.SetDisabled(ctx, uuid.New(), true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
}

func TestLastAdminGuardConcurrent(t *testing.T) {
	for range 5 {
		e := setup(t)
		ids := []uuid.UUID{e.admin.ID, e.local("b@x.com", "admin").ID}
		errs := make([]error, 2)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range ids {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				errs[i] = e.svc.SetDisabled(ctx, ids[i], true)
			}()
		}
		close(start)
		wg.Wait()
		ok, last := 0, 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, ErrLastAdmin):
				last++
			default:
				t.Fatal(err)
			}
		}
		var n int
		if err := e.svc.pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE role='admin' AND NOT disabled`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if ok != 1 || last != 1 || n != 1 {
			t.Fatalf("ok=%d last=%d usable=%d", ok, last, n)
		}
	}
}

func TestSetDisabledRevokesSessions(t *testing.T) {
	e := setup(t)
	u := e.local("s@x.com", "staff")
	tok, err := e.sessions.Create(ctx, u.ID, true, "1.1.1.1", "ua", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.SetDisabled(ctx, u.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := e.sessions.Lookup(ctx, tok); err == nil {
		t.Fatal("session survived")
	}
	if e.get(u.ID).Status != "disabled" {
		t.Fatal("not disabled")
	}
	if err := e.svc.SetDisabled(ctx, u.ID, false); err != nil {
		t.Fatal(err)
	}
	if e.get(u.ID).Status != "active" {
		t.Fatal("not active again")
	}
}

func TestSetRoleRules(t *testing.T) {
	e := setup(t)
	u := e.local("s@x.com", "staff")
	if err := e.svc.SetRole(ctx, u.ID, "admin"); err != nil || e.get(u.ID).Role != "admin" {
		t.Fatalf("promote: %v", err)
	}
	if err := e.svc.SetRole(ctx, e.vendor("v@x.com"), "staff"); !errors.Is(err, ErrState) {
		t.Fatalf("vendor: %v", err)
	}
	l := e.local("l@x.com", "staff")
	e.exec(`UPDATE users SET auth_source='ldap' WHERE id=$1`, l.ID)
	if err := e.svc.SetRole(ctx, l.ID, "admin"); !errors.Is(err, ErrExternal) {
		t.Fatalf("ldap: %v", err)
	}
	var ve *ValidationError
	for _, r := range []string{"vendor", "root", ""} {
		if err := e.svc.SetRole(ctx, u.ID, r); !errors.As(err, &ve) || ve.Field != "role" {
			t.Fatalf("role %q: %v", r, err)
		}
	}
	if err := e.svc.SetRole(ctx, uuid.New(), "staff"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
}

func TestResetTOTPLocal(t *testing.T) {
	e := setup(t)
	u := e.local("s@x.com", "staff")
	if err := e.svc.ResetTOTP(ctx, e.admin, u.ID); !errors.Is(err, ErrState) {
		t.Fatalf("no totp: %v", err)
	}
	if _, err := e.users.BeginTOTP(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	e.exec(`UPDATE users SET totp_enabled=true, totp_last_step=99 WHERE id=$1`, u.ID)
	tok, _ := e.sessions.Create(ctx, u.ID, true, "1.1.1.1", "ua", time.Hour)
	if err := e.svc.ResetTOTP(ctx, e.admin, u.ID); err != nil {
		t.Fatal(err)
	}
	var sealed []byte
	var step int64
	if err := e.svc.pool.QueryRow(ctx, `SELECT totp_secret_sealed, totp_last_step FROM users WHERE id=$1`, u.ID).Scan(&sealed, &step); err != nil {
		t.Fatal(err)
	}
	got, _ := e.users.ByID(ctx, u.ID)
	if got.TOTPEnabled || sealed != nil || step != 0 {
		t.Fatalf("%+v %v %d", got, sealed, step)
	}
	if !auth.VerifyPassword(got.PasswordHash, goodPW) {
		t.Fatal("password lost")
	}
	if _, err := e.sessions.Lookup(ctx, tok); err == nil {
		t.Fatal("session survived")
	}
	if err := e.svc.ResetTOTP(ctx, e.admin, uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
}

func TestResetTOTPVendor(t *testing.T) {
	e := setup(t)
	vid := e.vendor("v@x.com")
	old := e.lastToken(inviteRE)
	if err := e.svc.ResetTOTP(ctx, e.admin, vid); !errors.Is(err, ErrState) { // not enrolled yet
		t.Fatalf("not enrolled: %v", err)
	}
	_, u, err := e.vendors.InviteInfo(ctx, old)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.vendors.Activate(ctx, old, goodPW, code(t, u)); err != nil {
		t.Fatal(err)
	}
	tok, _ := e.sessions.Create(ctx, vid, true, "1.1.1.1", "ua", time.Hour)
	time.Sleep(5 * time.Millisecond)
	if err := e.svc.ResetTOTP(ctx, e.admin, vid); err != nil {
		t.Fatal(err)
	}
	got, _ := e.users.ByID(ctx, vid)
	if got.PasswordHash != "" || got.TOTPEnabled {
		t.Fatalf("%+v", got)
	}
	if _, err := e.sessions.Lookup(ctx, tok); err == nil {
		t.Fatal("session survived")
	}
	if st := e.get(vid).Status; st != "invited" {
		t.Fatalf("status %q", st)
	}
	if n := len(e.mails()); n != 2 {
		t.Fatalf("mails %d", n)
	}
	if _, _, err := e.vendors.InviteInfo(ctx, old); !errors.Is(err, vendor.ErrInviteGone) {
		t.Fatalf("old token: %v", err)
	}
	nt := e.lastToken(inviteRE)
	_, u, err = e.vendors.InviteInfo(ctx, nt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.vendors.Activate(ctx, nt, goodPW, code(t, u)); err != nil {
		t.Fatal(err)
	}
}

func TestResetTOTPExternal(t *testing.T) {
	e := setup(t)
	l := e.local("l@x.com", "staff")
	e.exec(`UPDATE users SET auth_source='ldap', totp_enabled=true WHERE id=$1`, l.ID)
	if err := e.svc.ResetTOTP(ctx, e.admin, l.ID); !errors.Is(err, ErrExternal) {
		t.Fatalf("%v", err)
	}
}
