package vendor

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"

	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/db/testdb"
	"github.com/tntrock/secure-exchange/internal/mail"
	"github.com/tntrock/secure-exchange/internal/mail/mailtest"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
)

const goodPW = "correct horse battery"

type env struct {
	t                    *testing.T
	svc                  *Service
	users                *auth.Users
	sessions             *auth.Sessions
	keys                 *sxcrypto.Keyring
	staff, staff2, admin *auth.User
}

func setup(t *testing.T, mode string) *env {
	t.Helper()
	pool := testdb.New(t)
	keys, err := sxcrypto.ParseKeyring("1:"+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), 1)
	if err != nil {
		t.Fatal(err)
	}
	users, sessions := auth.NewUsers(pool, keys), auth.NewSessions(pool)
	e := &env{t: t, users: users, sessions: sessions, keys: keys,
		svc: NewService(pool, users, sessions, mail.NewOutbox(pool, keys, nil), "https://sx.example", mode)}
	e.staff = e.account("Staff@x.com", "staff")
	e.staff2 = e.account("staff2@x.com", "staff")
	e.admin = e.account("adm@x.com", "admin")
	e.account("off@x.com", "admin") // a disabled admin: never mailed
	if _, err := pool.Exec(context.Background(), `UPDATE users SET disabled = true WHERE email = 'off@x.com'`); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) account(email, role string) *auth.User {
	e.t.Helper()
	u, err := e.users.Create(context.Background(), email, "Name "+email, role, goodPW)
	if err != nil {
		e.t.Fatal(err)
	}
	return u
}

func (e *env) input(email string) CreateInput {
	return CreateInput{Email: email, DisplayName: "Vic", Org: "ACME", ExpiresAt: time.Now().AddDate(0, 0, 30)}
}

func (e *env) create(by *auth.User, email string) *Vendor {
	e.t.Helper()
	v, err := e.svc.Create(context.Background(), by, e.input(email))
	if err != nil {
		e.t.Fatal(err)
	}
	return v
}

func (e *env) mails() []mail.Message { return mailtest.Messages(e.t, e.svc.pool, e.keys) }

var inviteRE = regexp.MustCompile(`https://sx\.example/invite/([A-Za-z0-9_-]{43})`)

// token returns the newest invitation token mailed to email, or "".
func (e *env) token(email string) string {
	tok := ""
	for _, m := range e.mails() {
		if r := inviteRE.FindStringSubmatch(m.Body); m.To == email && r != nil {
			tok = r[1]
		}
	}
	return tok
}

func (e *env) status(id uuid.UUID) string {
	e.t.Helper()
	vs, err := e.svc.List(context.Background(), false)
	if err != nil {
		e.t.Fatal(err)
	}
	for _, v := range vs {
		if v.ID == id {
			return v.Status
		}
	}
	e.t.Fatalf("vendor %s not listed", id)
	return ""
}

func codeAt(t *testing.T, otpauth string, at time.Time) string {
	t.Helper()
	u, err := url.Parse(otpauth)
	if err != nil {
		t.Fatal(err)
	}
	c, err := totp.GenerateCode(u.Query().Get("secret"), at)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// activate runs the invitation flow for a freshly invited vendor.
func (e *env) activate(email string) uuid.UUID {
	e.t.Helper()
	ctx := context.Background()
	tok := e.token(email)
	_, u, err := e.svc.InviteInfo(ctx, tok)
	if err != nil {
		e.t.Fatal(err)
	}
	id, err := e.svc.Activate(ctx, tok, goodPW, codeAt(e.t, u, time.Now()))
	if err != nil {
		e.t.Fatal(err)
	}
	return id
}

func TestCreatePolicy(t *testing.T) {
	for _, c := range []struct {
		mode, staffWant, adminWant string // "" = ErrForbidden
	}{{"staff", "invited", "invited"}, {"approval", "pending", "invited"}, {"admin", "", "invited"}} {
		t.Run(c.mode, func(t *testing.T) {
			e := setup(t, c.mode)
			ctx := context.Background()
			for _, by := range []struct {
				u    *auth.User
				want string
			}{{e.staff, c.staffWant}, {e.admin, c.adminWant}} {
				email := by.u.Role + "-made@v.com"
				before := len(e.mails())
				v, err := e.svc.Create(ctx, by.u, e.input(email))
				if by.want == "" {
					if !errors.Is(err, ErrForbidden) || len(e.mails()) != before {
						t.Fatalf("%s: %v", by.u.Role, err)
					}
					if _, err := e.users.ByEmail(ctx, email); !errors.Is(err, auth.ErrNotFound) {
						t.Fatalf("forbidden create left a user: %v", err)
					}
					continue
				}
				if err != nil || v.Status != by.want || v.Email != email || v.Org != "ACME" || v.CreatedByID == nil || *v.CreatedByID != by.u.ID ||
					v.CreatedByName != by.u.DisplayName {
					t.Fatalf("%s: %+v %v", by.u.Role, v, err)
				}
				u, err := e.users.ByID(ctx, v.ID)
				if err != nil || u.Role != "vendor" || u.PasswordHash != "" || u.CreatedBy == nil || *u.CreatedBy != by.u.ID {
					t.Fatalf("user row: %+v %v", u, err)
				}
				got := e.mails()[before:]
				if by.want == "invited" {
					if len(got) != 1 || got[0].To != email || e.token(email) == "" || !strings.Contains(got[0].Body, by.u.DisplayName) {
						t.Fatalf("invitation mail: %+v", got)
					}
				} else { // pending: the one active admin is asked
					if len(got) != 1 || got[0].To != "adm@x.com" || !strings.Contains(got[0].Body, email) ||
						!strings.Contains(got[0].Body, "https://sx.example/vendors") {
						t.Fatalf("approval mail: %+v", got)
					}
				}
			}
		})
	}
}

func TestCreateValidation(t *testing.T) {
	e := setup(t, "staff")
	ctx := context.Background()
	for _, c := range []struct {
		mod         func(*CreateInput)
		field, code string
	}{
		{func(in *CreateInput) { in.Email = "" }, "email", "required"},
		{func(in *CreateInput) { in.Email = "nope" }, "email", "invalid"},
		{func(in *CreateInput) { in.DisplayName = "  " }, "display_name", "required"},
		{func(in *CreateInput) { in.DisplayName = strings.Repeat("名", 101) }, "display_name", "out_of_range"},
		{func(in *CreateInput) { in.Org = strings.Repeat("o", 101) }, "org", "out_of_range"},
		{func(in *CreateInput) { in.ExpiresAt = time.Time{} }, "expires_at", "required"},
		{func(in *CreateInput) { in.ExpiresAt = time.Now().Add(23 * time.Hour) }, "expires_at", "out_of_range"},
		{func(in *CreateInput) { in.ExpiresAt = time.Now().AddDate(0, 0, 1096) }, "expires_at", "out_of_range"},
	} {
		in := e.input("new@v.com")
		c.mod(&in)
		var ve *ValidationError
		if _, err := e.svc.Create(ctx, e.staff, in); !errors.As(err, &ve) || ve.Field != c.field || ve.Code != c.code {
			t.Errorf("%s/%s: %v", c.field, c.code, err)
		}
	}
	// bounds and an empty org are fine
	in := e.input("edge@v.com")
	in.DisplayName, in.Org, in.ExpiresAt = strings.Repeat("名", 100), "", time.Now().AddDate(0, 0, 1094)
	if v, err := e.svc.Create(ctx, e.staff, in); err != nil || v.Org != "" {
		t.Fatal(v, err)
	}
	e.create(e.staff, "v@v.com")
	for _, dup := range []string{"V@v.com", "staff@x.com"} {
		if _, err := e.svc.Create(ctx, e.staff, e.input(dup)); !errors.Is(err, ErrEmailTaken) {
			t.Errorf("%s: %v", dup, err)
		}
	}
}

func TestOrgFindOrCreate(t *testing.T) {
	e := setup(t, "staff")
	ctx := context.Background()
	a := e.create(e.staff, "a@v.com")
	in := e.input("b@v.com")
	in.Org = " acme "
	b, err := e.svc.Create(ctx, e.staff, in)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := e.svc.pool.QueryRow(ctx, `SELECT count(*) FROM vendor_orgs`).Scan(&n); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if a.Org != "ACME" || b.Org != "ACME" {
		t.Fatal(a.Org, b.Org)
	}
}

func TestApproveRejectAdminOnly(t *testing.T) {
	e := setup(t, "approval")
	ctx := context.Background()
	v1, v2 := e.create(e.staff, "v1@v.com"), e.create(e.staff, "v2@v.com")
	if err := e.svc.Approve(ctx, e.staff, v1.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal(err)
	}
	if err := e.svc.Reject(ctx, e.staff, v2.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal(err)
	}
	if err := e.svc.Approve(ctx, e.admin, v1.ID); err != nil {
		t.Fatal(err)
	}
	if s := e.status(v1.ID); s != "invited" || e.token("v1@v.com") == "" {
		t.Fatal(s, "no invitation")
	}
	if err := e.svc.Reject(ctx, e.admin, v2.ID); err != nil {
		t.Fatal(err)
	}
	if s := e.status(v2.ID); s != "rejected" || e.token("v2@v.com") != "" {
		t.Fatal(s)
	}
	for _, id := range []uuid.UUID{v1.ID, v2.ID} { // no longer pending
		if err := e.svc.Approve(ctx, e.admin, id); !errors.Is(err, ErrState) {
			t.Fatal(err)
		}
		if err := e.svc.Reject(ctx, e.admin, id); !errors.Is(err, ErrState) {
			t.Fatal(err)
		}
	}
	for _, id := range []uuid.UUID{uuid.New(), e.staff.ID} {
		if err := e.svc.Approve(ctx, e.admin, id); !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
	}
}

func TestManagePermissions(t *testing.T) {
	e := setup(t, "staff")
	ctx := context.Background()
	v := e.create(e.staff, "v@v.com")
	later := time.Now().AddDate(0, 0, 60).Truncate(time.Second)
	if err := e.svc.SetDisabled(ctx, e.staff2, v.ID, true); !errors.Is(err, ErrForbidden) {
		t.Fatal(err)
	}
	if err := e.svc.SetExpiry(ctx, e.staff2, v.ID, later); !errors.Is(err, ErrForbidden) {
		t.Fatal(err)
	}
	if err := e.svc.Reinvite(ctx, e.staff2, v.ID); !errors.Is(err, ErrForbidden) {
		t.Fatal(err)
	}
	if err := e.svc.SetDisabled(ctx, e.staff2, uuid.New(), true); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	var ve *ValidationError
	if err := e.svc.SetExpiry(ctx, e.staff, v.ID, time.Now()); !errors.As(err, &ve) || ve.Code != "out_of_range" {
		t.Fatal(err)
	}
	for _, by := range []*auth.User{e.staff, e.admin} {
		if err := e.svc.SetExpiry(ctx, by, v.ID, later); err != nil {
			t.Fatal(err)
		}
		if err := e.svc.Reinvite(ctx, by, v.ID); err != nil {
			t.Fatal(err)
		}
		if err := e.svc.SetDisabled(ctx, by, v.ID, true); err != nil {
			t.Fatal(err)
		}
		if err := e.svc.Reinvite(ctx, by, v.ID); !errors.Is(err, ErrState) { // disabled: not invited
			t.Fatal(err)
		}
		if err := e.svc.SetDisabled(ctx, by, v.ID, false); err != nil {
			t.Fatal(err)
		}
	}
	vs, _ := e.svc.List(ctx, false)
	if len(vs) != 1 || !vs[0].ExpiresAt.Equal(later) || vs[0].Status != "invited" {
		t.Fatal(vs)
	}
}

func TestDisableRevokesSessions(t *testing.T) {
	e := setup(t, "staff")
	ctx := context.Background()
	v := e.create(e.staff, "v@v.com")
	e.activate("v@v.com")
	if _, err := e.sessions.Create(ctx, v.ID, true, "ip", "ua", time.Hour); err != nil {
		t.Fatal(err)
	}
	if vs, err := e.svc.List(ctx, true); err != nil || len(vs) != 1 || vs[0].Status != "active" {
		t.Fatal(vs, err)
	}
	if err := e.svc.SetDisabled(ctx, e.staff, v.ID, true); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := e.svc.pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE user_id = $1`, v.ID).Scan(&n); err != nil || n != 0 {
		t.Fatal(n, err)
	}
	if s := e.status(v.ID); s != "disabled" {
		t.Fatal(s)
	}
	if vs, _ := e.svc.List(ctx, true); len(vs) != 0 {
		t.Fatal("disabled vendor listed as active")
	}
	if err := e.svc.SetDisabled(ctx, e.staff, v.ID, false); err != nil {
		t.Fatal(err)
	}
	if s := e.status(v.ID); s != "active" {
		t.Fatal(s)
	}
	if _, err := e.svc.pool.Exec(ctx, `UPDATE users SET expires_at = now() WHERE id = $1`, v.ID); err != nil {
		t.Fatal(err)
	}
	if s := e.status(v.ID); s != "expired" {
		t.Fatal(s)
	}
}

func TestInviteTokenLifecycle(t *testing.T) {
	e := setup(t, "staff")
	ctx := context.Background()
	v := e.create(e.staff, "v@v.com")
	tok := e.token("v@v.com")
	email, otpauth, err := e.svc.InviteInfo(ctx, tok)
	if err != nil || email != "v@v.com" || !strings.HasPrefix(otpauth, "otpauth://totp/") {
		t.Fatal(email, otpauth, err)
	}
	var ve *ValidationError
	if _, err := e.svc.Activate(ctx, tok, strings.Repeat("密", 11), "123456"); !errors.As(err, &ve) || ve.Field != "password" || ve.Code != "too_short" {
		t.Fatal(err)
	}
	if _, err := e.svc.Activate(ctx, tok, strings.Repeat("密", 86), "123456"); !errors.As(err, &ve) || ve.Code != "invalid" { // 258 bytes
		t.Fatal(err)
	}
	if id, err := e.svc.Activate(ctx, tok, goodPW, codeAt(t, otpauth, time.Now().Add(10*time.Minute))); !errors.Is(err, ErrBadCode) || id != v.ID {
		t.Fatal(err)
	}
	if u, _ := e.users.ByID(ctx, v.ID); u.PasswordHash != "" || u.TOTPEnabled {
		t.Fatalf("wrong code changed the account: %+v", u)
	}
	id, err := e.svc.Activate(ctx, tok, goodPW, codeAt(t, otpauth, time.Now()))
	if err != nil || id != v.ID {
		t.Fatal(id, err)
	}
	if u, _ := e.users.ByID(ctx, v.ID); !auth.VerifyPassword(u.PasswordHash, goodPW) || !u.TOTPEnabled || e.status(v.ID) != "active" {
		t.Fatalf("not active: %+v", u)
	}
	if _, _, err := e.svc.InviteInfo(ctx, tok); !errors.Is(err, ErrInviteGone) {
		t.Fatal("reused token:", err)
	}
	if _, err := e.svc.Activate(ctx, tok, goodPW, "123456"); !errors.Is(err, ErrInviteGone) {
		t.Fatal("reused token:", err)
	}
	if err := e.svc.Reinvite(ctx, e.staff, v.ID); !errors.Is(err, ErrState) {
		t.Fatal("reinvite of an active vendor:", err)
	}

	// a newer invitation voids the older one
	e.create(e.staff, "w@v.com")
	first := e.token("w@v.com")
	w, _ := e.users.ByEmail(ctx, "w@v.com")
	if err := e.svc.Reinvite(ctx, e.staff, w.ID); err != nil {
		t.Fatal(err)
	}
	second := e.token("w@v.com")
	if second == first {
		t.Fatal("no new token")
	}
	if _, _, err := e.svc.InviteInfo(ctx, first); !errors.Is(err, ErrInviteGone) {
		t.Fatal("replaced token:", err)
	}
	if _, err := e.svc.Activate(ctx, first, goodPW, "123456"); !errors.Is(err, ErrInviteGone) {
		t.Fatal("replaced token:", err)
	}
	e.activate("w@v.com")

	// expired invitation, disabled account, unknown token
	x := e.create(e.staff, "x@v.com")
	if _, err := e.svc.pool.Exec(ctx, `UPDATE vendor_invites SET expires_at = now() - interval '1 second' WHERE user_id = $1`, x.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.InviteInfo(ctx, e.token("x@v.com")); !errors.Is(err, ErrInviteGone) {
		t.Fatal("expired:", err)
	}
	y := e.create(e.staff, "y@v.com")
	if err := e.svc.SetDisabled(ctx, e.staff, y.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.InviteInfo(ctx, e.token("y@v.com")); !errors.Is(err, ErrInviteGone) {
		t.Fatal("disabled:", err)
	}
	if _, err := e.svc.Activate(ctx, e.token("y@v.com"), goodPW, "123456"); !errors.Is(err, ErrInviteGone) {
		t.Fatal("disabled:", err)
	}
	if _, _, err := e.svc.InviteInfo(ctx, "nope"); !errors.Is(err, ErrInviteGone) {
		t.Fatal("unknown:", err)
	}
}
