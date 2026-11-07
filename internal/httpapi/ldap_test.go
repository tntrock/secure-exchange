package httpapi

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/ldapauth"
)

// fakeDir is a Directory keyed by username; Lookup finds the identity by external id.
type fakeDir struct {
	ids     map[string]ldapauth.Identity
	authErr error
	lookErr error
	lookups int
}

func (f *fakeDir) Authenticate(_ context.Context, username, password string) (ldapauth.Identity, error) {
	if f.authErr != nil {
		return ldapauth.Identity{}, f.authErr
	}
	id, ok := f.ids[username]
	if !ok || password != pw {
		return ldapauth.Identity{}, ldapauth.ErrInvalidCredentials
	}
	return id, nil
}

func (f *fakeDir) Lookup(_ context.Context, externalID string) (ldapauth.Identity, error) {
	f.lookups++
	if f.lookErr != nil {
		return ldapauth.Identity{}, f.lookErr
	}
	for _, id := range f.ids {
		if id.ExternalID == externalID {
			return id, nil
		}
	}
	return ldapauth.Identity{}, ldapauth.ErrGone
}

func ldapEnv(t *testing.T) (*env, *fakeDir) {
	t.Helper()
	f := &fakeDir{ids: map[string]ldapauth.Identity{
		"alice": {ExternalID: "a1", Email: "a@x.test", Name: "Alice"},
		"boss":  {ExternalID: "b2", Email: "boss@x.test", Name: "Boss", Admin: true},
	}}
	return newEnv(t, func(d *Deps) { d.LDAP = f }), f
}

// ldapLogin logs in on a fresh cookie jar.
func (e *env) ldapLogin(t *testing.T, username string) (*http.Response, []byte) {
	t.Helper()
	e.c.Jar, _ = cookiejar.New(nil)
	return e.do(t, "POST", "/api/auth/ldap", map[string]string{"username": username, "password": pw})
}

func (e *env) mustLDAPLogin(t *testing.T, username string) {
	t.Helper()
	if resp, b := e.ldapLogin(t, username); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode, string(b))
	}
}

func (e *env) lastDetail(t *testing.T, action string) map[string]any {
	t.Helper()
	got, _, err := e.audit.List(context.Background(), audit.Filter{ActionPrefix: action})
	if err != nil || len(got) == 0 {
		t.Fatalf("%s: %d %v", action, len(got), err)
	}
	return got[0].Event.Detail
}

func (e *env) ageSessions(t *testing.T) {
	t.Helper()
	if _, err := e.pool.Exec(context.Background(), `UPDATE sessions SET checked_at = now() - interval '16 minutes'`); err != nil {
		t.Fatal(err)
	}
}

func (e *env) meID(t *testing.T) string {
	t.Helper()
	resp, b := e.do(t, "GET", "/api/me", nil)
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode, string(b))
	}
	var me struct{ ID string }
	if err := json.Unmarshal(b, &me); err != nil {
		t.Fatal(err)
	}
	return me.ID
}

func TestLDAPLoginCreatesStaff(t *testing.T) {
	e, _ := ldapEnv(t)
	resp, b := e.ldapLogin(t, "alice")
	if resp.StatusCode != 200 || strings.TrimSpace(string(b)) != `{"mfa_required":false,"totp_setup_required":false}` ||
		!strings.Contains(resp.Header.Get("Set-Cookie"), "sx_session=") {
		t.Fatal(resp.StatusCode, string(b))
	}
	resp, b = e.do(t, "GET", "/api/me", nil)
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"role":"staff"`) || !strings.Contains(string(b), `"email":"a@x.test"`) {
		t.Fatal(resp.StatusCode, string(b))
	}
	var src string
	if err := e.pool.QueryRow(context.Background(), `SELECT auth_source FROM users WHERE email='a@x.test'`).Scan(&src); err != nil || src != "ldap" {
		t.Fatal(src, err)
	}
	if d := e.lastDetail(t, audit.ActLoginOK); d["source"] != "ldap" || d["username"] != "alice" {
		t.Fatal(d)
	}
}

func TestLDAPLoginAdminGroup(t *testing.T) {
	e, _ := ldapEnv(t)
	e.mustLDAPLogin(t, "boss")
	if resp, b := e.do(t, "GET", "/api/admin/users", nil); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode, string(b))
	}
}

func TestLDAPLoginRoleChangeAudited(t *testing.T) {
	e, f := ldapEnv(t)
	e.mustLDAPLogin(t, "boss")
	id := f.ids["boss"]
	id.Admin = false
	f.ids["boss"] = id
	e.mustLDAPLogin(t, "boss")
	if resp, b := e.do(t, "GET", "/api/me", nil); !strings.Contains(string(b), `"role":"staff"`) {
		t.Fatal(resp.StatusCode, string(b))
	}
	if d := e.lastDetail(t, audit.ActLoginOK); d["role_from"] != "admin" || d["role_to"] != "staff" {
		t.Fatal(d)
	}
}

func TestLDAPLoginNeverTouchesLocal(t *testing.T) {
	e, _ := ldapEnv(t)
	local := e.user(t, "a@x.test")
	e.mustLDAPLogin(t, "alice")
	if got := e.meID(t); got == local.ID.String() {
		t.Fatal("ldap login landed on the local account")
	}
	e.loginAs(t, "a@x.test", "")
	if got := e.meID(t); got != local.ID.String() {
		t.Fatal(got)
	}
}

func TestLDAPLoginErrors(t *testing.T) {
	e, f := ldapEnv(t)
	if resp, b := e.do(t, "POST", "/api/auth/ldap", map[string]string{"username": "alice", "password": "nope"}); resp.StatusCode != 401 || !strings.Contains(string(b), "invalid_credentials") {
		t.Fatal(resp.StatusCode, string(b))
	}
	if resp, _ := e.do(t, "POST", "/api/auth/ldap", "x"); resp.StatusCode != 400 {
		t.Fatal(resp.StatusCode)
	}
	for i, c := range []struct {
		err    error
		status int
		body   string
		stage  string
	}{
		{ldapauth.ErrDisabled, 401, "invalid_credentials", "ldap_disabled"},
		{ldapauth.ErrNoEmail, 401, "invalid_credentials", "ldap_no_email"},
		{ldapauth.ErrUnavailable, 503, "directory_unavailable", "ldap_unavailable"},
		{errors.New("other"), 503, "directory_unavailable", "ldap_unavailable"},
	} {
		f.authErr = c.err
		if resp, b := e.ldapLogin(t, fmt.Sprint("u", i)); resp.StatusCode != c.status || !strings.Contains(string(b), c.body) {
			t.Fatal(c.err, resp.StatusCode, string(b))
		}
		if d := e.lastDetail(t, audit.ActLoginFail); d["stage"] != c.stage {
			t.Fatal(c.err, d)
		}
	}
	if d := e.lastDetail(t, audit.ActLoginFail); d["stage"] != "ldap_unavailable" || d["source"] != "ldap" || d["reason"] != nil {
		t.Fatal(d)
	}
	f.authErr = nil

	// a second LDAP account with an email already used by another LDAP account
	e.mustLDAPLogin(t, "alice")
	f.ids["mallory"] = ldapauth.Identity{ExternalID: "c3", Email: "a@x.test", Name: "M"}
	if resp, b := e.ldapLogin(t, "mallory"); resp.StatusCode != 409 || !strings.Contains(string(b), "email_conflict") {
		t.Fatal(resp.StatusCode, string(b))
	}
	if d := e.lastDetail(t, audit.ActLoginFail); d["stage"] != "email_conflict" {
		t.Fatal(d)
	}

	off := newEnv(t)
	if resp, b := off.ldapLogin(t, "alice"); resp.StatusCode != 404 || !strings.Contains(string(b), "not_found") {
		t.Fatal(resp.StatusCode, string(b))
	}
}

func TestLDAPLoginInternalError(t *testing.T) {
	e, _ := ldapEnv(t)
	e.breakTable(t, "users")
	if resp, _ := e.ldapLogin(t, "alice"); resp.StatusCode != 500 {
		t.Fatal(resp.StatusCode)
	}
}

func TestLDAPLoginRateLimited(t *testing.T) {
	e, _ := ldapEnv(t)
	for i := 0; i < 5; i++ {
		e.do(t, "POST", "/api/auth/ldap", map[string]string{"username": "Alice", "password": "x"})
	}
	if resp, _ := e.ldapLogin(t, "alice"); resp.StatusCode != 429 {
		t.Fatal(resp.StatusCode)
	}
}

func TestLDAPLoginCertificateReason(t *testing.T) {
	e, f := ldapEnv(t)
	f.authErr = fmt.Errorf("%w: %w: %w", ldapauth.ErrUnavailable, ldapauth.ErrCertificate, &tls.CertificateVerificationError{Err: errors.New("x")})
	if resp, _ := e.ldapLogin(t, "alice"); resp.StatusCode != 503 {
		t.Fatal(resp.StatusCode)
	}
	if d := e.lastDetail(t, audit.ActLoginFail); d["reason"] != "certificate" || d["stage"] != "ldap_unavailable" {
		t.Fatal(d)
	}
}

func TestLDAPLoginLocallyDisabled(t *testing.T) {
	e, _ := ldapEnv(t)
	e.mustLDAPLogin(t, "alice")
	if _, err := e.pool.Exec(context.Background(), `UPDATE users SET disabled=true WHERE auth_source='ldap'`); err != nil {
		t.Fatal(err)
	}
	if resp, _ := e.do(t, "GET", "/api/me", nil); resp.StatusCode != 401 {
		t.Fatal("disabled LDAP user kept access", resp.StatusCode)
	}
	if resp, b := e.ldapLogin(t, "alice"); resp.StatusCode != 401 || !strings.Contains(string(b), "invalid_credentials") {
		t.Fatal(resp.StatusCode, string(b))
	}
	if d := e.lastDetail(t, audit.ActLoginFail); d["stage"] != "disabled" {
		t.Fatal(d)
	}
}

func TestAuthMethods(t *testing.T) {
	off := newEnv(t)
	if resp, b := off.do(t, "GET", "/api/auth/methods", nil); resp.StatusCode != 200 || strings.TrimSpace(string(b)) != `{"ldap":false}` {
		t.Fatal(resp.StatusCode, string(b))
	}
	on, _ := ldapEnv(t)
	if resp, b := on.do(t, "GET", "/api/auth/methods", nil); resp.StatusCode != 200 || strings.TrimSpace(string(b)) != `{"ldap":true}` {
		t.Fatal(resp.StatusCode, string(b))
	}
}

func (e *env) sessionCount(t *testing.T) int {
	t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(), `SELECT count(*) FROM sessions s JOIN users u ON u.id=s.user_id WHERE u.auth_source='ldap'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRecheckFailsClosed(t *testing.T) {
	e, f := ldapEnv(t)
	if _, err := e.users.Create(context.Background(), "adm@x.com", "A", "admin", pw); err != nil {
		t.Fatal(err)
	}
	e.loginAs(t, "adm@x.com", "")
	adminJar := e.c.Jar
	e.mustLDAPLogin(t, "alice")
	e.ageSessions(t)
	f.lookErr = ldapauth.ErrUnavailable
	if resp, _ := e.do(t, "GET", "/api/me", nil); resp.StatusCode != 401 {
		t.Fatal(resp.StatusCode)
	}
	if n := e.sessionCount(t); n != 0 {
		t.Fatal("ldap session survived", n)
	}
	if d := e.lastDetail(t, audit.ActSessionEnd); d["reason"] != "ldap_unavailable" {
		t.Fatal(d)
	}
	e.c.Jar = adminJar
	if resp, b := e.do(t, "GET", "/api/me", nil); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode, string(b))
	}
}

func TestRecheckGone(t *testing.T) {
	e, f := ldapEnv(t)
	e.mustLDAPLogin(t, "alice")
	jar := e.c.Jar
	e.mustLDAPLogin(t, "alice") // a second session for the same user
	e.c.Jar = jar
	e.ageSessions(t)
	f.lookErr = ldapauth.ErrGone
	if resp, _ := e.do(t, "GET", "/api/me", nil); resp.StatusCode != 401 {
		t.Fatal(resp.StatusCode)
	}
	if n := e.sessionCount(t); n != 0 {
		t.Fatal("sessions survived", n)
	}
	if d := e.lastDetail(t, audit.ActSessionEnd); d["reason"] != "ldap_gone" {
		t.Fatal(d)
	}
}

func TestRecheckDemotes(t *testing.T) {
	e, f := ldapEnv(t)
	e.mustLDAPLogin(t, "boss")
	e.ageSessions(t)
	f.ids["boss"] = ldapauth.Identity{ExternalID: "b2", Admin: false} // no email or name: kept
	if resp, b := e.do(t, "GET", "/api/admin/users", nil); resp.StatusCode != 403 {
		t.Fatal(resp.StatusCode, string(b))
	}
	var role, email, name string
	if err := e.pool.QueryRow(context.Background(), `SELECT role, email, display_name FROM users WHERE external_id='b2'`).Scan(&role, &email, &name); err != nil ||
		role != "staff" || email != "boss@x.test" || name != "Boss" {
		t.Fatal(role, email, name, err)
	}
}

func TestRecheckNotDueSkipsLookup(t *testing.T) {
	e, f := ldapEnv(t)
	e.mustLDAPLogin(t, "alice")
	if resp, _ := e.do(t, "GET", "/api/me", nil); resp.StatusCode != 200 || f.lookups != 0 {
		t.Fatal(resp.StatusCode, f.lookups)
	}
}

func TestRecheckUpdateFailsClosed(t *testing.T) {
	e, f := ldapEnv(t)
	e.mustLDAPLogin(t, "boss")
	e.mustLDAPLogin(t, "alice")
	e.ageSessions(t)
	f.ids["alice"] = ldapauth.Identity{ExternalID: "a1", Email: "boss@x.test"} // now collides with boss
	if resp, _ := e.do(t, "GET", "/api/me", nil); resp.StatusCode != 401 {
		t.Fatal(resp.StatusCode)
	}
	if d := e.lastDetail(t, audit.ActSessionEnd); d["reason"] != "ldap_error" {
		t.Fatal(d)
	}
}

func TestRecheckWithLDAPOff(t *testing.T) {
	e, _ := ldapEnv(t)
	e.mustLDAPLogin(t, "alice")
	e.ageSessions(t)
	d := e.deps
	d.LDAP = nil // the same database, restarted with LDAP turned off
	ts := httptest.NewTLSServer(NewServer(d))
	defer ts.Close()
	req, _ := http.NewRequest("GET", ts.URL+"/api/me", nil)
	u, _ := url.Parse(e.ts.URL)
	for _, c := range e.c.Jar.Cookies(u) {
		req.AddCookie(c)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatal(resp.StatusCode)
	}
	if n := e.sessionCount(t); n != 0 {
		t.Fatal("ldap session survived", n)
	}
	if d := e.lastDetail(t, audit.ActSessionEnd); d["reason"] != "ldap_unavailable" {
		t.Fatal(d)
	}
}

func TestLDAPUserCannotEnrolTOTP(t *testing.T) {
	e, _ := ldapEnv(t)
	e.mustLDAPLogin(t, "alice")
	for _, p := range []string{"/api/me/totp/setup", "/api/me/totp/enable"} {
		if resp, b := e.do(t, "POST", p, map[string]string{"code": "123456"}); resp.StatusCode != 409 || !strings.Contains(string(b), "external_account") {
			t.Fatal(p, resp.StatusCode, string(b))
		}
	}
	var noSecret, enabled bool
	if err := e.pool.QueryRow(context.Background(), `SELECT totp_secret_sealed IS NULL, totp_enabled FROM users WHERE auth_source='ldap'`).Scan(&noSecret, &enabled); err != nil || !noSecret || enabled {
		t.Fatal(err, noSecret, enabled)
	}
}
