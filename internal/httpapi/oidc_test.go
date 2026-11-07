package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/oidcauth"
)

type fakeOIDC struct {
	id       oidcauth.Identity
	startErr error
	exchErr  error
	calls    int
	gotCode  string
	gotFlow  oidcauth.Flow
}

func (f *fakeOIDC) Start(context.Context) (string, oidcauth.Flow, error) {
	if f.startErr != nil {
		return "", oidcauth.Flow{}, f.startErr
	}
	return "https://idp.test/authorize?x=1", oidcauth.Flow{State: "st", Nonce: "no", Verifier: "ve"}, nil
}

func (f *fakeOIDC) Exchange(_ context.Context, code string, fl oidcauth.Flow) (oidcauth.Identity, error) {
	f.calls++
	f.gotCode, f.gotFlow = code, fl
	return f.id, f.exchErr
}

func oidcEnv(t *testing.T) (*env, *fakeOIDC) {
	t.Helper()
	f := &fakeOIDC{id: oidcauth.Identity{ExternalID: "https://idp.test sub1", Email: "a@x.test", Name: "Alice"}}
	e := newEnv(t, func(d *Deps) { d.OIDC = f; d.OIDCLabel = "Sign in with Contoso" })
	// the callback's 302 is the thing under test
	e.c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return e, f
}

// setFlow plants the flow cookie that start would have set, on a fresh jar.
func (e *env) setFlow(t *testing.T, v string) {
	t.Helper()
	e.c.Jar, _ = cookiejar.New(nil)
	u, _ := url.Parse(e.ts.URL + "/api/auth/oidc/callback")
	e.c.Jar.SetCookies(u, []*http.Cookie{{Name: "sx_oidc", Value: v, Path: "/api/auth/oidc", Secure: true}})
}

// oidcCallback runs start (to get the flow cookie) and then the callback with the given query on a fresh jar.
func (e *env) oidcCallback(t *testing.T, query string) *http.Response {
	t.Helper()
	e.setFlow(t, "st.no.ve")
	resp, _ := e.do(t, "GET", "/api/auth/oidc/callback?"+query, nil)
	return resp
}

func setCookie(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func (e *env) mustOIDCLogin(t *testing.T) {
	t.Helper()
	resp := e.oidcCallback(t, "state=st&code=c1")
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "/files" {
		t.Fatal(resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestOIDCStartSetsFlowCookie(t *testing.T) {
	e, _ := oidcEnv(t)
	resp, _ := e.do(t, "GET", "/api/auth/oidc/start", nil)
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "https://idp.test/authorize?x=1" {
		t.Fatal(resp.StatusCode, resp.Header.Get("Location"))
	}
	c := setCookie(resp, "sx_oidc")
	if c == nil || c.Value != "st.no.ve" || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/api/auth/oidc" || c.MaxAge != 600 {
		t.Fatalf("%+v", c)
	}
}

func TestOIDCStartUnavailable(t *testing.T) {
	e, f := oidcEnv(t)
	f.startErr = oidcauth.ErrUnavailable
	resp, _ := e.do(t, "GET", "/api/auth/oidc/start", nil)
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "/login?oidc_error=unavailable" || setCookie(resp, "sx_oidc") != nil {
		t.Fatal(resp.StatusCode, resp.Header.Get("Location"))
	}
	if d := e.lastDetail(t, audit.ActLoginFail); d["stage"] != "oidc_unavailable" || d["source"] != "oidc" {
		t.Fatal(d)
	}
}

func TestOIDCCallbackCreatesStaff(t *testing.T) {
	e, f := oidcEnv(t)
	resp := e.oidcCallback(t, "state=st&code=c1")
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "/files" {
		t.Fatal(resp.StatusCode, resp.Header.Get("Location"))
	}
	if c := setCookie(resp, "sx_session"); c == nil || c.Value == "" || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("%+v", c)
	}
	if c := setCookie(resp, "sx_oidc"); c == nil || c.MaxAge >= 0 {
		t.Fatalf("flow cookie not cleared: %+v", c)
	}
	if f.gotCode != "c1" || f.gotFlow != (oidcauth.Flow{State: "st", Nonce: "no", Verifier: "ve"}) {
		t.Fatal(f.gotCode, f.gotFlow)
	}
	r, b := e.do(t, "GET", "/api/me", nil)
	if r.StatusCode != 200 || !strings.Contains(string(b), `"role":"staff"`) || !strings.Contains(string(b), `"auth_source":"oidc"`) {
		t.Fatal(r.StatusCode, string(b))
	}
	if d := e.lastDetail(t, audit.ActLoginOK); d["source"] != "oidc" || d["email"] != "a@x.test" {
		t.Fatal(d)
	}
}

func TestOIDCCallbackAdminAndRoleChange(t *testing.T) {
	e, f := oidcEnv(t)
	f.id.Admin = true
	e.mustOIDCLogin(t)
	if resp, b := e.do(t, "GET", "/api/admin/users", nil); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode, string(b))
	}
	f.id.Admin = false
	e.mustOIDCLogin(t)
	if _, b := e.do(t, "GET", "/api/me", nil); !strings.Contains(string(b), `"role":"staff"`) {
		t.Fatal(string(b))
	}
	if d := e.lastDetail(t, audit.ActLoginOK); d["role_from"] != "admin" || d["role_to"] != "staff" {
		t.Fatal(d)
	}
}

func TestOIDCCallbackStateMismatch(t *testing.T) {
	e, f := oidcEnv(t)
	check := func(name string, resp *http.Response) {
		t.Helper()
		if resp.StatusCode != 302 || resp.Header.Get("Location") != "/login?oidc_error=invalid" || setCookie(resp, "sx_session") != nil {
			t.Fatal(name, resp.StatusCode, resp.Header.Get("Location"))
		}
		if d := e.lastDetail(t, audit.ActLoginFail); d["stage"] != "oidc_state" {
			t.Fatal(name, d)
		}
	}
	check("mismatch", e.oidcCallback(t, "state=other&code=c1"))
	check("no state", e.oidcCallback(t, "code=c1"))

	e.c.Jar, _ = cookiejar.New(nil) // no cookie at all
	resp, _ := e.do(t, "GET", "/api/auth/oidc/callback?state=st&code=c1", nil)
	check("no cookie", resp)

	for _, v := range []string{"st.no", "st.no.", "st..ve", ".no.ve", "st.no.ve.x"} {
		e.setFlow(t, v)
		resp, _ := e.do(t, "GET", "/api/auth/oidc/callback?state=st&code=c1", nil)
		check(v, resp)
	}
	if f.calls != 0 {
		t.Fatal("Exchange called", f.calls)
	}
}

func TestOIDCCallbackErrors(t *testing.T) {
	e, f := oidcEnv(t)
	for _, c := range []struct {
		query string
		err   error
		code  string
		stage string
	}{
		{"error=access_denied&state=st", nil, "denied", "oidc_denied"},
		{"state=st&code=c", oidcauth.ErrInvalid, "invalid", "oidc_token"},
		{"state=st&code=c", oidcauth.ErrNoEmail, "invalid", "oidc_no_email"},
		{"state=st&code=c", oidcauth.ErrUnavailable, "unavailable", "oidc_unavailable"},
		{"state=st&code=c", errors.New("other"), "unavailable", "oidc_unavailable"},
	} {
		f.exchErr, f.calls = c.err, 0
		resp := e.oidcCallback(t, c.query)
		if resp.StatusCode != 302 || resp.Header.Get("Location") != "/login?oidc_error="+c.code || setCookie(resp, "sx_session") != nil {
			t.Fatal(c, resp.StatusCode, resp.Header.Get("Location"))
		}
		if cc := setCookie(resp, "sx_oidc"); cc == nil || cc.MaxAge >= 0 {
			t.Fatal(c, "flow cookie kept")
		}
		d := e.lastDetail(t, audit.ActLoginFail)
		if d["stage"] != c.stage || d["source"] != "oidc" {
			t.Fatal(c, d)
		}
		if c.stage == "oidc_denied" && (f.calls != 0 || d["idp_error"] != "access_denied") {
			t.Fatal(f.calls, d)
		}
	}
	f.exchErr = nil

	// the idp_error value is truncated
	e.oidcCallback(t, "error="+strings.Repeat("e", 200))
	if d := e.lastDetail(t, audit.ActLoginFail); len(d["idp_error"].(string)) > 64 {
		t.Fatal(len(d["idp_error"].(string)))
	}

}

func TestOIDCCallbackConflictAndDisabled(t *testing.T) {
	e, f := oidcEnv(t)
	// two identities, one email
	e.mustOIDCLogin(t)
	f.id = oidcauth.Identity{ExternalID: "https://idp.test sub2", Email: "a@x.test", Name: "M"}
	resp := e.oidcCallback(t, "state=st&code=c")
	if resp.Header.Get("Location") != "/login?oidc_error=email_conflict" || setCookie(resp, "sx_session") != nil {
		t.Fatal(resp.Header.Get("Location"))
	}
	if d := e.lastDetail(t, audit.ActLoginFail); d["stage"] != "email_conflict" || d["external_id"] != "https://idp.test sub2" {
		t.Fatal(d)
	}

	// locally disabled
	f.id = oidcauth.Identity{ExternalID: "https://idp.test sub1", Email: "a@x.test", Name: "Alice"}
	if _, err := e.pool.Exec(context.Background(), "UPDATE users SET disabled=true WHERE auth_source='oidc'"); err != nil {
		t.Fatal(err)
	}
	resp = e.oidcCallback(t, "state=st&code=c")
	if resp.Header.Get("Location") != "/login?oidc_error=invalid" || setCookie(resp, "sx_session") != nil {
		t.Fatal(resp.Header.Get("Location"))
	}
	if d := e.lastDetail(t, audit.ActLoginFail); d["stage"] != "disabled" {
		t.Fatal(d)
	}
}

func TestOIDCCallbackInternalErrors(t *testing.T) {
	for _, table := range []string{"users", "sessions"} { // a failed upsert, and a failed session create
		e, _ := oidcEnv(t)
		if _, err := e.pool.Exec(context.Background(), "ALTER TABLE "+table+" RENAME TO "+table+"_x"); err != nil {
			t.Fatal(err)
		}
		resp := e.oidcCallback(t, "state=st&code=c")
		_, _ = e.pool.Exec(context.Background(), "ALTER TABLE "+table+"_x RENAME TO "+table)
		if resp.StatusCode != 302 || resp.Header.Get("Location") != "/login?oidc_error=unavailable" || setCookie(resp, "sx_session") != nil {
			t.Fatal(table, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
}

func TestOIDCLoginNeverTouchesLocal(t *testing.T) {
	e, _ := oidcEnv(t)
	local := e.user(t, "a@x.test")
	e.mustOIDCLogin(t) // same email as the local user: a separate account, never a merge
	if got := e.meID(t); got == local.ID.String() {
		t.Fatal("oidc login landed on the local account")
	}
	e.loginAs(t, "a@x.test", "")
	if got := e.meID(t); got != local.ID.String() {
		t.Fatal(got)
	}
}

func TestOIDCLoginOverageAudited(t *testing.T) {
	e, f := oidcEnv(t)
	f.id.GroupsOverage = true
	e.mustOIDCLogin(t)
	if _, b := e.do(t, "GET", "/api/me", nil); !strings.Contains(string(b), `"role":"staff"`) {
		t.Fatal(string(b))
	}
	if d := e.lastDetail(t, audit.ActLoginOK); d["groups_overage"] != true {
		t.Fatal(d)
	}
}

func TestOIDCOff(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"/api/auth/oidc/start", "/api/auth/oidc/callback?state=x"} {
		if resp, b := e.do(t, "GET", p, nil); resp.StatusCode != 404 || !strings.Contains(string(b), "not_found") {
			t.Fatal(p, resp.StatusCode, string(b))
		}
	}
	if _, b := e.do(t, "GET", "/api/auth/methods", nil); !strings.Contains(string(b), `"oidc":false`) {
		t.Fatal(string(b))
	}
}

func TestOIDCSessionEndsWhenDisabled(t *testing.T) {
	e, _ := oidcEnv(t)
	e.mustOIDCLogin(t)
	d := e.deps
	d.OIDC = nil // the same database, restarted with OIDC turned off
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
	var n int
	if err := e.pool.QueryRow(context.Background(), "SELECT count(*) FROM sessions s JOIN users u ON u.id=s.user_id WHERE u.auth_source='oidc'").Scan(&n); err != nil || n != 0 {
		t.Fatal("oidc session survived", n, err)
	}
	if d := e.lastDetail(t, audit.ActSessionEnd); d["reason"] != "oidc_disabled" {
		t.Fatal(d)
	}
}

func TestOIDCAccountExternalGuards(t *testing.T) {
	e, _ := oidcEnv(t)
	e.mustOIDCLogin(t)
	for _, p := range []string{"/api/me/totp/setup", "/api/me/totp/enable"} {
		if resp, b := e.do(t, "POST", p, map[string]string{"code": "123456"}); resp.StatusCode != 409 || !strings.Contains(string(b), "external_account") {
			t.Fatal(p, resp.StatusCode, string(b))
		}
	}
	id := e.userID(t, "a@x.test")
	e.admin(t)
	e.loginAs(t, "adm@x.com", "")
	wantStatus(t, e, "PATCH", "/api/admin/users/"+id, map[string]string{"role": "admin"}, 409, `{"error":"external_account"}`+"\n")
	wantStatus(t, e, "POST", "/api/admin/users/"+id+"/reset-totp", nil, 409, `{"error":"external_account"}`+"\n")
}

func TestAuthMethodsOIDC(t *testing.T) {
	e, _ := oidcEnv(t)
	if resp, b := e.do(t, "GET", "/api/auth/methods", nil); resp.StatusCode != 200 ||
		strings.TrimSpace(string(b)) != `{"ldap":false,"oidc":true,"oidc_label":"Sign in with Contoso"}` {
		t.Fatal(resp.StatusCode, string(b))
	}
}
