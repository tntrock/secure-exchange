package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/mail/mailtest"
	"github.com/tntrock/secure-exchange/internal/rules"
)

var activateLinkRE = regexp.MustCompile(`https://x\.example/activate/([A-Za-z0-9_-]{43})`)

func (e *env) activateToken(t *testing.T, email string) string {
	t.Helper()
	tok := ""
	for _, m := range mailtest.Messages(t, e.pool, e.keys) {
		if r := activateLinkRE.FindStringSubmatch(m.Body); m.To == email && r != nil {
			tok = r[1]
		}
	}
	if tok == "" {
		t.Fatal("no activation link for", email)
	}
	return tok
}

func (e *env) admin(t *testing.T) {
	t.Helper()
	if _, err := e.users.Create(context.Background(), "adm@x.com", "A", "admin", pw); err != nil {
		t.Fatal(err)
	}
}

func (e *env) forceTOTP(t *testing.T, on bool) {
	t.Helper()
	e.setRules(t, func(r *rules.Rules) { r.ForceTOTP = on })
}

// invite creates a staff user as the admin (left logged in) and returns the activation token.
func (e *env) invite(t *testing.T, email string) string {
	t.Helper()
	e.loginAs(t, "adm@x.com", "")
	if resp, b := e.do(t, "POST", "/api/admin/users", map[string]string{"email": email, "display_name": "N", "role": "staff"}); resp.StatusCode != 201 {
		t.Fatal(resp.StatusCode, string(b))
	}
	return e.activateToken(t, email)
}

func (e *env) auditActions(t *testing.T, action string) []audit.Entry {
	t.Helper()
	got, err := e.audit.List(context.Background(), audit.Filter{Action: action})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func (e *env) userID(t *testing.T, email string) string {
	t.Helper()
	var id string
	if err := e.pool.QueryRow(context.Background(), `SELECT id FROM users WHERE email=$1`, email).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func (e *env) lastLogin(email string) (l *time.Time) {
	e.pool.QueryRow(context.Background(), `SELECT last_login_at FROM users WHERE email=$1`, email).Scan(&l)
	return l
}

func wantStatus(t *testing.T, e *env, method, path string, body any, status int, resp string) {
	t.Helper()
	r, b := e.do(t, method, path, body)
	if r.StatusCode != status || (resp != "" && string(b) != resp) {
		t.Fatalf("%s %s: %d %s", method, path, r.StatusCode, b)
	}
}

func otpURL(t *testing.T, b []byte) string {
	t.Helper()
	var o struct {
		URL string `json:"otpauth_url"`
	}
	if err := json.Unmarshal(b, &o); err != nil || o.URL == "" {
		t.Fatal(err, string(b))
	}
	return o.URL
}

const zeroID = "00000000-0000-0000-0000-000000000000"

func TestAdminUsersRequireAdmin(t *testing.T) {
	e := newEnv(t)
	e.user(t, "s@x.com")
	routes := [][2]string{{"GET", ""}, {"POST", ""}, {"PATCH", "/" + zeroID}, {"POST", "/" + zeroID + "/disable"},
		{"POST", "/" + zeroID + "/enable"}, {"POST", "/" + zeroID + "/reset-totp"}, {"POST", "/" + zeroID + "/reinvite"}}
	for _, rt := range routes {
		wantStatus(t, e, rt[0], "/api/admin/users"+rt[1], map[string]string{}, 401, "")
	}
	e.loginAs(t, "s@x.com", "")
	for _, rt := range routes {
		wantStatus(t, e, rt[0], "/api/admin/users"+rt[1], map[string]string{}, 403, forbiddenBody)
	}
}

func TestAdminCreateAndActivateStaff(t *testing.T) {
	e := newEnv(t)
	e.admin(t)
	tok := e.invite(t, "n@x.com")
	var list []map[string]any
	_, b := e.do(t, "GET", "/api/admin/users", nil)
	if err := json.Unmarshal(b, &list); err != nil || len(list) != 2 || list[0]["email"] != "n@x.com" || list[0]["status"] != "invited" ||
		list[0]["role"] != "staff" || list[0]["auth_source"] != "local" || list[0]["last_login_at"] != nil {
		t.Fatal(err, string(b))
	}
	wantStatus(t, e, "POST", "/api/admin/users", map[string]string{"email": "N@x.com", "role": "staff"}, 409, `{"error":"email_taken"}`+"\n")
	wantStatus(t, e, "POST", "/api/admin/users", map[string]string{"email": "bad", "role": "staff"}, 422,
		`{"code":"invalid","error":"validation","field":"email"}`+"\n")
	wantStatus(t, e, "POST", "/api/admin/users", "x", 400, "")

	e.c.Jar = nil // activation needs no session
	wantStatus(t, e, "GET", "/api/activate/"+tok, nil, 200, `{"email":"n@x.com","otpauth_url":"","totp_required":false}`+"\n")
	wantStatus(t, e, "POST", "/api/activate/"+tok, map[string]string{"password": "short"}, 422, "")
	wantStatus(t, e, "POST", "/api/activate/"+tok, "x", 400, "")
	wantStatus(t, e, "POST", "/api/activate/"+tok, map[string]string{"password": pw}, 204, "")
	wantStatus(t, e, "GET", "/api/activate/"+tok, nil, 410, `{"error":"gone"}`+"\n")
	wantStatus(t, e, "GET", "/api/activate/nope", nil, 410, "")

	e.loginAs(t, "n@x.com", "")
	wantStatus(t, e, "GET", "/api/me", nil, 200, "")
	c, a := e.auditActions(t, audit.ActUserCreate), e.auditActions(t, audit.ActUserActivate)
	if len(c) != 1 || len(a) != 1 || a[0].Event.Result != "ok" || a[0].Event.ActorID != a[0].Event.TargetID || a[0].ID < c[0].ID {
		t.Fatal(c, a)
	}
}

func TestLoginBodyAfterActivation(t *testing.T) {
	e := newEnv(t)
	e.admin(t)
	tok := e.invite(t, "n@x.com")
	wantStatus(t, e, "POST", "/api/activate/"+tok, map[string]string{"password": pw}, 204, "")
	e.c.Jar = nil
	wantStatus(t, e, "POST", "/api/auth/login", map[string]string{"email": "n@x.com", "password": pw}, 200,
		`{"mfa_required":false,"totp_setup_required":false}`+"\n")
}

func TestActivateNotIPGated(t *testing.T) {
	e := newEnv(t, func(d *Deps) { d.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")} })
	e.admin(t)
	tok := e.invite(t, "n@x.com")
	e.setRules(t, func(r *rules.Rules) { r.ExternalIPAllow = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")} })
	out := []string{"X-Forwarded-For", "203.0.113.5"}
	if resp, b := e.get(t, "/api/activate/"+tok, out...); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode, string(b))
	}
	if resp, b := e.get(t, "/api/invite/"+tok, out...); resp.StatusCode != 403 || string(b) != `{"error":"ip_denied"}`+"\n" {
		t.Fatal(resp.StatusCode, string(b))
	}
}

func TestCrossInviteTokens(t *testing.T) {
	e := newEnv(t)
	e.admin(t)
	e.loginAs(t, "adm@x.com", "")
	exp := time.Now().AddDate(0, 0, 30).UTC().Format(time.RFC3339)
	_, b := e.do(t, "POST", "/api/vendors", map[string]any{"email": "v@v.com", "display_name": "V", "org": "O", "expires_at": exp})
	var v vendorJSON
	json.Unmarshal(b, &v)
	vtok := e.inviteToken(t, "v@v.com")
	stok := e.invite(t, "n@x.com")
	e.c.Jar = nil
	wantStatus(t, e, "POST", "/api/invite/"+stok, map[string]string{"password": pw, "code": "000000"}, 410, "")
	wantStatus(t, e, "POST", "/api/activate/"+vtok, map[string]string{"password": pw}, 410, "")
	for _, email := range []string{"n@x.com", "v@v.com"} {
		var has bool
		e.pool.QueryRow(context.Background(), `SELECT password_hash IS NOT NULL FROM users WHERE email=$1`, email).Scan(&has)
		if has {
			t.Fatal("password set for", email)
		}
	}
}

func TestForcedTOTPLogin(t *testing.T) {
	e := newEnv(t)
	e.user(t, "s@x.com")
	e.forceTOTP(t, true)
	resp, b := e.login(t, "s@x.com", pw)
	if resp.StatusCode != 200 || string(b) != `{"mfa_required":false,"totp_setup_required":true}`+"\n" {
		t.Fatal(resp.StatusCode, string(b))
	}
	wantStatus(t, e, "GET", "/api/me", nil, 401, "")
	if e.lastLogin("s@x.com") != nil {
		t.Fatal("last login recorded before enrolment")
	}
	_, b = e.do(t, "POST", "/api/auth/totp/setup", nil)
	u1 := otpURL(t, b)
	_, b = e.do(t, "POST", "/api/auth/totp/setup", nil)
	if u1 != otpURL(t, b) {
		t.Fatal("setup url changed")
	}
	secret := otpSecret(t, u1)
	wrong, _ := totp.GenerateCode(secret, time.Now().Add(10*time.Minute))
	wantStatus(t, e, "POST", "/api/auth/totp/enroll", map[string]string{"code": wrong}, 401, `{"error":"invalid_code"}`+"\n")
	wantStatus(t, e, "POST", "/api/auth/totp/enroll", "x", 400, "")
	wantStatus(t, e, "GET", "/api/me", nil, 401, "")
	good, _ := totp.GenerateCode(secret, time.Now())
	wantStatus(t, e, "POST", "/api/auth/totp/enroll", map[string]string{"code": good}, 200, `{"mfa_required":false}`+"\n")
	wantStatus(t, e, "GET", "/api/me", nil, 200, "")
	if len(e.auditActions(t, audit.ActTOTPEnable)) != 1 || len(e.auditActions(t, audit.ActLoginOK)) != 1 || e.lastLogin("s@x.com") == nil {
		t.Fatal("audit or last login")
	}
}

func TestForcedTOTPNotForVendorsOrEnrolled(t *testing.T) {
	e := newEnv(t)
	e.mkVendor(t, "v@v.com")
	e.user(t, "s@x.com")
	e.forceTOTP(t, true)
	resp, b := e.login(t, "v@v.com", pw)
	if resp.StatusCode != 200 || string(b) != `{"mfa_required":true,"totp_setup_required":false}`+"\n" {
		t.Fatal(resp.StatusCode, string(b))
	}
	wantStatus(t, e, "POST", "/api/auth/totp/setup", nil, 401, "") // a vendor's half-session

	// staff enrols, then logs in again: a TOTP user's half-session cannot use the enrolment endpoints
	e.loginAs(t, "s@x.com", "")
	_, b = e.do(t, "POST", "/api/auth/totp/setup", nil)
	secret := otpSecret(t, otpURL(t, b))
	code, _ := totp.GenerateCode(secret, time.Now().Add(-30*time.Second))
	wantStatus(t, e, "POST", "/api/auth/totp/enroll", map[string]string{"code": code}, 200, "")
	e.c.Jar, _ = cookiejar.New(nil)
	resp, b = e.login(t, "s@x.com", pw)
	if string(b) != `{"mfa_required":true,"totp_setup_required":false}`+"\n" {
		t.Fatal(resp.StatusCode, string(b))
	}
	wantStatus(t, e, "POST", "/api/auth/totp/setup", nil, 401, "")
	wantStatus(t, e, "POST", "/api/auth/totp/enroll", map[string]string{"code": code}, 401, "")

	// a fully logged-in session
	next, _ := totp.GenerateCode(secret, time.Now().Add(30*time.Second))
	wantStatus(t, e, "POST", "/api/auth/totp", map[string]string{"code": next}, 200, "")
	wantStatus(t, e, "POST", "/api/auth/totp/setup", nil, 401, "")
	e.c.Jar = nil // no session at all
	wantStatus(t, e, "POST", "/api/auth/totp/setup", nil, 401, "")
}

func TestForcedTOTPOff(t *testing.T) {
	e := newEnv(t)
	e.user(t, "s@x.com")
	resp, b := e.login(t, "s@x.com", pw)
	if resp.StatusCode != 200 || string(b) != `{"mfa_required":false,"totp_setup_required":false}`+"\n" {
		t.Fatal(resp.StatusCode, string(b))
	}
	wantStatus(t, e, "GET", "/api/me", nil, 200, "")
}

func TestResetTOTPKillsSessions(t *testing.T) {
	e := newEnv(t)
	e.admin(t)
	u := e.user(t, "s@x.com")
	ctx := context.Background()
	url, _ := e.users.BeginTOTP(ctx, u.ID)
	secret := otpSecret(t, url)
	c0, _ := totp.GenerateCode(secret, time.Now().Add(-30*time.Second))
	if err := e.users.EnableTOTP(ctx, u.ID, c0); err != nil {
		t.Fatal(err)
	}
	e.loginAs(t, "s@x.com", secret) // S1: full
	s1 := e.c.Jar
	e.loginAs(t, "s@x.com", "") // S2: password only
	s2 := e.c.Jar
	e.loginAs(t, "adm@x.com", "")
	wantStatus(t, e, "POST", "/api/admin/users/"+u.ID.String()+"/reset-totp", nil, 204, "")
	e.c.Jar = s1
	wantStatus(t, e, "GET", "/api/me", nil, 401, "")
	e.c.Jar = s2
	next, _ := totp.GenerateCode(secret, time.Now().Add(30*time.Second))
	wantStatus(t, e, "POST", "/api/auth/totp", map[string]string{"code": next}, 401, "")
	e.c.Jar, _ = cookiejar.New(nil)
	resp, b := e.login(t, "s@x.com", pw)
	if resp.StatusCode != 200 || string(b) != `{"mfa_required":false,"totp_setup_required":false}`+"\n" {
		t.Fatal(resp.StatusCode, string(b))
	}
	if len(e.auditActions(t, audit.ActUserTOTPReset)) != 1 {
		t.Fatal("audit")
	}
}

func TestAdminUserActionsAudit(t *testing.T) {
	e := newEnv(t)
	e.admin(t)
	s := e.user(t, "s@x.com")
	e.mkVendor(t, "v@v.com")
	vid, admID, id := e.userID(t, "v@v.com"), e.userID(t, "adm@x.com"), s.ID.String()
	e.loginAs(t, "adm@x.com", "")
	base := "/api/admin/users/"

	wantStatus(t, e, "POST", base+id+"/disable", nil, 204, "")
	wantStatus(t, e, "POST", base+id+"/enable", nil, 204, "")
	wantStatus(t, e, "POST", base+admID+"/disable", nil, 409, `{"error":"last_admin"}`+"\n")
	wantStatus(t, e, "PATCH", base+admID, map[string]string{"role": "staff"}, 409, `{"error":"last_admin"}`+"\n")
	wantStatus(t, e, "PATCH", base+id, map[string]string{"role": "admin"}, 204, "")
	wantStatus(t, e, "PATCH", base+id, map[string]string{"role": "root"}, 422, "")
	wantStatus(t, e, "PATCH", base+vid, map[string]string{"role": "staff"}, 409, `{"error":"wrong_state"}`+"\n")
	wantStatus(t, e, "PATCH", base+zeroID, map[string]string{"role": "staff"}, 404, `{"error":"not_found"}`+"\n")
	wantStatus(t, e, "POST", base+zeroID+"/disable", nil, 404, "")
	wantStatus(t, e, "PATCH", base+id, "x", 400, "")
	wantStatus(t, e, "POST", base+"nope/disable", nil, 404, "")
	wantStatus(t, e, "POST", base+id+"/reset-totp", nil, 409, `{"error":"wrong_state"}`+"\n")
	wantStatus(t, e, "POST", base+id+"/reinvite", nil, 409, `{"error":"wrong_state"}`+"\n")
	if _, err := e.pool.Exec(context.Background(), `UPDATE users SET auth_source='oidc' WHERE id=$1`, s.ID); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, e, "PATCH", base+id, map[string]string{"role": "staff"}, 409, `{"error":"external_account"}`+"\n")

	for action, n := range map[string]int{audit.ActUserDisable: 1, audit.ActUserEnable: 1, audit.ActUserRole: 1} {
		if got := e.auditActions(t, action); len(got) != n || got[0].Event.TargetType != "user" || got[0].Event.TargetID != id {
			t.Errorf("%s: %+v", action, got)
		}
	}
	if d := e.auditActions(t, audit.ActUserRole)[0].Event.Detail; d["from"] != "staff" || d["to"] != "admin" {
		t.Fatal(d)
	}
}

func TestAdminReinvite(t *testing.T) {
	e := newEnv(t)
	e.admin(t)
	old := e.invite(t, "n@x.com")
	wantStatus(t, e, "POST", "/api/admin/users/"+e.userID(t, "n@x.com")+"/reinvite", nil, 204, "")
	if len(e.auditActions(t, audit.ActUserReinvite)) != 1 {
		t.Fatal("audit")
	}
	e.c.Jar = nil
	wantStatus(t, e, "GET", "/api/activate/"+old, nil, 410, "")
	wantStatus(t, e, "GET", "/api/activate/"+e.activateToken(t, "n@x.com"), nil, 200, "")
}

func TestAccountErrDefaultsToInternal(t *testing.T) {
	w := httptest.NewRecorder()
	accountErr(w, http.ErrAbortHandler)
	if w.Code != 500 || strings.TrimSpace(w.Body.String()) != `{"error":"internal"}` {
		t.Fatal(w.Code, w.Body)
	}
}

func TestActivateForcedTOTP(t *testing.T) {
	e := newEnv(t)
	e.admin(t)
	tok := e.invite(t, "n@x.com")
	e.forceTOTP(t, true)
	e.c.Jar = nil
	_, b := e.do(t, "GET", "/api/activate/"+tok, nil)
	var info struct {
		Required bool `json:"totp_required"`
	}
	if json.Unmarshal(b, &info); !info.Required {
		t.Fatal(string(b))
	}
	secret := otpSecret(t, otpURL(t, b))
	wantStatus(t, e, "POST", "/api/activate/"+tok, map[string]string{"password": pw}, 400, `{"error":"totp_required"}`+"\n")
	wrong, _ := totp.GenerateCode(secret, time.Now().Add(10*time.Minute))
	wantStatus(t, e, "POST", "/api/activate/"+tok, map[string]string{"password": pw, "code": wrong}, 401, `{"error":"invalid_code"}`+"\n")
	good, _ := totp.GenerateCode(secret, time.Now())
	wantStatus(t, e, "POST", "/api/activate/"+tok, map[string]string{"password": pw, "code": good}, 204, "")
	got := e.auditActions(t, audit.ActUserActivate)
	if len(got) != 2 || got[0].Event.Result+got[1].Event.Result != "okfail" && got[0].Event.Result+got[1].Event.Result != "failok" {
		t.Fatal(got)
	}
}

func TestRulesForceTOTPRoundTrip(t *testing.T) {
	e := newEnv(t)
	e.admin(t)
	e.loginAs(t, "adm@x.com", "")
	_, b := e.do(t, "GET", "/api/rules", nil)
	var rl map[string]any
	json.Unmarshal(b, &rl)
	if rl["force_totp"] != false {
		t.Fatal(string(b))
	}
	rl["force_totp"] = true
	resp, b := e.do(t, "PUT", "/api/admin/rules", rl)
	var out struct {
		Rules map[string]any `json:"rules"`
	}
	if json.Unmarshal(b, &out); resp.StatusCode != 200 || out.Rules["force_totp"] != true {
		t.Fatal(resp.StatusCode, string(b))
	}
	_, b = e.do(t, "GET", "/api/rules", nil)
	json.Unmarshal(b, &rl)
	if rl["force_totp"] != true {
		t.Fatal(string(b))
	}
}

func TestLoginTouchesLastLogin(t *testing.T) {
	e := newEnv(t)
	e.user(t, "s@x.com")
	secret := e.mkVendor(t, "v@v.com")
	if e.lastLogin("s@x.com") != nil {
		t.Fatal("preset")
	}
	e.login(t, "s@x.com", pw)
	if e.lastLogin("s@x.com") == nil {
		t.Fatal("password-only login not recorded")
	}
	e.c.Jar, _ = cookiejar.New(nil)
	e.login(t, "v@v.com", pw)
	if e.lastLogin("v@v.com") != nil {
		t.Fatal("recorded before the code step")
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	wantStatus(t, e, "POST", "/api/auth/totp", map[string]string{"code": code}, 200, "")
	if e.lastLogin("v@v.com") == nil {
		t.Fatal("code step not recorded")
	}
}

// A concurrent enrolment that wins between the session check and the enabling update must not become a 500.
func TestTOTPEnrolLosesRace(t *testing.T) {
	e := newEnv(t)
	u := e.user(t, "s@x.com")
	e.forceTOTP(t, true)
	e.login(t, "s@x.com", pw)
	_, b := e.do(t, "POST", "/api/auth/totp/setup", nil)
	secret := otpSecret(t, otpURL(t, b))
	good, _ := totp.GenerateCode(secret, time.Now())
	beforeEnableTOTP = func() { e.pool.Exec(context.Background(), `UPDATE users SET totp_enabled = true WHERE id = $1`, u.ID) }
	t.Cleanup(func() { beforeEnableTOTP = func() {} })
	wantStatus(t, e, "POST", "/api/auth/totp/enroll", map[string]string{"code": good}, 401, `{"error":"unauthorized"}`+"\n")
}

func TestTOTPEnableLosesRace(t *testing.T) {
	e := newEnv(t)
	u := e.user(t, "s@x.com")
	e.loginAs(t, "s@x.com", "")
	_, b := e.do(t, "POST", "/api/me/totp/setup", nil)
	good, _ := totp.GenerateCode(otpSecret(t, otpURL(t, b)), time.Now())
	beforeEnableTOTP = func() { e.pool.Exec(context.Background(), `UPDATE users SET totp_enabled = true WHERE id = $1`, u.ID) }
	t.Cleanup(func() { beforeEnableTOTP = func() {} })
	wantStatus(t, e, "POST", "/api/me/totp/enable", map[string]string{"code": good}, 409, `{"error":"totp_already_enabled"}`+"\n")
}
