package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/blob"
	"github.com/tntrock/secure-exchange/internal/config"
	"github.com/tntrock/secure-exchange/internal/db/testdb"
	"github.com/tntrock/secure-exchange/internal/mail"
	"github.com/tntrock/secure-exchange/internal/share"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
)

const pw = "password-12345"

type env struct {
	ts    *httptest.Server
	c     *http.Client
	users *auth.Users
	audit *audit.Log
	pool  *pgxpool.Pool
	keys  *sxcrypto.Keyring
	store blob.Store
	deps  Deps // as passed to NewServer, for calling handlers directly
}

func newEnv(t *testing.T, mods ...func(*Deps)) *env {
	t.Helper()
	pool := testdb.New(t)
	k := make([]byte, 32)
	rand.Read(k)
	kr, err := sxcrypto.ParseKeyring("1:"+base64.StdEncoding.EncodeToString(k), 1)
	if err != nil {
		t.Fatal(err)
	}
	store, err := blob.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e := &env{users: auth.NewUsers(pool, kr), audit: audit.New(pool), pool: pool, keys: kr, store: store}
	d := Deps{Users: e.users, Sessions: auth.NewSessions(pool), Audit: e.audit, SessionTTL: time.Hour, Pool: pool, Keys: kr, Store: store, Shares: share.NewService(pool, mail.NewOutbox(pool, kr, &mail.Recorder{}), kr, "https://x.example", 30),
		Uploads: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, auth.UserFrom(r.Context()).ID.String())
		}), Mark: config.MarkConfig{MaxBytes: 256 << 20, MaxPixels: 50_000_000, Policy: "warn"}}
	for _, m := range mods {
		m(&d)
	}
	e.deps = d
	e.ts = httptest.NewTLSServer(NewServer(d))
	t.Cleanup(e.ts.Close)
	e.c = e.ts.Client()
	e.c.Jar, _ = cookiejar.New(nil)
	return e
}

func (e *env) user(t *testing.T, email string) *auth.User {
	t.Helper()
	u, err := e.users.Create(context.Background(), email, "D", "staff", pw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func (e *env) do(t *testing.T, method, path string, body any) (*http.Response, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.ts.URL+path, r)
	resp, err := e.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func (e *env) login(t *testing.T, email, password string) (*http.Response, []byte) {
	return e.do(t, "POST", "/api/auth/login", map[string]string{"email": email, "password": password})
}

func TestLoginSuccessNoTOTP(t *testing.T) {
	e := newEnv(t)
	u := e.user(t, "a@x.com")
	resp, body := e.login(t, "A@x.com", pw)
	if resp.StatusCode != 200 || strings.TrimSpace(string(body)) != `{"mfa_required":false}` {
		t.Fatal(resp.StatusCode, string(body))
	}
	sc := resp.Header.Get("Set-Cookie")
	for _, want := range []string{"sx_session=", "HttpOnly", "Secure", "SameSite=Strict", "Path=/"} {
		if !strings.Contains(sc, want) {
			t.Fatalf("cookie %q missing %q", sc, want)
		}
	}
	if resp.Header.Get("Content-Security-Policy") != "default-src 'self'; img-src 'self' blob: data:; media-src 'self' blob:; frame-ancestors 'none'" ||
		resp.Header.Get("X-Content-Type-Options") != "nosniff" || resp.Header.Get("Referrer-Policy") != "no-referrer" ||
		resp.Header.Get("Strict-Transport-Security") != "max-age=31536000" {
		t.Fatal("security headers", resp.Header)
	}
	resp, body = e.do(t, "GET", "/api/me", nil)
	var me map[string]any
	json.Unmarshal(body, &me)
	if resp.StatusCode != 200 || me["id"] != u.ID.String() || me["email"] != "a@x.com" || me["totp_enabled"] != false {
		t.Fatal(resp.StatusCode, string(body))
	}

	// disabled users lose access on their existing session (R10)
	e.pool.Exec(context.Background(), `UPDATE users SET disabled=true WHERE id=$1`, u.ID)
	if resp, _ := e.do(t, "GET", "/api/me", nil); resp.StatusCode != 401 {
		t.Fatal("disabled user allowed", resp.StatusCode)
	}
	e.pool.Exec(context.Background(), `UPDATE users SET disabled=false WHERE id=$1`, u.ID)

	if resp, _ := e.do(t, "POST", "/api/auth/logout", nil); resp.StatusCode != 204 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := e.do(t, "GET", "/api/me", nil); resp.StatusCode != 401 {
		t.Fatal("session survived logout", resp.StatusCode)
	}
}

func otpSecret(t *testing.T, otpauth string) string {
	t.Helper()
	p, err := url.Parse(otpauth)
	if err != nil {
		t.Fatal(err)
	}
	return p.Query().Get("secret")
}

func TestLoginWithTOTP(t *testing.T) {
	e := newEnv(t)
	e.user(t, "t@x.com")
	// enrol through the API
	e.login(t, "t@x.com", pw)
	resp, body := e.do(t, "POST", "/api/me/totp/setup", nil)
	var setup struct {
		OtpauthURL string `json:"otpauth_url"`
	}
	json.Unmarshal(body, &setup)
	if resp.StatusCode != 200 || setup.OtpauthURL == "" {
		t.Fatal(resp.StatusCode, string(body))
	}
	secret := otpSecret(t, setup.OtpauthURL)
	if resp, _ := e.do(t, "POST", "/api/me/totp/enable", map[string]string{"code": "000000x"}); resp.StatusCode == 204 {
		t.Fatal("bad code enabled totp")
	}
	prev, _ := totp.GenerateCode(secret, time.Now().Add(-30*time.Second)) // previous step, so "now" stays usable
	if resp, body := e.do(t, "POST", "/api/me/totp/enable", map[string]string{"code": prev}); resp.StatusCode != 204 {
		t.Fatal(resp.StatusCode, string(body))
	}
	e.do(t, "POST", "/api/auth/logout", nil)

	resp, body = e.login(t, "t@x.com", pw)
	if resp.StatusCode != 200 || strings.TrimSpace(string(body)) != `{"mfa_required":true}` {
		t.Fatal(resp.StatusCode, string(body))
	}
	if resp, _ := e.do(t, "GET", "/api/me", nil); resp.StatusCode != 401 {
		t.Fatal("mfa-pending session allowed", resp.StatusCode)
	}
	if resp, _ := e.do(t, "POST", "/api/auth/totp", map[string]string{"code": "123456x"}); resp.StatusCode != 401 {
		t.Fatal("bad totp code", resp.StatusCode)
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	if resp, body := e.do(t, "POST", "/api/auth/totp", map[string]string{"code": code}); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode, string(body))
	}
	resp, body = e.do(t, "GET", "/api/me", nil)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"totp_enabled":true`) {
		t.Fatal(resp.StatusCode, string(body))
	}
}

func TestTOTPWithoutPendingSession(t *testing.T) {
	e := newEnv(t)
	if resp, _ := e.do(t, "POST", "/api/auth/totp", map[string]string{"code": "123456"}); resp.StatusCode != 401 {
		t.Fatal(resp.StatusCode)
	}
}

func TestLoginUniformFailure(t *testing.T) {
	e := newEnv(t)
	e.user(t, "u@x.com")
	e.user(t, "d@x.com")
	e.pool.Exec(context.Background(), `UPDATE users SET disabled=true WHERE email='d@x.com'`)
	r1, b1 := e.login(t, "nobody@x.com", pw)
	r2, b2 := e.login(t, "u@x.com", "wrong-password-1")
	r3, b3 := e.login(t, "d@x.com", pw)
	if r1.StatusCode != 401 || r2.StatusCode != 401 || r3.StatusCode != 401 ||
		!bytes.Equal(b1, b2) || !bytes.Equal(b1, b3) || strings.TrimSpace(string(b1)) != `{"error":"invalid_credentials"}` {
		t.Fatal(r1.StatusCode, r2.StatusCode, r3.StatusCode, string(b1), string(b2), string(b3))
	}
	if r1.Header.Get("Set-Cookie") != "" || r2.Header.Get("Set-Cookie") != "" || r3.Header.Get("Set-Cookie") != "" {
		t.Fatal("cookie set on failure")
	}
}

func TestLoginRateLimited(t *testing.T) {
	e := newEnv(t)
	e.user(t, "r@x.com")
	for i := 1; i <= 5; i++ {
		if resp, _ := e.login(t, "r@x.com", "wrong-password-1"); resp.StatusCode != 401 {
			t.Fatal(i, resp.StatusCode)
		}
	}
	if resp, _ := e.login(t, "R@x.com", pw); resp.StatusCode != 429 {
		t.Fatal("6th attempt", resp.StatusCode)
	}
	// another email from the same IP still works (IP budget is 10)
	if resp, _ := e.login(t, "other@x.com", pw); resp.StatusCode != 401 {
		t.Fatal(resp.StatusCode)
	}
}

func TestCrossOriginPostRejected(t *testing.T) {
	e := newEnv(t)
	e.user(t, "c@x.com")
	req, _ := http.NewRequest("POST", e.ts.URL+"/api/auth/login", strings.NewReader(`{"email":"c@x.com","password":"`+pw+`"}`))
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := e.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatal(resp.StatusCode)
	}
}

func TestClientIP(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	cases := []struct{ remote, xff, want string }{
		{"203.0.113.9:1234", "1.1.1.1", "203.0.113.9"},             // untrusted peer: XFF ignored
		{"10.0.0.1:1234", "1.1.1.1, 2.2.2.2, 10.0.0.5", "2.2.2.2"}, // rightmost non-trusted
		{"10.0.0.1:1234", "", "10.0.0.1"},
		{"10.0.0.1:1234", "10.0.0.7", "10.0.0.1"}, // all trusted
		{"[::ffff:10.0.0.1]:1234", "198.51.100.4", "198.51.100.4"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := ClientIP(r, trusted); got != c.want {
			t.Errorf("%s %q: got %s want %s", c.remote, c.xff, got, c.want)
		}
	}
}

func TestAuditOnLogin(t *testing.T) {
	e := newEnv(t)
	u := e.user(t, "au@x.com")
	e.login(t, "au@x.com", "wrong-password-1")
	e.login(t, "au@x.com", pw)
	ctx := context.Background()
	for _, act := range []string{audit.ActLoginFail, audit.ActLoginOK} {
		got, err := e.audit.List(ctx, audit.Filter{Action: act})
		if err != nil || len(got) != 1 {
			t.Fatalf("%s: %d %v", act, len(got), err)
		}
		if act == audit.ActLoginOK && got[0].Event.ActorID != u.ID.String() {
			t.Fatal(got[0].Event)
		}
	}
	if bad, err := e.audit.Verify(ctx); err != nil || bad != 0 {
		t.Fatal(bad, err)
	}
}

func TestAuditFieldsTruncated(t *testing.T) {
	e := newEnv(t)
	e.user(t, "tr@x.com")
	long := strings.Repeat("é", 1500) // 3000 bytes, multi-byte to exercise rune safety
	ua := strings.Repeat("u", 10<<10)
	post := func(body string) int {
		req, _ := http.NewRequest("POST", e.ts.URL+"/api/auth/login", strings.NewReader(body))
		req.Header.Set("User-Agent", ua)
		resp, err := e.c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := post(`{"email":"` + long + `@x.com","password":"x"}`); code != 401 {
		t.Fatal(code)
	}
	if code := post(`{"email":"` + strings.Repeat("a", 10<<10) + `","password":"x"}`); code != 400 {
		t.Fatal("oversized body", code)
	}
	if code := post(`{"email":"tr@x.com","password":"` + pw + `"}`); code != 200 {
		t.Fatal(code)
	}
	ctx := context.Background()
	got, err := e.audit.List(ctx, audit.Filter{Action: audit.ActLoginFail})
	if err != nil || len(got) != 1 {
		t.Fatal(len(got), err)
	}
	email, _ := got[0].Event.Detail["email"].(string)
	if n := len(got[0].Event.UserAgent); n == 0 || n > 512 {
		t.Fatal("audit user_agent bytes", n)
	}
	if len(email) == 0 || len(email) > 254 || !utf8.ValidString(email) {
		t.Fatal("audit email bytes", len(email))
	}
	var n int
	if err := e.pool.QueryRow(ctx, `SELECT max(octet_length(user_agent)) FROM sessions`).Scan(&n); err != nil || n == 0 || n > 512 {
		t.Fatal("session user_agent bytes", n, err)
	}
}

func TestUploadsRequireUser(t *testing.T) {
	e := newEnv(t)
	u := e.user(t, "a@x.com")
	if resp, _ := e.do(t, "HEAD", "/api/uploads/x", nil); resp.StatusCode != 401 {
		t.Fatal("anonymous upload access", resp.StatusCode)
	}
	e.login(t, "a@x.com", pw)
	if resp, body := e.do(t, "GET", "/api/uploads/x", nil); resp.StatusCode != 200 || string(body) != u.ID.String() {
		t.Fatal(resp.StatusCode, string(body))
	}
}

// An audit event must be stored even when the client already hung up.
func TestRecordSurvivesCanceledRequest(t *testing.T) {
	e := newEnv(t)
	s := &server{Deps: Deps{Audit: e.audit}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.record(httptest.NewRequest("DELETE", "/", nil).WithContext(ctx), audit.Event{Action: audit.ActDelete, Result: "ok"})
	if ents, err := e.audit.List(context.Background(), audit.Filter{Action: audit.ActDelete}); err != nil || len(ents) != 1 {
		t.Fatalf("audit: %v %d", err, len(ents))
	}
}
