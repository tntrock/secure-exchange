package httpapi

import (
	"context"
	"encoding/json"
	"net/http/cookiejar"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/tntrock/secure-exchange/internal/audit"
)

// mkVendor creates an active vendor (password, TOTP enabled, approved, expiring in 30 days) and returns its TOTP secret.
func (e *env) mkVendor(t *testing.T, email string) (secret string) {
	t.Helper()
	ctx := context.Background()
	u, err := e.users.Create(ctx, email, "V", "vendor", pw)
	if err != nil {
		t.Fatal(err)
	}
	url, err := e.users.BeginTOTP(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	secret = otpSecret(t, url)
	prev, _ := totp.GenerateCode(secret, time.Now().Add(-30*time.Second))
	if err := e.users.EnableTOTP(ctx, u.ID, prev); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.Exec(ctx, `UPDATE users SET expires_at = now() + interval '30 days' WHERE id=$1`, u.ID); err != nil {
		t.Fatal(err)
	}
	return secret
}

// loginAs logs in on a fresh cookie jar, adding the TOTP step when secret is set.
func (e *env) loginAs(t *testing.T, email, secret string) {
	t.Helper()
	e.c.Jar, _ = cookiejar.New(nil)
	if resp, b := e.login(t, email, pw); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode, string(b))
	}
	if secret == "" {
		return
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	if resp, b := e.do(t, "POST", "/api/auth/totp", map[string]string{"code": code}); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode, string(b))
	}
}

const forbiddenBody = "{\"error\":\"forbidden\"}\n"

func TestRoleGates(t *testing.T) {
	e := newEnv(t)
	e.user(t, "staff@x.com")
	if _, err := e.users.Create(context.Background(), "adm@x.com", "A", "admin", pw); err != nil {
		t.Fatal(err)
	}
	vsecret := e.mkVendor(t, "v@x.com")

	const zero = "00000000-0000-0000-0000-000000000000"
	// forbidden lists the roles that must get 403. Tasks 2-4 append their /api/vendor/... rows (staff and admin: 403).
	routes := []struct {
		method, path string
		forbidden    []string
	}{
		{"GET", "/api/files", []string{"vendor"}},
		{"GET", "/api/files/" + zero + "/content", []string{"vendor"}},
		{"DELETE", "/api/files/" + zero, []string{"vendor"}},
		{"POST", "/api/shares", []string{"vendor"}},
		{"GET", "/api/shares", []string{"vendor"}},
		{"GET", "/api/shares/" + zero, []string{"vendor"}},
		{"POST", "/api/shares/" + zero + "/revoke", []string{"vendor"}},
		{"POST", "/api/shares/" + zero + "/recipients", []string{"vendor"}},
		{"POST", "/api/shares/" + zero + "/recipients/" + zero + "/revoke", []string{"vendor"}},
		{"POST", "/api/requests", []string{"vendor"}},
		{"GET", "/api/requests", []string{"vendor"}},
		{"GET", "/api/requests/" + zero, []string{"vendor"}},
		{"POST", "/api/requests/" + zero + "/revoke", []string{"vendor"}},
		{"GET", "/api/uploads/", []string{"vendor"}},
		{"POST", "/api/admin/trace", []string{"vendor", "staff"}},
		{"GET", "/api/vendors", []string{"vendor"}},
		{"POST", "/api/vendors", []string{"vendor"}},
		{"POST", "/api/vendors/" + zero + "/approve", []string{"vendor", "staff"}},
		{"POST", "/api/vendors/" + zero + "/reject", []string{"vendor", "staff"}},
		{"POST", "/api/vendors/" + zero + "/disable", []string{"vendor"}},
		{"POST", "/api/vendors/" + zero + "/enable", []string{"vendor"}},
		{"POST", "/api/vendors/" + zero + "/reinvite", []string{"vendor"}},
		{"PATCH", "/api/vendors/" + zero, []string{"vendor"}},
		{"GET", "/api/files/" + zero + "/preview", []string{"vendor"}},
		{"GET", "/api/files/" + zero + "/preview/pages/0", []string{"vendor"}},
		{"GET", "/api/files/" + zero + "/preview/video.m3u8", []string{"vendor"}},
		{"GET", "/api/files/" + zero + "/preview/segments/0.ts", []string{"vendor"}},
		{"GET", "/api/vendor/shares", []string{"staff", "admin"}},
		{"GET", "/api/vendor/shares/" + zero, []string{"staff", "admin"}},
		{"GET", "/api/vendor/shares/" + zero + "/files/" + zero + "/content", []string{"staff", "admin"}},
		{"GET", "/api/vendor/shares/" + zero + "/files/" + zero + "/preview", []string{"staff", "admin"}},
		{"GET", "/api/vendor/shares/" + zero + "/files/" + zero + "/preview/pages/0", []string{"staff", "admin"}},
		{"GET", "/api/vendor/shares/" + zero + "/files/" + zero + "/preview/video.m3u8", []string{"staff", "admin"}},
		{"GET", "/api/vendor/shares/" + zero + "/files/" + zero + "/preview/segments/0.ts", []string{"staff", "admin"}},
		{"GET", "/api/vendor/recipients", []string{"staff", "admin"}},
		{"GET", "/api/vendor/uploads", []string{"staff", "admin"}},
		{"POST", "/api/vendor/uploads/", []string{"staff", "admin"}},
	}
	logins := []struct{ role, email, secret string }{
		{"staff", "staff@x.com", ""}, {"admin", "adm@x.com", ""}, {"vendor", "v@x.com", vsecret},
	}
	for _, l := range logins {
		t.Run(l.role, func(t *testing.T) {
			e.loginAs(t, l.email, l.secret)
			resp, b := e.do(t, "GET", "/api/me", nil)
			var me struct{ Role string }
			json.Unmarshal(b, &me)
			if resp.StatusCode != 200 || me.Role != l.role {
				t.Fatal("/api/me", resp.StatusCode, string(b))
			}
			for _, rt := range routes {
				want403 := false
				for _, f := range rt.forbidden {
					want403 = want403 || f == l.role
				}
				resp, b := e.do(t, rt.method, rt.path, map[string]any{})
				if want403 && (resp.StatusCode != 403 || string(b) != forbiddenBody) {
					t.Errorf("%s %s: got %d %s, want 403 forbidden", rt.method, rt.path, resp.StatusCode, b)
				}
				if !want403 && (resp.StatusCode == 401 || resp.StatusCode == 403) {
					t.Errorf("%s %s: got %d, want access", rt.method, rt.path, resp.StatusCode)
				}
			}
		})
	}
}

func TestVendorExpiredSessionRejected(t *testing.T) {
	e := newEnv(t)
	secret := e.mkVendor(t, "v@x.com")
	e.loginAs(t, "v@x.com", secret)
	if resp, _ := e.do(t, "GET", "/api/me", nil); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	if _, err := e.pool.Exec(context.Background(), `UPDATE users SET expires_at = now() - interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	if resp, _ := e.do(t, "GET", "/api/me", nil); resp.StatusCode != 401 {
		t.Fatal("expired vendor still has a session", resp.StatusCode)
	}
}

func TestLoginRejectsInactiveVendor(t *testing.T) {
	for name, set := range map[string]string{
		"pending":  `approval='pending'`,
		"rejected": `approval='rejected'`,
		"expired":  `expires_at = now() - interval '1 second'`,
		"no totp":  `totp_enabled=false`,
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.mkVendor(t, "v@x.com")
			if _, err := e.pool.Exec(context.Background(), `UPDATE users SET `+set); err != nil {
				t.Fatal(err)
			}
			resp, b := e.login(t, "v@x.com", pw)
			if resp.StatusCode != 401 || string(b) != "{\"error\":\"invalid_credentials\"}\n" {
				t.Fatal(resp.StatusCode, string(b))
			}
			got, err := e.audit.List(context.Background(), audit.Filter{Action: audit.ActLoginFail})
			if err != nil || len(got) != 1 || got[0].Event.Detail["stage"] != "inactive" {
				t.Fatal(got, err)
			}
		})
	}
}

func TestLogoutWorksBeforeTOTP(t *testing.T) {
	e := newEnv(t)
	e.mkVendor(t, "v@x.com")
	if resp, b := e.login(t, "v@x.com", pw); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode, string(b))
	}
	count := func() (n int) {
		e.pool.QueryRow(context.Background(), `SELECT count(*) FROM sessions`).Scan(&n)
		return
	}
	if count() != 1 {
		t.Fatal("expected one pending session")
	}
	resp, _ := e.do(t, "POST", "/api/auth/logout", nil)
	cleared := false
	for _, c := range resp.Cookies() {
		cleared = cleared || (c.Name == cookieName && c.MaxAge < 0)
	}
	if resp.StatusCode != 204 || !cleared || count() != 0 {
		t.Fatal(resp.StatusCode, cleared, count())
	}
}
