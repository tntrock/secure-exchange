package httpapi

import (
	"context"
	"encoding/json"
	"regexp"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/mail"
	"github.com/tntrock/secure-exchange/internal/mail/mailtest"
	"github.com/tntrock/secure-exchange/internal/vendor"
)

type vendorJSON struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	DisplayName   string `json:"display_name"`
	Org           string `json:"org"`
	Status        string `json:"status"`
	ExpiresAt     string `json:"expires_at"`
	CreatedByName string `json:"created_by_name"`
	CreatedAt     string `json:"created_at"`
	CanManage     bool   `json:"can_manage"`
}

func (e *env) vendors(t *testing.T, query string) []vendorJSON {
	t.Helper()
	resp, b := e.do(t, "GET", "/api/vendors"+query, nil)
	var out []vendorJSON
	if resp.StatusCode != 200 || json.Unmarshal(b, &out) != nil {
		t.Fatal(resp.StatusCode, string(b))
	}
	return out
}

var inviteLinkRE = regexp.MustCompile(`https://x\.example/invite/([A-Za-z0-9_-]{43})`)

func (e *env) inviteToken(t *testing.T, email string) string {
	t.Helper()
	tok := ""
	for _, m := range mailtest.Messages(t, e.pool, e.keys) {
		if r := inviteLinkRE.FindStringSubmatch(m.Body); m.To == email && r != nil {
			tok = r[1]
		}
	}
	if tok == "" {
		t.Fatal("no invitation for", email)
	}
	return tok
}

func TestVendorRoutes(t *testing.T) {
	e := newEnv(t) // approval mode
	ctx := context.Background()
	e.user(t, "s1@x.com")
	e.user(t, "s2@x.com")
	if _, err := e.users.Create(ctx, "adm@x.com", "A", "admin", pw); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().AddDate(0, 0, 30).UTC().Format(time.RFC3339)
	body := func(email string) map[string]any {
		return map[string]any{"email": email, "display_name": "Vic", "org": "ACME", "expires_at": exp}
	}

	e.loginAs(t, "s1@x.com", "")
	if resp, b := e.do(t, "POST", "/api/vendors", map[string]any{"email": "bad", "display_name": "V", "expires_at": exp}); resp.StatusCode != 422 ||
		string(b) != "{\"code\":\"invalid\",\"error\":\"validation\",\"field\":\"email\"}\n" {
		t.Fatal(resp.StatusCode, string(b))
	}
	if resp, b := e.do(t, "POST", "/api/vendors", "x"); resp.StatusCode != 400 {
		t.Fatal(resp.StatusCode, string(b))
	}
	resp, b := e.do(t, "POST", "/api/vendors", body("v@v.com"))
	var v vendorJSON
	if json.Unmarshal(b, &v); resp.StatusCode != 201 || v.Status != "pending" || !v.CanManage || v.Org != "ACME" || v.Email != "v@v.com" ||
		v.CreatedByName != "D" || v.ExpiresAt != exp || v.CreatedAt == "" {
		t.Fatal(resp.StatusCode, string(b))
	}
	if resp, b := e.do(t, "POST", "/api/vendors", body("V@v.com")); resp.StatusCode != 409 || string(b) != "{\"error\":\"email_taken\"}\n" {
		t.Fatal(resp.StatusCode, string(b))
	}
	if vs := e.vendors(t, ""); len(vs) != 1 || vs[0].ID != v.ID {
		t.Fatal(vs)
	}
	resp, b = e.do(t, "POST", "/api/vendors", body("r@v.com"))
	var rv vendorJSON
	if json.Unmarshal(b, &rv); resp.StatusCode != 201 || rv.ID == "" {
		t.Fatal(resp.StatusCode, string(b))
	}

	// another staff member sees the vendor but cannot manage it
	e.loginAs(t, "s2@x.com", "")
	if vs := e.vendors(t, ""); len(vs) != 2 || vs[0].ID != rv.ID || vs[0].CanManage || vs[1].CanManage {
		t.Fatal(vs)
	}
	for _, rt := range []struct{ method, path string }{
		{"POST", "/disable"}, {"POST", "/enable"}, {"POST", "/reinvite"}, {"PATCH", ""}, {"POST", "/approve"},
	} {
		if resp, b := e.do(t, rt.method, "/api/vendors/"+v.ID+rt.path, map[string]any{"expires_at": exp}); resp.StatusCode != 403 || string(b) != forbiddenBody {
			t.Errorf("%s %s: %d %s", rt.method, rt.path, resp.StatusCode, b)
		}
	}

	e.loginAs(t, "adm@x.com", "")
	if vs := e.vendors(t, ""); !vs[0].CanManage || !vs[1].CanManage {
		t.Fatal(vs)
	}
	for _, c := range []struct {
		path string
		want int
	}{{"/" + v.ID + "/approve", 204}, {"/" + rv.ID + "/reject", 204}, {"/" + v.ID + "/reject", 409}, {"/nope/approve", 404}} {
		path, want := c.path, c.want
		if resp, b := e.do(t, "POST", "/api/vendors"+path, nil); resp.StatusCode != want {
			t.Errorf("%s: %d %s", path, resp.StatusCode, b)
		}
	}
	if vs := e.vendors(t, "?active=1"); len(vs) != 0 {
		t.Fatal("invited vendor listed as active", vs)
	}

	e.loginAs(t, "s1@x.com", "")
	later := time.Now().AddDate(0, 0, 60).UTC().Format(time.RFC3339)
	for _, c := range []struct {
		method, path string
		body         any
		want         int
	}{
		{"POST", "/reinvite", nil, 204},
		{"PATCH", "", map[string]any{"expires_at": later}, 204},
		{"PATCH", "", map[string]any{"expires_at": time.Now().UTC().Format(time.RFC3339)}, 422},
		{"PATCH", "", "x", 400},
		{"POST", "/disable", nil, 204},
		{"POST", "/reinvite", nil, 409},
		{"POST", "/enable", nil, 204},
	} {
		if resp, b := e.do(t, c.method, "/api/vendors/"+v.ID+c.path, c.body); resp.StatusCode != c.want {
			t.Errorf("%s %s: %d %s", c.method, c.path, resp.StatusCode, b)
		}
	}
	if vs := e.vendors(t, ""); vs[1].ExpiresAt != later || vs[0].Status != "rejected" {
		t.Fatal(vs)
	}

	// invitation landing and activation: no login needed
	tok := e.inviteToken(t, "v@v.com")
	resp, b = e.do(t, "GET", "/api/invite/"+tok, nil)
	var info struct {
		Email      string `json:"email"`
		OTPAuthURL string `json:"otpauth_url"`
	}
	if json.Unmarshal(b, &info); resp.StatusCode != 200 || info.Email != "v@v.com" || info.OTPAuthURL == "" {
		t.Fatal(resp.StatusCode, string(b))
	}
	secret := otpSecret(t, info.OTPAuthURL)
	wrong, _ := totp.GenerateCode(secret, time.Now().Add(10*time.Minute))
	good, _ := totp.GenerateCode(secret, time.Now())
	for _, c := range []struct {
		body any
		want int
		resp string
	}{
		{map[string]string{"password": "short", "code": good}, 422, "{\"code\":\"too_short\",\"error\":\"validation\",\"field\":\"password\"}\n"},
		{map[string]string{"password": pw, "code": wrong}, 401, "{\"error\":\"invalid_code\"}\n"},
		{"x", 400, "{\"error\":\"bad_request\"}\n"},
		{map[string]string{"password": pw, "code": good}, 204, ""},
		{map[string]string{"password": pw, "code": good}, 410, "{\"error\":\"gone\"}\n"},
	} {
		if resp, b := e.do(t, "POST", "/api/invite/"+tok, c.body); resp.StatusCode != c.want || string(b) != c.resp {
			t.Errorf("activate %v: %d %s", c.body, resp.StatusCode, b)
		}
	}
	if resp, b := e.do(t, "GET", "/api/invite/"+tok, nil); resp.StatusCode != 410 {
		t.Fatal(resp.StatusCode, string(b))
	}
	if vs := e.vendors(t, "?active=1"); len(vs) != 1 || vs[0].ID != v.ID || vs[0].Status != "active" {
		t.Fatal(vs)
	}

	// the activated vendor can sign in
	next, _ := totp.GenerateCode(secret, time.Now().Add(30*time.Second))
	e.loginAs(t, "v@v.com", "")
	if resp, b := e.do(t, "POST", "/api/auth/totp", map[string]string{"code": next}); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode, string(b))
	}

	for action, want := range map[string]struct {
		n     int
		actor string
	}{
		audit.ActVendorCreate: {2, "user"}, audit.ActVendorApprove: {1, "user"}, audit.ActVendorReject: {1, "user"},
		audit.ActVendorReinvite: {1, "user"}, audit.ActVendorExpiry: {1, "user"}, audit.ActVendorDisable: {1, "user"},
		audit.ActVendorEnable: {1, "user"}, audit.ActVendorActivate: {2, "vendor"},
	} {
		got, _, err := e.audit.List(ctx, audit.Filter{ActionPrefix: action})
		if err != nil || len(got) != want.n || got[0].Event.ActorType != want.actor || got[0].Event.TargetType != "user" {
			t.Errorf("%s: %+v %v", action, got, err)
		}
	}
	ok, _, _ := e.audit.List(ctx, audit.Filter{ActionPrefix: audit.ActVendorActivate})
	results := map[string]bool{}
	for _, a := range ok {
		results[a.Event.Result] = true
		if a.Event.ActorID != v.ID || a.Event.TargetID != v.ID {
			t.Error("activate actor/target", a.Event)
		}
	}
	if !results["ok"] || !results["fail"] {
		t.Error("activate results", results)
	}
}

func TestVendorCreateAdminMode(t *testing.T) {
	e := newEnv(t, func(d *Deps) {
		d.Vendors = vendor.NewService(d.Pool, d.Users, d.Sessions, mail.NewOutbox(d.Pool, d.Keys, nil), "https://x.example", "admin", d.Rules)
	})
	e.user(t, "s@x.com")
	e.loginAs(t, "s@x.com", "")
	resp, b := e.do(t, "POST", "/api/vendors", map[string]any{"email": "v@v.com", "display_name": "V",
		"expires_at": time.Now().AddDate(0, 0, 30).UTC().Format(time.RFC3339)})
	if resp.StatusCode != 403 || string(b) != forbiddenBody {
		t.Fatal(resp.StatusCode, string(b))
	}
}
