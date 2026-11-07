package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/rules"
)

func (e *env) setRules(t *testing.T, mod func(*rules.Rules)) {
	t.Helper()
	ctx := context.Background()
	tx, err := e.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	r, err := e.deps.Rules.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mod(&r)
	if _, err := e.deps.Rules.Update(ctx, tx, r); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func banRules(r *rules.Rules) { r.ForbidDownload, r.ForceWatermark = true, true }

func wantBanned(t *testing.T, b []byte) {
	t.Helper()
	var m map[string]any
	json.Unmarshal(b, &m)
	if m["allow_download"] != false || m["watermark"] != true || m["download_forbidden"] != true {
		t.Fatal(string(b))
	}
	// test files have no preview row, so they are unsupported: the UI shows "blocked by admin"
	if fs, _ := m["files"].([]any); len(fs) == 0 || fs[0].(map[string]any)["previewable"] != false {
		t.Fatal("previewable:", string(b))
	}
}

func TestBanAppliesToExistingShare(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "a@x.com")
	f := e.putFile(t, a.ID, "doc", []byte("x"))
	e.login(t, "a@x.com", pw)
	_, tok := e.recipShare(t, true, []uuid.UUID{f}, "r@y.com")
	e.setRules(t, banRules)
	e.recipVerify(t, tok, "r@y.com")
	_, b := e.get(t, "/api/s/"+tok+"/files")
	wantBanned(t, b)
	resp, b := e.get(t, "/api/s/"+tok+"/files/"+f.String()+"/content")
	if resp.StatusCode != 403 || string(b) != `{"error":"view_only"}`+"\n" {
		t.Fatal(resp.StatusCode, string(b))
	}
}

func TestBanAppliesToVendorShare(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "a@x.com")
	f := e.putFile(t, a.ID, "doc", []byte("x"))
	sec := e.mkVendor(t, "v@vendor.com")
	e.loginAs(t, "a@x.com", "")
	resp, b := e.do(t, "POST", "/api/shares", map[string]any{"file_ids": []uuid.UUID{f}, "vendor_ids": []uuid.UUID{e.vendorID(t, "v@vendor.com")},
		"allow_download": true, "expires_at": time.Now().Add(48 * time.Hour).Format(time.RFC3339)})
	var sh struct{ ID string }
	json.Unmarshal(b, &sh)
	if resp.StatusCode != 201 {
		t.Fatal(resp.StatusCode, string(b))
	}
	e.setRules(t, banRules)
	e.loginAs(t, "v@vendor.com", sec)
	_, b = e.get(t, "/api/vendor/shares/"+sh.ID)
	wantBanned(t, b)
	resp, b = e.get(t, "/api/vendor/shares/"+sh.ID+"/files/"+f.String()+"/content")
	if resp.StatusCode != 403 || string(b) != `{"error":"view_only"}`+"\n" {
		t.Fatal(resp.StatusCode, string(b))
	}
}

func TestDomainBlockedAfterShare(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "a@x.com")
	f := e.putFile(t, a.ID, "doc", []byte("x"))
	sec := e.mkVendor(t, "v@evil.com")
	e.loginAs(t, "a@x.com", "")
	_, tok := e.recipShare(t, true, []uuid.UUID{f}, "r@evil.com")
	_, b := e.do(t, "POST", "/api/shares", map[string]any{"file_ids": []uuid.UUID{f}, "vendor_ids": []uuid.UUID{e.vendorID(t, "v@evil.com")},
		"allow_download": true, "expires_at": time.Now().Add(48 * time.Hour).Format(time.RFC3339)})
	var sh struct{ ID string }
	json.Unmarshal(b, &sh)
	e.setRules(t, func(r *rules.Rules) { r.DomainBlock = []string{"evil.com"} })

	// the code is still mailed (same answer); verify then refuses with the reason
	if resp, b := e.do(t, "POST", "/api/s/"+tok+"/code", map[string]string{"email": "r@evil.com"}); resp.StatusCode != 200 || string(b) != `{"sent":true}`+"\n" {
		t.Fatal(resp.StatusCode, string(b))
	}
	code := otpRE.FindStringSubmatch(e.lastMail(t, "r@evil.com").Body)[1]
	if resp, b := e.do(t, "POST", "/api/s/"+tok+"/verify", map[string]string{"email": "r@evil.com", "code": "000000"}); resp.StatusCode != 401 || string(b) != `{"error":"invalid_code"}`+"\n" {
		t.Fatal(resp.StatusCode, string(b))
	}
	resp, b := e.do(t, "POST", "/api/s/"+tok+"/verify", map[string]string{"email": "r@evil.com", "code": code})
	if resp.StatusCode != 403 || string(b) != `{"error":"domain_blocked"}`+"\n" {
		t.Fatal(resp.StatusCode, string(b))
	}
	wantReasons(t, e, audit.ActShareOTPVerify, "reason", "domain_blocked", "invalid_code")
	e.loginAs(t, "v@evil.com", sec)
	resp, b = e.get(t, "/api/vendor/shares/"+sh.ID)
	if resp.StatusCode != 403 || string(b) != `{"error":"domain_blocked"}`+"\n" {
		t.Fatal(resp.StatusCode, string(b))
	}
}

func TestExternalIPAllow(t *testing.T) {
	e := newEnv(t, func(d *Deps) { d.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")} })
	a := e.user(t, "a@x.com")
	f := e.putFile(t, a.ID, "doc", []byte("x"))
	e.mkVendor(t, "v@vendor.com")
	e.login(t, "a@x.com", pw)
	_, tok := e.recipShare(t, true, []uuid.UUID{f}, "r@y.com")
	e.setRules(t, func(r *rules.Rules) { r.ExternalIPAllow = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")} })
	out := []string{"X-Forwarded-For", "192.168.1.1"}
	for _, p := range []string{"/api/s/" + tok, "/api/r/" + tok, "/api/invite/" + tok, "/api/vendor/shares"} {
		if resp, b := e.get(t, p, out...); resp.StatusCode != 403 || string(b) != `{"error":"ip_denied"}`+"\n" {
			t.Fatal(p, resp.StatusCode, string(b))
		}
	}
	// vendor login from outside; the vendor password is right, so only the IP rule can refuse it
	req := func(ip string) int {
		body, _ := json.Marshal(map[string]string{"email": "v@vendor.com", "password": pw})
		rq, _ := newReq(e.ts.URL+"/api/auth/login", body, ip)
		resp, err := e.c.Do(rq)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := req("192.168.1.1"); c != 401 {
		t.Fatal(c)
	}
	wantReasons(t, e, audit.ActLoginFail, "stage", "ip_denied")
	if c := req("10.1.1.1"); c == 401 {
		t.Fatal("allowed vendor IP denied")
	}
	body, _ := json.Marshal(map[string]string{"email": "a@x.com", "password": pw})
	if rq, _ := newReq(e.ts.URL+"/api/auth/login", body, "192.168.1.1"); true {
		resp, err := e.c.Do(rq)
		if err != nil || resp.StatusCode != 200 {
			t.Fatal(err, resp)
		}
		resp.Body.Close()
	}
	if resp, _ := e.get(t, "/api/files", out...); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	if resp, b := e.get(t, "/api/s/"+tok, "X-Forwarded-For", "10.1.1.1"); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode, string(b))
	}
}

func newReq(url string, body []byte, xff string) (*http.Request, error) {
	rq, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err == nil {
		rq.Header.Set("X-Forwarded-For", xff)
	}
	return rq, err
}

// wantReasons asserts the failure events of action carry exactly these values for key (any order).
func wantReasons(t *testing.T, e *env, action, key string, want ...string) {
	t.Helper()
	ents, _, err := e.audit.List(context.Background(), audit.Filter{ActionPrefix: action, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, en := range ents {
		if en.Event.Result == "fail" {
			if v, _ := en.Event.Detail[key].(string); v != "" {
				got[v]++
			}
		}
	}
	for _, w := range want {
		if got[w] != 1 {
			t.Fatalf("%s: want one %q, got %v", action, w, got)
		}
	}
}

func TestVendorIPDeniedSameAsBadPassword(t *testing.T) {
	e := newEnv(t, func(d *Deps) { d.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")} })
	e.mkVendor(t, "v@vendor.com")
	e.setRules(t, func(r *rules.Rules) { r.ExternalIPAllow = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")} })
	post := func(password string) (int, string) {
		body, _ := json.Marshal(map[string]string{"email": "v@vendor.com", "password": password})
		rq, _ := newReq(e.ts.URL+"/api/auth/login", body, "192.168.1.1")
		resp, err := e.c.Do(rq)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	cGood, bGood := post(pw)
	cBad, bBad := post("wrong-password-123")
	if cGood != 401 || cGood != cBad || bGood != bBad || bGood != `{"error":"invalid_credentials"}`+"\n" {
		t.Fatal(cGood, bGood, cBad, bBad)
	}
	wantReasons(t, e, audit.ActLoginFail, "reason", "ip_denied")
}
