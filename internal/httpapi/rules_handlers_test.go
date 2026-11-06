package httpapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/mail/mailtest"
)

func (e *env) putRules(t *testing.T, mod func(map[string]any)) (int, map[string]any) {
	t.Helper()
	resp, b := e.do(t, "GET", "/api/rules", nil)
	m := map[string]any{}
	if err := json.Unmarshal(b, &m); err != nil || resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode, string(b))
	}
	mod(m)
	resp, b = e.do(t, "PUT", "/api/admin/rules", m)
	out := map[string]any{}
	json.Unmarshal(b, &out)
	return resp.StatusCode, out
}

func TestRulesAccess(t *testing.T) {
	e := newEnv(t)
	e.user(t, "a@x.com")
	e.login(t, "a@x.com", pw)
	if resp, b := e.do(t, "GET", "/api/rules", nil); resp.StatusCode != 200 || !strings.Contains(string(b), "share_max_days") {
		t.Fatal(resp.StatusCode, string(b))
	}
	if resp, _ := e.do(t, "PUT", "/api/admin/rules", map[string]any{}); resp.StatusCode != 403 {
		t.Fatal(resp.StatusCode)
	}
}

func TestRulesInvalid(t *testing.T) {
	e := newEnv(t)
	e.adminLogin(t)
	code, out := e.putRules(t, func(m map[string]any) { m["share_max_days"] = 0 })
	if code != 422 || out["field"] != "share_max_days" || out["code"] != "out_of_range" {
		t.Fatal(code, out)
	}
}

func TestRulesTighteningDigest(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a := e.user(t, "a@x.com")
	b := e.user(t, "b@x.com")
	fa := e.putFile(t, a.ID, "a.txt", []byte("x"))
	fb := e.putFile(t, b.ID, "b.txt", []byte("y"))
	e.login(t, "a@x.com", pw)
	e.mkShare(t, []string{fa.String()}, "r@y.com")
	e.mkShare(t, []string{fa.String()}, "r@y.com")
	old := e.mkShare(t, []string{fa.String()}, "r@y.com")
	e.do(t, "POST", "/api/shares/"+old["id"].(string)+"/revoke", nil)
	e.login(t, "b@x.com", pw)
	sb := e.mkShare(t, []string{fb.String()}, "r@y.com")
	if _, err := e.pool.Exec(ctx, `UPDATE shares SET watermark=false, allow_download=false WHERE id=$1`, sb["id"]); err != nil {
		t.Fatal(err)
	}
	e.adminLogin(t)
	code, out := e.putRules(t, func(m map[string]any) { m["forbid_download"], m["force_watermark"] = true, true })
	if code != 200 || out["affected_shares"] != float64(3) {
		t.Fatal(code, out)
	}
	if out["rules"].(map[string]any)["forbid_download"] != true {
		t.Fatal(out)
	}
	n := map[string]int{}
	for _, m := range mailtest.Messages(t, e.pool, e.keys) {
		if strings.Contains(m.Subject, "規則") || strings.Contains(m.Subject, "rules") {
			n[m.To]++
			if m.To == "a@x.com" && strings.Count(m.Body, "https://x.example/shares/") != 4 { // 2 lines, zh + en
				t.Fatal(m.Body)
			}
		}
	}
	if len(n) != 2 || n["a@x.com"] != 1 || n["b@x.com"] != 1 {
		t.Fatal(n)
	}
	ents, _ := e.audit.List(ctx, audit.Filter{Action: audit.ActRulesUpdate})
	if len(ents) != 1 {
		t.Fatal(ents)
	}
	d := ents[0].Event.Detail
	if d["before"].(map[string]any)["forbid_download"] != false || d["after"].(map[string]any)["forbid_download"] != true {
		t.Fatal(d)
	}
	before := len(mailtest.Messages(t, e.pool, e.keys))
	code, out = e.putRules(t, func(m map[string]any) {})
	if code != 200 || out["affected_shares"] != float64(0) {
		t.Fatal(code, out)
	}
	if got := len(mailtest.Messages(t, e.pool, e.keys)); got != before {
		t.Fatal(got)
	}
}

func TestRulesDomainDigest(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "a@x.com")
	f := e.putFile(t, a.ID, "a.txt", []byte("x"))
	e.mkVendor(t, "v@y.com")
	vid := e.vendorID(t, "v@y.com")
	e.login(t, "a@x.com", pw)
	ids := []string{f.String()}
	s1 := e.mkShare(t, ids, "r@y.com")
	s2 := e.mkShare(t, ids, "gone@y.com", "z@z.com")
	e.mkShare(t, ids, "z@z.com")
	resp, b := e.do(t, "POST", "/api/shares", map[string]any{"file_ids": ids, "vendor_ids": []any{vid}, "allow_download": true,
		"expires_at": time.Now().Add(48 * time.Hour).Format(time.RFC3339)})
	var s3 struct{ ID string }
	if json.Unmarshal(b, &s3); resp.StatusCode != 201 {
		t.Fatal(resp.StatusCode, string(b))
	}
	for _, r := range s2["recipients"].([]any) {
		if m := r.(map[string]any); m["email"] == "gone@y.com" {
			if resp, b := e.do(t, "POST", "/api/shares/"+s2["id"].(string)+"/recipients/"+m["id"].(string)+"/revoke", nil); resp.StatusCode != 200 && resp.StatusCode != 204 {
				t.Fatal(resp.StatusCode, string(b))
			}
		}
	}
	e.adminLogin(t)
	code, out := e.putRules(t, func(m map[string]any) { m["domain_block"] = []string{"y.com"} })
	if code != 200 || out["affected_shares"] != float64(2) {
		t.Fatal(code, out)
	}
	msgs := mailtest.Messages(t, e.pool, e.keys)
	var body string
	for _, m := range msgs {
		if m.To == "a@x.com" && strings.Contains(m.Subject, "rules") {
			body = m.Body
		}
	}
	if body == "" || !strings.Contains(body, s1["id"].(string)+" — 收件人網域") || !strings.Contains(body, s3.ID+" — 收件人網域") || strings.Contains(body, s2["id"].(string)) {
		t.Fatal(body)
	}
}
