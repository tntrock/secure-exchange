package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/preview"
	"github.com/tntrock/secure-exchange/internal/rules"
)

func (e *env) vendorID(t *testing.T, email string) uuid.UUID {
	t.Helper()
	u, err := e.users.ByEmail(context.Background(), email)
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

func TestVendorShareFlow(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "a@x.com")
	plain := []byte("vendor contents")
	f := e.putFile(t, a.ID, "doc.txt", plain)
	g := e.putFile(t, a.ID, "doc.pdf", []byte("x"))
	e.seedPreview(t, g, preview.KindPages, preview.StatusReady, 1)
	s1, s2 := e.mkVendor(t, "v1@vendor.com"), e.mkVendor(t, "v2@vendor.com")
	v1, v2 := e.vendorID(t, "v1@vendor.com"), e.vendorID(t, "v2@vendor.com")
	// as switches to email's session, logging in once (a TOTP code cannot be replayed)
	jars := map[string]http.CookieJar{}
	as := func(t *testing.T, email, secret string) {
		if jars[email] == nil {
			e.loginAs(t, email, secret)
			jars[email] = e.c.Jar
		}
		e.c.Jar = jars[email]
	}

	as(t, "a@x.com", "")
	resp, b := e.do(t, "POST", "/api/shares", map[string]any{"file_ids": []uuid.UUID{f, g}, "vendor_ids": []uuid.UUID{v1}, "allow_download": true,
		"expires_at": time.Now().Add(48 * time.Hour).Format(time.RFC3339), "message": "hi"})
	var created struct {
		ID         string
		Recipients []struct {
			Email  string
			Vendor bool
		}
	}
	json.Unmarshal(b, &created)
	if resp.StatusCode != 201 || len(created.Recipients) != 1 || !created.Recipients[0].Vendor || created.Recipients[0].Email != "v1@vendor.com" {
		t.Fatal(resp.StatusCode, string(b))
	}
	id := created.ID
	if resp, _ := e.get(t, "/api/vendor/shares"); resp.StatusCode != 403 {
		t.Fatal("staff on vendor list", resp.StatusCode)
	}

	as(t, "v1@vendor.com", s1)
	resp, b = e.get(t, "/api/vendor/shares")
	var list []map[string]any
	json.Unmarshal(b, &list)
	if resp.StatusCode != 200 || len(list) != 1 || len(list[0]) != 8 || list[0]["id"] != id || list[0]["owner_name"] != "D" ||
		list[0]["message"] != "hi" || list[0]["file_count"] != 2.0 || list[0]["allow_download"] != true || list[0]["watermark"] != false || list[0]["expires_at"] == nil {
		t.Fatal(resp.StatusCode, string(b))
	}
	base := "/api/vendor/shares/" + id
	resp, b = e.get(t, base)
	var files struct{ Files []map[string]any }
	json.Unmarshal(b, &files)
	if resp.StatusCode != 200 || len(files.Files) != 2 {
		t.Fatal(resp.StatusCode, string(b))
	}
	resp, b = e.get(t, base+"/files/"+f.String()+"/content")
	if resp.StatusCode != 200 || !bytes.Equal(b, plain) {
		t.Fatal(resp.StatusCode, string(b))
	}
	resp, _ = e.get(t, base+"/files/"+g.String()+"/preview/pages/0")
	viewHeadersOK(t, resp, "image/jpeg")
	if ev := e.auditOne(t, audit.ActFileView); ev.ActorType != "vendor" || ev.TargetID != g.String() || ev.Detail["share_id"] != id {
		t.Fatalf("%+v", ev)
	}
	req, _ := http.NewRequest("HEAD", e.ts.URL+base+"/files/"+g.String()+"/preview", nil)
	if resp, err := e.c.Do(req); err != nil || resp.StatusCode != 405 {
		t.Fatal("HEAD preview", resp, err)
	}
	if resp, _ := e.get(t, base+"/files/"+uuid.NewString()+"/content"); resp.StatusCode != 404 {
		t.Fatal("file not in share", resp.StatusCode)
	}

	// another vendor: not a recipient
	as(t, "v2@vendor.com", s2)
	for _, p := range []string{"", "/files/" + f.String() + "/content", "/files/" + g.String() + "/preview"} {
		if resp, b := e.get(t, base+p); resp.StatusCode != 404 {
			t.Fatal(p, resp.StatusCode, string(b))
		}
	}
	if _, b := e.get(t, "/api/vendor/shares"); string(b) != "[]\n" {
		t.Fatal(string(b))
	}

	// staff adds v2 by vendor id; then revokes the share
	as(t, "a@x.com", "")
	resp, b = e.do(t, "POST", "/api/shares/"+id+"/recipients", map[string]any{"vendor_ids": []uuid.UUID{v2}})
	if resp.StatusCode != 200 || string(b) == "[]\n" || !bytes.Contains(b, []byte(`"vendor":true`)) {
		t.Fatal(resp.StatusCode, string(b))
	}
	as(t, "v2@vendor.com", s2)
	if resp, _ := e.get(t, base+"/files/"+f.String()+"/content"); resp.StatusCode != 200 {
		t.Fatal("added vendor", resp.StatusCode)
	}
	as(t, "a@x.com", "")
	if resp, _ := e.do(t, "POST", "/api/shares/"+id+"/revoke", nil); resp.StatusCode != 204 {
		t.Fatal(resp.StatusCode)
	}
	as(t, "v1@vendor.com", s1)
	for _, p := range []string{"", "/files/" + f.String() + "/content"} {
		if resp, _ := e.get(t, base+p); resp.StatusCode != 410 {
			t.Fatal("revoked", p, resp.StatusCode)
		}
	}
}

// A file viewed through two shares in one vendor login gets a trace (and file.view) per share.
func TestVendorSameFileTwoSharesTracedApart(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "a@x.com")
	g := e.putFile(t, a.ID, "doc.pdf", []byte("x"))
	e.seedPreview(t, g, preview.KindPages, preview.StatusReady, 1)
	secret := e.mkVendor(t, "v@vendor.com")
	v := e.vendorID(t, "v@vendor.com")
	e.loginAs(t, "a@x.com", "")
	ids := make([]string, 2)
	for i := range ids {
		resp, b := e.do(t, "POST", "/api/shares", map[string]any{"file_ids": []uuid.UUID{g}, "vendor_ids": []uuid.UUID{v}, "allow_download": true,
			"watermark": true, "expires_at": time.Now().Add(48 * time.Hour).Format(time.RFC3339)})
		var m map[string]any
		json.Unmarshal(b, &m)
		if resp.StatusCode != 201 {
			t.Fatal(resp.StatusCode, string(b))
		}
		ids[i] = m["id"].(string)
	}
	e.loginAs(t, "v@vendor.com", secret)
	for _, id := range ids {
		if resp, b := e.get(t, "/api/vendor/shares/"+id+"/files/"+g.String()+"/preview/pages/0"); resp.StatusCode != 200 {
			t.Fatal(resp.StatusCode, string(b))
		}
	}
	var n, codes, shares int
	e.pool.QueryRow(context.Background(), `SELECT count(*), count(DISTINCT code), count(DISTINCT share_id) FROM view_traces WHERE file_id = $1`, g).
		Scan(&n, &codes, &shares)
	if n != 2 || codes != 2 || shares != 2 {
		t.Fatalf("traces %d, codes %d, shares %d", n, codes, shares)
	}
	ents, _, err := e.audit.List(context.Background(), audit.Filter{ActionPrefix: audit.ActFileView, Limit: 5})
	if err != nil || len(ents) != 2 || ents[0].Event.Detail["share_id"] == ents[1].Event.Detail["share_id"] {
		t.Fatal(err, ents)
	}
}

func TestVendorShareListDomainBlocked(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "a@x.com")
	f := e.putFile(t, a.ID, "doc.txt", []byte("x"))
	secret := e.mkVendor(t, "v@vendor.com")
	v := e.vendorID(t, "v@vendor.com")
	e.loginAs(t, "a@x.com", "")
	if resp, b := e.do(t, "POST", "/api/shares", map[string]any{"file_ids": []uuid.UUID{f}, "vendor_ids": []uuid.UUID{v}, "allow_download": true,
		"expires_at": time.Now().Add(48 * time.Hour).Format(time.RFC3339)}); resp.StatusCode != 201 {
		t.Fatal(resp.StatusCode, string(b))
	}
	e.loginAs(t, "v@vendor.com", secret)
	e.setRules(t, func(r *rules.Rules) { r.DomainBlock = []string{"vendor.com"} })
	if resp, b := e.get(t, "/api/vendor/shares"); resp.StatusCode != 403 || !bytes.Contains(b, []byte("domain_blocked")) {
		t.Fatal(resp.StatusCode, string(b))
	}
}

// Vendor downloads and views are audited as the vendor (user id), not as the share_recipients row.
func TestVendorDownloadAndViewAuditActor(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "a@x.com")
	f := e.putFile(t, a.ID, "doc.txt", []byte("x"))
	g := e.putFile(t, a.ID, "doc.pdf", []byte("x"))
	e.seedPreview(t, g, preview.KindPages, preview.StatusReady, 1)
	secret := e.mkVendor(t, "v@vendor.com")
	v := e.vendorID(t, "v@vendor.com")
	e.loginAs(t, "a@x.com", "")
	resp, b := e.do(t, "POST", "/api/shares", map[string]any{"file_ids": []uuid.UUID{f, g}, "vendor_ids": []uuid.UUID{v}, "allow_download": true,
		"expires_at": time.Now().Add(48 * time.Hour).Format(time.RFC3339)})
	var m map[string]any
	json.Unmarshal(b, &m)
	if resp.StatusCode != 201 {
		t.Fatal(resp.StatusCode, string(b))
	}
	base := "/api/vendor/shares/" + m["id"].(string) + "/files/"
	e.loginAs(t, "v@vendor.com", secret)
	if resp, _ := e.get(t, base+f.String()+"/content"); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := e.get(t, base+g.String()+"/preview/pages/0"); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	for _, act := range []string{audit.ActDownload, audit.ActFileView} {
		if ev := e.auditOne(t, act); ev.ActorType != "vendor" || ev.ActorID != v.String() {
			t.Fatalf("%s: %+v", act, ev)
		}
	}
}
