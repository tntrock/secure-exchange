package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tntrock/secure-exchange/internal/audit"
)

func (e *env) mkShare(t *testing.T, fileIDs any, emails ...string) map[string]any {
	t.Helper()
	resp, b := e.do(t, "POST", "/api/shares", map[string]any{"file_ids": fileIDs, "emails": emails, "allow_download": true,
		"expires_at": time.Now().Add(48 * time.Hour).Format(time.RFC3339), "ip_allow": []string{"10.0.0.0/8"}, "message": "hi"})
	if resp.StatusCode != 201 {
		t.Fatal(resp.StatusCode, string(b))
	}
	var m map[string]any
	json.Unmarshal(b, &m)
	return m
}

func TestCreateShareAPI(t *testing.T) {
	e := newEnv(t)
	u := e.user(t, "a@x.com")
	f := e.putFile(t, u.ID, "doc.txt", []byte("hello"))
	e.login(t, "a@x.com", pw)
	m := e.mkShare(t, []string{f.String()}, "R@y.com", "z@y.com")
	if m["allow_download"] != true || m["message"] != "hi" || m["revoked"] != false || m["expired"] != false || m["max_views"] != nil {
		t.Fatal(m)
	}
	if ip := m["ip_allow"].([]any); len(ip) != 1 || ip[0] != "10.0.0.0/8" {
		t.Fatal(ip)
	}
	if fs := m["files"].([]any); len(fs) != 1 || fs[0].(map[string]any)["name"] != "doc.txt" || fs[0].(map[string]any)["size"] != float64(5) {
		t.Fatal(m["files"])
	}
	if rs := m["recipients"].([]any); len(rs) != 2 || rs[0].(map[string]any)["email"] != "r@y.com" {
		t.Fatal(m["recipients"])
	}
	_, b := e.do(t, "GET", "/api/shares/"+m["id"].(string), nil)
	var got map[string]any
	json.Unmarshal(b, &got)
	if got["id"] != m["id"] {
		t.Fatal(string(b))
	}
	_, b = e.do(t, "GET", "/api/shares", nil)
	var l []map[string]any
	json.Unmarshal(b, &l)
	if len(l) != 1 || l[0]["file_count"] != float64(1) || l[0]["recipient_count"] != float64(2) || l[0]["view_count"] != float64(0) {
		t.Fatal(string(b))
	}
	ents, _ := e.audit.List(context.Background(), audit.Filter{Action: audit.ActShareCreate, Limit: 5})
	if len(ents) != 1 || ents[0].Event.TargetType != "share" || ents[0].Event.TargetID != m["id"] ||
		ents[0].Event.Detail["recipient_count"] != float64(2) || ents[0].Event.Detail["file_count"] != float64(1) {
		t.Fatalf("%+v", ents)
	}
}

func TestCreateShareValidationAPI(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "a@x.com")
	e.user(t, "b@x.com")
	f := e.putFile(t, a.ID, "doc", []byte("x"))
	e.login(t, "b@x.com", pw)
	resp, b := e.do(t, "POST", "/api/shares", map[string]any{"file_ids": []string{f.String()}, "emails": []string{"r@y.com"},
		"expires_at": time.Now().Add(48 * time.Hour).Format(time.RFC3339)})
	if resp.StatusCode != 422 || string(b) != `{"code":"not_found","error":"validation","field":"file_ids"}`+"\n" {
		t.Fatal(resp.StatusCode, string(b))
	}
	resp, _ = e.do(t, "POST", "/api/shares", map[string]any{"file_ids": []string{"nope"}})
	if resp.StatusCode != 400 {
		t.Fatal(resp.StatusCode)
	}
}

func TestShareOwnerOnly(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "a@x.com")
	e.user(t, "b@x.com")
	f := e.putFile(t, a.ID, "doc", []byte("x"))
	e.login(t, "a@x.com", pw)
	id := e.mkShare(t, []string{f.String()}, "r@y.com")["id"].(string)
	e.login(t, "b@x.com", pw)
	for _, c := range [][2]string{{"GET", ""}, {"POST", "/revoke"}, {"POST", "/recipients"}} {
		resp, _ := e.do(t, c[0], "/api/shares/"+id+c[1], map[string]any{"emails": []string{"q@y.com"}})
		if resp.StatusCode != 404 {
			t.Fatal(c, resp.StatusCode)
		}
	}
	if resp, _ := e.do(t, "GET", "/api/shares/not-a-uuid", nil); resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}
	_, b := e.do(t, "GET", "/api/shares", nil)
	if string(b) != "[]\n" {
		t.Fatal(string(b))
	}
}

func TestRevokeAndRecipientAPI(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "a@x.com")
	f := e.putFile(t, a.ID, "doc", []byte("x"))
	e.login(t, "a@x.com", pw)
	m := e.mkShare(t, []string{f.String()}, "r@y.com")
	id := m["id"].(string)
	rid := m["recipients"].([]any)[0].(map[string]any)["id"].(string)

	resp, b := e.do(t, "POST", "/api/shares/"+id+"/recipients", map[string]any{"emails": []string{"r@y.com", "n@y.com"}})
	var added []map[string]any
	json.Unmarshal(b, &added)
	if resp.StatusCode != 200 || len(added) != 1 || added[0]["email"] != "n@y.com" {
		t.Fatal(resp.StatusCode, string(b))
	}
	if resp, _ = e.do(t, "POST", "/api/shares/"+id+"/recipients/"+rid+"/revoke", nil); resp.StatusCode != 204 {
		t.Fatal(resp.StatusCode)
	}
	_, b = e.do(t, "GET", "/api/shares/"+id, nil)
	var d struct {
		Recipients []map[string]any `json:"recipients"`
	}
	json.Unmarshal(b, &d)
	if d.Recipients[0]["id"] != rid || d.Recipients[0]["revoked"] != true || d.Recipients[1]["revoked"] != false {
		t.Fatal(string(b))
	}
	if resp, _ = e.do(t, "POST", "/api/shares/"+id+"/recipients/"+uuidZero+"/revoke", nil); resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ = e.do(t, "POST", "/api/shares/"+id+"/revoke", nil); resp.StatusCode != 204 {
		t.Fatal(resp.StatusCode)
	}
	resp, b = e.do(t, "POST", "/api/shares/"+id+"/recipients", map[string]any{"emails": []string{"late@y.com"}})
	if resp.StatusCode != http.StatusConflict || string(b) != `{"error":"revoked"}`+"\n" {
		t.Fatal(resp.StatusCode, string(b))
	}
	_, b = e.do(t, "GET", "/api/shares/"+id, nil)
	if json.Unmarshal(b, &d); len(d.Recipients) != 2 {
		t.Fatal(string(b))
	}
	for act, n := range map[string]int{audit.ActShareRevoke: 1, audit.ActShareRecipientAdd: 1, audit.ActShareRecipientRevoke: 1} {
		ents, _ := e.audit.List(context.Background(), audit.Filter{Action: act, Limit: 5})
		if len(ents) != n || ents[0].Event.TargetType != "share" || ents[0].Event.TargetID != id {
			t.Fatal(act, ents)
		}
	}
	ents, _ := e.audit.List(context.Background(), audit.Filter{Action: audit.ActShareRecipientRevoke, Limit: 5})
	if ents[0].Event.Detail["recipient_id"] != rid {
		t.Fatal(ents[0].Event.Detail)
	}
}

const uuidZero = "00000000-0000-0000-0000-000000000000"

func TestAddRecipientsExpiredAPI(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "a@x.com")
	f := e.putFile(t, a.ID, "doc", []byte("x"))
	e.login(t, "a@x.com", pw)
	id := e.mkShare(t, []string{f.String()}, "r@y.com")["id"].(string)
	if _, err := e.pool.Exec(context.Background(), `UPDATE shares SET expires_at = now() - interval '1 second' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	resp, b := e.do(t, "POST", "/api/shares/"+id+"/recipients", map[string]any{"emails": []string{"late@y.com"}})
	if resp.StatusCode != http.StatusConflict || string(b) != `{"error":"expired"}`+"\n" {
		t.Fatal(resp.StatusCode, string(b))
	}
}

// Share endpoints refuse (500) rather than guess when the data they depend on cannot be read.
func TestShareEndpointsAnswer500WhenTablesFail(t *testing.T) {
	e := newEnv(t, func(d *Deps) { d.Mark.Policy = "block" })
	a := e.user(t, "a@x.com")
	f := e.putFile(t, a.ID, "a.zip", []byte("PK\x03\x04 not much"))
	e.login(t, "a@x.com", pw)
	e.breakTable(t, "file_previews")
	in := map[string]any{"file_ids": []uuid.UUID{f}, "emails": []string{"r@y.com"}, "allow_download": true, "watermark": true,
		"expires_at": time.Now().Add(48 * time.Hour).Format(time.RFC3339)}
	if resp, b := e.do(t, "POST", "/api/shares", in); resp.StatusCode != 500 {
		t.Fatal("create:", resp.StatusCode, string(b))
	}
	if resp, b := e.do(t, "GET", "/api/shares", nil); resp.StatusCode != 200 {
		t.Fatal("list before:", resp.StatusCode, string(b))
	}
	e.breakTable(t, "share_files")
	if resp, b := e.do(t, "GET", "/api/shares", nil); resp.StatusCode != 500 {
		t.Fatal("list:", resp.StatusCode, string(b))
	}
}
