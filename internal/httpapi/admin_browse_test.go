package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/preview"
)

func TestAdminBrowseRequiresAdmin(t *testing.T) {
	e := newEnv(t)
	e.user(t, "s@x.com")
	routes := [][2]string{{"GET", "/shares"}, {"GET", "/shares/" + zeroID}, {"POST", "/shares/" + zeroID + "/revoke"},
		{"GET", "/requests"}, {"GET", "/requests/" + zeroID}, {"POST", "/requests/" + zeroID + "/revoke"},
		{"GET", "/files/" + zeroID + "/preview"}, {"GET", "/files/" + zeroID + "/preview/pages/0"},
		{"GET", "/files/" + zeroID + "/preview/video.m3u8"}, {"GET", "/files/" + zeroID + "/preview/segments/0.ts"}}
	for _, rt := range routes {
		wantStatus(t, e, rt[0], "/api/admin"+rt[1], nil, 401, "")
	}
	e.loginAs(t, "s@x.com", "")
	for _, rt := range routes {
		wantStatus(t, e, rt[0], "/api/admin"+rt[1], nil, 403, forbiddenBody)
	}
}

func TestAdminRevokeShareAudited(t *testing.T) {
	e := newEnv(t)
	e.admin(t)
	b := e.user(t, "b@x.com")
	f := e.putFile(t, b.ID, "doc.txt", []byte("x"))
	e.loginAs(t, "b@x.com", "")
	sh := e.mkShare(t, []string{f.String()}, "r@y.com")
	id := sh["id"].(string)

	e.loginAs(t, "adm@x.com", "")
	wantStatus(t, e, "POST", "/api/admin/shares/"+id+"/revoke", nil, 204, "")
	ev := e.auditActions(t, audit.ActShareRevoke)
	if len(ev) != 1 || ev[0].Event.ActorID != e.userID(t, "adm@x.com") || ev[0].Event.TargetID != id ||
		ev[0].Event.Detail["owner_id"] != b.ID.String() || ev[0].Event.Detail["admin"] != true || len(ev[0].Event.Detail) != 2 {
		t.Fatalf("%+v", ev)
	}
	wantStatus(t, e, "POST", "/api/admin/shares/"+zeroID+"/revoke", nil, 404, "")
	wantStatus(t, e, "POST", "/api/admin/shares/nope/revoke", nil, 404, "")

	e.loginAs(t, "b@x.com", "")
	_, body := e.do(t, "GET", "/api/shares/"+id, nil)
	var m map[string]any
	json.Unmarshal(body, &m)
	if m["revoked"] != true {
		t.Fatal(m)
	}
}

func TestAdminBrowseSharesAndRequests(t *testing.T) {
	e := newEnv(t)
	e.admin(t)
	b := e.user(t, "b@x.com")
	f := e.putFile(t, b.ID, "doc.txt", []byte("x"))
	e.loginAs(t, "b@x.com", "")
	shID := e.mkShare(t, []string{f.String()}, "r@y.com")["id"].(string)
	reqID, tok := e.newRequest(t, "u@y.com")

	e.loginAs(t, "adm@x.com", "")
	var list []map[string]any
	_, body := e.do(t, "GET", "/api/admin/shares?q=B@X&offset=0", nil)
	json.Unmarshal(body, &list)
	if len(list) != 1 || list[0]["id"] != shID || list[0]["owner_email"] != "b@x.com" || list[0]["file_count"] != float64(1) || list[0]["recipient_count"] != float64(1) {
		t.Fatal(string(body))
	}
	_, body = e.do(t, "GET", "/api/admin/shares?q=nobody", nil)
	if string(body) != "null\n" && string(body) != "[]\n" {
		t.Fatal(string(body))
	}
	var m map[string]any
	_, body = e.do(t, "GET", "/api/admin/shares/"+shID, nil)
	json.Unmarshal(body, &m)
	if m["owner_email"] != "b@x.com" || len(m["files"].([]any)) != 1 {
		t.Fatal(string(body))
	}
	wantStatus(t, e, "GET", "/api/admin/shares/"+zeroID, nil, 404, "")

	list = nil
	_, body = e.do(t, "GET", "/api/admin/requests?q=b@x.com&offset=-3", nil)
	json.Unmarshal(body, &list)
	if len(list) != 1 || list[0]["id"] != reqID || list[0]["owner_email"] != "b@x.com" {
		t.Fatal(string(body))
	}
	m = nil
	_, body = e.do(t, "GET", "/api/admin/requests/"+reqID, nil)
	json.Unmarshal(body, &m)
	if m["owner_email"] != "b@x.com" || m["message"] != "hi" || len(m["uploaders"].([]any)) != 1 {
		t.Fatal(string(body))
	}
	wantStatus(t, e, "GET", "/api/admin/requests/"+zeroID, nil, 404, "")
	wantStatus(t, e, "POST", "/api/admin/requests/"+zeroID+"/revoke", nil, 404, "")
	wantStatus(t, e, "POST", "/api/admin/requests/nope/revoke", nil, 404, "")

	wantStatus(t, e, "POST", "/api/admin/requests/"+reqID+"/revoke", nil, 204, "")
	ev := e.auditActions(t, audit.ActRequestRevoke)
	if len(ev) != 1 || ev[0].Event.ActorID != e.userID(t, "adm@x.com") || ev[0].Event.Detail["owner_id"] != b.ID.String() || ev[0].Event.Detail["admin"] != true {
		t.Fatalf("%+v", ev)
	}
	wantStatus(t, e, "GET", "/api/r/"+tok, nil, 410, "")
}

func TestAdminViewWatermarked(t *testing.T) {
	e := newEnv(t)
	e.admin(t)
	b := e.user(t, "b@x.com")
	f := e.putFile(t, b.ID, "pic.png", []byte("x"))
	want := e.seedPreview(t, f, preview.KindImage, preview.StatusReady, 1)
	base := "/api/files/" + f.String() + "/preview"

	e.loginAs(t, "b@x.com", "")
	_, own := e.get(t, base+"/pages/0")
	if d, m := meanDiff(t, own, want); d >= 3 || m > 0.001 {
		t.Fatalf("owner copy marked: %.2f %.4f", d, m)
	}

	e.loginAs(t, "adm@x.com", "")
	adm := "/api/admin/files/" + f.String() + "/preview"
	resp, body := e.get(t, adm)
	if resp.StatusCode != 200 || !bytes.Contains(body, []byte(`"kind":"image"`)) {
		t.Fatal(resp.StatusCode, string(body))
	}
	resp, page := e.get(t, adm+"/pages/0")
	viewHeadersOK(t, resp, "image/jpeg")
	if bytes.Equal(page, own) {
		t.Fatal("admin copy equals the owner's")
	}
	if _, m := meanDiff(t, page, want); m < 0.01 {
		t.Fatalf("admin copy not visibly marked: %.4f", m)
	}
	e.get(t, adm+"/pages/0")
	ents := e.auditActions(t, audit.ActFileView)
	if len(ents) != 1 {
		t.Fatalf("%d file.view rows after one open", len(ents))
	}
	ev := ents[0].Event
	if ev.ActorType != "user" || ev.ActorID != e.userID(t, "adm@x.com") || ev.TargetType != "file" || ev.TargetID != f.String() ||
		len(ev.Detail) != 1 || ev.Detail["admin"] != true {
		t.Fatalf("%+v", ev)
	}
	e.get(t, adm)
	if n := len(e.auditActions(t, audit.ActFileView)); n != 2 {
		t.Fatalf("%d rows after the second open", n)
	}
	if e.traces(t, f) != 0 {
		t.Fatal("admin view left a trace")
	}
	var dl int
	e.pool.QueryRow(context.Background(), `SELECT count(*) FROM download_traces`).Scan(&dl)
	if dl != 0 {
		t.Fatal("admin view left a download trace")
	}
}

func TestAdminViewRefusesDeletedOrUnscanned(t *testing.T) {
	e := newEnv(t)
	e.admin(t)
	b := e.user(t, "b@x.com")
	e.loginAs(t, "adm@x.com", "")
	del := e.putFile(t, b.ID, "a.png", []byte("x"))
	e.seedPreview(t, del, preview.KindImage, preview.StatusReady, 1)
	if _, err := e.pool.Exec(context.Background(), `UPDATE files SET deleted_at = now() WHERE id = $1`, del); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, e, "GET", "/api/admin/files/"+del.String()+"/preview", nil, 404, "")
	for _, st := range []string{"infected", "pending", "error"} {
		f := e.putFile(t, b.ID, "b.png", []byte("x"))
		e.seedPreview(t, f, preview.KindImage, preview.StatusReady, 1)
		e.setScan(t, f, st, "")
		wantStatus(t, e, "GET", "/api/admin/files/"+f.String()+"/preview", nil, 404, "")
		wantStatus(t, e, "GET", "/api/admin/files/"+f.String()+"/preview/pages/0", nil, 404, "")
	}
	wantStatus(t, e, "GET", "/api/admin/files/nope/preview", nil, 404, "")
	if n := len(e.auditActions(t, audit.ActFileView)); n != 0 {
		t.Fatalf("%d file.view rows for refused views", n)
	}
}

func TestAdminNoDownloadRoute(t *testing.T) {
	e := newEnv(t)
	e.admin(t)
	b := e.user(t, "b@x.com")
	f := e.putFile(t, b.ID, "a.txt", []byte("x"))
	e.loginAs(t, "adm@x.com", "")
	wantStatus(t, e, "GET", "/api/admin/files/"+f.String()+"/content", nil, 404, "{\"error\":\"not_found\"}\n")
}
