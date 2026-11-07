package httpapi

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/auth"
)

func TestAuditListAdminOnly(t *testing.T) {
	e := newEnv(t)
	e.user(t, "s@x.com")
	e.admin(t)
	e.loginAs(t, "s@x.com", "")
	wantStatus(t, e, "GET", "/api/admin/audit", nil, 403, forbiddenBody)
	e.loginAs(t, "adm@x.com", "")
	_, b := e.do(t, "GET", "/api/admin/audit?limit=1", nil)
	var m struct {
		Entries    []map[string]any `json:"entries"`
		NextBefore int64            `json:"next_before"`
	}
	if err := json.Unmarshal(b, &m); err != nil || len(m.Entries) != 1 || m.NextBefore == 0 || m.Entries[0]["action"] == nil {
		t.Fatal(err, string(b))
	}
	wantStatus(t, e, "GET", "/api/admin/audit?since=garbage", nil, 400, "{\"error\":\"bad_time\"}\n")
}

func TestAuditCSVEscapesFormulas(t *testing.T) {
	e := newEnv(t)
	e.admin(t)
	if err := e.audit.Append(context.Background(), audit.Event{ActorType: "user", Action: "test.x", UserAgent: "=HYPERLINK(1)",
		Result: "ok", Detail: map[string]any{"n": "+1"}}); err != nil {
		t.Fatal(err)
	}
	e.loginAs(t, "adm@x.com", "")
	resp, b := e.do(t, "GET", "/api/admin/audit/export?action=test.", nil)
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/csv") ||
		!strings.HasPrefix(resp.Header.Get("Content-Disposition"), `attachment; filename="audit-`) {
		t.Fatal(resp.StatusCode, resp.Header)
	}
	if !strings.HasPrefix(string(b), "\xEF\xBB\xBF") {
		t.Fatal("no BOM")
	}
	rows, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(b), "\xEF\xBB\xBF"))).ReadAll()
	if err != nil || len(rows) != 2 || len(rows[0]) != 14 || rows[0][0] != "id" || rows[0][13] != "hash" {
		t.Fatal(err, string(b))
	}
	if rows[1][6] != "'=HYPERLINK(1)" || !strings.HasPrefix(rows[1][11], "{") {
		t.Fatalf("%q", rows[1])
	}
	ev := e.auditActions(t, audit.ActAuditExport)
	if len(ev) != 1 || ev[0].Event.Detail["filter"] == nil {
		t.Fatalf("%+v", ev)
	}
}

func TestAuditVerifyEndpoint(t *testing.T) {
	e := newEnv(t)
	e.admin(t)
	e.loginAs(t, "adm@x.com", "")
	_, b := e.do(t, "POST", "/api/admin/audit/verify", nil)
	var m struct{ Checked, BadID int64 }
	if err := json.Unmarshal(b, &m); err != nil || m.Checked == 0 || m.BadID != 0 {
		t.Fatal(err, string(b))
	}
	ev := e.auditActions(t, audit.ActAuditVerify)
	if len(ev) != 1 || ev[0].Event.Result != "ok" {
		t.Fatalf("%+v", ev)
	}
}

func TestAuditForwardingStatus(t *testing.T) {
	e := newEnv(t)
	e.admin(t)
	e.loginAs(t, "adm@x.com", "")
	_, b := e.do(t, "GET", "/api/admin/audit/forwarding", nil)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil || m["enabled"] != false {
		t.Fatal(err, string(b))
	}
}

func TestShareAuditOwnerOnly(t *testing.T) {
	e := newEnv(t)
	e.admin(t)
	o := e.user(t, "o@x.com")
	e.user(t, "other@x.com")
	secret := e.mkVendor(t, "v@vendor.com")
	f := e.putFile(t, o.ID, "doc.txt", []byte("x"))
	e.loginAs(t, "o@x.com", "")
	id := e.mkShare(t, []string{f.String()}, "r@y.com")["id"].(string)

	_, b := e.do(t, "GET", "/api/shares/"+id+"/audit", nil)
	var m struct{ Entries []map[string]any }
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err, string(b))
	}
	found := false
	for _, en := range m.Entries {
		found = found || en["action"] == audit.ActShareCreate
	}
	if !found {
		t.Fatal(string(b))
	}
	e.loginAs(t, "other@x.com", "")
	wantStatus(t, e, "GET", "/api/shares/"+id+"/audit", nil, 404, "")
	e.loginAs(t, "v@vendor.com", secret)
	wantStatus(t, e, "GET", "/api/shares/"+id+"/audit", nil, 403, "")
	e.loginAs(t, "adm@x.com", "")
	wantStatus(t, e, "GET", "/api/admin/shares/"+id+"/audit", nil, 200, "")
}

func TestAuditEndpointsStaffForbidden(t *testing.T) {
	e := newEnv(t)
	e.user(t, "s@x.com")
	e.loginAs(t, "s@x.com", "")
	for _, c := range [][2]string{{"GET", "/api/admin/audit/export"}, {"POST", "/api/admin/audit/verify"}, {"GET", "/api/admin/audit/forwarding"}} {
		wantStatus(t, e, c[0], c[1], nil, 403, forbiddenBody)
	}
}

func TestAuditExportAbortsOnFailure(t *testing.T) {
	e := newEnv(t)
	e.admin(t)
	req := httptest.NewRequest("GET", "/api/admin/audit/export", nil)
	req = req.WithContext(auth.WithUser(req.Context(), &auth.User{ID: uuid.New()}))
	var panicked any
	func() {
		defer func() { panicked = recover() }()
		(&server{Deps: e.deps}).auditExport(&failAfter{h: http.Header{}, n: 3}, req) // BOM goes out, the rest fails
	}()
	if panicked != any(http.ErrAbortHandler) {
		t.Fatalf("want abort, got %v", panicked)
	}
}

func adminReq(method, target string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	return r.WithContext(auth.WithUser(r.Context(), &auth.User{ID: uuid.New()}))
}

func TestAuditBadParams(t *testing.T) {
	e := newEnv(t)
	e.admin(t)
	e.loginAs(t, "adm@x.com", "")
	wantStatus(t, e, "GET", "/api/admin/audit/export?until=garbage", nil, 400, "{\"error\":\"bad_time\"}\n")
	wantStatus(t, e, "GET", "/api/admin/audit?before=x&limit=y", nil, 200, "")
}

func TestAuditEndpoints500WhenStorageFails(t *testing.T) {
	e := newEnv(t)
	e.admin(t)
	o := e.user(t, "o@x.com")
	f := e.putFile(t, o.ID, "doc.txt", []byte("x"))
	e.loginAs(t, "o@x.com", "")
	id := e.mkShare(t, []string{f.String()}, "r@y.com")["id"].(string)
	e.loginAs(t, "adm@x.com", "")
	e.breakTable(t, "syslog_cursor")
	wantStatus(t, e, "GET", "/api/admin/audit/forwarding", nil, 500, "")
	e.breakTable(t, "audit_log")
	for _, p := range []string{"/api/admin/audit", "/api/admin/shares/" + id + "/audit"} {
		wantStatus(t, e, "GET", p, nil, 500, "")
	}
	wantStatus(t, e, "POST", "/api/admin/audit/verify", nil, 500, "")
	e.loginAs(t, "o@x.com", "")
	wantStatus(t, e, "GET", "/api/shares/"+id+"/audit", nil, 500, "")

	// export: headers already sent, so the failure must abort the response
	var panicked any
	func() {
		defer func() { panicked = recover() }()
		(&server{Deps: e.deps}).auditExport(httptest.NewRecorder(), adminReq("GET", "/api/admin/audit/export"))
	}()
	if panicked != any(http.ErrAbortHandler) {
		t.Fatalf("want abort, got %v", panicked)
	}
}

func TestAdminShareAuditNotFound(t *testing.T) {
	e := newEnv(t)
	e.admin(t)
	e.loginAs(t, "adm@x.com", "")
	wantStatus(t, e, "GET", "/api/admin/shares/"+uuid.NewString()+"/audit", nil, 404, "")
}

func TestNotifyPrefsUnknownUser(t *testing.T) {
	e := newEnv(t)
	s := &server{Deps: e.deps}
	rec := httptest.NewRecorder()
	s.getNotifyPrefs(rec, adminReq("GET", "/api/me/notify"))
	if rec.Code != 500 {
		t.Fatal(rec.Code)
	}
	rec = httptest.NewRecorder()
	r := adminReq("PUT", "/api/me/notify")
	r.Body = io.NopCloser(strings.NewReader(`{"first_open":true,"download":true,"upload":true}`))
	s.setNotifyPrefs(rec, r)
	if rec.Code != 500 {
		t.Fatal(rec.Code)
	}
}

func TestAuditVerifyBrokenAndExportFlush(t *testing.T) {
	e := newEnv(t)
	e.admin(t)
	ctx := context.Background()
	for i := 0; i < 500; i++ { // export flushes every 500 rows
		if err := e.audit.Append(ctx, audit.Event{ActorType: "user", Action: "test.bulk", Result: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	e.loginAs(t, "adm@x.com", "")
	resp, b := e.do(t, "GET", "/api/admin/audit/export?action=test.bulk&since=2000-01-01T00:00:00Z&until=2999-01-01T00:00:00Z", nil)
	if resp.StatusCode != 200 || strings.Count(string(b), "test.bulk") != 500 {
		t.Fatal(resp.StatusCode, len(b))
	}
	wantStatus(t, e, "GET", "/api/admin/shares/not-a-uuid/audit", nil, 404, "")
	// a client that is gone before the BOM is written
	(&server{Deps: e.deps}).auditExport(&failAfter{h: http.Header{}}, adminReq("GET", "/api/admin/audit/export"))

	if _, err := e.pool.Exec(ctx, `DROP RULE audit_no_update ON audit_log`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.Exec(ctx, `UPDATE audit_log SET result='x' WHERE id = (SELECT min(id) FROM audit_log)`); err != nil {
		t.Fatal(err)
	}
	_, b = e.do(t, "POST", "/api/admin/audit/verify", nil)
	var m struct {
		BadID int64 `json:"bad_id"`
	}
	if err := json.Unmarshal(b, &m); err != nil || m.BadID == 0 {
		t.Fatal(err, string(b))
	}
}
