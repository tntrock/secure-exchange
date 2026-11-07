package httpapi

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tntrock/secure-exchange/internal/audit"
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
