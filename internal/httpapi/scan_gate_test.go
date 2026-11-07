package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func (e *env) setScan(t *testing.T, id any, status, result string) {
	t.Helper()
	if _, err := e.pool.Exec(context.Background(), `UPDATE files SET scan_status = $2, scan_result = $3 WHERE id = $1`, id, status, result); err != nil {
		t.Fatal(err)
	}
}

func TestOwnerDownloadGate(t *testing.T) {
	e := newEnv(t)
	u := e.user(t, "a@x.com")
	e.login(t, "a@x.com", pw)
	for _, c := range []struct {
		status string
		code   int
		errMsg string
	}{
		{"pending", 409, "scan_pending"}, {"infected", 403, "quarantined"}, {"error", 403, "scan_failed"},
		{"clean", 200, ""}, {"skipped", 200, ""}, {"none", 200, ""},
	} {
		id := e.putFile(t, u.ID, "f", []byte("data"))
		e.setScan(t, id, c.status, "")
		resp, body := e.get(t, "/api/files/"+id.String()+"/content")
		if resp.StatusCode != c.code {
			t.Fatalf("%s: %d %s", c.status, resp.StatusCode, body)
		}
		if c.errMsg != "" {
			var m map[string]string
			json.Unmarshal(body, &m)
			if m["error"] != c.errMsg {
				t.Fatalf("%s: %s", c.status, body)
			}
		}
	}
}

func TestOwnerPreviewGate(t *testing.T) {
	e := newEnv(t)
	u := e.user(t, "a@x.com")
	e.login(t, "a@x.com", pw)
	for _, c := range []struct {
		status string
		code   int
		errMsg string
	}{{"infected", 403, "quarantined"}, {"pending", 409, "scan_pending"}, {"error", 403, "scan_failed"}} {
		id := e.putFile(t, u.ID, "f", []byte("data"))
		e.setScan(t, id, c.status, "Eicar")
		resp, body := e.get(t, "/api/files/"+id.String()+"/preview")
		var m map[string]string
		json.Unmarshal(body, &m)
		if resp.StatusCode != c.code || m["error"] != c.errMsg {
			t.Fatalf("%s: %d %s", c.status, resp.StatusCode, body)
		}
	}
}

func TestDeleteQuarantined(t *testing.T) {
	e := newEnv(t)
	u := e.user(t, "a@x.com")
	e.login(t, "a@x.com", pw)
	id := e.putFile(t, u.ID, "f", []byte("data"))
	e.setScan(t, id, "infected", "Eicar")
	if resp, _ := e.do(t, "DELETE", "/api/files/"+id.String(), nil); resp.StatusCode != 204 {
		t.Fatal(resp.StatusCode)
	}
}

func TestListFilesScanFields(t *testing.T) {
	e := newEnv(t)
	u := e.user(t, "a@x.com")
	e.login(t, "a@x.com", pw)
	id := e.putFile(t, u.ID, "f", []byte("data"))
	e.setScan(t, id, "infected", "Win.Test.EICAR_HDB-1")
	_, body := e.get(t, "/api/files")
	var out []map[string]any
	if err := json.Unmarshal(body, &out); err != nil || len(out) != 1 {
		t.Fatal(err, string(body))
	}
	if out[0]["scan_status"] != "infected" || out[0]["scan_result"] != "Win.Test.EICAR_HDB-1" {
		t.Fatal(out[0])
	}
	if v, ok := out[0]["request_id"]; !ok || v != nil {
		t.Fatal(out[0])
	}
}

// scanGateCases are the scan_status values the share paths must answer like scanRefusal says.
var scanGateCases = []string{"pending", "infected", "error", "clean", "skipped", "none"}

// wantScanGate checks url answers like scanRefusal says for scan (200 when it allows).
func wantScanGate(t *testing.T, e *env, url, scan string) {
	t.Helper()
	code, msg := scanRefusal(scan)
	resp, b := e.get(t, url)
	if code == 0 {
		if resp.StatusCode != 200 {
			t.Fatal(url, scan, resp.StatusCode, string(b))
		}
		return
	}
	var body struct{ Error string }
	json.Unmarshal(b, &body)
	if resp.StatusCode != code || body.Error != msg {
		t.Fatal(url, scan, resp.StatusCode, string(b), "want", code, msg)
	}
}

func TestRecipientDownloadRefusesUnscanned(t *testing.T) {
	for _, scan := range scanGateCases {
		e, f, tok := markShare(t, "doc.txt", []byte("hello"), false)
		e.setScan(t, f, scan, "")
		wantScanGate(t, e, contentURL(tok, f), scan)
	}
}

func TestSharedPreviewRefusesUnscanned(t *testing.T) {
	for _, scan := range scanGateCases {
		e, f, tok := markShare(t, "doc.txt", []byte("hello"), false)
		e.setScan(t, f, scan, "")
		wantScanGate(t, e, "/api/s/"+tok+"/files/"+f.String()+"/preview", scan)
	}
}

func TestVendorShareRefusesUnscanned(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "a@x.com")
	f := e.putFile(t, a.ID, "doc.txt", []byte("hello"))
	secret := e.mkVendor(t, "v1@vendor.com")
	v := e.vendorID(t, "v1@vendor.com")
	e.loginAs(t, "a@x.com", "")
	staff := e.c.Jar
	resp, b := e.do(t, "POST", "/api/shares", map[string]any{"file_ids": []uuid.UUID{f}, "vendor_ids": []uuid.UUID{v}, "allow_download": true,
		"expires_at": time.Now().Add(48 * time.Hour).Format(time.RFC3339)})
	var created struct{ ID string }
	json.Unmarshal(b, &created)
	if resp.StatusCode != http.StatusCreated {
		t.Fatal(resp.StatusCode, string(b))
	}
	e.c.Jar = staff
	e.loginAs(t, "v1@vendor.com", secret)
	base := "/api/vendor/shares/" + created.ID + "/files/" + f.String()
	for _, scan := range scanGateCases {
		e.setScan(t, f, scan, "")
		wantScanGate(t, e, base+"/content", scan)
		wantScanGate(t, e, base+"/preview", scan)
	}
}
