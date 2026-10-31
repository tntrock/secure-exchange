package httpapi

import (
	"context"
	"encoding/json"
	"testing"
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
	id := e.putFile(t, u.ID, "f", []byte("data"))
	e.setScan(t, id, "infected", "Eicar")
	if resp, body := e.get(t, "/api/files/"+id.String()+"/preview"); resp.StatusCode != 403 {
		t.Fatal(resp.StatusCode, string(body))
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
