package httpapi

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func TestVendorUploadEndpoints(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, b := e.user(t, "a@x.com"), e.user(t, "b@x.com")
	secret := e.mkVendor(t, "v@vendor.com")
	v := e.vendorID(t, "v@vendor.com")
	if _, err := e.pool.Exec(ctx, `UPDATE users SET created_by = $2 WHERE id = $1`, v, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.Exec(ctx, `UPDATE users SET display_name = 'Ann' WHERE id = $1`, a.ID); err != nil {
		t.Fatal(err)
	}
	sid := uuid.New()
	if _, err := e.pool.Exec(ctx, `INSERT INTO shares (id, owner_id, token_hash, token_sealed, allow_download, watermark, expires_at)
		VALUES ($1,$2,$3,'\x00',true,false,now() + interval '1 day')`, sid, b.ID, sid[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.Exec(ctx, `INSERT INTO share_recipients (id, share_id, email, vendor_id) VALUES ($1,$2,'v@vendor.com',$3)`, uuid.New(), sid, v); err != nil {
		t.Fatal(err)
	}
	staffFile := e.putFile(t, a.ID, "mine.txt", []byte("x"))
	older := e.putFile(t, b.ID, "old.pdf", []byte("12345"))
	newer := e.putFile(t, a.ID, "new.pdf", []byte("1"))
	gone := e.putFile(t, a.ID, "gone.pdf", []byte("1"))
	if _, err := e.pool.Exec(ctx, `UPDATE files SET vendor_id = $1, created_at = now() - make_interval(mins => CASE id WHEN $2 THEN 2 ELSE 1 END)
		WHERE id = ANY($3)`, v, older, []uuid.UUID{older, newer, gone}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.Exec(ctx, `UPDATE files SET deleted_at = now() WHERE id = $1`, gone); err != nil {
		t.Fatal(err)
	}

	e.loginAs(t, "v@vendor.com", secret)
	resp, body := e.get(t, "/api/vendor/recipients")
	var rcpts []map[string]any
	json.Unmarshal(body, &rcpts)
	if resp.StatusCode != 200 || len(rcpts) != 2 || len(rcpts[0]) != 3 || rcpts[0]["id"] != a.ID.String() || rcpts[0]["name"] != "Ann" ||
		rcpts[0]["email"] != "a@x.com" || rcpts[1]["id"] != b.ID.String() || rcpts[1]["name"] != "D" {
		t.Fatal(resp.StatusCode, string(body))
	}
	resp, body = e.get(t, "/api/vendor/uploads")
	var ups []map[string]any
	json.Unmarshal(body, &ups)
	if resp.StatusCode != 200 || len(ups) != 2 || len(ups[0]) != 5 || ups[0]["id"] != newer.String() || ups[0]["name"] != "new.pdf" ||
		ups[0]["size"] != 1.0 || ups[0]["recipient_name"] != "Ann" || ups[0]["created_at"] == nil ||
		ups[1]["id"] != older.String() || ups[1]["recipient_name"] != "D" || ups[1]["size"] != 5.0 {
		t.Fatal(resp.StatusCode, string(body))
	}
	// the tus mount reaches the upload handler with the vendor in the context
	if resp, body := e.do(t, "POST", "/api/vendor/uploads/", nil); resp.StatusCode != 200 || string(body) != v.String() {
		t.Fatal(resp.StatusCode, string(body))
	}

	e.loginAs(t, "a@x.com", "")
	resp, body = e.get(t, "/api/files")
	var files []map[string]any
	json.Unmarshal(body, &files)
	byID := map[string]map[string]any{}
	for _, f := range files {
		byID[f["id"].(string)] = f
	}
	if mine, ok := byID[staffFile.String()]; resp.StatusCode != 200 || len(files) != 2 || byID[newer.String()]["vendor_email"] != "v@vendor.com" ||
		!ok || mine["vendor_email"] != nil {
		t.Fatal(resp.StatusCode, string(body))
	}
	if _, ok := byID[staffFile.String()]["vendor_email"]; !ok {
		t.Fatal("vendor_email key missing", string(body))
	}
}
