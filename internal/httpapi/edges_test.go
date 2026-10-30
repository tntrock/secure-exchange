package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"

	"github.com/tntrock/secure-exchange/internal/blob"
	"github.com/tntrock/secure-exchange/internal/preview"
)

func TestHealthz(t *testing.T) {
	e := newEnv(t)
	if resp, b := e.get(t, "/healthz"); resp.StatusCode != 200 || string(b) != "ok" {
		t.Fatal(resp.StatusCode, string(b))
	}
}

func TestBadSessionCookie(t *testing.T) {
	e := newEnv(t)
	if resp, _ := e.get(t, "/api/me", "Cookie", cookieName+"=bogus"); resp.StatusCode != 401 {
		t.Fatal(resp.StatusCode)
	}
}

func TestTOTPEdges(t *testing.T) {
	e := newEnv(t)
	e.user(t, "t@x.com")
	e.login(t, "t@x.com", pw)
	_, body := e.do(t, "POST", "/api/me/totp/setup", nil)
	var setup struct {
		OtpauthURL string `json:"otpauth_url"`
	}
	json.Unmarshal(body, &setup)
	secret := otpSecret(t, setup.OtpauthURL)
	if resp, _ := e.do(t, "POST", "/api/me/totp/enable", "not an object"); resp.StatusCode != 400 {
		t.Fatal("bad body", resp.StatusCode)
	}
	prev, _ := totp.GenerateCode(secret, time.Now().Add(-30*time.Second))
	if resp, b := e.do(t, "POST", "/api/me/totp/enable", map[string]string{"code": prev}); resp.StatusCode != 204 {
		t.Fatal(resp.StatusCode, string(b))
	}
	// enrolled: neither setup nor enable may start over (the session still says TOTP is off, the DB does not)
	if resp, b := e.do(t, "POST", "/api/me/totp/setup", nil); resp.StatusCode != 409 || strings.TrimSpace(string(b)) != `{"error":"totp_already_enabled"}` {
		t.Fatal(resp.StatusCode, string(b))
	}
	e.do(t, "POST", "/api/auth/logout", nil)
	e.login(t, "t@x.com", pw)
	code, _ := totp.GenerateCode(secret, time.Now())
	if resp, _ := e.do(t, "POST", "/api/auth/totp", "not an object"); resp.StatusCode != 400 {
		t.Fatal("bad body", resp.StatusCode)
	}
	if resp, _ := e.do(t, "POST", "/api/auth/totp", map[string]string{"code": code}); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	if resp, b := e.do(t, "POST", "/api/me/totp/enable", map[string]string{"code": code}); resp.StatusCode != 409 || strings.TrimSpace(string(b)) != `{"error":"totp_already_enabled"}` {
		t.Fatal(resp.StatusCode, string(b))
	}

	// the code step is rate limited per user
	e.do(t, "POST", "/api/auth/logout", nil)
	e.login(t, "t@x.com", pw)
	limited := false
	for range 6 {
		resp, b := e.do(t, "POST", "/api/auth/totp", map[string]string{"code": "000000x"})
		if resp.StatusCode == 429 {
			limited = strings.TrimSpace(string(b)) == `{"error":"rate_limited"}`
			break
		}
		if resp.StatusCode != 401 {
			t.Fatal(resp.StatusCode)
		}
	}
	if !limited {
		t.Fatal("totp not rate limited")
	}
}

func TestDownloadUnwrapFailure(t *testing.T) {
	e := newEnv(t)
	u := e.user(t, "a@x.com")
	id := e.putFile(t, u.ID, "f", []byte("data"))
	e.pool.Exec(context.Background(), `UPDATE files SET key_id = 99 WHERE id = $1`, id)
	e.login(t, "a@x.com", pw)
	if resp, b := e.get(t, "/api/files/"+id.String()+"/content"); resp.StatusCode != 500 || bytes.Contains(b, []byte("data")) {
		t.Fatal(resp.StatusCode, string(b))
	}
}

// noDelete is a blob store whose deletes fail.
type noDelete struct{ blob.Store }

func (noDelete) Delete(context.Context, string) error { return errors.New("store down") }

func TestDeleteFileBlobFailureStillDeletes(t *testing.T) {
	e := newEnv(t, func(d *Deps) { d.Store = noDelete{d.Store} })
	u := e.user(t, "a@x.com")
	id := e.putFile(t, u.ID, "f", []byte("data"))
	e.seedPreview(t, id, preview.KindImage, preview.StatusReady, 1)
	e.login(t, "a@x.com", pw)
	// the row is the source of truth: a blob left behind is logged, not a failed delete
	if resp, _ := e.do(t, "DELETE", "/api/files/"+id.String(), nil); resp.StatusCode != 204 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := e.get(t, "/api/files/"+id.String()+"/content"); resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}
	if items, _ := preview.ListItems(context.Background(), e.pool, id, "image"); len(items) != 0 {
		t.Fatal("item rows kept")
	}
}

func TestBadPathIDs(t *testing.T) {
	e := newEnv(t)
	e.user(t, "a@x.com")
	e.login(t, "a@x.com", pw)
	for _, c := range []struct{ method, path string }{
		{"POST", "/api/shares/x/revoke"},
		{"POST", "/api/shares/x/recipients"},
		{"POST", "/api/shares/x/recipients/" + uuid.NewString() + "/revoke"},
		{"POST", "/api/shares/" + uuid.NewString() + "/recipients/x/revoke"},
	} {
		if resp, b := e.do(t, c.method, c.path, map[string]any{"emails": []string{"n@y.com"}}); resp.StatusCode != 404 {
			t.Fatal(c.path, resp.StatusCode, string(b))
		}
	}
	if resp, _ := e.do(t, "POST", "/api/shares/"+uuid.NewString()+"/recipients", "not an object"); resp.StatusCode != 400 {
		t.Fatal(resp.StatusCode)
	}
}

func TestRecipientEdges(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "a@x.com")
	f := e.putFile(t, a.ID, "doc.pdf", []byte("x"))
	e.login(t, "a@x.com", pw)
	_, tok := e.recipShare(t, true, []uuid.UUID{f}, "r@y.com")
	for _, p := range []string{"/code", "/verify"} {
		if resp, _ := e.do(t, "POST", "/api/s/"+tok+p, "not an object"); resp.StatusCode != 400 {
			t.Fatal(p, resp.StatusCode)
		}
	}
	if resp, _ := e.do(t, "POST", "/api/s/nosuchtoken/verify", map[string]string{"email": "r@y.com", "code": "123456"}); resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}
	e.recipVerify(t, tok, "r@y.com")
	if resp, _ := e.get(t, "/api/s/"+tok+"/files/x/content"); resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}
}

func TestPreviewEdges(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "a@x.com")
	ctx := context.Background()
	none := e.putFile(t, a.ID, "x.bin", []byte("x"))
	short := e.putFile(t, a.ID, "short.pdf", []byte("x"))
	e.seedPreview(t, short, preview.KindPages, preview.StatusReady, 1)
	// page_count 2 puts page 1 in range, but only page 0 was stored
	if tag, err := e.pool.Exec(ctx, `UPDATE file_previews SET page_count = 2 WHERE file_id = $1`, short); err != nil || tag.RowsAffected() != 1 {
		t.Fatal(tag, err)
	}
	junk := e.putFile(t, a.ID, "junk.png", []byte("x"))
	if _, err := e.pool.Exec(ctx, `INSERT INTO file_previews (file_id, kind, status) VALUES ($1,'image','ready')`, junk); err != nil {
		t.Fatal(err)
	}
	if _, err := preview.PutItem(ctx, e.pool, e.store, e.keys, junk, "image", 0, strings.NewReader("not a png"), 9, preview.Item{}); err != nil {
		t.Fatal(err)
	}
	empty := e.putFile(t, a.ID, "v.mp4", []byte("x"))
	if _, err := e.pool.Exec(ctx, `INSERT INTO file_previews (file_id, kind, status) VALUES ($1,'video','ready')`, empty); err != nil {
		t.Fatal(err)
	}
	vid := e.putFile(t, a.ID, "v2.mp4", []byte("x"))
	e.seedVideo(t, vid)
	e.login(t, "a@x.com", pw)

	// The handler answers "page out of range" and "item missing" with the same 404 not_found,
	// so the two are told apart by setup: page 0 of short serves, page 1 is in range
	// (page_count 2) but has no stored item, page 2 is out of range.
	for p, want := range map[string]int{
		none.String() + "/preview/pages/0":      404, // no preview row
		short.String() + "/preview/pages/0":     200, // stored page serves
		short.String() + "/preview/pages/1":     404, // in range, item missing
		short.String() + "/preview/pages/2":     404, // out of range
		junk.String() + "/preview/pages/0":      500, // stored item is not a PNG
		empty.String() + "/preview/video.m3u8":  404, // no segments
		vid.String() + "/preview/segments/0":    404, // no .ts
		vid.String() + "/preview/segments/x.ts": 404,
	} {
		resp, b := e.get(t, "/api/files/"+p)
		if resp.StatusCode != want {
			t.Fatal(p, resp.StatusCode, string(b))
		}
		if want == 404 && !strings.Contains(string(b), "not_found") {
			t.Fatal(p, string(b))
		}
	}

	_, tok := e.recipShare(t, false, []uuid.UUID{vid}, "r@y.com")
	e.recipVerify(t, tok, "r@y.com")
	if resp, _ := e.get(t, "/api/s/"+tok+"/files/not-a-uuid/preview"); resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}
}
