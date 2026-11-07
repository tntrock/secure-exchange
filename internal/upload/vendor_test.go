package upload

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/tntrock/secure-exchange/internal/auth"
)

// vendor adds a vendor account created by staff user creator, reachable as X-Test-User name.
func (e *env) vendor(name, creator string) *auth.User {
	e.t.Helper()
	u, err := auth.NewUsers(e.pool, e.keys).Create(context.Background(), name+"@vendor.com", name, "vendor", "password-12345")
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.pool.Exec(context.Background(), `UPDATE users SET created_by = $2 WHERE id = $1`, u.ID, e.users[creator].ID); err != nil {
		e.t.Fatal(err)
	}
	e.users[name] = u
	return u
}

// shareTo records a share from owner to vendor v.
func (e *env) shareTo(owner, v uuid.UUID) {
	e.t.Helper()
	sid := uuid.New()
	if _, err := e.pool.Exec(context.Background(), `INSERT INTO shares (id, owner_id, token_hash, token_sealed, allow_download, watermark, expires_at)
		VALUES ($1,$2,$3,'\x00',true,false,now() + interval '1 day')`, sid, owner, sid[:]); err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.pool.Exec(context.Background(), `INSERT INTO share_recipients (id, share_id, email, vendor_id) VALUES ($1,$2,'v@vendor.com',$3)`, uuid.New(), sid, v); err != nil {
		e.t.Fatal(err)
	}
}

// vreq sends a request on the vendor mount as user; it returns the response and its body.
func (e *env) vreq(user, method, path string, body io.Reader, hdr ...string) (*http.Response, string) {
	e.t.Helper()
	if !strings.HasPrefix(path, "/") {
		path = "/api/vendor/uploads/" + path
	}
	r, _ := http.NewRequest(method, e.ts.URL+path, body)
	r.Header.Set("X-Test-User", user)
	r.Header.Set("Tus-Resumable", "1.0.0")
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		e.t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

// vcreate starts a vendor upload; recipient "" leaves the metadata key out.
func (e *env) vcreate(user, recipient string, size int64) (*http.Response, string) {
	e.t.Helper()
	meta := "filename " + base64.StdEncoding.EncodeToString([]byte("v.pdf"))
	if recipient != "" {
		meta += ",recipient " + base64.StdEncoding.EncodeToString([]byte(recipient))
	}
	return e.vreq(user, "POST", "/api/vendor/uploads/", nil, "Upload-Length", strconv.FormatInt(size, 10), "Upload-Metadata", meta)
}

func TestVendorUploadCreatesPendingFile(t *testing.T) {
	e := newEnv(t)
	v := e.vendor("v", "b")
	e.shareTo(e.users["a"].ID, v.ID)
	data := random(1000)
	resp, _ := e.vcreate("v", e.users["a"].ID.String(), int64(len(data)))
	loc := resp.Header.Get("Location")
	if resp.StatusCode != 201 || !strings.HasPrefix(loc, "/api/vendor/uploads/") {
		t.Fatalf("create: %d %q", resp.StatusCode, loc)
	}
	if r, _ := e.vreq("v", "PATCH", loc, strings.NewReader(string(data)), "Content-Type", "application/offset+octet-stream", "Upload-Offset", "0"); r.StatusCode != 204 {
		t.Fatalf("patch: %d", r.StatusCode)
	}
	id := loc[strings.LastIndex(loc, "/")+1:]
	if n := e.count(`SELECT count(*) FROM files WHERE id = $1 AND owner_id = $2 AND vendor_id = $3 AND request_id IS NULL AND uploader_id IS NULL AND scan_status = 'pending'`,
		id, e.users["a"].ID, v.ID); n != 1 {
		t.Fatal("files row wrong")
	}
	if n := e.count(`SELECT count(*) FROM scan_jobs WHERE file_id = $1`, id); n != 1 {
		t.Fatal("no scan job")
	}
	if n := e.count(`SELECT count(*) FROM audit_log WHERE actor_type = 'vendor' AND actor_id = $1 AND target_id = $2 AND detail->>'recipient_id' = $3`,
		v.ID.String(), id, e.users["a"].ID.String()); n != 1 {
		t.Fatal("audit wrong")
	}
	// the creator of the vendor account is a target too; an empty file finishes on create
	if resp, _ := e.vcreate("v", e.users["b"].ID.String(), 0); resp.StatusCode != 201 || resp.Header.Get("X-SX-File-ID") == "" {
		t.Fatalf("creator: %d", resp.StatusCode)
	}
}

func TestVendorUploadTargetNotAllowed(t *testing.T) {
	e := newEnv(t)
	v := e.vendor("v", "b")
	adm, err := auth.NewUsers(e.pool, e.keys).Create(context.Background(), "adm@example.com", "adm", "admin", "password-12345")
	if err != nil {
		t.Fatal(err)
	}
	e.shareTo(e.users["a"].ID, v.ID)
	if _, err := e.pool.Exec(context.Background(), `UPDATE users SET disabled = true WHERE id = $1`, e.users["a"].ID); err != nil {
		t.Fatal(err)
	}
	for name, rcpt := range map[string]string{"arbitrary": uuid.NewString(), "admin never shared": adm.ID.String(),
		"disabled staff who shared": e.users["a"].ID.String(), "missing": "", "malformed": "not-a-uuid", "vendor itself": v.ID.String()} {
		resp, body := e.vcreate("v", rcpt, 10)
		if resp.StatusCode != 403 || body != "recipient_not_allowed" || resp.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
			t.Errorf("%s: %d %q", name, resp.StatusCode, body)
		}
	}
	if n := e.count(`SELECT count(*) FROM uploads`); n != 0 {
		t.Fatal("upload row created", n)
	}
}

func TestVendorUploadIsolation(t *testing.T) {
	e := newEnv(t)
	va, vb := e.vendor("va", "a"), e.vendor("vb", "a")
	resp, _ := e.vcreate("va", e.users["a"].ID.String(), 10)
	loc := resp.Header.Get("Location")
	id := loc[strings.LastIndex(loc, "/")+1:]
	if resp.StatusCode != 201 {
		t.Fatal(resp.StatusCode)
	}
	if r, _ := e.vreq("vb", "HEAD", loc, nil); r.StatusCode != 404 {
		t.Fatalf("vb head: %d", r.StatusCode)
	}
	if r, _ := e.vreq("vb", "PATCH", loc, strings.NewReader("x"), "Content-Type", "application/offset+octet-stream", "Upload-Offset", "0"); r.StatusCode != 404 {
		t.Fatalf("vb patch: %d", r.StatusCode)
	}
	if r, _ := e.vreq("vb", "DELETE", loc, nil); r.StatusCode != 404 {
		t.Fatalf("vb delete: %d", r.StatusCode)
	}
	if r := e.head("a", id); r.StatusCode != 404 { // the target, as staff
		t.Fatalf("staff head: %d", r.StatusCode)
	}
	if r := e.req("a", "DELETE", id, nil); r.StatusCode != 404 {
		t.Fatalf("staff delete: %d", r.StatusCode)
	}
	sid := e.create("a", 10)
	if r, _ := e.vreq("va", "HEAD", sid, nil); r.StatusCode != 404 {
		t.Fatalf("vendor head of staff upload: %d", r.StatusCode)
	}
	if r, _ := e.vreq("va", "HEAD", loc, nil); r.StatusCode != 200 {
		t.Fatalf("own head: %d", r.StatusCode)
	}
	if r, _ := e.vreq("va", "DELETE", loc, nil); r.StatusCode != 204 {
		t.Fatalf("own delete: %d", r.StatusCode)
	}
	if n := e.count(`SELECT count(*) FROM uploads WHERE vendor_id = ANY($1)`, []uuid.UUID{va.ID, vb.ID}); n != 0 {
		t.Fatal("vendor upload left", n)
	}
}

func TestVendorUploadRecipientNotAllowedAudited(t *testing.T) {
	e := newEnv(t)
	v := e.vendor("v", "b")
	rcpt := uuid.NewString()
	if resp, body := e.vcreate("v", rcpt, 10); resp.StatusCode != 403 || body != "recipient_not_allowed" {
		t.Fatal(resp.StatusCode, body)
	}
	if n := e.count(`SELECT count(*) FROM audit_log WHERE action = 'file.upload' AND result = 'fail' AND actor_type = 'vendor' AND actor_id = $1 AND detail->>'reason' = 'recipient_not_allowed'`, v.ID.String()); n != 1 {
		t.Fatal("denied audit rows", n)
	}
}
