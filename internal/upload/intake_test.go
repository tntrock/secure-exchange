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

	"github.com/tntrock/secure-exchange/internal/intake"
)

// extUploader makes an upload request owned by staff user "a" with one verified uploader.
func (e *env) extUploader(email string, exts []string, maxFiles int, reqID *uuid.UUID) *intake.Access {
	e.t.Helper()
	ctx := context.Background()
	if exts == nil {
		exts = []string{}
	}
	if *reqID == uuid.Nil {
		*reqID = uuid.New()
		if _, err := e.pool.Exec(ctx, `INSERT INTO upload_requests (id, owner_id, token_hash, token_sealed, expires_at, max_files, max_total_bytes, allowed_exts)
			VALUES ($1,$2,$3,'\x00', now() + interval '1 day', $4, 1000000000, $5)`, *reqID, e.users["a"].ID, reqID[:], maxFiles, exts); err != nil {
			e.t.Fatal(err)
		}
	}
	a := &intake.Access{Request: &intake.Request{ID: *reqID, OwnerID: e.users["a"].ID, MaxFiles: maxFiles, MaxTotalBytes: 1000000000, AllowedExts: exts},
		Uploader: intake.Uploader{ID: uuid.New(), Email: email}}
	if _, err := e.pool.Exec(ctx, `INSERT INTO request_uploaders (id, request_id, email) VALUES ($1,$2,$3)`, a.Uploader.ID, *reqID, email); err != nil {
		e.t.Fatal(err)
	}
	e.access[a.Uploader.ID.String()] = a
	return a
}

// ext sends a request on the external mount as uploader a (nil = nobody extra).
func (e *env) ext(a *intake.Access, method, path string, body io.Reader, hdr ...string) (*http.Response, string) {
	e.t.Helper()
	r, _ := http.NewRequest(method, e.ts.URL+path, body)
	r.Header.Set("Tus-Resumable", "1.0.0")
	r.Header.Set("X-Test-Uploader", a.Uploader.ID.String())
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

func (e *env) extCreate(a *intake.Access, tok, name string, size int64) (*http.Response, string) {
	meta := "filename " + base64.StdEncoding.EncodeToString([]byte(name))
	return e.ext(a, "POST", "/api/r/"+tok+"/uploads/", nil, "Upload-Length", strconv.FormatInt(size, 10), "Upload-Metadata", meta)
}

func TestIntakeUploadCreatesPendingFile(t *testing.T) {
	e := newEnv(t)
	var rid uuid.UUID
	a := e.extUploader("x@example.com", nil, 3, &rid)
	data := random(1000)
	resp, _ := e.extCreate(a, "tok", "a.pdf", int64(len(data)))
	loc := resp.Header.Get("Location")
	if resp.StatusCode != 201 || !strings.HasPrefix(loc, "/api/r/tok/uploads/") {
		t.Fatalf("create: %d %q", resp.StatusCode, loc)
	}
	if resp, _ := e.ext(a, "PATCH", loc, strings.NewReader(string(data)), "Content-Type", "application/offset+octet-stream", "Upload-Offset", "0"); resp.StatusCode != 204 {
		t.Fatalf("patch: %d", resp.StatusCode)
	}
	id := loc[strings.LastIndex(loc, "/")+1:]
	if n := e.count(`SELECT count(*) FROM files WHERE id = $1 AND owner_id = $2 AND request_id = $3 AND uploader_id = $4 AND scan_status = 'pending'`,
		id, e.users["a"].ID, rid, a.Uploader.ID); n != 1 {
		t.Fatal("files row wrong")
	}
	if n := e.count(`SELECT count(*) FROM scan_jobs WHERE file_id = $1`, id); n != 1 {
		t.Fatal("no scan job")
	}
	if n := e.count(`SELECT count(*) FROM audit_log WHERE actor_type = 'uploader' AND actor_id = 'x@example.com' AND target_id = $1 AND detail->>'request_id' = $2`, id, rid.String()); n != 1 {
		t.Fatal("audit wrong")
	}
}

func TestIntakeUploadLimits(t *testing.T) {
	e := newEnv(t)
	var rid uuid.UUID
	a := e.extUploader("x@example.com", []string{"pdf"}, 1, &rid)
	if resp, body := e.extCreate(a, "tok", "x.exe", 10); resp.StatusCode != 403 || body != "ext_not_allowed" {
		t.Fatalf("ext: %d %q", resp.StatusCode, body)
	}
	if resp, _ := e.extCreate(a, "tok", "a.pdf", 10); resp.StatusCode != 201 {
		t.Fatalf("a.pdf: %d", resp.StatusCode)
	}
	if resp, body := e.extCreate(a, "tok", "b.pdf", 10); resp.StatusCode != 403 || body != "too_many_files" {
		t.Fatalf("count: %d %q", resp.StatusCode, body)
	}
}

func TestIntakeUploadIsolation(t *testing.T) {
	e := newEnv(t)
	var rid uuid.UUID
	a := e.extUploader("a@example.com", nil, 5, &rid)
	b := e.extUploader("b@example.com", nil, 5, &rid)
	resp, _ := e.extCreate(a, "tok", "a.pdf", 10)
	loc := resp.Header.Get("Location")
	id := loc[strings.LastIndex(loc, "/")+1:]
	if r, _ := e.ext(b, "HEAD", loc, nil); r.StatusCode != 404 {
		t.Fatalf("b head: %d", r.StatusCode)
	}
	if r, _ := e.ext(b, "PATCH", loc, strings.NewReader("x"), "Content-Type", "application/offset+octet-stream", "Upload-Offset", "0"); r.StatusCode != 404 {
		t.Fatalf("b patch: %d", r.StatusCode)
	}
	if r, _ := e.ext(b, "DELETE", loc, nil); r.StatusCode != 404 {
		t.Fatalf("b delete: %d", r.StatusCode)
	}
	if r := e.head("a", id); r.StatusCode != 404 { // the owner, as staff
		t.Fatalf("staff head: %d", r.StatusCode)
	}
	sid := e.create("a", 10)
	if r, _ := e.ext(a, "HEAD", "/api/r/tok/uploads/"+sid, nil); r.StatusCode != 404 {
		t.Fatalf("uploader head of staff upload: %d", r.StatusCode)
	}
}

func TestStaffUploadStillNone(t *testing.T) {
	e := newEnv(t)
	id := e.create("a", 10)
	if r := e.patch("a", id, 0, random(10)); r.StatusCode != 204 {
		t.Fatal(r.StatusCode)
	}
	if n := e.count(`SELECT count(*) FROM files WHERE id = $1 AND scan_status = 'none' AND request_id IS NULL AND uploader_id IS NULL`, id); n != 1 {
		t.Fatal("scan_status")
	}
	if n := e.count(`SELECT count(*) FROM scan_jobs`); n != 0 {
		t.Fatal("scan job for staff upload")
	}
}

func TestSweepRemovesExternalUpload(t *testing.T) {
	e := newEnv(t)
	var rid uuid.UUID
	a := e.extUploader("a@example.com", nil, 5, &rid)
	resp, _ := e.extCreate(a, "tok", "a.pdf", 10)
	id := resp.Header.Get("Location")[len("/api/r/tok/uploads/"):]
	if _, err := e.pool.Exec(context.Background(), `UPDATE uploads SET updated_at = now() - interval '2 days'`); err != nil {
		t.Fatal(err)
	}
	sweep(context.Background(), e.pool, e.store, e.staging, 3600e9)
	if n := e.count(`SELECT count(*) FROM uploads WHERE id = $1`, id); n != 0 {
		t.Fatal("not swept")
	}
}
