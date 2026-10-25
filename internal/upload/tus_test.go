package upload

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/blob"
	"github.com/tntrock/secure-exchange/internal/config"
	"github.com/tntrock/secure-exchange/internal/db/testdb"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
)

const testMax = 16 << 20

type env struct {
	t       *testing.T
	ts      *httptest.Server
	pool    *pgxpool.Pool
	keys    *sxcrypto.Keyring
	keySpec string
	store   blob.Store
	staging string
	users   map[string]*auth.User
	h       *handler
	failPut atomic.Bool // makes blob Put fail, so a completed upload's row survives
}

func newEnv(t *testing.T) *env {
	t.Helper()
	pool := testdb.New(t)
	k := make([]byte, 32)
	rand.Read(k)
	keys, err := sxcrypto.ParseKeyring("1:"+base64.StdEncoding.EncodeToString(k), 1)
	if err != nil {
		t.Fatal(err)
	}
	store, err := blob.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, pool: pool, keys: keys, keySpec: "1:" + base64.StdEncoding.EncodeToString(k), store: store, staging: t.TempDir(), users: map[string]*auth.User{}}
	us := auth.NewUsers(pool, keys)
	for _, name := range []string{"a", "b"} {
		u, err := us.Create(context.Background(), name+"@example.com", name, "staff", "password-12345")
		if err != nil {
			t.Fatal(err)
		}
		e.users[name] = u
	}
	e.h = NewHandler(pool, keys, flakyStore{store, &e.failPut}, audit.New(pool), e.staging, testMax, nil, config.PreviewConfig{MaxBytes: testMax, MaxVideoBytes: testMax}).(*handler)
	h := e.h
	// stands in for httpapi's requireUser
	e.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), e.users[r.Header.Get("X-Test-User")])))
	}))
	t.Cleanup(e.ts.Close)
	return e
}

func (e *env) req(user, method, path string, body io.Reader, hdr ...string) *http.Response {
	e.t.Helper()
	if !strings.HasPrefix(path, "/") {
		path = "/api/uploads/" + path
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
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp
}

func (e *env) create(user string, size int64) string {
	e.t.Helper()
	meta := "filename " + base64.StdEncoding.EncodeToString([]byte("報告.bin")) + ",filetype " + base64.StdEncoding.EncodeToString([]byte("application/x-test"))
	resp := e.req(user, "POST", "/api/uploads/", nil, "Upload-Length", strconv.FormatInt(size, 10), "Upload-Metadata", meta)
	if resp.StatusCode != 201 {
		e.t.Fatalf("create: %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	return loc[strings.LastIndex(loc, "/")+1:]
}

func (e *env) patch(user, id string, off int64, data []byte) *http.Response {
	e.t.Helper()
	return e.req(user, "PATCH", id, bytes.NewReader(data),
		"Content-Type", "application/offset+octet-stream", "Upload-Offset", strconv.FormatInt(off, 10))
}

func (e *env) head(user, id string) *http.Response { e.t.Helper(); return e.req(user, "HEAD", id, nil) }

// readBack checks the files row and decrypts the stored blob.
func (e *env) readBack(id string, want []byte) {
	e.t.Helper()
	ctx := context.Background()
	var size int64
	var sum, wrapped []byte
	var keyID int
	var key, name, ctype string
	err := e.pool.QueryRow(ctx, `SELECT size, sha256, wrapped_dek, key_id, storage_key, name, content_type FROM files WHERE id = $1`, id).
		Scan(&size, &sum, &wrapped, &keyID, &key, &name, &ctype)
	if err != nil {
		e.t.Fatal(err)
	}
	if h := sha256.Sum256(want); size != int64(len(want)) || !bytes.Equal(sum, h[:]) || key != id || name != "報告.bin" || ctype != "application/x-test" {
		e.t.Fatalf("files row mismatch: size=%d key=%s name=%q type=%q", size, key, name, ctype)
	}
	dek, err := e.keys.UnwrapDEK(wrapped, keyID)
	if err != nil {
		e.t.Fatal(err)
	}
	open := func(ctx context.Context, off, n int64) (io.ReadCloser, error) {
		return e.store.OpenRange(ctx, key, off, n)
	}
	r := sxcrypto.OpenPlain(ctx, open, dek, uuid.MustParse(id), size)
	defer r.Close()
	got, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(got, want) {
		e.t.Fatalf("read back: err=%v equal=%v", err, bytes.Equal(got, want))
	}
	var n int
	e.pool.QueryRow(ctx, `SELECT count(*) FROM uploads WHERE id = $1`, id).Scan(&n)
	if _, err := os.Stat(filepath.Join(e.staging, id)); n != 0 || !os.IsNotExist(err) {
		e.t.Fatalf("upload leftovers: rows=%d stat=%v", n, err)
	}
}

func random(n int) []byte { b := make([]byte, n); rand.Read(b); return b }

func TestTusFullUpload(t *testing.T) {
	e := newEnv(t)
	data := random(3*sxcrypto.ChunkSize + sxcrypto.ChunkSize/2)
	id := e.create("a", int64(len(data)))
	resp := e.patch("a", id, 0, data)
	if resp.StatusCode != 204 || resp.Header.Get("Upload-Offset") != strconv.Itoa(len(data)) || resp.Header.Get("X-SX-File-ID") != id {
		t.Fatalf("patch: %d %v", resp.StatusCode, resp.Header)
	}
	if resp.Header.Get("Tus-Resumable") != "1.0.0" {
		t.Fatal("missing Tus-Resumable")
	}
	e.readBack(id, data)
	ents, err := audit.New(e.pool).List(context.Background(), audit.Filter{Action: audit.ActUpload})
	if err != nil || len(ents) != 1 || ents[0].Event.TargetID != id || ents[0].Event.ActorID != e.users["a"].ID.String() {
		t.Fatalf("audit: %v %+v", err, ents)
	}
}

func TestTusEmptyFile(t *testing.T) {
	e := newEnv(t)
	meta := "filename " + base64.StdEncoding.EncodeToString([]byte("報告.bin")) + ",filetype " + base64.StdEncoding.EncodeToString([]byte("application/x-test"))
	resp := e.req("a", "POST", "/api/uploads/", nil, "Upload-Length", "0", "Upload-Metadata", meta)
	id := resp.Header.Get("X-SX-File-ID")
	if resp.StatusCode != 201 || id == "" {
		t.Fatalf("create: %d %v", resp.StatusCode, resp.Header)
	}
	e.readBack(id, nil)
}

func TestTusResumeAfterPartialPatch(t *testing.T) {
	e := newEnv(t)
	data := random(4 * sxcrypto.ChunkSize)
	id := e.create("a", int64(len(data)))
	// body ends after 2.5 MiB: the half chunk is discarded
	if resp := e.patch("a", id, 0, data[:5*sxcrypto.ChunkSize/2]); resp.StatusCode != 204 || resp.Header.Get("Upload-Offset") != strconv.Itoa(2*sxcrypto.ChunkSize) {
		t.Fatalf("partial patch: %d %v", resp.StatusCode, resp.Header)
	}
	resp := e.head("a", id)
	if resp.StatusCode != 200 || resp.Header.Get("Upload-Offset") != strconv.Itoa(2*sxcrypto.ChunkSize) || resp.Header.Get("Upload-Length") != strconv.Itoa(len(data)) {
		t.Fatalf("head: %d %v", resp.StatusCode, resp.Header)
	}
	if resp := e.patch("a", id, 2*sxcrypto.ChunkSize, data[2*sxcrypto.ChunkSize:]); resp.StatusCode != 204 {
		t.Fatalf("resume: %d", resp.StatusCode)
	}
	e.readBack(id, data)
}

// A crash after appending a chunk but before the DB update leaves extra ciphertext; it must be cut off.
func TestTusTruncatesTornWrite(t *testing.T) {
	e := newEnv(t)
	data := random(2*sxcrypto.ChunkSize + 10)
	id := e.create("a", int64(len(data)))
	e.patch("a", id, 0, data[:sxcrypto.ChunkSize])
	f, err := os.OpenFile(filepath.Join(e.staging, id), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.Write(random(3*sxcrypto.SealedChunkSize + 7))
	f.Close()
	if resp := e.patch("a", id, sxcrypto.ChunkSize, data[sxcrypto.ChunkSize:]); resp.StatusCode != 204 {
		t.Fatalf("patch: %d", resp.StatusCode)
	}
	e.readBack(id, data)
}

func TestTusRejectsMisalignedOffset(t *testing.T) {
	e := newEnv(t)
	data := random(3 * sxcrypto.ChunkSize)
	id := e.create("a", int64(len(data)))
	if resp := e.patch("a", id, sxcrypto.ChunkSize, data[:sxcrypto.ChunkSize]); resp.StatusCode != 409 {
		t.Fatalf("wrong offset: %d", resp.StatusCode)
	}
	e.patch("a", id, 0, data[:sxcrypto.ChunkSize])
	if resp := e.patch("a", id, sxcrypto.ChunkSize+1, data[:10]); resp.StatusCode != 409 {
		t.Fatalf("unaligned offset: %d", resp.StatusCode)
	}
}

func TestTusConcurrentPatchConflict(t *testing.T) {
	e := newEnv(t)
	id := e.create("a", 10)
	// a PATCH whose body stalls holds the upload's lock
	pr, pw := io.Pipe()
	done := make(chan *http.Response)
	go func() {
		r, _ := http.NewRequest("PATCH", e.ts.URL+"/api/uploads/"+id, pr)
		r.Header.Set("X-Test-User", "a")
		r.Header.Set("Tus-Resumable", "1.0.0")
		r.Header.Set("Content-Type", "application/offset+octet-stream")
		r.Header.Set("Upload-Offset", "0")
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Error(err)
			done <- nil
			return
		}
		resp.Body.Close()
		done <- resp
	}()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		e.h.mu.Lock()
		busy := e.h.active[uuid.MustParse(id)]
		e.h.mu.Unlock()
		if busy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("slow PATCH never took the lock")
		}
	}
	if resp := e.patch("a", id, 0, random(10)); resp.StatusCode != 409 {
		t.Fatalf("concurrent patch: %d", resp.StatusCode)
	}
	if resp := e.req("a", "DELETE", id, nil); resp.StatusCode != 409 {
		t.Fatalf("concurrent delete: %d", resp.StatusCode)
	}
	pw.Close() // empty body: nothing appended, lock released
	if resp := <-done; resp == nil || resp.StatusCode != 204 || resp.Header.Get("Upload-Offset") != "0" {
		t.Fatalf("slow patch: %v", resp)
	}
	if resp := e.patch("a", id, 0, random(10)); resp.StatusCode != 204 {
		t.Fatalf("unlocked patch: %d", resp.StatusCode)
	}
}

func TestTusTooLarge(t *testing.T) {
	e := newEnv(t)
	if resp := e.req("a", "POST", "/api/uploads/", nil, "Upload-Length", strconv.Itoa(testMax+1)); resp.StatusCode != 413 {
		t.Fatalf("got %d", resp.StatusCode)
	}
}

func TestTusProtocol(t *testing.T) {
	e := newEnv(t)
	resp := e.req("a", "OPTIONS", "/api/uploads/", nil, "Tus-Resumable", "")
	if resp.StatusCode != 204 || resp.Header.Get("Tus-Version") != "1.0.0" || resp.Header.Get("Tus-Extension") != "creation,termination" || resp.Header.Get("Tus-Max-Size") != strconv.Itoa(testMax) {
		t.Fatalf("options: %d %v", resp.StatusCode, resp.Header)
	}
	if resp := e.req("a", "POST", "/api/uploads/", nil, "Tus-Resumable", "0.2.0", "Upload-Length", "5"); resp.StatusCode != 412 {
		t.Fatalf("bad version: %d", resp.StatusCode)
	}
	if resp := e.req("a", "POST", "/api/uploads/", nil); resp.StatusCode != 400 {
		t.Fatalf("no length: %d", resp.StatusCode)
	}
	hostile := "filename " + base64.StdEncoding.EncodeToString(append([]byte("a\x00\xff"), bytes.Repeat([]byte("x"), 1000)...))
	if resp := e.req("a", "POST", "/api/uploads/", nil, "Upload-Length", "5", "Upload-Metadata", hostile); resp.StatusCode != 201 {
		t.Fatalf("hostile filename: %d", resp.StatusCode)
	}
	var name string
	e.pool.QueryRow(context.Background(), `SELECT name FROM uploads WHERE size = 5`).Scan(&name)
	if len(name) > maxMetaLen || !strings.HasPrefix(name, "a�x") {
		t.Fatalf("stored name %q", name)
	}
	id := e.create("a", 10)
	if resp := e.req("a", "PATCH", id, bytes.NewReader(random(10)), "Upload-Offset", "0"); resp.StatusCode != 415 {
		t.Fatalf("content type: %d", resp.StatusCode)
	}
}

func TestTusOtherUserCannotAccess(t *testing.T) {
	e := newEnv(t)
	id := e.create("a", 10)
	if resp := e.head("b", id); resp.StatusCode != 404 {
		t.Fatalf("head: %d", resp.StatusCode)
	}
	if resp := e.patch("b", id, 0, random(10)); resp.StatusCode != 404 {
		t.Fatalf("patch: %d", resp.StatusCode)
	}
	if resp := e.req("b", "DELETE", id, nil); resp.StatusCode != 404 {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	if resp := e.head("a", id); resp.StatusCode != 200 {
		t.Fatalf("owner head: %d", resp.StatusCode)
	}
}

func TestTusDelete(t *testing.T) {
	e := newEnv(t)
	id := e.create("a", 10)
	if resp := e.req("a", "DELETE", id, nil); resp.StatusCode != 204 {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	if resp := e.head("a", id); resp.StatusCode != 404 {
		t.Fatalf("head after delete: %d", resp.StatusCode)
	}
	if _, err := os.Stat(filepath.Join(e.staging, id)); !os.IsNotExist(err) {
		t.Fatalf("staging left: %v", err)
	}
}

func TestStagingIsEncrypted(t *testing.T) {
	e := newEnv(t)
	plain := bytes.Repeat([]byte("PLAINTEXT"), 4*sxcrypto.ChunkSize/9)
	id := e.create("a", int64(len(plain)))
	e.patch("a", id, 0, plain[:5*sxcrypto.ChunkSize/2])
	st, err := os.ReadFile(filepath.Join(e.staging, id))
	if err != nil {
		t.Fatal(err)
	}
	if len(st) != 2*sxcrypto.SealedChunkSize || bytes.Contains(st, []byte("PLAINTEXT")) {
		t.Fatalf("staging len=%d contains plaintext=%v", len(st), bytes.Contains(st, []byte("PLAINTEXT")))
	}
}

func TestJanitorRemovesStale(t *testing.T) {
	e := newEnv(t)
	stale, fresh := e.create("a", 10), e.create("a", 10)
	ctx := context.Background()
	if _, err := e.pool.Exec(ctx, `UPDATE uploads SET updated_at = now() - interval '25 hours' WHERE id = $1`, stale); err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(e.staging, uuid.NewString()) // e.g. crash after completion, before the staging file was removed
	os.WriteFile(orphan, []byte("x"), 0o600)
	old := time.Now().Add(-25 * time.Hour)
	os.Chtimes(orphan, old, old)

	sweep(ctx, e.pool, e.store, e.staging, 24*time.Hour)

	var n int
	e.pool.QueryRow(ctx, `SELECT count(*) FROM uploads`).Scan(&n)
	if n != 1 {
		t.Fatalf("rows left: %d", n)
	}
	for p, gone := range map[string]bool{filepath.Join(e.staging, stale): true, orphan: true, filepath.Join(e.staging, fresh): false} {
		if _, err := os.Stat(p); os.IsNotExist(err) != gone {
			t.Fatalf("%s: gone=%v err=%v", p, gone, err)
		}
	}
}

type flakyStore struct {
	blob.Store
	fail *atomic.Bool
}

func (s flakyStore) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	if s.fail.Load() {
		return io.ErrClosedPipe
	}
	return s.Store.Put(ctx, key, r, size)
}

// sha256's marshalled state holds the unprocessed tail (<64 B) in the clear,
// so it must be sealed before it reaches the database.
func TestHashStateNotPlaintext(t *testing.T) {
	e := newEnv(t)
	marker := []byte("SECRET-MARKER-0123456789-abcdefghijklmn") // 39 bytes: all of it stays in sha256's buffer
	id := e.create("a", int64(len(marker)))
	e.failPut.Store(true)
	if resp := e.patch("a", id, 0, marker); resp.StatusCode != 500 {
		t.Fatalf("patch with failing store: %d", resp.StatusCode)
	}
	var state []byte
	if err := e.pool.QueryRow(context.Background(), `SELECT hash_state FROM uploads WHERE id = $1`, id).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(state, marker[:16]) {
		t.Fatal("hash_state contains plaintext")
	}
	e.failPut.Store(false)
	if resp := e.patch("a", id, int64(len(marker)), nil); resp.StatusCode != 204 || resp.Header.Get("X-SX-File-ID") != id {
		t.Fatalf("retry: %d %v", resp.StatusCode, resp.Header)
	}
	e.readBack(id, marker)
}

// A PATCH that began before key rotation holds the old wrapped DEK in memory;
// finishing it must still store the rotated DEK in files.
func TestFinishUsesRotatedDEK(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	data := random(1000)
	id := e.create("a", int64(len(data)))
	e.failPut.Store(true) // upload completes but finish fails, leaving the uploads row and staging file
	if resp := e.patch("a", id, 0, data); resp.StatusCode == 204 {
		t.Fatal("expected finish to fail")
	}
	e.failPut.Store(false)

	uid := uuid.MustParse(id)
	stale := &upload{id: uid}
	if err := e.pool.QueryRow(ctx, `SELECT owner_id, name, content_type, size, wrapped_dek, key_id FROM uploads WHERE id=$1`, uid).
		Scan(&stale.owner, &stale.name, &stale.contentType, &stale.size, &stale.wrappedDEK, &stale.keyID); err != nil {
		t.Fatal(err)
	}
	if stale.keyID != 1 {
		t.Fatalf("setup: key_id %d", stale.keyID)
	}
	both, err := sxcrypto.ParseKeyring(e.keySpec+",2:"+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)), 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sxcrypto.RotateAll(ctx, e.pool, both); err != nil {
		t.Fatal(err)
	}

	e.h.keys = both // the running server holds the rotated keyring too; finish classifies with the re-read DEK
	r := httptest.NewRequest("PATCH", "/", nil)
	if err := e.h.finish(r, stale, sha256.New()); err != nil {
		t.Fatal(err)
	}
	var kid int
	var w []byte
	if err := e.pool.QueryRow(ctx, `SELECT key_id, wrapped_dek FROM files WHERE id=$1`, uid).Scan(&kid, &w); err != nil {
		t.Fatal(err)
	}
	if kid != 2 {
		t.Fatalf("files.key_id = %d, want 2 (stale DEK stored)", kid)
	}
	if _, err := both.UnwrapDEK(w, kid); err != nil {
		t.Fatal(err)
	}
}

// A failed finish leaves offset == size committed; tus clients then HEAD and
// would report success, so HEAD must complete the upload (or fail with 500).
func TestHeadCompletesFailedFinish(t *testing.T) {
	e := newEnv(t)
	data := random(sxcrypto.ChunkSize + 100)
	id := e.create("a", int64(len(data)))
	e.failPut.Store(true)
	if resp := e.patch("a", id, 0, data); resp.StatusCode != 500 {
		t.Fatalf("patch with failing store: %d", resp.StatusCode)
	}
	if resp := e.head("a", id); resp.StatusCode != 500 {
		t.Fatalf("head with failing store: %d", resp.StatusCode)
	}
	e.failPut.Store(false)
	resp := e.head("a", id)
	if resp.StatusCode != 200 || resp.Header.Get("Upload-Offset") != strconv.Itoa(len(data)) ||
		resp.Header.Get("Upload-Length") != strconv.Itoa(len(data)) || resp.Header.Get("X-SX-File-ID") != id {
		t.Fatalf("head: %d %v", resp.StatusCode, resp.Header)
	}
	e.readBack(id, data)
	if resp := e.head("a", id); resp.StatusCode != 404 {
		t.Fatalf("head after completion: %d", resp.StatusCode)
	}
}

// A stale row whose finish failed after Put may have left a blob behind.
func TestJanitorDeletesOrphanBlob(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	id := e.create("a", 10)
	if err := e.store.Put(ctx, id, bytes.NewReader([]byte("x")), 1); err != nil {
		t.Fatal(err)
	}
	e.pool.Exec(ctx, `UPDATE uploads SET updated_at = now() - interval '25 hours' WHERE id = $1`, id)
	sweep(ctx, e.pool, e.store, e.staging, 24*time.Hour)
	if r, err := e.store.OpenRange(ctx, id, 0, 1); err == nil {
		r.Close()
		t.Fatal("orphan blob survived")
	}
}

// createNamed uploads data under name in one PATCH and returns the file id.
func (e *env) createNamed(name string, data []byte) string {
	e.t.Helper()
	meta := "filename " + base64.StdEncoding.EncodeToString([]byte(name))
	resp := e.req("a", "POST", "/api/uploads/", nil, "Upload-Length", strconv.Itoa(len(data)), "Upload-Metadata", meta)
	if resp.StatusCode != 201 {
		e.t.Fatalf("create: %d", resp.StatusCode)
	}
	id := resp.Header.Get("Location")
	id = id[strings.LastIndex(id, "/")+1:]
	if len(data) > 0 {
		if resp := e.patch("a", id, 0, data); resp.StatusCode != 204 {
			e.t.Fatalf("patch: %d", resp.StatusCode)
		}
	}
	return id
}

func TestUploadEnqueuesPreview(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	state := func(id string) (kind, status string, jobs int) {
		e.t.Helper()
		if err := e.pool.QueryRow(ctx, `SELECT kind, status FROM file_previews WHERE file_id = $1`, id).Scan(&kind, &status); err != nil {
			e.t.Fatalf("file_previews: %v", err)
		}
		e.pool.QueryRow(ctx, `SELECT count(*) FROM render_jobs WHERE file_id = $1 AND status = 'queued'`, id).Scan(&jobs)
		return
	}
	// multi-chunk upload: classification must read chunk 0 back from staging
	big := append([]byte("%PDF-1.7\n"), make([]byte, sxcrypto.ChunkSize+5)...)
	for name, tc := range map[string]struct {
		data         []byte
		kind, status string
		jobs         int
	}{
		"a.pdf":     {[]byte("%PDF-1.4 tiny"), "pages", "pending", 1},
		"b.pdf":     {big, "pages", "pending", 1},
		"c.zip":     {[]byte("PK\x03\x04zip"), "none", "unsupported", 0},
		"empty.txt": {nil, "none", "unsupported", 0},
	} {
		k, s, j := state(e.createNamed(name, tc.data))
		if k != tc.kind || s != tc.status || j != tc.jobs {
			t.Errorf("%s: got %s/%s jobs=%d, want %s/%s jobs=%d", name, k, s, j, tc.kind, tc.status, tc.jobs)
		}
	}
}

func TestUploadSurvivesClassifyFailure(t *testing.T) {
	e := newEnv(t)
	data := []byte("%PDF-1.4 tiny")
	id := e.create("a", int64(len(data)))
	e.failPut.Store(true) // complete the upload but stop before finish commits
	e.patch("a", id, 0, data)
	e.failPut.Store(false)
	path := filepath.Join(e.staging, id)
	b, _ := os.ReadFile(path)
	b[0] ^= 0xff // corrupt chunk 0 so decryption fails
	os.WriteFile(path, b, 0o600)
	if resp := e.head("a", id); resp.StatusCode != 200 || resp.Header.Get("X-SX-File-ID") != id {
		t.Fatalf("head: %d", resp.StatusCode)
	}
	var kind, status string
	if err := e.pool.QueryRow(context.Background(), `SELECT kind, status FROM file_previews WHERE file_id = $1`, id).Scan(&kind, &status); err != nil || kind != "none" || status != "failed" {
		t.Fatalf("preview %s/%s %v", kind, status, err)
	}
}
