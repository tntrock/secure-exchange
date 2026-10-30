package upload

import (
	"bytes"
	"context"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/blob"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
)

func (e *env) count(q string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func TestTusRequestErrors(t *testing.T) {
	e := newEnv(t)
	if resp := e.req("", "POST", "/api/uploads/", nil, "Upload-Length", "5"); resp.StatusCode != 401 {
		t.Fatalf("no user: %d", resp.StatusCode)
	}
	if resp := e.req("a", "POST", "/api/uploads/", nil, "Upload-Length", "5", "Upload-Metadata", "filename !!!"); resp.StatusCode != 400 {
		t.Fatalf("bad base64 metadata: %d", resp.StatusCode)
	}
	// empty pairs are skipped
	if resp := e.req("a", "POST", "/api/uploads/", nil, "Upload-Length", "5", "Upload-Metadata", " ,filename eA==,"); resp.StatusCode != 201 {
		t.Fatalf("metadata with empty pairs: %d", resp.StatusCode)
	}
	id := e.create("a", 10)
	if resp := e.req("a", "PATCH", id, bytes.NewReader(random(10)), "Content-Type", "application/offset+octet-stream", "Upload-Offset", "x"); resp.StatusCode != 400 {
		t.Fatalf("bad offset: %d", resp.StatusCode)
	}
	for _, m := range []string{"HEAD", "PATCH", "DELETE"} {
		if resp := e.req("a", m, "not-a-uuid", nil, "Content-Type", "application/offset+octet-stream", "Upload-Offset", "0"); resp.StatusCode != 404 {
			t.Fatalf("%s bad id: %d", m, resp.StatusCode)
		}
	}
}

func TestTusBusyUpload(t *testing.T) {
	e := newEnv(t)
	data := random(10)
	id := e.create("a", int64(len(data)))
	e.failPut.Store(true)
	e.patch("a", id, 0, data) // offset == size, finish pending
	e.failPut.Store(false)

	e.h.tryLock(uuid.MustParse(id)) // another request holds the upload
	if resp := e.head("a", id); resp.StatusCode != 409 {
		t.Fatalf("head while busy: %d", resp.StatusCode)
	}
	if resp := e.req("a", "DELETE", id, nil); resp.StatusCode != 409 {
		t.Fatalf("delete while busy: %d", resp.StatusCode)
	}
	e.h.unlock(uuid.MustParse(id))
	if resp := e.head("a", id); resp.StatusCode != 200 || resp.Header.Get("X-SX-File-ID") != id {
		t.Fatalf("head after unlock: %d", resp.StatusCode)
	}
}

func TestTusCreateFailures(t *testing.T) {
	t.Run("user row gone", func(t *testing.T) {
		e := newEnv(t)
		e.users["ghost"] = &auth.User{ID: uuid.New()} // in the session but not in the database
		if resp := e.req("ghost", "POST", "/api/uploads/", nil, "Upload-Length", "5"); resp.StatusCode != 500 {
			t.Fatalf("got %d", resp.StatusCode)
		}
		if ents, _ := os.ReadDir(e.staging); len(ents) != 0 {
			t.Fatalf("staging file left: %v", ents)
		}
	})
	t.Run("staging dir missing", func(t *testing.T) {
		e := newEnv(t)
		os.RemoveAll(e.staging)
		if resp := e.req("a", "POST", "/api/uploads/", nil, "Upload-Length", "5"); resp.StatusCode != 500 {
			t.Fatalf("got %d", resp.StatusCode)
		}
		if n := e.count(`SELECT count(*) FROM uploads`); n != 0 {
			t.Fatalf("rows: %d", n)
		}
	})
	t.Run("empty file finish fails", func(t *testing.T) {
		e := newEnv(t)
		e.failPut.Store(true)
		if resp := e.req("a", "POST", "/api/uploads/", nil, "Upload-Length", "0"); resp.StatusCode != 500 {
			t.Fatalf("got %d", resp.StatusCode)
		}
		if n := e.count(`SELECT count(*) FROM files`); n != 0 {
			t.Fatalf("files: %d", n)
		}
	})
}

func TestTusPatchFailures(t *testing.T) {
	data := random(2 * sxcrypto.ChunkSize)
	cases := []struct {
		name string
		brk  func(e *env, id string)
	}{
		{"staging file missing", func(e *env, id string) { os.Remove(filepath.Join(e.staging, id)) }},
		{"staging file shorter than offset", func(e *env, id string) { os.Truncate(filepath.Join(e.staging, id), 10) }},
		{"hash state corrupt", func(e *env, id string) {
			e.pool.Exec(context.Background(), `UPDATE uploads SET hash_state = 'x' WHERE id = $1`, id)
		}},
		{"wrapped dek corrupt", func(e *env, id string) {
			e.pool.Exec(context.Background(), `UPDATE uploads SET wrapped_dek = 'x' WHERE id = $1`, id)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			id := e.create("a", int64(len(data)))
			if resp := e.patch("a", id, 0, data[:sxcrypto.ChunkSize]); resp.StatusCode != 204 {
				t.Fatalf("first patch: %d", resp.StatusCode)
			}
			c.brk(e, id)
			if resp := e.patch("a", id, sxcrypto.ChunkSize, data[sxcrypto.ChunkSize:]); resp.StatusCode != 500 {
				t.Fatalf("got %d", resp.StatusCode)
			}
			if n := e.count(`SELECT "offset" FROM uploads WHERE id = $1`, id); n != sxcrypto.ChunkSize {
				t.Fatalf("offset moved to %d", n)
			}
		})
	}
}

func TestHeadFinishFailsWithoutStaging(t *testing.T) {
	e := newEnv(t)
	data := random(10)
	id := e.create("a", int64(len(data)))
	e.failPut.Store(true)
	e.patch("a", id, 0, data)
	e.failPut.Store(false)
	os.Remove(filepath.Join(e.staging, id))
	if resp := e.head("a", id); resp.StatusCode != 500 {
		t.Fatalf("got %d", resp.StatusCode)
	}
	if n := e.count(`SELECT count(*) FROM files`); n != 0 {
		t.Fatalf("files: %d", n)
	}
}

func TestRunJanitor(t *testing.T) {
	e := newEnv(t)
	stale := e.create("a", 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := e.pool.Exec(ctx, `UPDATE uploads SET updated_at = now() - interval '2 hours' WHERE id = $1`, stale); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { RunJanitor(ctx, e.pool, e.store, e.staging, time.Hour); close(done) }()
	deadline := time.Now().Add(10 * time.Second)
	for e.count(`SELECT count(*) FROM uploads`) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("janitor did not sweep")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunJanitor did not return after cancel")
	}
}

func TestSweepSurvivesErrors(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	stale := e.create("a", 10)
	e.pool.Exec(ctx, `UPDATE uploads SET updated_at = now() - interval '25 hours' WHERE id = $1`, stale)
	// staging path and blob key are non-empty directories: neither can be removed
	sp := filepath.Join(e.staging, stale)
	os.Remove(sp)
	os.MkdirAll(filepath.Join(sp, "x"), 0o700)
	store := t.TempDir()
	bs, err := blob.NewLocal(store)
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(store, stale, "x"), 0o700)

	sweep(ctx, e.pool, bs, e.staging, 24*time.Hour)
	if n := e.count(`SELECT count(*) FROM uploads`); n != 0 {
		t.Fatalf("stale row kept: %d", n)
	}

	// missing staging dir and canceled context only log
	sweep(ctx, e.pool, bs, filepath.Join(e.staging, "missing"), 24*time.Hour)
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	fresh := e.create("a", 10)
	sweep(cctx, e.pool, bs, e.staging, 0)
	if n := e.count(`SELECT count(*) FROM uploads WHERE id = $1`, fresh); n != 1 {
		t.Fatalf("canceled sweep deleted rows: %d", n)
	}
}

// serve calls the handler directly, so the request context and body are fully controlled.
func (e *env) serve(ctx context.Context, user, method, id string, body io.Reader) *httptest.ResponseRecorder {
	e.t.Helper()
	if user != "" { // "" = ctx already carries the user
		ctx = auth.WithUser(ctx, e.users[user])
	}
	r := httptest.NewRequest(method, "/api/uploads/"+id, body).WithContext(ctx)
	r.Header.Set("Tus-Resumable", "1.0.0")
	r.Header.Set("Content-Type", "application/offset+octet-stream")
	r.Header.Set("Upload-Offset", "0")
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

func TestTusCanceledRequest(t *testing.T) {
	e := newEnv(t)
	id := e.create("a", 10)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, m := range []string{"HEAD", "PATCH", "DELETE"} {
		if w := e.serve(ctx, "a", m, id, bytes.NewReader(random(10))); w.Code != 500 {
			t.Fatalf("%s: %d", m, w.Code)
		}
	}
	if n := e.count(`SELECT count(*) FROM uploads WHERE id = $1`, id); n != 1 {
		t.Fatalf("upload row: %d", n)
	}
}

// cancelOnLookup cancels itself on the nth user lookup: ServeHTTP is 1, load 2,
// and the re-read under the upload lock 3 (the client gave up while waiting).
type cancelOnLookup struct {
	context.Context
	cancel func()
	n, at  int
}

func (c *cancelOnLookup) Value(k any) any {
	v := c.Context.Value(k)
	if _, ok := v.(*auth.User); ok {
		if c.n++; c.n == c.at {
			c.cancel()
		}
	}
	return v
}

func TestTusCanceledWhileWaitingForLock(t *testing.T) {
	e := newEnv(t)
	data := random(10)
	id := e.create("a", int64(len(data)))
	e.failPut.Store(true)
	e.patch("a", id, 0, data) // offset == size: HEAD takes the lock and re-reads
	e.failPut.Store(false)
	for _, m := range []string{"HEAD", "PATCH"} {
		ctx, cancel := context.WithCancel(auth.WithUser(context.Background(), e.users["a"]))
		w := e.serve(&cancelOnLookup{Context: ctx, cancel: cancel, at: 3}, "", m, id, bytes.NewReader(nil))
		cancel()
		if w.Code != 500 {
			t.Fatalf("%s: %d", m, w.Code)
		}
	}
	if n := e.count(`SELECT count(*) FROM files`); n != 0 {
		t.Fatalf("files: %d", n)
	}
}

// readHook runs fn on the first Read, i.e. after the handler loaded the upload.
type readHook struct {
	r    io.Reader
	fn   func()
	done bool
}

func (h *readHook) Read(p []byte) (int, error) {
	if !h.done {
		h.done = true
		h.fn()
	}
	return h.r.Read(p)
}

func TestTusPatchRowVanishes(t *testing.T) {
	e := newEnv(t)
	id := e.create("a", 10)
	body := &readHook{r: bytes.NewReader(random(10)), fn: func() {
		e.pool.Exec(context.Background(), `DELETE FROM uploads WHERE id = $1`, id) // e.g. the janitor
	}}
	if w := e.serve(context.Background(), "a", "PATCH", id, body); w.Code != 500 {
		t.Fatalf("got %d", w.Code)
	}
	if n := e.count(`SELECT count(*) FROM files`); n != 0 {
		t.Fatalf("files: %d", n)
	}
}

type hookStore struct {
	blob.Store
	put func()
}

func (s hookStore) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	if err := s.Store.Put(ctx, key, r, size); err != nil {
		return err
	}
	s.put()
	return nil
}

func TestFinishFailures(t *testing.T) {
	data := random(10)
	cases := []struct {
		name string
		hook func(e *env, id string)
	}{
		{"upload row deleted during Put", func(e *env, id string) {
			e.pool.Exec(context.Background(), `DELETE FROM uploads WHERE id = $1`, id)
		}},
		{"file id already taken", func(e *env, id string) {
			if _, err := e.pool.Exec(context.Background(), `INSERT INTO files (id, owner_id, name, content_type, size, sha256, wrapped_dek, key_id, storage_key)
				SELECT id, owner_id, name, content_type, size, '\x00', wrapped_dek, key_id, id::text FROM uploads WHERE id = $1`, id); err != nil {
				e.t.Fatal(err)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			id := e.create("a", int64(len(data)))
			e.h.store = hookStore{e.store, func() { c.hook(e, id) }}
			if resp := e.patch("a", id, 0, data); resp.StatusCode != 500 {
				t.Fatalf("got %d", resp.StatusCode)
			}
			if n := e.count(`SELECT count(*) FROM file_previews`); n != 0 {
				t.Fatalf("previews: %d", n)
			}
		})
	}
}

// An unreadable DEK or a staging file lost after Put only skips classification.
func TestFinishClassifyFallbacks(t *testing.T) {
	cases := []struct {
		name string
		hook func(e *env, id string)
	}{
		{"wrapped dek unreadable", func(e *env, id string) {
			e.pool.Exec(context.Background(), `UPDATE uploads SET wrapped_dek = 'x' WHERE id = $1`, id)
		}},
		// finish still holds the file open; removal only succeeds where open files can be unlinked
		{"staging file gone", func(e *env, id string) { os.Remove(filepath.Join(e.staging, id)) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			data := []byte("%PDF-1.4 tiny")
			id := e.create("a", int64(len(data)))
			removed := false
			e.h.store = hookStore{e.store, func() {
				c.hook(e, id)
				_, err := os.Stat(filepath.Join(e.staging, id))
				removed = os.IsNotExist(err)
			}}
			if resp := e.patch("a", id, 0, data); resp.StatusCode != 204 || resp.Header.Get("X-SX-File-ID") != id {
				t.Fatalf("patch: %d", resp.StatusCode)
			}
			var kind, status string
			if err := e.pool.QueryRow(context.Background(), `SELECT kind, status FROM file_previews WHERE file_id = $1`, id).Scan(&kind, &status); err != nil {
				t.Fatal(err)
			}
			if (removed || c.name == "wrapped dek unreadable") && (kind != "none" || status != "failed") {
				t.Fatalf("preview %s/%s", kind, status)
			}
		})
	}
}

func TestTusDeleteStagingUnremovable(t *testing.T) {
	e := newEnv(t)
	id := e.create("a", 10)
	sp := filepath.Join(e.staging, id)
	os.Remove(sp)
	os.MkdirAll(filepath.Join(sp, "x"), 0o700)
	if resp := e.req("a", "DELETE", id, nil); resp.StatusCode != 204 {
		t.Fatalf("got %d", resp.StatusCode)
	}
	if n := e.count(`SELECT count(*) FROM uploads`); n != 0 {
		t.Fatalf("rows: %d", n)
	}
}
