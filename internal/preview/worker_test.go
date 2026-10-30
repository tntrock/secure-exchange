package preview

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"image"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tntrock/secure-exchange/internal/config"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
)

// storeFile encrypts plain into the store like an upload does and enqueues its preview.
func (e *itemEnv) storeFile(t *testing.T, name string, plain []byte, kind Kind) uuid.UUID {
	t.Helper()
	dek, wrapped, keyID, _ := e.keys.NewDEK()
	id := uuid.New()
	var sealed bytes.Buffer
	n := sxcrypto.ChunkCount(int64(len(plain)))
	for i := int64(0); i < n; i++ {
		chunk := plain[i*sxcrypto.ChunkSize : min(int64(len(plain)), (i+1)*sxcrypto.ChunkSize)]
		sealed.Write(sxcrypto.SealChunk(dek, id, uint64(i), i == n-1, chunk))
	}
	if err := e.store.Put(ctx, id.String(), &sealed, int64(sealed.Len())); err != nil {
		t.Fatal(err)
	}
	var owner uuid.UUID
	e.pool.QueryRow(ctx, `SELECT owner_id FROM files WHERE id = $1`, e.file).Scan(&owner)
	if _, err := e.pool.Exec(ctx, `INSERT INTO files (id, owner_id, name, content_type, size, sha256, wrapped_dek, key_id, storage_key)
		VALUES ($1,$2,$3,'x',$4,'\x00',$5,$6,$7)`, id, owner, name, len(plain), wrapped, keyID, id.String()); err != nil {
		t.Fatal(err)
	}
	if err := Enqueue(ctx, e.pool, id, kind, StatusPending); err != nil {
		t.Fatal(err)
	}
	return id
}

func (e *itemEnv) worker(t *testing.T) *Worker {
	return &Worker{Pool: e.pool, Store: e.store, Keys: e.keys, Sandbox: Sandbox{Root: t.TempDir()},
		Cfg: config.PreviewConfig{MaxBytes: 1 << 30, MaxPages: 5, DPI: 50}}
}

// runUntil runs the worker until every file has left pending (or 20s pass).
func runUntil(t *testing.T, e *itemEnv, w *Worker, files ...uuid.UUID) {
	t.Helper()
	wctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	done := make(chan struct{})
	go func() { w.Run(wctx); close(done) }()
	defer func() { cancel(); <-done }()
	for wctx.Err() == nil {
		left := 0
		for _, f := range files {
			if p, _ := GetStatus(ctx, e.pool, f); p == nil || p.Status == StatusPending {
				left++
			}
		}
		if left == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("worker did not finish")
}

func TestWorkerLoopProcessesJobs(t *testing.T) {
	e := newItemEnv(t)
	f := e.storeFile(t, "pic.png", encodePNG(t, image.NewGray(image.Rect(0, 0, 40, 30))), KindImage)
	w := e.worker(t)
	runUntil(t, e, w, f)
	p, _ := GetStatus(ctx, e.pool, f)
	if p.Status != StatusReady || p.Kind != KindImage || p.Width != 40 || p.Height != 30 {
		t.Fatalf("%+v", p)
	}
	items, _ := ListItems(ctx, e.pool, f, "image")
	if len(items) != 1 {
		t.Fatalf("items %+v", items)
	}
	if ents, _ := os.ReadDir(w.Sandbox.Root); len(ents) != 0 {
		t.Fatal("work dir left behind")
	}
}

func TestMislabeledFile(t *testing.T) {
	e := newItemEnv(t)
	junk := make([]byte, 3000)
	rand.Read(junk)
	bad := e.storeFile(t, "fake.png", junk, KindImage)
	good := e.storeFile(t, "ok.png", encodePNG(t, image.NewGray(image.Rect(0, 0, 4, 4))), KindImage)
	runUntil(t, e, e.worker(t), bad, good)
	if p, _ := GetStatus(ctx, e.pool, bad); p.Status != StatusFailed {
		t.Fatalf("bad: %+v", p)
	}
	if p, _ := GetStatus(ctx, e.pool, good); p.Status != StatusReady {
		t.Fatalf("good: %+v", p)
	}
}

func TestWorkerPanicRecovered(t *testing.T) {
	e := newItemEnv(t)
	orig := pipelines[KindImage]
	pipelines[KindImage] = func(*jobEnv) (Result, error) { panic("kaboom") }
	defer func() { pipelines[KindImage] = orig }()
	f := e.storeFile(t, "pic.png", encodePNG(t, image.NewGray(image.Rect(0, 0, 4, 4))), KindImage)
	runUntil(t, e, e.worker(t), f)
	var msg string
	e.pool.QueryRow(ctx, `SELECT error FROM file_previews WHERE file_id = $1`, f).Scan(&msg)
	if p, _ := GetStatus(ctx, e.pool, f); p.Status != StatusFailed || msg != "internal error" {
		t.Fatalf("%+v %q", p, msg)
	}
}

func TestWorkerDeletedFile(t *testing.T) {
	e := newItemEnv(t)
	f := e.storeFile(t, "pic.png", encodePNG(t, image.NewGray(image.Rect(0, 0, 4, 4))), KindImage)
	orig := pipelines[KindImage]
	pipelines[KindImage] = func(j *jobEnv) (Result, error) {
		res, err := orig(j)
		e.pool.Exec(ctx, `UPDATE files SET deleted_at = now() WHERE id = $1`, f)
		return res, err
	}
	defer func() { pipelines[KindImage] = orig }()
	runUntil(t, e, e.worker(t), f)
	var msg string
	e.pool.QueryRow(ctx, `SELECT error FROM file_previews WHERE file_id = $1`, f).Scan(&msg)
	if p, _ := GetStatus(ctx, e.pool, f); p.Status != StatusFailed || msg != "file deleted" {
		t.Fatalf("%+v %q", p, msg)
	}
	if items, _ := ListItems(ctx, e.pool, f, "image"); len(items) != 0 {
		t.Fatal("items kept for deleted file")
	}
}

func TestWorkerFailureDropsPartialItems(t *testing.T) {
	e := newItemEnv(t)
	orig := pipelines[KindImage]
	pipelines[KindImage] = func(j *jobEnv) (Result, error) {
		if err := j.put("image", 0, bytes.NewReader([]byte("x")), 1, Item{}); err != nil {
			return Result{}, err
		}
		return Result{}, errors.New("later step failed")
	}
	defer func() { pipelines[KindImage] = orig }()
	f := e.storeFile(t, "pic.png", encodePNG(t, image.NewGray(image.Rect(0, 0, 4, 4))), KindImage)
	runUntil(t, e, e.worker(t), f)
	if p, _ := GetStatus(ctx, e.pool, f); p.Status != StatusFailed {
		t.Fatalf("%+v", p)
	}
	if items, _ := ListItems(ctx, e.pool, f, "image"); len(items) != 0 {
		t.Fatal("partial items kept")
	}
}

func TestWorkerTransientErrorRequeues(t *testing.T) {
	e := newItemEnv(t)
	defer func(d time.Duration) { retryDelay = d }(retryDelay)
	retryDelay = 0
	orig := pipelines[KindImage]
	defer func() { pipelines[KindImage] = orig }()
	calls := 0
	pipelines[KindImage] = func(j *jobEnv) (Result, error) {
		calls++
		if calls == 1 {
			// a partial item from the failed attempt must not clash with the retry
			if err := j.put("image", 0, bytes.NewReader([]byte("x")), 1, Item{}); err != nil {
				return Result{}, err
			}
			return Result{}, retryable(errors.New("blob store down"))
		}
		return orig(j)
	}
	f := e.storeFile(t, "pic.png", encodePNG(t, image.NewGray(image.Rect(0, 0, 4, 4))), KindImage)
	runUntil(t, e, e.worker(t), f)
	if p, _ := GetStatus(ctx, e.pool, f); p.Status != StatusReady || calls != 2 {
		t.Fatalf("%+v calls=%d", p, calls)
	}

	// always transient: maxAttempts ends it as failed
	calls = 0
	pipelines[KindImage] = func(*jobEnv) (Result, error) { calls++; return Result{}, retryable(errors.New("db down")) }
	g := e.storeFile(t, "pic2.png", encodePNG(t, image.NewGray(image.Rect(0, 0, 4, 4))), KindImage)
	runUntil(t, e, e.worker(t), g)
	if p, _ := GetStatus(ctx, e.pool, g); p.Status != StatusFailed || calls != maxAttempts {
		t.Fatalf("%+v calls=%d", p, calls)
	}

	// fenced like Fail/Complete
	if err := Requeue(ctx, e.pool, &Job{ID: uuid.New(), Attempts: 1}, "x"); !errors.Is(err, ErrLeaseLost) {
		t.Fatal(err)
	}
}

func TestWorkerWorkDirFullIsTooLarge(t *testing.T) {
	e := newItemEnv(t)
	orig := pipelines[KindImage]
	defer func() { pipelines[KindImage] = orig }()
	// as render reports a full tmpfs while writing the decrypted input
	enospc := retryable(fmt.Errorf("decrypt input: %w", &os.PathError{Op: "write", Path: "in", Err: syscall.ENOSPC}))
	pipelines[KindImage] = func(*jobEnv) (Result, error) { return Result{}, enospc }
	f := e.storeFile(t, "pic.png", encodePNG(t, image.NewGray(image.Rect(0, 0, 4, 4))), KindImage)
	runUntil(t, e, e.worker(t), f)
	if p, _ := GetStatus(ctx, e.pool, f); p.Status != StatusTooLarge {
		t.Fatalf("%+v", p)
	}
}

func previewError(t *testing.T, e *itemEnv, f uuid.UUID) (Status, string) {
	t.Helper()
	var st Status
	var msg string
	if err := e.pool.QueryRow(ctx, `SELECT status, error FROM file_previews WHERE file_id = $1`, f).Scan(&st, &msg); err != nil {
		t.Fatal(err)
	}
	return st, msg
}

func TestWorkerNoPipelineForKind(t *testing.T) {
	e := newItemEnv(t)
	f := e.storeFile(t, "x.bin", []byte("data"), KindNone)
	runUntil(t, e, e.worker(t), f)
	if st, msg := previewError(t, e, f); st != StatusFailed || msg != `no pipeline for kind "none"` {
		t.Fatalf("%s %q", st, msg)
	}
}

func TestWorkerUnwrapFailureRetried(t *testing.T) {
	e := newItemEnv(t)
	defer func(d time.Duration) { retryDelay = d }(retryDelay)
	retryDelay = 0
	f := e.storeFile(t, "pic.png", encodePNG(t, image.NewGray(image.Rect(0, 0, 4, 4))), KindImage)
	// a key id the keyring does not have: transient (a key may be added on restart), retried until maxAttempts
	if _, err := e.pool.Exec(ctx, `UPDATE files SET key_id = 99 WHERE id = $1`, f); err != nil {
		t.Fatal(err)
	}
	runUntil(t, e, e.worker(t), f)
	var attempts int
	e.pool.QueryRow(ctx, `SELECT attempts FROM render_jobs WHERE file_id = $1`, f).Scan(&attempts)
	if st, _ := previewError(t, e, f); st != StatusFailed || attempts != maxAttempts {
		t.Fatalf("%s attempts %d", st, attempts)
	}
}

func TestWorkerUnsafeExtensionDropped(t *testing.T) {
	e := newItemEnv(t)
	orig := pipelines[KindImage]
	defer func() { pipelines[KindImage] = orig }()
	var in string
	pipelines[KindImage] = func(j *jobEnv) (Result, error) { in = filepath.Base(j.in); return orig(j) }
	f := e.storeFile(t, "pic.p n;g", encodePNG(t, image.NewGray(image.Rect(0, 0, 4, 4))), KindImage)
	runUntil(t, e, e.worker(t), f)
	if st, _ := previewError(t, e, f); st != StatusReady || in != "in" {
		t.Fatalf("%s in=%q", st, in)
	}
}

// TestRunJobLeaseLost: when the job is no longer this worker's attempt (or the
// worker shuts down), runJob records nothing.
func TestRunJobLeaseLost(t *testing.T) {
	steal := func(e *itemEnv, j *jobEnv) {
		e.pool.Exec(ctx, `UPDATE render_jobs SET attempts = attempts + 1`)
	}
	for _, c := range []struct {
		name string
		p    func(e *itemEnv, cancel func(), j *jobEnv) (Result, error)
	}{
		{"pipeline reports lease lost", func(_ *itemEnv, _ func(), _ *jobEnv) (Result, error) { return Result{}, ErrLeaseLost }},
		{"shutdown", func(_ *itemEnv, cancel func(), _ *jobEnv) (Result, error) {
			cancel()
			return Result{}, errors.New("killed")
		}},
		{"reclaimed before complete", func(e *itemEnv, _ func(), j *jobEnv) (Result, error) {
			steal(e, j)
			return Result{Kind: KindImage}, nil
		}},
		{"reclaimed before fail", func(e *itemEnv, _ func(), j *jobEnv) (Result, error) { steal(e, j); return Result{}, errors.New("bad") }},
		{"reclaimed before requeue", func(e *itemEnv, _ func(), j *jobEnv) (Result, error) {
			steal(e, j)
			return Result{}, retryable(errors.New("down"))
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newItemEnv(t)
			orig := pipelines[KindImage]
			defer func() { pipelines[KindImage] = orig }()
			jctx, cancel := context.WithCancel(ctx)
			defer cancel()
			pipelines[KindImage] = func(j *jobEnv) (Result, error) {
				if err := j.put("image", 0, bytes.NewReader([]byte("x")), 1, Item{}); err != nil {
					t.Fatal(err)
				}
				return c.p(e, cancel, j)
			}
			f := e.storeFile(t, "pic.png", []byte("png"), KindImage)
			w := e.worker(t)
			w.Lease = time.Minute
			j, err := Claim(ctx, e.pool, w.Lease)
			if err != nil || j == nil || j.FileID != f {
				t.Fatalf("claim: %+v %v", j, err)
			}
			w.runJob(jctx, j)
			var jobStatus string
			e.pool.QueryRow(ctx, `SELECT status FROM render_jobs WHERE id = $1`, j.ID).Scan(&jobStatus)
			if st, _ := previewError(t, e, f); st != StatusPending || jobStatus != "running" {
				t.Fatalf("preview %s job %s", st, jobStatus)
			}
			// the current attempt owns the items: a stale worker leaves them alone
			if items, _ := ListItems(ctx, e.pool, f, "image"); len(items) != 1 {
				t.Fatalf("items %d", len(items))
			}
		})
	}
}

func TestProcessStaleAttempt(t *testing.T) {
	e := newItemEnv(t)
	f := e.storeFile(t, "pic.png", []byte("png"), KindImage)
	j, err := Claim(ctx, e.pool, time.Minute)
	if err != nil || j == nil || j.FileID != f {
		t.Fatalf("claim: %+v %v", j, err)
	}
	stale := *j
	stale.Attempts--
	// a stale attempt must not clear the current attempt's items
	if _, err := e.worker(t).process(ctx, &stale); !errors.Is(err, ErrLeaseLost) || errors.Is(err, errRetry) {
		t.Fatalf("err = %v", err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("chunk auth failed") }

func TestRenderErrorsAreTransient(t *testing.T) {
	never := func(*jobEnv) (Result, error) { t.Fatal("pipeline ran"); return Result{}, nil }
	// work dir cannot be created
	w := &Worker{Sandbox: Sandbox{Root: filepath.Join(t.TempDir(), "missing")}}
	if _, err := w.render(ctx, never, ".png", strings.NewReader("x"), nil); !errors.Is(err, errRetry) {
		t.Fatalf("err = %v", err)
	}
	// decrypting the input fails midway
	root := t.TempDir()
	w = &Worker{Sandbox: Sandbox{Root: root}}
	if _, err := w.render(ctx, never, ".png", errReader{}, nil); !errors.Is(err, errRetry) || !strings.Contains(err.Error(), "decrypt input: chunk auth failed") {
		t.Fatalf("err = %v", err)
	}
	if ents, _ := os.ReadDir(root); len(ents) != 0 {
		t.Fatalf("leftover work dirs: %d", len(ents))
	}
}
