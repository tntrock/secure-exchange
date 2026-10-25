package preview

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"image"
	"os"
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
