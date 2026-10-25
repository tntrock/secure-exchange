package preview

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tntrock/secure-exchange/internal/blob"
	"github.com/tntrock/secure-exchange/internal/config"
	"github.com/tntrock/secure-exchange/internal/db/testdb"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
)

var ctx = context.Background()

func newPool(t *testing.T) (*pgxpool.Pool, uuid.UUID) {
	t.Helper()
	pool := testdb.New(t)
	owner := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, email, role) VALUES ($1,'o@example.com','staff')`, owner); err != nil {
		t.Fatal(err)
	}
	return pool, owner
}

func addFile(t *testing.T, pool *pgxpool.Pool, owner uuid.UUID, name string, size int64, wrapped []byte, keyID int, key string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if key == "" {
		key = id.String()
	}
	if _, err := pool.Exec(ctx, `INSERT INTO files (id, owner_id, name, content_type, size, sha256, wrapped_dek, key_id, storage_key)
		VALUES ($1,$2,$3,'x',$4,'\x00',$5,$6,$7)`, id, owner, name, size, wrapped, keyID, key); err != nil {
		t.Fatal(err)
	}
	return id
}

func pending(t *testing.T, pool *pgxpool.Pool, owner uuid.UUID, n int) []uuid.UUID {
	t.Helper()
	var ids []uuid.UUID
	for i := 0; i < n; i++ {
		id := addFile(t, pool, owner, "a.pdf", 1, []byte{1}, 1, "")
		if err := Enqueue(ctx, pool, id, KindPages, StatusPending); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	return ids
}

func TestEnqueueAndClaim(t *testing.T) {
	pool, owner := newPool(t)
	ids := pending(t, pool, owner, 2)
	for i, want := range ids {
		j, err := Claim(ctx, pool, time.Minute)
		if err != nil || j == nil || j.FileID != want || j.Attempts != 1 {
			t.Fatalf("claim %d: %+v %v", i, j, err)
		}
	}
	if j, err := Claim(ctx, pool, time.Minute); j != nil || err != nil {
		t.Fatalf("third claim: %+v %v", j, err)
	}
	// non-pending classification writes no job
	id := addFile(t, pool, owner, "a.zip", 1, []byte{1}, 1, "")
	if err := Enqueue(ctx, pool, id, KindNone, StatusUnsupported); err != nil {
		t.Fatal(err)
	}
	if j, _ := Claim(ctx, pool, time.Minute); j != nil {
		t.Fatalf("unsupported file got a job: %+v", j)
	}
	if p, err := GetStatus(ctx, pool, id); err != nil || p.Status != StatusUnsupported || p.Kind != KindNone {
		t.Fatalf("status: %+v %v", p, err)
	}
	if _, err := GetStatus(ctx, pool, uuid.New()); !errors.Is(err, ErrNoPreview) {
		t.Fatalf("want ErrNoPreview, got %v", err)
	}
}

func TestClaimConcurrentNoDouble(t *testing.T) {
	pool, owner := newPool(t)
	pending(t, pool, owner, 10)
	var mu sync.Mutex
	seen := map[uuid.UUID]int{}
	var wg sync.WaitGroup
	for g := 0; g < 5; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				j, err := Claim(ctx, pool, time.Minute)
				if err != nil {
					t.Error(err)
					return
				}
				if j == nil {
					return
				}
				mu.Lock()
				seen[j.ID]++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(seen) != 10 {
		t.Fatalf("claimed %d distinct jobs, want 10", len(seen))
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("job %s claimed %d times", id, n)
		}
	}
}

func expire(t *testing.T, pool *pgxpool.Pool, id uuid.UUID) {
	t.Helper()
	if _, err := pool.Exec(ctx, `UPDATE render_jobs SET lease_until = now() - interval '1 second' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
}

func TestLeaseExpiryRequeues(t *testing.T) {
	pool, owner := newPool(t)
	file := pending(t, pool, owner, 1)[0]
	j, _ := Claim(ctx, pool, time.Minute)
	if j == nil {
		t.Fatal("no job")
	}
	if again, _ := Claim(ctx, pool, time.Minute); again != nil {
		t.Fatal("job with a live lease was handed out")
	}
	expire(t, pool, j.ID)
	j2, err := Claim(ctx, pool, time.Minute)
	if err != nil || j2 == nil || j2.ID != j.ID || j2.Attempts != 2 {
		t.Fatalf("reclaim: %+v %v", j2, err)
	}
	expire(t, pool, j.ID)
	if j3, _ := Claim(ctx, pool, time.Minute); j3 == nil || j3.Attempts != 3 {
		t.Fatalf("third attempt: %+v", j3)
	}
	expire(t, pool, j.ID)
	if j4, err := Claim(ctx, pool, time.Minute); j4 != nil || err != nil {
		t.Fatalf("exhausted job handed out: %+v %v", j4, err)
	}
	p, _ := GetStatus(ctx, pool, file)
	var msg string
	pool.QueryRow(ctx, `SELECT error FROM file_previews WHERE file_id = $1`, file).Scan(&msg)
	if p.Status != StatusFailed || msg != "too many attempts" {
		t.Fatalf("status %s error %q", p.Status, msg)
	}
}

func TestRenew(t *testing.T) {
	pool, owner := newPool(t)
	pending(t, pool, owner, 1)
	j, _ := Claim(ctx, pool, time.Minute)
	expire(t, pool, j.ID)
	if err := Renew(ctx, pool, j, time.Minute); err != nil {
		t.Fatal(err)
	}
	if again, _ := Claim(ctx, pool, time.Minute); again != nil {
		t.Fatal("renewed job was handed out")
	}
}

func TestCompleteAndFail(t *testing.T) {
	pool, owner := newPool(t)
	files := pending(t, pool, owner, 3)
	j1, _ := Claim(ctx, pool, time.Minute)
	if err := Complete(ctx, pool, j1, Result{Kind: KindPages, PageCount: 7, Width: 800, Height: 1000}); err != nil {
		t.Fatal(err)
	}
	if p, err := GetStatus(ctx, pool, files[0]); err != nil || p.Status != StatusReady || p.PageCount != 7 || p.Width != 800 || p.Height != 1000 {
		t.Fatalf("complete: %+v %v", p, err)
	}
	var js string
	pool.QueryRow(ctx, `SELECT status FROM render_jobs WHERE id = $1`, j1.ID).Scan(&js)
	if js != "done" {
		t.Fatalf("job status %s", js)
	}
	j2, _ := Claim(ctx, pool, time.Minute)
	if err := Fail(ctx, pool, j2, StatusTooLarge, "too big"); err != nil {
		t.Fatal(err)
	}
	if p, _ := GetStatus(ctx, pool, files[1]); p.Status != StatusTooLarge {
		t.Fatalf("fail: %+v", p)
	}
	// hostile error text: NUL, invalid UTF-8, over-long
	j3, _ := Claim(ctx, pool, time.Minute)
	if err := Fail(ctx, pool, j3, StatusFailed, "a\x00b\xff"+strings.Repeat("é", 600)); err != nil {
		t.Fatal(err)
	}
	var msg string
	pool.QueryRow(ctx, `SELECT error FROM file_previews WHERE file_id = $1`, files[2]).Scan(&msg)
	if len([]rune(msg)) != 500 || strings.ContainsRune(msg, 0) {
		t.Fatalf("error text not sanitized: %d runes", len([]rune(msg)))
	}
}

func TestBackfill(t *testing.T) {
	pool, owner := newPool(t)
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
	dek, wrapped, keyID, _ := keys.NewDEK()
	plain := []byte("%PDF-1.7 hello")
	id := uuid.New()
	if err := store.Put(ctx, id.String(), bytes.NewReader(sxcrypto.SealChunk(dek, id, 0, true, plain)), int64(len(plain))+16); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO files (id, owner_id, name, content_type, size, sha256, wrapped_dek, key_id, storage_key)
		VALUES ($1,$2,'old.pdf','x',$3,'\x00',$4,$5,$6)`, id, owner, len(plain), wrapped, keyID, id.String()); err != nil {
		t.Fatal(err)
	}
	// a deleted file is skipped
	gone := addFile(t, pool, owner, "gone.pdf", 1, wrapped, keyID, "")
	pool.Exec(ctx, `UPDATE files SET deleted_at = now() WHERE id = $1`, gone)

	cfg := config.PreviewConfig{MaxBytes: 1 << 20, MaxVideoBytes: 1 << 20}
	if n, err := Backfill(ctx, pool, store, keys, cfg); err != nil || n != 1 {
		t.Fatalf("backfill = %d, %v", n, err)
	}
	if p, err := GetStatus(ctx, pool, id); err != nil || p.Kind != KindPages || p.Status != StatusPending {
		t.Fatalf("status: %+v %v", p, err)
	}
	if j, _ := Claim(ctx, pool, time.Minute); j == nil || j.FileID != id {
		t.Fatalf("no job for backfilled file: %+v", j)
	}
	if n, err := Backfill(ctx, pool, store, keys, cfg); err != nil || n != 0 {
		t.Fatalf("second backfill = %d, %v", n, err)
	}
}

func TestStaleWorkerFenced(t *testing.T) {
	pool, owner := newPool(t)
	file := pending(t, pool, owner, 1)[0]
	old, _ := Claim(ctx, pool, time.Minute)
	expire(t, pool, old.ID)
	cur, _ := Claim(ctx, pool, time.Minute)
	if cur == nil || cur.Attempts != 2 {
		t.Fatalf("reclaim: %+v", cur)
	}
	if err := Renew(ctx, pool, old, time.Minute); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale Renew: %v", err)
	}
	if err := Complete(ctx, pool, old, Result{Kind: KindPages, PageCount: 3}); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale Complete: %v", err)
	}
	if err := Fail(ctx, pool, old, StatusFailed, "x"); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale Fail: %v", err)
	}
	if p, _ := GetStatus(ctx, pool, file); p.Status != StatusPending || p.PageCount != 0 {
		t.Fatalf("file_previews touched by stale worker: %+v", p)
	}
	if err := Fail(ctx, pool, cur, StatusReady, "x"); err == nil {
		t.Fatal("Fail accepted status ready")
	}
	if err := Complete(ctx, pool, cur, Result{Kind: KindPages, PageCount: 3}); err != nil {
		t.Fatal(err)
	}
}

func TestBackfillSkipsBadFile(t *testing.T) {
	pool, owner := newPool(t)
	k := make([]byte, 32)
	rand.Read(k)
	keys, _ := sxcrypto.ParseKeyring("1:"+base64.StdEncoding.EncodeToString(k), 1)
	store, _ := blob.NewLocal(t.TempDir())
	dek, wrapped, keyID, _ := keys.NewDEK()
	plain := []byte("%PDF-1.7 hello")
	good := uuid.New()
	store.Put(ctx, good.String(), bytes.NewReader(sxcrypto.SealChunk(dek, good, 0, true, plain)), int64(len(plain))+16)
	// the bad file is older, so it is listed first or not; either order must work
	bad := addFile(t, pool, owner, "missing.pdf", 10, wrapped, keyID, "")
	pool.Exec(ctx, `INSERT INTO files (id, owner_id, name, content_type, size, sha256, wrapped_dek, key_id, storage_key)
		VALUES ($1,$2,'good.pdf','x',$3,'\x00',$4,$5,$6)`, good, owner, len(plain), wrapped, keyID, good.String())
	cfg := config.PreviewConfig{MaxBytes: 1 << 20, MaxVideoBytes: 1 << 20}
	if n, err := Backfill(ctx, pool, store, keys, cfg); err != nil || n != 2 {
		t.Fatalf("backfill = %d, %v", n, err)
	}
	if p, _ := GetStatus(ctx, pool, bad); p == nil || p.Status != StatusFailed || p.Kind != KindNone {
		t.Fatalf("bad file: %+v", p)
	}
	if p, _ := GetStatus(ctx, pool, good); p == nil || p.Status != StatusPending {
		t.Fatalf("good file: %+v", p)
	}
}

func TestCompleteDeletedFile(t *testing.T) {
	pool, owner := newPool(t)
	file := pending(t, pool, owner, 1)[0]
	j, _ := Claim(ctx, pool, time.Minute)
	pool.Exec(ctx, `UPDATE files SET deleted_at = now() WHERE id = $1`, file)
	if err := Complete(ctx, pool, j, Result{Kind: KindPages, PageCount: 1}); !errors.Is(err, ErrFileDeleted) {
		t.Fatalf("err = %v", err)
	}
	if p, _ := GetStatus(ctx, pool, file); p.Status != StatusPending {
		t.Fatalf("%+v", p)
	}
	if err := Fail(ctx, pool, j, StatusFailed, "file deleted"); err != nil {
		t.Fatal("job no longer running:", err)
	}
}
