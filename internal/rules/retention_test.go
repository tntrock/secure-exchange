package rules

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/blob"
	"github.com/tntrock/secure-exchange/internal/db/testdb"
)

type retFx struct {
	t     *testing.T
	pool  *pgxpool.Pool
	store *blob.Local
	owner uuid.UUID
}

func (f retFx) exec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.pool.Exec(context.Background(), sql, args...); err != nil {
		f.t.Fatal(err)
	}
}

// file inserts a file (with a blob) optionally tied to a request / vendor.
func (f retFx) file(req *uuid.UUID, vendor bool) uuid.UUID {
	id := uuid.New()
	if err := f.store.Put(context.Background(), id.String(), bytes.NewReader([]byte("x")), 1); err != nil {
		f.t.Fatal(err)
	}
	var v *uuid.UUID
	if vendor {
		v = &f.owner
	}
	f.exec(`INSERT INTO files (id,owner_id,name,content_type,size,sha256,wrapped_dek,key_id,storage_key,request_id,vendor_id)
		VALUES ($1::uuid,$2,'a','x',1,'\x00','\x00',1,$1::text,$3,$4)`, id, f.owner, req, v)
	return id
}

// share creates a share of the files; end is an interval string relative to now (past or future).
func (f retFx) share(revoked bool, end string, files ...uuid.UUID) {
	sid := uuid.New()
	exp := end
	if revoked {
		exp = "100 days"
	}
	f.exec(`INSERT INTO shares (id,owner_id,token_hash,token_sealed,allow_download,watermark,expires_at,revoked_at)
		VALUES ($1,$2,$3,'\x01',true,true,now()+$4::interval,CASE WHEN $5::bool THEN now()+$6::interval END)`, sid, f.owner, sid[:], exp, revoked, end)
	for _, id := range files {
		f.exec(`INSERT INTO share_files (share_id,file_id) VALUES ($1,$2)`, sid, id)
	}
}

func (f retFx) request(end string) uuid.UUID {
	id := uuid.New()
	f.exec(`INSERT INTO upload_requests (id,owner_id,token_hash,token_sealed,expires_at,max_files,max_total_bytes)
		VALUES ($1,$2,$3,'\x01',now()+$4::interval,1,1)`, id, f.owner, id[:], end)
	return id
}

func (f retFx) gone(id uuid.UUID) bool {
	var d bool
	if err := f.pool.QueryRow(context.Background(), `SELECT deleted_at IS NOT NULL FROM files WHERE id=$1`, id).Scan(&d); err != nil {
		f.t.Fatal(err)
	}
	rc, err := f.store.OpenRange(context.Background(), id.String(), 0, 1)
	if err == nil {
		rc.Close()
	}
	if d != (err != nil) {
		f.t.Fatalf("file %s: deleted_at=%v but blob missing=%v", id, d, err != nil)
	}
	return d
}

func TestSweepRetention(t *testing.T) {
	ctx := context.Background()
	pool := testdb.New(t)
	store, err := blob.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := retFx{t: t, pool: pool, store: store, owner: uuid.New()}
	f.exec(`INSERT INTO users (id,email,role) VALUES ($1,'o@example.com','staff')`, f.owner)
	s := New(pool, 1<<30)
	if err := s.Seed(ctx, 30); err != nil {
		t.Fatal(err)
	}
	log := audit.New(pool)

	revoked8 := f.file(nil, false)
	f.share(true, "-8 days", revoked8)
	reqOld := f.request("-8 days")
	reqFile := f.file(&reqOld, false)
	ended6 := f.file(nil, false)
	f.share(false, "-6 days", ended6)
	mixed := f.file(nil, false)
	f.share(false, "-30 days", mixed)
	f.share(false, "5 days", mixed)
	reqShared := f.file(&reqOld, false)
	f.share(false, "5 days", reqShared)
	staff := f.file(nil, false)
	vendor := f.file(nil, true)

	if n, err := s.SweepRetention(ctx, store, log); err != nil || n != 0 {
		t.Fatalf("retention off: %d %v", n, err)
	}
	r, _ := s.Get(ctx)
	r.RetentionDays = 7
	tx, _ := pool.Begin(ctx)
	if _, err := s.Update(ctx, tx, r); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	if n, err := s.SweepRetention(ctx, store, log); err != nil || n != 2 {
		t.Fatalf("sweep: %d %v", n, err)
	}
	for id, want := range map[uuid.UUID]bool{revoked8: true, reqFile: true, ended6: false, mixed: false, reqShared: false, staff: false, vendor: false} {
		if f.gone(id) != want {
			t.Errorf("file %s: deleted want %v", id, want)
		}
	}
	var n int
	pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='file.retention_delete' AND actor_type='system'`).Scan(&n)
	if n != 2 {
		t.Errorf("audit rows %d", n)
	}
	if n, err := s.SweepRetention(ctx, store, log); err != nil || n != 0 {
		t.Fatalf("second sweep: %d %v", n, err)
	}
}

func retSetup(t *testing.T) (retFx, *Service, *audit.Log) {
	ctx := context.Background()
	pool := testdb.New(t)
	store, err := blob.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := retFx{t: t, pool: pool, store: store, owner: uuid.New()}
	f.exec(`INSERT INTO users (id,email,role) VALUES ($1,'o@example.com','staff')`, f.owner)
	s := New(pool, 1<<30)
	if err := s.Seed(ctx, 30); err != nil {
		t.Fatal(err)
	}
	f.exec(`UPDATE site_rules SET retention_days = 7`)
	return f, s, audit.New(pool)
}

func TestSweepRetentionLaterShared(t *testing.T) {
	f, s, log := retSetup(t)
	oldShared, activeShared, activeReq, plain := f.file(nil, true), f.file(nil, true), f.file(nil, false), f.file(nil, true)
	f.share(false, "-8 days", oldShared)
	f.share(false, "3 days", activeShared)
	req := f.request("3 days")
	f.exec(`UPDATE files SET request_id=$1 WHERE id=$2`, req, activeReq)
	if n, err := s.SweepRetention(context.Background(), f.store, log); err != nil || n != 1 {
		t.Fatalf("%d %v", n, err)
	}
	for id, want := range map[uuid.UUID]bool{oldShared: true, activeShared: false, activeReq: false, plain: false} {
		if f.gone(id) != want {
			t.Errorf("file %s: deleted want %v", id, want)
		}
	}
}

// A share created after candidate selection must save the file.
func TestSweepRetentionRaceWithNewShare(t *testing.T) {
	f, s, log := retSetup(t)
	id := f.file(nil, false)
	f.share(false, "-8 days", id)
	afterCandidates = func() { f.share(false, "5 days", id) }
	t.Cleanup(func() { afterCandidates = func() {} })
	if n, err := s.SweepRetention(context.Background(), f.store, log); err != nil || n != 0 {
		t.Fatalf("%d %v", n, err)
	}
	if f.gone(id) {
		t.Fatal("file with a new active share was deleted")
	}
}
