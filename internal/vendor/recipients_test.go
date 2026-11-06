package vendor

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// shareTo records a share by owner with vendor v as a (revoked, if so) recipient.
func (e *env) shareTo(owner, v uuid.UUID, revoked bool) {
	e.t.Helper()
	sid := uuid.New()
	if _, err := e.svc.pool.Exec(context.Background(), `INSERT INTO shares (id, owner_id, token_hash, token_sealed, allow_download, watermark, expires_at)
		VALUES ($1,$2,$3,'\x00',true,false,now() + interval '1 day')`, sid, owner, sid[:]); err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.svc.pool.Exec(context.Background(), `INSERT INTO share_recipients (id, share_id, email, vendor_id, revoked_at)
		VALUES ($1,$2,'v@x.com',$3, CASE WHEN $4 THEN now() END)`, uuid.New(), sid, v, revoked); err != nil {
		e.t.Fatal(err)
	}
}

func TestUploadTargets(t *testing.T) {
	e := setup(t, "staff")
	ctx := context.Background()
	pool := e.svc.pool
	v := e.create(e.staff, "v@vendor.com")
	w := e.create(e.staff, "w@vendor.com")
	off := e.account("gone@x.com", "staff")
	for id, name := range map[uuid.UUID]string{e.staff.ID: "Bob", e.staff2.ID: "Alice", e.admin.ID: "Carol"} {
		if _, err := pool.Exec(ctx, `UPDATE users SET display_name = $2 WHERE id = $1`, id, name); err != nil {
			t.Fatal(err)
		}
	}
	e.shareTo(e.staff2.ID, v.ID, true) // a revoked recipient still counts: the vendor had the share
	e.shareTo(e.staff2.ID, v.ID, false)
	e.shareTo(e.staff.ID, v.ID, false) // also the creator: listed once
	e.shareTo(off.ID, v.ID, false)
	e.shareTo(e.admin.ID, w.ID, false) // w's target only
	if _, err := pool.Exec(ctx, `UPDATE users SET disabled = true WHERE id = $1`, off.ID); err != nil {
		t.Fatal(err)
	}

	got, err := UploadTargets(ctx, pool, v.ID)
	if err != nil || len(got) != 2 || got[0] != (Target{e.staff2.ID, "Alice", "staff2@x.com"}) || got[1] != (Target{e.staff.ID, "Bob", "Staff@x.com"}) {
		t.Fatalf("%+v %v", got, err)
	}
	for id, want := range map[uuid.UUID]bool{e.staff.ID: true, e.staff2.ID: true, e.admin.ID: false, off.ID: false, uuid.New(): false, v.ID: false} {
		if ok, err := CanUploadTo(ctx, pool, v.ID, id); ok != want || err != nil {
			t.Errorf("CanUploadTo %v: %v %v", id, ok, err)
		}
	}
	got, err = UploadTargets(ctx, pool, w.ID)
	if err != nil || len(got) != 2 || got[0].Name != "Bob" || got[1].Name != "Carol" {
		t.Fatalf("w: %+v %v", got, err)
	}
	if got, err := UploadTargets(ctx, pool, uuid.New()); err != nil || len(got) != 0 {
		t.Fatalf("unknown vendor: %+v %v", got, err)
	}
}
