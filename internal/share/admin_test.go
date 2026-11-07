package share

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func (e *env) setDisabled(t *testing.T, id uuid.UUID, disabled bool) {
	t.Helper()
	if _, err := e.pool.Exec(context.Background(), `UPDATE users SET disabled = $2 WHERE id = $1`, id, disabled); err != nil {
		t.Fatal(err)
	}
}

func TestDisabledOwnerShareGone(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	_, tok := e.newShare(t, nil, "bob@x.com")
	st, _, err := e.svc.VerifyCode(ctx, tok, "bob@x.com", e.code(t, tok, "bob@x.com"), ip1, "")
	if err != nil {
		t.Fatal(err)
	}
	v := e.vendor(t, "v@vendor.com")
	vsh := e.vendorShare(t, nil, v)

	e.setDisabled(t, e.owner.ID, true)
	if l, err := e.svc.VendorShares(ctx, v); err != nil || len(l) != 0 {
		t.Fatalf("VendorShares while disabled: %v %v", l, err)
	}
	if _, err := e.svc.Landing(ctx, tok, ip1); !errors.Is(err, ErrGone) {
		t.Fatalf("Landing: %v", err)
	}
	if _, err := e.svc.Authorize(ctx, st, ip1); !errors.Is(err, ErrGone) {
		t.Fatalf("Authorize: %v", err)
	}
	if _, err := e.svc.VendorAccess(ctx, v, vsh.ID, []byte("s"), ip1); !errors.Is(err, ErrGone) {
		t.Fatalf("VendorAccess: %v", err)
	}

	e.setDisabled(t, e.owner.ID, false)
	if l, err := e.svc.VendorShares(ctx, v); err != nil || len(l) != 1 {
		t.Fatalf("VendorShares after enable: %v %v", l, err)
	}
	if _, err := e.svc.Landing(ctx, tok, ip1); err != nil {
		t.Fatalf("Landing after enable: %v", err)
	}
	if _, err := e.svc.Authorize(ctx, st, ip1); err != nil {
		t.Fatalf("Authorize after enable: %v", err)
	}
	if _, err := e.svc.VendorAccess(ctx, v, vsh.ID, []byte("s"), ip1); err != nil {
		t.Fatalf("VendorAccess after enable: %v", err)
	}
}

func TestAdminListGetRevoke(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	other := e.user(t, "Other@y.com", "Other")
	mine, tok := e.newShare(t, func(in *CreateInput) { in.Message = "Quarterly Report" }, "bob@x.com")
	st, _, err := e.svc.VerifyCode(ctx, tok, "bob@x.com", e.code(t, tok, "bob@x.com"), ip1, "")
	if err != nil {
		t.Fatal(err)
	}
	in := e.input(t)
	in.FileIDs = []uuid.UUID{e.file(t, other, false)}
	theirs, err := e.svc.Create(ctx, other, in)
	if err != nil {
		t.Fatal(err)
	}

	for q, want := range map[string][]uuid.UUID{"": {theirs.ID, mine.ID}, "OTHER@y": {theirs.ID}, "quarterly": {mine.ID}, "nomatch": nil} {
		got, err := e.svc.AdminList(ctx, q, 0)
		if err != nil || len(got) != len(want) {
			t.Fatalf("q=%q: %+v, %v", q, got, err)
		}
		for i := range want {
			if got[i].ID != want[i] {
				t.Fatalf("q=%q: order %v", q, got)
			}
		}
	}
	if got, err := e.svc.AdminList(ctx, "", 1); err != nil || len(got) != 1 || got[0].ID != mine.ID {
		t.Fatalf("offset: %+v, %v", got, err)
	}
	if got, err := e.svc.AdminList(ctx, "", -5); err != nil || len(got) != 2 {
		t.Fatalf("negative offset: %+v, %v", got, err)
	}

	g, err := e.svc.AdminGet(ctx, theirs.ID)
	if err != nil || g.OwnerEmail != "Other@y.com" || len(g.Files) != 1 || len(g.Recipients) != 1 {
		t.Fatalf("AdminGet: %+v, %v", g, err)
	}
	if _, err := e.svc.AdminGet(ctx, uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown get: %v", err)
	}
	if err := e.svc.AdminRevoke(ctx, uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown revoke: %v", err)
	}

	if err := e.svc.AdminRevoke(ctx, mine.ID); err != nil {
		t.Fatal(err)
	}
	if g, err := e.svc.AdminGet(ctx, mine.ID); err != nil || g.RevokedAt == nil {
		t.Fatalf("revoked_at: %+v, %v", g, err)
	}
	if _, err := e.svc.Authorize(ctx, st, ip1); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("session should be gone: %v", err)
	}
	if n := count(t, e, `SELECT count(*) FROM share_sessions`); n != 0 {
		t.Fatalf("sessions: %d", n)
	}
}
