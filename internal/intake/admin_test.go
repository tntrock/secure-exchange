package intake

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

func TestDisabledOwnerRequestGone(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	_, tok := e.newRequest(t, nil, "bob@x.com")
	st := e.login(t, tok, "bob@x.com")
	a, err := e.svc.Authorize(ctx, st, ip1)
	if err != nil {
		t.Fatal(err)
	}

	e.setDisabled(t, e.owner.ID, true)
	if _, err := e.svc.Landing(ctx, tok, ip1); !errors.Is(err, ErrGone) {
		t.Fatalf("Landing: %v", err)
	}
	if _, err := e.svc.Authorize(ctx, st, ip1); !errors.Is(err, ErrGone) {
		t.Fatalf("Authorize: %v", err)
	}
	// a request authorized just before the owner was disabled
	if err := e.check(t, a, "a.txt", 1); !errors.Is(err, ErrGone) {
		t.Fatalf("CheckUpload: %v", err)
	}

	e.setDisabled(t, e.owner.ID, false)
	if _, err := e.svc.Landing(ctx, tok, ip1); err != nil {
		t.Fatalf("Landing after enable: %v", err)
	}
	if _, err := e.svc.Authorize(ctx, st, ip1); err != nil {
		t.Fatalf("Authorize after enable: %v", err)
	}
	if err := e.check(t, a, "a.txt", 1); err != nil {
		t.Fatalf("CheckUpload after enable: %v", err)
	}
}

func TestCheckUploadRevokedMeanwhile(t *testing.T) {
	e := setup(t)
	a := e.access(t, nil)
	if err := e.svc.Revoke(context.Background(), e.owner.ID, a.Request.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.check(t, a, "a.txt", 1); !errors.Is(err, ErrGone) {
		t.Fatalf("got %v", err)
	}
}

func TestAdminListGetRevoke(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	other := e.user(t, "Other@y.com", "Other")
	mine, tok := e.newRequest(t, func(in *CreateInput) { in.Message = "Quarterly Report" }, "bob@x.com")
	in := e.input()
	in.Emails = []string{"eve@x.com"}
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
	if err != nil || g.OwnerEmail != "Other@y.com" || len(g.Uploaders) != 1 || g.URL == "" {
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
	if _, err := e.svc.Landing(ctx, tok, ip1); !errors.Is(err, ErrGone) {
		t.Fatalf("Landing: %v", err)
	}
}
