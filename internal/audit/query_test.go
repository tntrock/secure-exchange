package audit

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tntrock/secure-exchange/internal/db/testdb"
)

func seed(t *testing.T, l *Log, evs ...Event) {
	t.Helper()
	for _, e := range evs {
		if err := l.Append(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
}

func TestListFilterAndPaging(t *testing.T) {
	ctx := context.Background()
	l := New(testdb.New(t))
	const S = "share-1"
	mk := func(act string, detail map[string]any) Event {
		return Event{ActorType: "user", ActorID: "u1", Action: act, TargetType: "share", TargetID: S, Result: "ok", Detail: detail}
	}
	before := time.Now().Add(-time.Minute)
	seed(t, l, mk(ActShareCreate, nil), mk(ActShareRevoke, nil),
		Event{ActorType: "recipient", ActorID: "r", Action: ActFileView, TargetType: "file", TargetID: "f", Detail: map[string]any{"share_id": S}},
		Event{ActorType: "user", ActorID: "u1", Action: ActLoginOK, Result: "ok"}, mk(ActShareCreate, nil))

	p1, next, err := l.List(ctx, Filter{ActionPrefix: "share.", Limit: 2})
	if err != nil || len(p1) != 2 || next == 0 || p1[0].ID < p1[1].ID {
		t.Fatalf("page1: %d next=%d %v", len(p1), next, err)
	}
	p2, next2, err := l.List(ctx, Filter{ActionPrefix: "share.", BeforeID: next, Limit: 2})
	if err != nil || len(p2) != 1 || next2 != 0 {
		t.Fatalf("page2: %d next=%d %v", len(p2), next2, err)
	}
	if got, _, _ := l.List(ctx, Filter{Target: S}); len(got) != 4 {
		t.Fatalf("target: %d want 4", len(got))
	}
	if got, _, _ := l.List(ctx, Filter{Since: before, Until: time.Now().Add(time.Minute)}); len(got) != 5 {
		t.Fatalf("window: %d want 5", len(got))
	}
	if got, _, _ := l.List(ctx, Filter{Until: before}); len(got) != 0 {
		t.Fatalf("until: %d want 0", len(got))
	}
	if got, _, _ := l.List(ctx, Filter{Since: time.Now().Add(time.Minute)}); len(got) != 0 {
		t.Fatalf("since: %d want 0", len(got))
	}
}

func TestListActorLabel(t *testing.T) {
	ctx := context.Background()
	pool := testdb.New(t)
	l := New(pool)
	id := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO users (id,email,role) VALUES ($1,'a@x.test','staff')`, id); err != nil {
		t.Fatal(err)
	}
	seed(t, l, Event{ActorType: "user", ActorID: id.String(), Action: ActLoginOK}, Event{ActorType: "user", ActorID: "other", Action: ActLoginOK})
	for _, a := range []string{"A@X.TEST", id.String()} {
		got, _, err := l.List(ctx, Filter{Actor: a})
		if err != nil || len(got) != 1 || got[0].ActorLabel != "a@x.test" {
			t.Fatalf("actor %q: %+v %v", a, got, err)
		}
	}
}

func TestEachAscendingIgnoresPaging(t *testing.T) {
	ctx := context.Background()
	l := New(testdb.New(t))
	seed(t, l, ev(1), ev(2), ev(3))
	var ids []int64
	err := l.Each(ctx, Filter{BeforeID: 2, Limit: 1}, func(e Entry) error { ids = append(ids, e.ID); return nil })
	if err != nil || len(ids) != 3 || ids[0] >= ids[1] || ids[1] >= ids[2] {
		t.Fatalf("ids=%v err=%v", ids, err)
	}
}

func TestVerifyCountsAndFindsTamper(t *testing.T) {
	ctx := context.Background()
	pool := testdb.New(t)
	l := New(pool)
	seed(t, l, ev(1), ev(2), ev(3))
	if n, bad, err := l.Verify(ctx); err != nil || n != 3 || bad != 0 {
		t.Fatalf("n=%d bad=%d %v", n, bad, err)
	}
	var id int64
	if err := pool.QueryRow(ctx, `SELECT id FROM audit_log ORDER BY id OFFSET 1 LIMIT 1`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DROP RULE audit_no_update ON audit_log`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE audit_log SET result='x' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if _, bad, err := l.Verify(ctx); err != nil || bad != id {
		t.Fatalf("bad=%d want %d err=%v", bad, id, err)
	}
}

func TestAfter(t *testing.T) {
	ctx := context.Background()
	pool := testdb.New(t)
	l := New(pool)
	seed(t, l, ev(1), ev(2), ev(3))
	all, _, _ := l.List(ctx, Filter{})
	first := all[2].ID
	got, err := After(ctx, pool, first, 10)
	if err != nil || len(got) != 2 || got[0].ID != all[1].ID || got[1].ID != all[0].ID {
		t.Fatalf("got %+v %v", got, err)
	}
}
