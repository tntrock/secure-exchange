package audit

import (
	"context"
	"sync"
	"testing"

	"github.com/tntrock/secure-exchange/internal/db/testdb"
)

func ev(i int) Event {
	return Event{ActorType: "user", ActorID: "u1", IP: "1.2.3.4", UserAgent: "ua", Action: ActLoginOK,
		TargetType: "file", TargetID: "f", Result: "ok", Detail: map[string]any{"n": i, "z": "é", "a": []any{1, "x"}}}
}

func TestAuditChainVerifies(t *testing.T) {
	pool := testdb.New(t)
	l := New(pool)
	ctx := context.Background()
	if bad, err := l.Verify(ctx); err != nil || bad != 0 {
		t.Fatalf("empty: %d %v", bad, err)
	}
	for i := 0; i < 3; i++ {
		if err := l.Append(ctx, ev(i)); err != nil {
			t.Fatal(err)
		}
	}
	e := ev(9)
	e.Detail = nil
	if err := l.Append(ctx, e); err != nil {
		t.Fatal(err)
	}
	if bad, err := l.Verify(ctx); err != nil || bad != 0 {
		t.Fatalf("verify: %d %v", bad, err)
	}
	got, err := l.List(ctx, Filter{Action: ActLoginOK, Limit: 2})
	if err != nil || len(got) != 2 {
		t.Fatalf("list: %d %v", len(got), err)
	}
}

func TestAuditDetectsTamper(t *testing.T) {
	pool := testdb.New(t)
	l := New(pool)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := l.Append(ctx, ev(i)); err != nil {
			t.Fatal(err)
		}
	}
	var id int64
	if err := pool.QueryRow(ctx, `SELECT id FROM audit_log ORDER BY id OFFSET 1 LIMIT 1`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DROP RULE audit_no_update ON audit_log`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE audit_log SET result='fail' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if bad, err := l.Verify(ctx); err != nil || bad != id {
		t.Fatalf("want %d got %d %v", id, bad, err)
	}
}

func TestAuditConcurrentAppends(t *testing.T) {
	pool := testdb.New(t)
	l := New(pool)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := l.Append(ctx, ev(i)); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if bad, err := l.Verify(ctx); err != nil || bad != 0 {
		t.Fatalf("verify: %d %v", bad, err)
	}
	var n int
	pool.QueryRow(ctx, `SELECT count(*) FROM audit_log`).Scan(&n)
	if n != 50 {
		t.Fatalf("count %d", n)
	}
}
