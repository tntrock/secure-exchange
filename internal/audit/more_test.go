package audit

import (
	"context"
	"testing"
	"time"

	"github.com/tntrock/secure-exchange/internal/db/testdb"
)

func TestListFilters(t *testing.T) {
	pool := testdb.New(t)
	l := New(pool)
	ctx := context.Background()
	before := time.Now().Add(-time.Second)
	for i := 0; i < 3; i++ {
		e := ev(i)
		if i == 2 {
			e.ActorID = "u2"
		}
		if err := l.Append(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	after := time.Now().Add(time.Second)
	cases := []struct {
		name string
		f    Filter
		want int
	}{
		{"default limit", Filter{}, 3},
		{"actor", Filter{ActorID: "u2"}, 1},
		{"since now", Filter{Since: after}, 0},
		{"until before", Filter{Until: before}, 0},
		{"window", Filter{Since: before, Until: after}, 3},
	}
	for _, c := range cases {
		got, err := l.List(ctx, c.f)
		if err != nil || len(got) != c.want {
			t.Errorf("%s: %d entries, %v; want %d", c.name, len(got), err, c.want)
		}
	}
	got, _ := l.List(ctx, Filter{})
	if got[0].ID < got[1].ID || got[0].Event.ActorID != "u2" || got[0].Event.Detail["n"] != float64(2) {
		t.Fatalf("newest first with detail: %+v", got[0])
	}
}

func TestAppendErrors(t *testing.T) {
	pool := testdb.New(t)
	l := New(pool)
	e := ev(0)
	e.Detail = map[string]any{"bad": make(chan int)}
	if err := l.Append(context.Background(), e); err == nil {
		t.Fatal("unmarshalable detail accepted")
	}
	e = ev(0)
	e.UserAgent = "a\x00b" // Postgres text rejects NUL
	if err := l.Append(context.Background(), e); err == nil {
		t.Fatal("NUL in a text column accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.Append(ctx, ev(0)); err == nil {
		t.Fatal("Append on a canceled context succeeded")
	}
	if _, err := l.Verify(ctx); err == nil {
		t.Fatal("Verify on a canceled context succeeded")
	}
	if _, err := l.List(ctx, Filter{}); err == nil {
		t.Fatal("List on a canceled context succeeded")
	}
	if got, _ := l.List(context.Background(), Filter{}); len(got) != 0 {
		t.Fatalf("failed appends wrote %d rows", len(got))
	}
}

// A row whose detail is not a JSON object (written outside Append) is reported, not skipped.
func TestNonObjectDetailIsAnError(t *testing.T) {
	pool := testdb.New(t)
	l := New(pool)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO audit_log (at, actor_type, actor_id, ip, user_agent, action, target_type, target_id, result, detail, prev_hash, hash)
		VALUES (now(), 'user', 'u1', '', '', 'x', '', '', 'ok', '[1]', '\x00', '\x01')`); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Verify(ctx); err == nil {
		t.Fatal("Verify accepted a non-object detail")
	}
	if _, err := l.List(ctx, Filter{}); err == nil {
		t.Fatal("List accepted a non-object detail")
	}
}
