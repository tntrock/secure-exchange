package rules

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tntrock/secure-exchange/internal/db/testdb"
)

func TestParsePrefixes(t *testing.T) {
	got, err := ParsePrefixes([]string{"203.0.113.5", "10.1.2.3/8", "::ffff:10.0.0.0/104", "2001:db8::1"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"203.0.113.5/32", "10.0.0.0/8", "10.0.0.0/8", "2001:db8::1/128"}
	for i, p := range got {
		if p.String() != want[i] {
			t.Fatalf("%d: %s, want %s", i, p, want[i])
		}
	}
	if _, err := ParsePrefixes([]string{"nope"}, 10); !errors.Is(err, ErrInvalid) {
		t.Fatal("invalid:", err)
	}
	if _, err := ParsePrefixes([]string{"1.1.1.1", "2.2.2.2"}, 1); !errors.Is(err, ErrTooMany) {
		t.Fatal("too many:", err)
	}
	if got, err := ParsePrefixes(nil, 1); err != nil || len(got) != 0 {
		t.Fatal("empty:", got, err)
	}
}

func TestValidationErrorAndAccessors(t *testing.T) {
	if s := (&ValidationError{Field: "f", Code: "c"}).Error(); s != "rules: f c" {
		t.Fatal(s)
	}
	ctx := context.Background()
	pool := testdb.New(t)
	s := New(pool, 1234)
	if s.HardMaxFile() != 1234 {
		t.Fatal("hard max")
	}
	if err := s.Seed(ctx, 30); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	r, err := s.GetTx(ctx, tx)
	if err != nil || r.ShareMaxDays != 30 {
		t.Fatal(r, err)
	}
	r.ExternalIPAllow = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	if _, err := s.Update(ctx, tx, r); err != nil {
		t.Fatal(err)
	}
	if r, err = s.GetTx(ctx, tx); err != nil || len(r.ExternalIPAllow) != 1 {
		t.Fatal(r, err)
	}
}

func TestRunRetentionStopsOnCancel(t *testing.T) {
	f, s, log := retSetup(t)
	id := f.file(nil, false)
	f.share(true, "-30 days", id)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.RunRetention(ctx, f.store, log, time.Hour); close(done) }()
	deadline := time.Now().Add(10 * time.Second)
	// The sweep marks the row deleted before removing the blob, so only poll the row while it runs;
	// the row/blob invariant (f.gone) is checked once it has stopped.
	for deleted := false; !deleted; {
		if time.Now().After(deadline) {
			t.Fatal("first sweep did not run")
		}
		time.Sleep(20 * time.Millisecond)
		if err := f.pool.QueryRow(context.Background(), `SELECT deleted_at IS NOT NULL FROM files WHERE id=$1`, id).Scan(&deleted); err != nil {
			t.Fatal(err)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunRetention did not stop")
	}
	if !f.gone(id) {
		t.Fatal("file not gone after the sweep")
	}
}
