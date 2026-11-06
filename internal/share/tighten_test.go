package share

import (
	"context"
	"strings"
	"testing"

	"github.com/tntrock/secure-exchange/internal/mail/mailtest"
	"github.com/tntrock/secure-exchange/internal/rules"
)

func TestNotifyRulesTightened(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	e.newShare(t, nil, "a@y.com")                                            // download allowed, no watermark, y.com recipient
	e.newShare(t, func(in *CreateInput) { in.Watermark = true }, "b@ok.com") // download allowed only
	revoked, _ := e.newShare(t, nil, "c@y.com")
	if _, err := e.pool.Exec(ctx, `UPDATE shares SET revoked_at = now() WHERE id = $1`, revoked.ID); err != nil {
		t.Fatal(err)
	}
	before := len(mailtest.Messages(t, e.pool, e.keys))

	notify := func(b, a rules.Rules) int {
		t.Helper()
		tx, err := e.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		n, err := e.svc.NotifyRulesTightened(ctx, tx, b, a)
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// an IP-only change is not share-specific: no digest
	if n := notify(rules.Rules{}, rules.Rules{}); n != 0 {
		t.Fatal("unchanged:", n)
	}
	n := notify(rules.Rules{}, rules.Rules{ForbidDownload: true, ForceWatermark: true, DomainBlock: []string{"y.com"}})
	if n != 2 {
		t.Fatalf("affected = %d, want 2 (revoked share excluded)", n)
	}
	msgs := mailtest.Messages(t, e.pool, e.keys)[before:]
	if len(msgs) != 1 || msgs[0].To != e.owner.Email {
		t.Fatalf("want one digest to the owner, got %+v", msgs)
	}
	if lines := strings.Count(msgs[0].Body, "/shares/"); lines < 2 {
		t.Fatalf("digest lists %d shares:\n%s", lines, msgs[0].Body)
	}
}
