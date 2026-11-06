package share

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tntrock/secure-exchange/internal/rules"
)

func (e *env) setRules(t *testing.T, mod func(*rules.Rules)) {
	t.Helper()
	ctx := context.Background()
	r, err := e.svc.rules.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mod(&r)
	tx, err := e.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := e.svc.rules.Update(ctx, tx, r); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func wantValidation(t *testing.T, err error, field, code string) {
	t.Helper()
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Field != field || ve.Code != code {
		t.Fatalf("want %s/%s, got %v", field, code, err)
	}
}

func TestCreateEnforcesRules(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name        string
		rule        func(*rules.Rules)
		mod         func(*env, *CreateInput)
		field, code string
	}{
		{"forbid download", func(r *rules.Rules) { r.ForbidDownload = true }, func(_ *env, in *CreateInput) { in.AllowDownload = true }, "allow_download", "locked"},
		{"force watermark", func(r *rules.Rules) { r.ForceWatermark = true }, func(_ *env, in *CreateInput) { in.Watermark = false }, "watermark", "locked"},
		{"max days", func(r *rules.Rules) { r.ShareMaxDays, r.ShareDefaultDays = 3, 3 },
			func(e *env, in *CreateInput) { in.ExpiresAt = e.now.Add(4 * 24 * time.Hour) }, "expires_at", "out_of_range"},
		{"max share bytes", func(r *rules.Rules) { r.MaxShareBytes = 10 },
			func(e *env, in *CreateInput) {
				in.FileIDs = append(in.FileIDs, e.file(t, e.owner, false))
				if _, err := e.pool.Exec(ctx, `UPDATE files SET size = 6 WHERE id = ANY($1)`, in.FileIDs); err != nil {
					t.Fatal(err)
				}
			}, "file_ids", "too_large"},
		{"domain block email", func(r *rules.Rules) { r.DomainBlock = []string{"evil.com"} },
			func(_ *env, in *CreateInput) { in.Emails = []string{"a@evil.com"} }, "emails", "domain_blocked"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := setup(t)
			e.setRules(t, c.rule)
			in := e.input(t)
			c.mod(e, &in)
			_, err := e.svc.Create(ctx, e.owner, in)
			wantValidation(t, err, c.field, c.code)
		})
	}
}

func TestRulesDomainBlockVendorAndAddRecipients(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	v := e.vendor(t, "v@evil.com")
	sh, _ := e.newShare(t, nil, "bob@x.com")
	e.setRules(t, func(r *rules.Rules) { r.DomainBlock = []string{"evil.com"} })
	in := e.input(t)
	in.Emails, in.VendorIDs = nil, []uuid.UUID{v}
	_, err := e.svc.Create(ctx, e.owner, in)
	wantValidation(t, err, "vendor_ids", "domain_blocked")
	_, err = e.svc.AddRecipients(ctx, e.owner, sh.ID, []string{"c@evil.com"}, nil)
	wantValidation(t, err, "emails", "domain_blocked")
}

func TestForbidDownloadStillNeedsPreview(t *testing.T) {
	e := setup(t)
	e.setRules(t, func(r *rules.Rules) { r.ForbidDownload = true })
	in := e.input(t)
	in.AllowDownload = false
	if _, err := e.pool.Exec(context.Background(), `INSERT INTO file_previews (file_id, kind, status) VALUES ($1,'pages','unsupported')`, in.FileIDs[0]); err != nil {
		t.Fatal(err)
	}
	_, err := e.svc.Create(context.Background(), e.owner, in)
	wantValidation(t, err, "file_ids", "not_previewable")
}
