package rules

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/tntrock/secure-exchange/internal/db/testdb"
)

func TestSeedOnceAndGet(t *testing.T) {
	ctx := context.Background()
	pool := testdb.New(t)
	s := New(pool, 1<<30)
	if err := s.Seed(ctx, 30); err != nil {
		t.Fatal(err)
	}
	r, err := s.Get(ctx)
	if err != nil || r.ShareMaxDays != 30 || r.ShareDefaultDays != 7 {
		t.Fatalf("%+v %v", r, err)
	}
	if err := s.Seed(ctx, 90); err != nil {
		t.Fatal(err)
	}
	if r, _ = s.Get(ctx); r.ShareMaxDays != 30 {
		t.Fatalf("reseeded: %+v", r)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM site_rules`); err != nil {
		t.Fatal(err)
	}
	if err := s.Seed(ctx, 5); err != nil {
		t.Fatal(err)
	}
	if r, _ = s.Get(ctx); r.ShareMaxDays != 5 || r.ShareDefaultDays != 5 {
		t.Fatalf("%+v", r)
	}
}

func TestUpdateValidates(t *testing.T) {
	ctx := context.Background()
	pool := testdb.New(t)
	s := New(pool, 1000)
	if err := s.Seed(ctx, 30); err != nil {
		t.Fatal(err)
	}
	many := make([]string, 201)
	for i := range many {
		many[i] = "a.com"
	}
	cases := []struct {
		name        string
		mod         func(*Rules)
		field, code string
	}{
		{"max 0", func(r *Rules) { r.ShareMaxDays = 0 }, "share_max_days", "out_of_range"},
		{"max 366", func(r *Rules) { r.ShareMaxDays = 366 }, "share_max_days", "out_of_range"},
		{"default>max", func(r *Rules) { r.ShareDefaultDays = 31 }, "share_default_days", "out_of_range"},
		{"default 0", func(r *Rules) { r.ShareDefaultDays = 0 }, "share_default_days", "out_of_range"},
		{"file>hard", func(r *Rules) { r.MaxFileBytes = 1001 }, "max_file_bytes", "out_of_range"},
		{"neg file", func(r *Rules) { r.MaxFileBytes = -1 }, "max_file_bytes", "out_of_range"},
		{"neg share", func(r *Rules) { r.MaxShareBytes = -1 }, "max_share_bytes", "out_of_range"},
		{"neg upload", func(r *Rules) { r.UploadMaxBytes = -1 }, "upload_max_bytes", "out_of_range"},
		{"neg quota", func(r *Rules) { r.QuotaBytes = -1 }, "quota_bytes", "out_of_range"},
		{"retention", func(r *Rules) { r.RetentionDays = 3651 }, "retention_days", "out_of_range"},
		{"neg retention", func(r *Rules) { r.RetentionDays = -1 }, "retention_days", "out_of_range"},
		{"bad block", func(r *Rules) { r.DomainBlock = []string{"bad domain"} }, "domain_block", "invalid"},
		{"no dot", func(r *Rules) { r.DomainAllow = []string{"localhost"} }, "domain_allow", "invalid"},
		{"many block", func(r *Rules) { r.DomainBlock = many }, "domain_block", "too_many"},
		{"many allow", func(r *Rules) { r.DomainAllow = many }, "domain_allow", "too_many"},
		{"bad ext", func(r *Rules) { r.UploadExts = []string{"ex e"} }, "upload_exts", "invalid"},
		{"many ip", func(r *Rules) {
			r.ExternalIPAllow = make([]netip.Prefix, 101)
			for i := range r.ExternalIPAllow {
				r.ExternalIPAllow[i] = netip.MustParsePrefix("10.0.0.0/8")
			}
		}, "external_ip_allow", "too_many"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Rules{ShareMaxDays: 30, ShareDefaultDays: 7}
			c.mod(&r)
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			_, err = s.Update(ctx, tx, r)
			var ve *ValidationError
			if !errors.As(err, &ve) || ve.Field != c.field || ve.Code != c.code {
				t.Fatalf("got %v", err)
			}
		})
	}

	r := Rules{ShareMaxDays: 10, ShareDefaultDays: 3,
		DomainBlock: []string{" Example.COM ", "example.com"},
		UploadExts:  []string{".PDF", "pdf", "Docx"}}
	tx, _ := pool.Begin(ctx)
	defer tx.Rollback(ctx)
	before, err := s.Update(ctx, tx, r)
	if err != nil || before.ShareMaxDays != 30 {
		t.Fatalf("%+v %v", before, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(ctx)
	if !reflect.DeepEqual(got.DomainBlock, []string{"example.com"}) || !reflect.DeepEqual(got.UploadExts, []string{"pdf", "docx"}) || got.ShareMaxDays != 10 {
		t.Fatalf("%+v", got)
	}
}

func TestDomainAllowed(t *testing.T) {
	cases := []struct {
		r     Rules
		email string
		want  bool
	}{
		{Rules{DomainBlock: []string{"evil.com"}}, "a@evil.com", false},
		{Rules{DomainBlock: []string{"evil.com"}}, "a@x.evil.com", false},
		{Rules{DomainBlock: []string{"evil.com"}}, "a@notevil.com", true},
		{Rules{DomainAllow: []string{"corp.com"}}, "a@other.com", false},
		{Rules{DomainAllow: []string{"corp.com"}}, "a@corp.com", true},
		{Rules{DomainAllow: []string{"corp.com"}, DomainBlock: []string{"corp.com"}}, "a@corp.com", false},
		{Rules{}, "a@anything.org", true},
	}
	for _, c := range cases {
		if got := c.r.DomainAllowed(c.email); got != c.want {
			t.Errorf("%+v %s: got %v", c.r, c.email, got)
		}
	}
}

func TestIPAllowed(t *testing.T) {
	if !(Rules{}).IPAllowed(netip.MustParseAddr("1.2.3.4")) {
		t.Fatal("empty should allow")
	}
	r := Rules{ExternalIPAllow: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	for ip, want := range map[string]bool{"10.1.2.3": true, "::ffff:10.1.2.3": true, "192.168.1.1": false} {
		if got := r.IPAllowed(netip.MustParseAddr(ip)); got != want {
			t.Errorf("%s: %v", ip, got)
		}
	}
}

func TestExtAllowed(t *testing.T) {
	r := Rules{UploadExts: []string{"pdf"}}
	for n, want := range map[string]bool{"a.PDF": true, "a.exe": false, "noext": false} {
		if got := r.ExtAllowed(n); got != want {
			t.Errorf("%s: %v", n, got)
		}
	}
	if !(Rules{}).ExtAllowed("a.exe") {
		t.Fatal("empty should allow")
	}
}
