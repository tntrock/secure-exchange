package share

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tntrock/secure-exchange/internal/mail/mailtest"
)

// vendor inserts an active vendor account (password and TOTP set, approved) and returns its id.
func (e *env) vendor(t *testing.T, email string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := e.pool.Exec(context.Background(), `INSERT INTO users (id,email,display_name,role,password_hash,totp_enabled)
		VALUES ($1,$2,'V','vendor','x',true)`, id, email); err != nil {
		t.Fatal(err)
	}
	return id
}

func (e *env) vendorShare(t *testing.T, mod func(*CreateInput), vendors ...uuid.UUID) *Share {
	t.Helper()
	in := e.input(t)
	in.Emails, in.VendorIDs = nil, vendors
	if mod != nil {
		mod(&in)
	}
	sh, err := e.svc.Create(context.Background(), e.owner, in)
	if err != nil {
		t.Fatal(err)
	}
	return sh
}

func isValidation(err error, field, code string) bool {
	var ve *ValidationError
	return errors.As(err, &ve) && ve.Field == field && ve.Code == code
}

func TestCreateWithVendors(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	v := e.vendor(t, "v@vendor.com")

	sh := e.vendorShare(t, func(in *CreateInput) { in.Message = "please review" }, v, v)
	if len(sh.Recipients) != 1 || sh.Recipients[0].VendorID == nil || *sh.Recipients[0].VendorID != v || sh.Recipients[0].Email != "v@vendor.com" {
		t.Fatalf("%+v", sh.Recipients)
	}
	msgs := mailtest.Messages(t, e.pool, e.keys)
	if len(msgs) != 1 || msgs[0].To != "v@vendor.com" || !strings.Contains(msgs[0].Body, "https://sx.example/vendor/shares") ||
		!strings.Contains(msgs[0].Body, "please review") || !strings.Contains(msgs[0].Body, "Olivia") || linkRE.MatchString(msgs[0].Body) {
		t.Fatalf("%+v", msgs)
	}

	// an email entry equal to a vendor's address keeps only the vendor row
	sh = e.vendorShare(t, func(in *CreateInput) { in.Emails = []string{"V@Vendor.com", "bob@x.com"} }, v)
	if len(sh.Recipients) != 2 {
		t.Fatalf("%+v", sh.Recipients)
	}
	for _, r := range sh.Recipients {
		if (r.Email == "v@vendor.com") != (r.VendorID != nil) {
			t.Fatalf("%+v", r)
		}
	}

	staff := e.user(t, "staff@x.com", "S")
	disabled := e.vendor(t, "d@vendor.com")
	expired := e.vendor(t, "e@vendor.com")
	pending := e.vendor(t, "p@vendor.com")
	e.pool.Exec(ctx, `UPDATE users SET disabled = true WHERE id = $1`, disabled)
	e.pool.Exec(ctx, `UPDATE users SET expires_at = $2 WHERE id = $1`, expired, e.now)
	e.pool.Exec(ctx, `UPDATE users SET approval = 'pending' WHERE id = $1`, pending)
	for name, id := range map[string]uuid.UUID{"unknown": uuid.New(), "staff": staff.ID, "disabled": disabled, "expired": expired, "pending": pending} {
		in := e.input(t)
		in.VendorIDs = []uuid.UUID{v, id}
		if _, err := e.svc.Create(ctx, e.owner, in); !isValidation(err, "vendor_ids", "not_found") {
			t.Errorf("%s: %v", name, err)
		}
	}

	in := e.input(t)
	in.Emails = nil
	if _, err := e.svc.Create(ctx, e.owner, in); !isValidation(err, "recipients", "required") {
		t.Fatal(err)
	}
	in.Emails = make([]string, 50)
	for i := range in.Emails {
		in.Emails[i] = uuid.NewString() + "@x.com"
	}
	in.VendorIDs = []uuid.UUID{v}
	if _, err := e.svc.Create(ctx, e.owner, in); !isValidation(err, "emails", "too_many") {
		t.Fatal(err)
	}
	if n := count(t, e, `SELECT count(*) FROM shares`); n != 2 {
		t.Fatalf("shares: %d", n)
	}
}

func TestAddVendorRecipients(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	v, w := e.vendor(t, "v@vendor.com"), e.vendor(t, "w@vendor.com")
	sh := e.vendorShare(t, nil, v)
	added, err := e.svc.AddRecipients(ctx, e.owner, sh.ID, []string{"w@vendor.com", "bob@x.com"}, []uuid.UUID{v, w})
	if err != nil || len(added) != 2 {
		t.Fatal(added, err)
	}
	for _, r := range added {
		if (r.Email == "w@vendor.com") != (r.VendorID != nil && *r.VendorID == w) {
			t.Fatalf("%+v", r)
		}
	}
	if mailsTo(t, e, "w@vendor.com", "") != 1 {
		t.Fatal("no vendor mail")
	}
	if _, err := e.svc.AddRecipients(ctx, e.owner, sh.ID, nil, nil); !isValidation(err, "recipients", "required") {
		t.Fatal(err)
	}
	if _, err := e.svc.AddRecipients(ctx, e.owner, sh.ID, nil, []uuid.UUID{uuid.New()}); !isValidation(err, "vendor_ids", "not_found") {
		t.Fatal(err)
	}
	got, err := e.svc.Get(ctx, e.owner.ID, sh.ID)
	if err != nil || len(got.Recipients) != 3 {
		t.Fatal(got, err)
	}
}

func TestRequestCodeIgnoresVendorRows(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	v := e.vendor(t, "v@vendor.com")
	sh, tok := e.newShare(t, nil, "bob@x.com")
	if _, err := e.svc.AddRecipients(ctx, e.owner, sh.ID, nil, []uuid.UUID{v}); err != nil {
		t.Fatal(err)
	}
	if sent, err := e.svc.RequestCode(ctx, tok, "v@vendor.com", ip1); err != nil || sent {
		t.Fatal(sent, err)
	}
	if n := count(t, e, `SELECT count(*) FROM share_otps`); n != 0 {
		t.Fatalf("otps: %d", n)
	}
	// even a code row planted for the vendor recipient is never accepted
	var rid uuid.UUID
	e.pool.QueryRow(ctx, `SELECT id FROM share_recipients WHERE vendor_id = $1`, v).Scan(&rid)
	oid := uuid.New()
	if _, err := e.pool.Exec(ctx, `INSERT INTO share_otps (id, recipient_id, code_hash, expires_at) VALUES ($1,$2,$3,$4)`,
		oid, rid, otpHash(oid, "123456"), e.now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.VerifyCode(ctx, tok, "v@vendor.com", "123456", ip1, ""); !errors.Is(err, ErrBadCode) {
		t.Fatal(err)
	}
}

func TestVendorAccessCountsViewOncePerSession(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	v := e.vendor(t, "v@vendor.com")
	sh := e.vendorShare(t, func(in *CreateInput) { two := 2; in.MaxViews = &two }, v)
	s1, s2, s3 := []byte("session-1"), []byte("session-2"), []byte("session-3")
	for range 2 {
		a, err := e.svc.VendorAccess(ctx, v, sh.ID, s1, ip1)
		if err != nil || a.Share.ViewCount != 1 || a.Recipient.Email != "v@vendor.com" || len(a.Share.Files) != 1 || string(a.SessionHash) != "session-1" {
			t.Fatal(a, err)
		}
	}
	if a, err := e.svc.VendorAccess(ctx, v, sh.ID, s2, ip1); err != nil || a.Share.ViewCount != 2 {
		t.Fatal(a, err)
	}
	if _, err := e.svc.VendorAccess(ctx, v, sh.ID, s3, ip1); !errors.Is(err, ErrViewLimit) {
		t.Fatal(err)
	}
	if _, err := e.svc.VendorAccess(ctx, v, sh.ID, s1, ip1); err != nil {
		t.Fatal("a counted session must keep working", err)
	}
	if n := count(t, e, `SELECT count(*) FROM share_recipients WHERE vendor_id = $1 AND first_opened_at IS NOT NULL AND last_access_at IS NOT NULL`, v); n != 1 {
		t.Fatal("first_opened_at / last_access_at not set")
	}
	if n := mailsTo(t, e, "owner@x.com", "opened"); n != 1 {
		t.Fatalf("first-open mails: %d", n)
	}
}

func TestVendorShareIsolation(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	a, b := e.vendor(t, "a@vendor.com"), e.vendor(t, "b@vendor.com")
	sess := []byte("s")
	sh := e.vendorShare(t, nil, a)
	if _, err := e.svc.VendorAccess(ctx, b, sh.ID, sess, ip1); !errors.Is(err, ErrNotFound) {
		t.Fatal("non-recipient vendor", err)
	}
	if _, err := e.svc.VendorAccess(ctx, a, uuid.New(), sess, ip1); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown share", err)
	}

	// IP allow list
	ipSh := e.vendorShare(t, func(in *CreateInput) { in.IPAllow = []string{"10.0.0.0/8"} }, a)
	if _, err := e.svc.VendorAccess(ctx, a, ipSh.ID, sess, ip1); !errors.Is(err, ErrIPDenied) {
		t.Fatal("ip", err)
	}
	if _, err := e.svc.VendorAccess(ctx, a, ipSh.ID, sess, netip.MustParseAddr("10.1.2.3")); err != nil {
		t.Fatal("allowed ip", err)
	}

	// revoked recipient: not found, even for a session that already counted a view
	if _, err := e.svc.VendorAccess(ctx, a, sh.ID, sess, ip1); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.RevokeRecipient(ctx, e.owner.ID, sh.ID, sh.Recipients[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.VendorAccess(ctx, a, sh.ID, sess, ip1); !errors.Is(err, ErrNotFound) {
		t.Fatal("revoked recipient", err)
	}

	// revoked and expired shares are gone; a non-recipient still sees not found
	sh2 := e.vendorShare(t, nil, a)
	if err := e.svc.Revoke(ctx, e.owner.ID, sh2.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.VendorAccess(ctx, a, sh2.ID, sess, ip1); !errors.Is(err, ErrGone) {
		t.Fatal("revoked share", err)
	}
	if _, err := e.svc.VendorAccess(ctx, b, sh2.ID, sess, ip1); !errors.Is(err, ErrNotFound) {
		t.Fatal("revoked share, non-recipient", err)
	}
	sh3 := e.vendorShare(t, nil, a)
	e.now = e.now.Add(8 * 24 * time.Hour)
	if _, err := e.svc.VendorAccess(ctx, a, sh3.ID, sess, ip1); !errors.Is(err, ErrGone) {
		t.Fatal("expired share", err)
	}
}

func TestVendorSharesList(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	a, b := e.vendor(t, "a@vendor.com"), e.vendor(t, "b@vendor.com")
	older := e.vendorShare(t, nil, a)
	e.pool.Exec(ctx, `UPDATE shares SET created_at = now() - interval '1 hour' WHERE id = $1`, older.ID)
	newer := e.vendorShare(t, nil, a, b)
	e.vendorShare(t, nil, b)
	revoked := e.vendorShare(t, nil, a)
	e.svc.Revoke(ctx, e.owner.ID, revoked.ID)
	expired := e.vendorShare(t, nil, a)
	e.pool.Exec(ctx, `UPDATE shares SET expires_at = $2 WHERE id = $1`, expired.ID, e.now)
	dropped := e.vendorShare(t, nil, a)
	e.svc.RevokeRecipient(ctx, e.owner.ID, dropped.ID, dropped.Recipients[0].ID)
	e.newShare(t, nil, "a@vendor.com") // email recipient with the vendor's address: not a vendor share

	got, err := e.svc.VendorShares(ctx, a)
	if err != nil || len(got) != 2 || got[0].ID != newer.ID || got[1].ID != older.ID || got[0].OwnerName != "Olivia" || got[0].FileCount != 1 {
		t.Fatalf("%+v %v", got, err)
	}
}
