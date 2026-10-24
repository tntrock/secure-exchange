package share

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tntrock/secure-exchange/internal/mail/mailtest"
)

var (
	ip1    = netip.MustParseAddr("192.0.2.1")
	codeRE = regexp.MustCompile(`驗證碼是：(\d{6})`)
)

// newShare creates a share for emails and returns it with its link token.
func (e *env) newShare(t *testing.T, mod func(*CreateInput), emails ...string) (*Share, string) {
	t.Helper()
	in := e.input(t)
	in.Emails = emails
	if mod != nil {
		mod(&in)
	}
	sh, err := e.svc.Create(context.Background(), e.owner, in)
	if err != nil {
		t.Fatal(err)
	}
	msgs := mailtest.Messages(t, e.pool, e.keys)
	m := linkRE.FindStringSubmatch(msgs[len(msgs)-1].Body)
	if m == nil {
		t.Fatal("no link")
	}
	return sh, m[1]
}

// code requests a code for email and returns it from the outbox.
func (e *env) code(t *testing.T, token, email string) string {
	t.Helper()
	if err := e.svc.RequestCode(context.Background(), token, email, ip1); err != nil {
		t.Fatal(err)
	}
	msgs := mailtest.Messages(t, e.pool, e.keys)
	last := msgs[len(msgs)-1]
	m := codeRE.FindStringSubmatch(last.Body)
	if last.To != email || m == nil {
		t.Fatalf("no code mail for %s: %+v", email, last)
	}
	return m[1]
}

func wrong(code string) string {
	if code == "000000" {
		return "000001"
	}
	return "000000"
}

func mailsTo(t *testing.T, e *env, to, subjectPart string) int {
	t.Helper()
	n := 0
	for _, m := range mailtest.Messages(t, e.pool, e.keys) {
		if m.To == to && strings.Contains(m.Subject, subjectPart) {
			n++
		}
	}
	return n
}

func TestRequestCodeUniform(t *testing.T) {
	e := setup(t)
	_, tok := e.newShare(t, nil, "bob@x.com")
	before := len(mailtest.Messages(t, e.pool, e.keys))
	if err := e.svc.RequestCode(context.Background(), tok, " Bob@X.com", ip1); err != nil {
		t.Fatal(err)
	}
	if n := len(mailtest.Messages(t, e.pool, e.keys)); n != before+1 {
		t.Fatalf("listed: outbox %d want %d", n, before+1)
	}
	if err := e.svc.RequestCode(context.Background(), tok, "eve@x.com", ip1); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.RequestCode(context.Background(), tok, "not an email", ip1); err != nil {
		t.Fatal(err)
	}
	if n := len(mailtest.Messages(t, e.pool, e.keys)); n != before+1 {
		t.Fatalf("unlisted: outbox %d want %d", n, before+1)
	}
	if err := e.svc.RequestCode(context.Background(), "nope", "bob@x.com", ip1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bad token: %v", err)
	}
}

func TestVerifyCodeFlow(t *testing.T) {
	e := setup(t)
	sh, tok := e.newShare(t, nil, "bob@x.com")
	code := e.code(t, tok, "bob@x.com")
	var hash []byte
	if err := e.pool.QueryRow(context.Background(), `SELECT code_hash FROM share_otps`).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(hash, []byte(code)) {
		t.Fatal("plaintext code stored")
	}
	st, a, err := e.svc.VerifyCode(context.Background(), tok, "bob@x.com", code, ip1, "ua")
	if err != nil {
		t.Fatal(err)
	}
	if st == "" || a.Share.ID != sh.ID || a.Recipient.Email != "bob@x.com" || len(a.Share.Files) != 1 {
		t.Fatalf("%q %+v", st, a)
	}
	if n := count(t, e, `SELECT count(*) FROM share_sessions WHERE token_hash = sha256($1::bytea)`, []byte(st)); n != 1 {
		t.Fatalf("session hash rows %d", n)
	}
	if n := count(t, e, `SELECT view_count FROM shares WHERE id=$1`, sh.ID); n != 1 {
		t.Fatalf("view_count %d", n)
	}
	if _, err := e.svc.Authorize(context.Background(), st, ip1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.VerifyCode(context.Background(), tok, "bob@x.com", code, ip1, "ua"); !errors.Is(err, ErrBadCode) {
		t.Fatalf("reuse: %v", err)
	}
	if _, _, err := e.svc.VerifyCode(context.Background(), tok, "eve@x.com", code, ip1, "ua"); !errors.Is(err, ErrBadCode) {
		t.Fatalf("unlisted: %v", err)
	}
	if _, err := e.svc.Authorize(context.Background(), "bogus", ip1); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("bogus session: %v", err)
	}
	e.now = e.now.Add(time.Hour + time.Second)
	if _, err := e.svc.Authorize(context.Background(), st, ip1); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired session: %v", err)
	}
}

func TestOTPAttemptsLimit(t *testing.T) {
	e := setup(t)
	_, tok := e.newShare(t, nil, "bob@x.com")
	code := e.code(t, tok, "bob@x.com")
	for i := 0; i < 5; i++ {
		if _, _, err := e.svc.VerifyCode(context.Background(), tok, "bob@x.com", wrong(code), ip1, ""); !errors.Is(err, ErrBadCode) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if _, _, err := e.svc.VerifyCode(context.Background(), tok, "bob@x.com", code, ip1, ""); !errors.Is(err, ErrBadCode) {
		t.Fatalf("after 5: %v", err)
	}
}

func TestOTPExpired(t *testing.T) {
	e := setup(t)
	_, tok := e.newShare(t, nil, "bob@x.com")
	code := e.code(t, tok, "bob@x.com")
	if _, err := e.pool.Exec(context.Background(), `UPDATE share_otps SET expires_at = $1`, e.now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.VerifyCode(context.Background(), tok, "bob@x.com", code, ip1, ""); !errors.Is(err, ErrBadCode) {
		t.Fatalf("%v", err)
	}
}

func TestOTPSingleUseConcurrent(t *testing.T) {
	e := setup(t)
	_, tok := e.newShare(t, nil, "bob@x.com")
	code := e.code(t, tok, "bob@x.com")
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, bad := 0, 0
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := e.svc.VerifyCode(context.Background(), tok, "bob@x.com", code, ip1, "")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, ErrBadCode):
				bad++
			default:
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if ok != 1 || bad != 9 {
		t.Fatalf("ok %d bad %d", ok, bad)
	}
}

func TestMaxViewsConcurrent(t *testing.T) {
	e := setup(t)
	emails := []string{"a@x.com", "b@x.com", "c@x.com", "d@x.com", "f@x.com"}
	sh, tok := e.newShare(t, func(in *CreateInput) { mv := 3; in.MaxViews = &mv }, emails...)
	codes := make([]string, len(emails))
	for i, em := range emails {
		codes[i] = e.code(t, tok, em)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, limited := 0, 0
	for i := range emails {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, err := e.svc.VerifyCode(context.Background(), tok, emails[i], codes[i], ip1, "")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, ErrViewLimit):
				limited++
			default:
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if ok != 3 || limited != 2 {
		t.Fatalf("ok %d limited %d", ok, limited)
	}
	if n := count(t, e, `SELECT view_count FROM shares WHERE id=$1`, sh.ID); n != 3 {
		t.Fatalf("view_count %d", n)
	}
}

func TestNewCodeInvalidatesOld(t *testing.T) {
	e := setup(t)
	_, tok := e.newShare(t, nil, "bob@x.com")
	first := e.code(t, tok, "bob@x.com")
	second := e.code(t, tok, "bob@x.com")
	if first != second { // same digits would make the check meaningless
		if _, _, err := e.svc.VerifyCode(context.Background(), tok, "bob@x.com", first, ip1, ""); !errors.Is(err, ErrBadCode) {
			t.Fatalf("old code: %v", err)
		}
	}
	if n := count(t, e, `SELECT count(*) FROM share_otps WHERE used_at IS NULL`); n != 1 {
		t.Fatalf("unused otps %d", n)
	}
	if _, _, err := e.svc.VerifyCode(context.Background(), tok, "bob@x.com", second, ip1, ""); err != nil {
		t.Fatalf("new code: %v", err)
	}
}

func TestAccessRecheckedEveryRequest(t *testing.T) {
	cases := []struct {
		name string
		mod  func(t *testing.T, e *env, sh *Share, a *Access)
		want error
	}{
		{"revoked share", func(t *testing.T, e *env, sh *Share, _ *Access) {
			if err := e.svc.Revoke(context.Background(), e.owner.ID, sh.ID); err != nil {
				t.Fatal(err)
			}
		}, ErrUnauthorized}, // Revoke drops sessions
		{"revoked share, session kept", func(t *testing.T, e *env, sh *Share, _ *Access) {
			if _, err := e.pool.Exec(context.Background(), `UPDATE shares SET revoked_at = now() WHERE id=$1`, sh.ID); err != nil {
				t.Fatal(err)
			}
		}, ErrGone},
		{"revoked recipient", func(t *testing.T, e *env, sh *Share, a *Access) {
			if err := e.svc.RevokeRecipient(context.Background(), e.owner.ID, sh.ID, a.Recipient.ID); err != nil {
				t.Fatal(err)
			}
		}, ErrUnauthorized},
		{"expired", func(t *testing.T, e *env, sh *Share, _ *Access) {
			if _, err := e.pool.Exec(context.Background(), `UPDATE shares SET expires_at = $2 WHERE id=$1`, sh.ID, e.now.Add(-time.Second)); err != nil {
				t.Fatal(err)
			}
		}, ErrGone},
		{"ip denied", func(t *testing.T, e *env, sh *Share, _ *Access) {
			if _, err := e.pool.Exec(context.Background(), `UPDATE shares SET ip_allow = '{10.0.0.0/8}' WHERE id=$1`, sh.ID); err != nil {
				t.Fatal(err)
			}
		}, ErrIPDenied},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := setup(t)
			sh, tok := e.newShare(t, nil, "bob@x.com")
			st, a, err := e.svc.VerifyCode(context.Background(), tok, "bob@x.com", e.code(t, tok, "bob@x.com"), ip1, "")
			if err != nil {
				t.Fatal(err)
			}
			c.mod(t, e, sh, a)
			if _, err := e.svc.Authorize(context.Background(), st, ip1); !errors.Is(err, c.want) {
				t.Fatalf("got %v want %v", err, c.want)
			}
		})
	}
}

func TestLandingChecks(t *testing.T) {
	e := setup(t)
	sh, tok := e.newShare(t, func(in *CreateInput) { in.Message = "hi"; in.IPAllow = []string{"192.0.2.0/24"} }, "bob@x.com")
	got, err := e.svc.Landing(context.Background(), tok, ip1)
	if err != nil || got.Message != "hi" || got.OwnerName != "Olivia" || !got.ExpiresAt.Equal(sh.ExpiresAt) {
		t.Fatalf("%v %+v", err, got)
	}
	if _, err := e.svc.Landing(context.Background(), tok, netip.MustParseAddr("198.51.100.1")); !errors.Is(err, ErrIPDenied) {
		t.Fatalf("ip: %v", err)
	}
	if _, err := e.svc.Landing(context.Background(), "nope", ip1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("token: %v", err)
	}
	e.now = sh.ExpiresAt
	if _, err := e.svc.Landing(context.Background(), tok, ip1); !errors.Is(err, ErrGone) {
		t.Fatalf("expired: %v", err)
	}
}

func TestFirstOpenNotifiesOnce(t *testing.T) {
	e := setup(t)
	sh, tok := e.newShare(t, nil, "bob@x.com")
	for i := 0; i < 2; i++ {
		if _, _, err := e.svc.VerifyCode(context.Background(), tok, "bob@x.com", e.code(t, tok, "bob@x.com"), ip1, ""); err != nil {
			t.Fatal(err)
		}
	}
	if n := mailsTo(t, e, "owner@x.com", "opened"); n != 1 {
		t.Fatalf("first-open mails %d", n)
	}
	var body string
	for _, m := range mailtest.Messages(t, e.pool, e.keys) {
		if m.To == "owner@x.com" {
			body = m.Body
		}
	}
	if !strings.Contains(body, "https://sx.example/shares/"+sh.ID.String()) || strings.Contains(body, tok) {
		t.Fatalf("body %q", body)
	}
	if n := count(t, e, `SELECT count(*) FROM share_recipients WHERE first_opened_at IS NOT NULL AND last_access_at IS NOT NULL`); n != 1 {
		t.Fatalf("timestamps %d", n)
	}
}

func TestRecordDownloadNotifiesOnce(t *testing.T) {
	e := setup(t)
	f2 := e.file(t, e.owner, false)
	_, tok := e.newShare(t, func(in *CreateInput) { in.FileIDs = append(in.FileIDs, f2) }, "bob@x.com")
	_, a, err := e.svc.VerifyCode(context.Background(), tok, "bob@x.com", e.code(t, tok, "bob@x.com"), ip1, "")
	if err != nil {
		t.Fatal(err)
	}
	f1 := a.Share.Files[0].ID
	if f1 == f2 {
		f1 = a.Share.Files[1].ID
	}
	for _, f := range []uuid.UUID{f1, f1} {
		if err := e.svc.RecordDownload(context.Background(), a, f); err != nil {
			t.Fatal(err)
		}
	}
	if n := mailsTo(t, e, "owner@x.com", "downloaded"); n != 1 {
		t.Fatalf("after same file: %d", n)
	}
	if err := e.svc.RecordDownload(context.Background(), a, f2); err != nil {
		t.Fatal(err)
	}
	if n := mailsTo(t, e, "owner@x.com", "downloaded"); n != 2 {
		t.Fatalf("after other file: %d", n)
	}
	if err := e.svc.RecordDownload(context.Background(), a, uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign file: %v", err)
	}
}

func TestIPAllowed(t *testing.T) {
	ten := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	if !ipAllowed(nil, ip1) {
		t.Fatal("empty list must allow")
	}
	if !ipAllowed(ten, netip.MustParseAddr("::ffff:10.1.2.3")) {
		t.Fatal("mapped v4 must match")
	}
	if ipAllowed(ten, ip1) {
		t.Fatal("outside must deny")
	}
}
