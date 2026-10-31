package intake

import (
	"context"
	"errors"
	"net/netip"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/tntrock/secure-exchange/internal/mail/mailtest"
)

var (
	ip1    = netip.MustParseAddr("192.0.2.1")
	codeRE = regexp.MustCompile(`驗證碼是：(\d{6})`)
)

// code requests a code for email and returns it from the outbox.
func (e *env) code(t *testing.T, token, email string) string {
	t.Helper()
	if sent, err := e.svc.RequestCode(context.Background(), token, email, ip1); err != nil || !sent {
		t.Fatalf("RequestCode: %v %v", sent, err)
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

// login runs the whole code flow and returns the session token.
func (e *env) login(t *testing.T, token, email string) string {
	t.Helper()
	sess, _, err := e.svc.VerifyCode(context.Background(), token, email, e.code(t, token, email), ip1, "ua")
	if err != nil {
		t.Fatal(err)
	}
	return sess
}

func TestCodeFlow(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	_, tok := e.newRequest(t, nil, "bob@x.com")
	before := len(mailtest.Messages(t, e.pool, e.keys))

	if sent, err := e.svc.RequestCode(ctx, tok, "stranger@x.com", ip1); sent || err != nil {
		t.Fatalf("unlisted: sent=%v err=%v", sent, err)
	}
	if sent, err := e.svc.RequestCode(ctx, tok, "not an address", ip1); sent || err != nil {
		t.Fatalf("invalid: sent=%v err=%v", sent, err)
	}
	if n := len(mailtest.Messages(t, e.pool, e.keys)); n != before {
		t.Fatalf("mail sent to an unlisted address (%d -> %d)", before, n)
	}
	code := e.code(t, tok, "bob@x.com")
	for i := 0; i < otpAttempts; i++ {
		if _, _, err := e.svc.VerifyCode(ctx, tok, "bob@x.com", wrong(code), ip1, "ua"); !errors.Is(err, ErrBadCode) {
			t.Fatalf("wrong code %d: %v", i, err)
		}
	}
	if _, _, err := e.svc.VerifyCode(ctx, tok, "bob@x.com", code, ip1, "ua"); !errors.Is(err, ErrBadCode) {
		t.Fatalf("right code after 5 failures: %v", err)
	}
	if _, _, err := e.svc.VerifyCode(ctx, tok, "stranger@x.com", code, ip1, "ua"); !errors.Is(err, ErrBadCode) {
		t.Fatalf("stranger: %v", err)
	}

	code = e.code(t, tok, "bob@x.com")
	sess, a, err := e.svc.VerifyCode(ctx, tok, "Bob@X.com", code, ip1, "ua")
	if err != nil || sess == "" || a.Uploader.Email != "bob@x.com" || a.Request.OwnerName != "Olivia" {
		t.Fatalf("verify: %q %+v %v", sess, a, err)
	}
	if _, _, err := e.svc.VerifyCode(ctx, tok, "bob@x.com", code, ip1, "ua"); !errors.Is(err, ErrBadCode) {
		t.Fatalf("code reuse: %v", err)
	}
	a, err = e.svc.Authorize(ctx, sess, ip1)
	if err != nil || a.Uploader.Email != "bob@x.com" || a.Request.ID == uuid.Nil || a.Uploader.FirstOpenedAt == nil {
		t.Fatalf("authorize: %+v %v", a, err)
	}
	var opened *time.Time
	if err := e.pool.QueryRow(ctx, `SELECT first_opened_at FROM request_uploaders WHERE id = $1`, a.Uploader.ID).Scan(&opened); err != nil || opened == nil {
		t.Fatalf("first_opened_at = %v, %v", opened, err)
	}
	if n := len(mailtest.Messages(t, e.pool, e.keys)); n != before+2 { // the two codes, no first-open mail
		t.Fatalf("outbox has %d messages, want %d", n, before+2)
	}
	if err := e.svc.Logout(ctx, sess); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Authorize(ctx, sess, ip1); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("after logout: %v", err)
	}
	if err := e.svc.Logout(ctx, "unknown"); err != nil {
		t.Fatalf("logout of unknown session: %v", err)
	}
	if _, err := e.svc.Authorize(ctx, "unknown", ip1); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unknown session: %v", err)
	}
}

func TestRequestCodeLimits(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	_, tok := e.newRequest(t, nil, "bob@x.com")
	for i := 0; i < otpsPerHour; i++ {
		e.code(t, tok, "bob@x.com")
	}
	if sent, err := e.svc.RequestCode(ctx, tok, "bob@x.com", ip1); sent || err != nil {
		t.Fatalf("over the hourly cap: sent=%v err=%v", sent, err)
	}
}

func TestCodeExpires(t *testing.T) {
	e := setup(t)
	_, tok := e.newRequest(t, nil, "bob@x.com")
	code := e.code(t, tok, "bob@x.com")
	e.now = e.now.Add(otpTTL + time.Second)
	if _, _, err := e.svc.VerifyCode(context.Background(), tok, "bob@x.com", code, ip1, "ua"); !errors.Is(err, ErrBadCode) {
		t.Fatalf("expired code: %v", err)
	}
}

func TestSessionTTL(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	_, tok := e.newRequest(t, nil, "bob@x.com")
	sess := e.login(t, tok, "bob@x.com")
	e.now = e.now.Add(24*time.Hour - time.Minute)
	if _, err := e.svc.Authorize(ctx, sess, ip1); err != nil {
		t.Fatalf("within 24h: %v", err)
	}
	e.now = e.now.Add(2 * time.Minute)
	if _, err := e.svc.Authorize(ctx, sess, ip1); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("after 24h: %v", err)
	}

	// a request that ends sooner caps the session
	e.now = time.Now().Truncate(time.Second)
	_, tok = e.newRequest(t, func(in *CreateInput) { in.ExpiresAt = e.now.Add(2 * time.Hour) }, "carol@x.com")
	e.login(t, tok, "carol@x.com")
	var exp time.Time
	if err := e.pool.QueryRow(ctx, `SELECT expires_at FROM request_sessions ORDER BY created_at DESC LIMIT 1`).Scan(&exp); err != nil || !exp.Equal(e.now.Add(2*time.Hour)) {
		t.Fatalf("session expires %v (%v), want request expiry", exp, err)
	}
}

func TestAuthorizeRechecks(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	r, tok := e.newRequest(t, nil, "bob@x.com")
	sess := e.login(t, tok, "bob@x.com")
	if err := e.svc.Revoke(ctx, e.owner.ID, r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Authorize(ctx, sess, ip1); !errors.Is(err, ErrGone) {
		t.Fatalf("after revoke: %v", err)
	}
	if _, _, err := e.svc.VerifyCode(ctx, tok, "bob@x.com", "123456", ip1, "ua"); !errors.Is(err, ErrGone) {
		t.Fatalf("verify after revoke: %v", err)
	}
	if _, err := e.svc.RequestCode(ctx, tok, "bob@x.com", ip1); !errors.Is(err, ErrGone) {
		t.Fatalf("request code after revoke: %v", err)
	}

	r, tok = e.newRequest(t, nil, "bob@x.com")
	sess = e.login(t, tok, "bob@x.com")
	e.now = r.ExpiresAt.Add(time.Second)
	if _, err := e.svc.Authorize(ctx, sess, ip1); !errors.Is(err, ErrGone) {
		t.Fatalf("after expiry: %v", err)
	}
}

func (e *env) access(t *testing.T, mod func(*CreateInput)) *Access {
	t.Helper()
	_, tok := e.newRequest(t, mod, "bob@x.com")
	a, err := e.svc.Authorize(context.Background(), e.login(t, tok, "bob@x.com"), ip1)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// addUpload records an in-progress upload against the request.
func (e *env) addUpload(tx pgx.Tx, a *Access, size int64) error {
	_, err := tx.Exec(context.Background(), `INSERT INTO uploads (id,owner_id,name,content_type,size,wrapped_dek,key_id,hash_state,request_id,uploader_id)
		VALUES ($1,$2,'x','x',$3,'\x00',1,'\x00',$4,$5)`, uuid.New(), a.Request.OwnerID, size, a.Request.ID, a.Uploader.ID)
	return err
}

// check runs CheckUpload in its own transaction and inserts an upload row when it passes.
func (e *env) check(t *testing.T, a *Access, name string, size int64) error {
	t.Helper()
	ctx := context.Background()
	tx, err := e.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err := CheckUpload(ctx, tx, a, name, size); err != nil {
		return err
	}
	if err := e.addUpload(tx, a, size); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return nil
}

func TestCheckUpload(t *testing.T) {
	e := setup(t)
	a := e.access(t, func(in *CreateInput) { in.MaxFiles, in.MaxTotalBytes, in.AllowedExts = 2, 100, []string{"pdf"} })
	for _, c := range []struct {
		name string
		size int64
		want error
	}{
		{"a.PDF", 60, nil},
		{"b.exe", 1, ErrExtNotAllowed},
		{"noext", 1, ErrExtNotAllowed},
		{"b.pdf", 41, ErrQuotaExceeded},
		{"b.pdf", 40, nil},
		{"c.pdf", 0, ErrTooManyFiles},
	} {
		if err := e.check(t, a, c.name, c.size); !errors.Is(err, c.want) {
			t.Errorf("%s/%d: got %v, want %v", c.name, c.size, err, c.want)
		}
	}
	if n, b, err := Usage(context.Background(), e.pool, a.Request.ID); err != nil || n != 2 || b != 100 {
		t.Fatalf("usage = %d, %d, %v", n, b, err)
	}

	a = e.access(t, nil)
	if err := e.check(t, a, "anything.xyz", 1); err != nil {
		t.Fatalf("empty AllowedExts: %v", err)
	}
	if err := e.check(t, a, "noext", 1); err != nil {
		t.Fatalf("empty AllowedExts, no extension: %v", err)
	}
}

func TestUsageCountsFilesAndUploads(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	a := e.access(t, nil)
	if _, err := e.pool.Exec(ctx, `INSERT INTO files (id,owner_id,name,content_type,size,sha256,wrapped_dek,key_id,storage_key,request_id,deleted_at)
		VALUES ($1,$2,'a','x',30,'\x00','\x00',1,'k',$3,now())`, uuid.New(), a.Request.OwnerID, a.Request.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.check(t, a, "b.txt", 5); err != nil {
		t.Fatal(err)
	}
	if n, b, err := Usage(ctx, e.pool, a.Request.ID); err != nil || n != 2 || b != 35 {
		t.Fatalf("usage = %d, %d, %v (a deleted file still counts)", n, b, err)
	}
	if n, b, err := Usage(ctx, e.pool, uuid.New()); err != nil || n != 0 || b != 0 {
		t.Fatalf("empty usage = %d, %d, %v", n, b, err)
	}
}

func TestCheckUploadSerialises(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	a := e.access(t, func(in *CreateInput) { in.MaxFiles, in.MaxTotalBytes = 10, 100 })
	start := make(chan struct{})
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tx, err := e.pool.Begin(ctx)
			if err != nil {
				errs[i] = err
				return
			}
			defer tx.Rollback(ctx)
			<-start
			if err := CheckUpload(ctx, tx, a, "a.bin", 60); err != nil {
				errs[i] = err
				return
			}
			if err := e.addUpload(tx, a, 60); err != nil {
				errs[i] = err
				return
			}
			time.Sleep(200 * time.Millisecond) // hold the row lock: the other check must wait for the commit
			errs[i] = tx.Commit(ctx)
		}()
	}
	close(start)
	wg.Wait()
	quota := 0
	for _, err := range errs {
		switch {
		case errors.Is(err, ErrQuotaExceeded):
			quota++
		case err != nil:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if quota != 1 {
		t.Fatalf("errors = %v, want exactly one ErrQuotaExceeded", errs)
	}
}

func TestAccessContext(t *testing.T) {
	if AccessFrom(context.Background()) != nil {
		t.Fatal("empty context has an Access")
	}
	a := &Access{}
	if AccessFrom(WithAccess(context.Background(), a)) != a {
		t.Fatal("Access not carried")
	}
}

func TestRequestCodeDailyCap(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	_, tok := e.newRequest(t, nil, "bob@x.com")
	var uid uuid.UUID
	if err := e.pool.QueryRow(ctx, `SELECT id FROM request_uploaders`).Scan(&uid); err != nil {
		t.Fatal(err)
	}
	// otpsPerDay codes spread over the day, none within the last hour
	if _, err := e.pool.Exec(ctx, `INSERT INTO request_otps (id, uploader_id, code_hash, expires_at, used_at, created_at)
		SELECT gen_random_uuid(), $1, '\x00', now(), now(), now() - interval '5 hours' FROM generate_series(1, $2)`, uid, otpsPerDay); err != nil {
		t.Fatal(err)
	}
	before := len(mailtest.Messages(t, e.pool, e.keys))
	if sent, err := e.svc.RequestCode(ctx, tok, "bob@x.com", ip1); sent || err != nil {
		t.Fatalf("over the daily cap: sent=%v err=%v", sent, err)
	}
	if n := len(mailtest.Messages(t, e.pool, e.keys)); n != before {
		t.Fatal("code mailed over the cap")
	}
}

func TestRequestCodeSupersedesOlder(t *testing.T) {
	e := setup(t)
	_, tok := e.newRequest(t, nil, "bob@x.com")
	old := e.code(t, tok, "bob@x.com")
	cur := e.code(t, tok, "bob@x.com")
	if old != cur {
		if _, _, err := e.svc.VerifyCode(context.Background(), tok, "bob@x.com", old, ip1, "ua"); !errors.Is(err, ErrBadCode) {
			t.Fatalf("superseded code: %v", err)
		}
	}
	if _, _, err := e.svc.VerifyCode(context.Background(), tok, "bob@x.com", cur, ip1, "ua"); err != nil {
		t.Fatalf("current code: %v", err)
	}
}

func TestCheckUploadZeroSize(t *testing.T) {
	e := setup(t)
	a := e.access(t, func(in *CreateInput) { in.MaxFiles, in.MaxTotalBytes = 2, 10 })
	if err := e.check(t, a, "a.txt", 10); err != nil {
		t.Fatal(err)
	}
	if err := e.check(t, a, "empty.txt", 0); err != nil { // fills the quota exactly: still room for an empty file
		t.Fatalf("zero-size at quota: %v", err)
	}
	if err := e.check(t, a, "b.txt", 0); !errors.Is(err, ErrTooManyFiles) {
		t.Fatalf("third file: %v", err)
	}
}

func TestValidationErrorText(t *testing.T) {
	if got := invalid("emails", "required").Error(); got != "intake: emails: required" {
		t.Fatal(got)
	}
}
