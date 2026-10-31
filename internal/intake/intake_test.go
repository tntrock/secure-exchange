package intake

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/db/testdb"
	"github.com/tntrock/secure-exchange/internal/mail"
	"github.com/tntrock/secure-exchange/internal/mail/mailtest"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
)

type env struct {
	pool  *pgxpool.Pool
	keys  *sxcrypto.Keyring
	svc   *Service
	owner *auth.User
	now   time.Time
}

func setup(t *testing.T) *env {
	t.Helper()
	pool := testdb.New(t)
	keys, err := sxcrypto.ParseKeyring("1:"+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), 1)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(pool, mail.NewOutbox(pool, keys, nil), keys, "https://sx.example", 30)
	e := &env{pool: pool, keys: keys, svc: svc, now: time.Now().Truncate(time.Second)}
	svc.now = func() time.Time { return e.now }
	e.owner = e.user(t, "owner@x.com", "Olivia")
	return e
}

func (e *env) user(t *testing.T, email, name string) *auth.User {
	t.Helper()
	u := &auth.User{ID: uuid.New(), Email: email, DisplayName: name}
	if _, err := e.pool.Exec(context.Background(), `INSERT INTO users (id,email,display_name,role) VALUES ($1,$2,$3,'staff')`, u.ID, email, name); err != nil {
		t.Fatal(err)
	}
	return u
}

func (e *env) input() CreateInput {
	return CreateInput{Emails: []string{"bob@x.com"}, ExpiresAt: e.now.Add(7 * 24 * time.Hour), MaxFiles: 10, MaxTotalBytes: 1000}
}

var linkRE = regexp.MustCompile(`https://sx\.example/r/([A-Za-z0-9_-]+)`)

// newRequest creates a request and returns it with its link token.
func (e *env) newRequest(t *testing.T, mod func(*CreateInput), emails ...string) (*Request, string) {
	t.Helper()
	in := e.input()
	in.Emails = emails
	if mod != nil {
		mod(&in)
	}
	r, err := e.svc.Create(context.Background(), e.owner, in)
	if err != nil {
		t.Fatal(err)
	}
	msgs := mailtest.Messages(t, e.pool, e.keys)
	m := linkRE.FindStringSubmatch(msgs[len(msgs)-1].Body)
	if m == nil {
		t.Fatal("no link")
	}
	return r, m[1]
}

func TestCreateValidation(t *testing.T) {
	e := setup(t)
	emails := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("u%d@x.com", i)
		}
		return out
	}
	exts := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("e%d", i)
		}
		return out
	}
	cases := []struct {
		name        string
		mod         func(*CreateInput)
		field, code string
	}{
		{"no emails", func(in *CreateInput) { in.Emails = nil }, "emails", "required"},
		{"bad email", func(in *CreateInput) { in.Emails = []string{"nope"} }, "emails", "invalid"},
		{"51 emails", func(in *CreateInput) { in.Emails = emails(51) }, "emails", "too_many"},
		{"no expiry", func(in *CreateInput) { in.ExpiresAt = time.Time{} }, "expires_at", "required"},
		{"expiry too soon", func(in *CreateInput) { in.ExpiresAt = e.now.Add(30 * time.Minute) }, "expires_at", "out_of_range"},
		{"expiry too late", func(in *CreateInput) { in.ExpiresAt = e.now.AddDate(0, 0, 31) }, "expires_at", "out_of_range"},
		{"max_files 0", func(in *CreateInput) { in.MaxFiles = 0 }, "max_files", "out_of_range"},
		{"max_files 1001", func(in *CreateInput) { in.MaxFiles = 1001 }, "max_files", "out_of_range"},
		{"max_total_bytes 0", func(in *CreateInput) { in.MaxTotalBytes = 0 }, "max_total_bytes", "out_of_range"},
		{"max_total_bytes huge", func(in *CreateInput) { in.MaxTotalBytes = 1<<50 + 1 }, "max_total_bytes", "out_of_range"},
		{"bad ext", func(in *CreateInput) { in.AllowedExts = []string{"p/df"} }, "allowed_exts", "invalid"},
		{"ext too long", func(in *CreateInput) { in.AllowedExts = []string{"abcdefghijk"} }, "allowed_exts", "invalid"},
		{"51 exts", func(in *CreateInput) { in.AllowedExts = exts(51) }, "allowed_exts", "too_many"},
		{"long message", func(in *CreateInput) { in.Message = strings.Repeat("字", 2001) }, "message", "too_many"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := e.input()
			c.mod(&in)
			_, err := e.svc.Create(context.Background(), e.owner, in)
			var ve *ValidationError
			if !errors.As(err, &ve) || ve.Field != c.field || ve.Code != c.code {
				t.Fatalf("got %v, want %s/%s", err, c.field, c.code)
			}
		})
	}
	// the boundaries are accepted
	in := e.input()
	in.MaxFiles, in.MaxTotalBytes, in.Message = 1000, 1<<50, strings.Repeat("字", 2000)
	in.ExpiresAt = e.now.AddDate(0, 0, 30)
	in.Emails, in.AllowedExts = emails(50), exts(50)
	if _, err := e.svc.Create(context.Background(), e.owner, in); err != nil {
		t.Fatalf("boundary values: %v", err)
	}
}

func TestCreateNormalisesExts(t *testing.T) {
	e := setup(t)
	r, _ := e.newRequest(t, func(in *CreateInput) { in.AllowedExts = []string{".PDF", "pdf", " Docx "} }, "bob@x.com")
	if !reflect.DeepEqual(r.AllowedExts, []string{"pdf", "docx"}) {
		t.Fatalf("exts = %q", r.AllowedExts)
	}
	r, _ = e.newRequest(t, nil, "bob@x.com")
	if r.AllowedExts == nil || len(r.AllowedExts) != 0 {
		t.Fatalf("empty exts = %#v, want empty non-nil", r.AllowedExts)
	}
}

func TestCreateSendsInvitations(t *testing.T) {
	e := setup(t)
	r, tok := e.newRequest(t, func(in *CreateInput) { in.Message = "please send" }, "bob@x.com", "Carol@Y.org", "bob@x.com")
	msgs := mailtest.Messages(t, e.pool, e.keys)
	if len(msgs) != 2 || msgs[0].To+msgs[1].To != "bob@x.comcarol@y.org" && msgs[0].To+msgs[1].To != "carol@y.orgbob@x.com" { // one tx: created_at ties
		t.Fatalf("outbox = %+v", msgs)
	}
	for _, m := range msgs {
		if !strings.Contains(m.Body, "https://sx.example/r/"+tok) || !strings.Contains(m.Body, "Olivia") || !strings.Contains(m.Body, "please send") {
			t.Fatalf("body: %s", m.Body)
		}
	}
	if r.URL != "https://sx.example/r/"+tok || len(r.Uploaders) != 2 || r.UploaderCount != 2 {
		t.Fatalf("request = %+v", r)
	}
	if r.OwnerName != "Olivia" || r.OwnerEmail != "owner@x.com" || r.FileCount != 0 || r.TotalBytes != 0 {
		t.Fatalf("request = %+v", r)
	}
	// without a display name the sender is the email
	e.owner = e.user(t, "anon@x.com", "")
	r, _ = e.newRequest(t, nil, "bob@x.com")
	if r.OwnerName != "anon@x.com" {
		t.Fatalf("owner name = %q", r.OwnerName)
	}
}

func TestListGetRevokeOwnerOnly(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	r1, tok := e.newRequest(t, nil, "bob@x.com")
	r2, _ := e.newRequest(t, nil, "bob@x.com", "eve@x.com")
	other := e.user(t, "other@x.com", "Other")

	list, err := e.svc.List(ctx, e.owner.ID)
	if err != nil || len(list) != 2 || list[0].ID != r2.ID || list[1].ID != r1.ID || list[0].UploaderCount != 2 || list[1].UploaderCount != 1 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	if list, err := e.svc.List(ctx, other.ID); err != nil || len(list) != 0 {
		t.Fatalf("other's list = %+v, %v", list, err)
	}
	if _, err := e.svc.Get(ctx, other.ID, r1.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other's Get: %v", err)
	}
	if err := e.svc.Revoke(ctx, other.ID, r1.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other's Revoke: %v", err)
	}
	if _, err := e.svc.Landing(ctx, tok, ip1); err != nil {
		t.Fatalf("Landing before revoke: %v", err)
	}
	if err := e.svc.Revoke(ctx, e.owner.ID, r1.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Revoke(ctx, e.owner.ID, r1.ID); err != nil {
		t.Fatalf("second Revoke: %v", err)
	}
	if _, err := e.svc.Landing(ctx, tok, ip1); !errors.Is(err, ErrGone) {
		t.Fatalf("Landing after revoke: %v", err)
	}
	got, err := e.svc.Get(ctx, e.owner.ID, r1.ID)
	if err != nil || got.RevokedAt == nil {
		t.Fatalf("Get after revoke: %+v, %v", got, err)
	}
	if _, err := e.svc.Landing(ctx, "nosuchtoken", ip1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown token: %v", err)
	}
}

func TestGetCountsFiles(t *testing.T) {
	e := setup(t)
	r, _ := e.newRequest(t, nil, "bob@x.com")
	for _, deleted := range []bool{false, true} {
		if _, err := e.pool.Exec(context.Background(), `INSERT INTO files (id,owner_id,name,content_type,size,sha256,wrapped_dek,key_id,storage_key,request_id,deleted_at)
			VALUES ($1,$2,'a.txt','text/plain',7,'\x00','\x00',1,$3,$4,CASE WHEN $5 THEN now() END)`,
			uuid.New(), e.owner.ID, uuid.NewString(), r.ID, deleted); err != nil {
			t.Fatal(err)
		}
	}
	got, err := e.svc.Get(context.Background(), e.owner.ID, r.ID)
	if err != nil || got.FileCount != 2 || got.TotalBytes != 14 {
		t.Fatalf("got %+v, %v", got, err)
	}
}

// A service whose database is unusable reports the failure instead of treating it as "not found".
func TestServiceDatabaseErrors(t *testing.T) {
	e := setup(t)
	r, tok := e.newRequest(t, nil, "bob@x.com")
	sess := e.login(t, tok, "bob@x.com")
	a, err := e.svc.Authorize(context.Background(), sess, ip1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sentinel := []error{ErrNotFound, ErrGone, ErrBadCode, ErrUnauthorized}
	notDomain := func(name string, err error) {
		t.Helper()
		if err == nil {
			t.Errorf("%s: no error on a canceled context", name)
		}
		for _, s := range sentinel {
			if errors.Is(err, s) {
				t.Errorf("%s: database failure reported as %v", name, err)
			}
		}
	}
	_, err = e.svc.Create(ctx, e.owner, e.input())
	notDomain("Create", err)
	_, err = e.svc.List(ctx, e.owner.ID)
	notDomain("List", err)
	_, err = e.svc.Get(ctx, e.owner.ID, r.ID)
	notDomain("Get", err)
	notDomain("Revoke", e.svc.Revoke(ctx, e.owner.ID, r.ID))
	_, err = e.svc.Landing(ctx, tok, ip1)
	notDomain("Landing", err)
	_, err = e.svc.RequestCode(ctx, tok, "bob@x.com", ip1)
	notDomain("RequestCode", err)
	_, _, err = e.svc.VerifyCode(ctx, tok, "bob@x.com", "123456", ip1, "ua")
	notDomain("VerifyCode", err)
	_, err = e.svc.Authorize(ctx, sess, ip1)
	notDomain("Authorize", err)
	notDomain("Logout", e.svc.Logout(ctx, sess))
	_, _, err = Usage(ctx, e.pool, r.ID)
	notDomain("Usage", err)

	tx, err := e.pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	notDomain("CheckUpload", CheckUpload(ctx, tx, a, "a.txt", 1))
}

func TestGetFailsOnUnreadableLink(t *testing.T) {
	e := setup(t)
	r, _ := e.newRequest(t, nil, "bob@x.com")
	if _, err := e.pool.Exec(context.Background(), `UPDATE upload_requests SET token_sealed = '\x00' WHERE id = $1`, r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Get(context.Background(), e.owner.ID, r.ID); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want a decryption error", err)
	}
}
