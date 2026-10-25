package share

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
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

func (e *env) file(t *testing.T, owner *auth.User, deleted bool) uuid.UUID {
	t.Helper()
	id := uuid.New()
	var del *time.Time
	if deleted {
		n := time.Now()
		del = &n
	}
	if _, err := e.pool.Exec(context.Background(), `INSERT INTO files (id,owner_id,name,content_type,size,sha256,wrapped_dek,key_id,storage_key,deleted_at)
		VALUES ($1,$2,'a.txt','text/plain',5,'\x00','\x00',1,$3,$4)`, id, owner.ID, id.String(), del); err != nil {
		t.Fatal(err)
	}
	return id
}

func (e *env) input(t *testing.T) CreateInput {
	return CreateInput{FileIDs: []uuid.UUID{e.file(t, e.owner, false)}, Emails: []string{"bob@x.com"},
		AllowDownload: true, ExpiresAt: e.now.Add(7 * 24 * time.Hour)}
}

func count(t *testing.T, e *env, q string, args ...any) int {
	t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

var linkRE = regexp.MustCompile(`https://sx\.example/s/([A-Za-z0-9_-]+)`)

func TestCreateShareSendsInvitations(t *testing.T) {
	e := setup(t)
	in := e.input(t)
	in.Emails = []string{"bob@x.com", "carol@y.org"}
	sh, err := e.svc.Create(context.Background(), e.owner, in)
	if err != nil {
		t.Fatal(err)
	}
	if sh.OwnerName != "Olivia" || len(sh.Recipients) != 2 || len(sh.Files) != 1 {
		t.Fatalf("%+v", sh)
	}
	if n := count(t, e, `SELECT count(*) FROM share_recipients WHERE share_id=$1`, sh.ID); n != 2 {
		t.Fatalf("recipients %d", n)
	}
	msgs := mailtest.Messages(t, e.pool, e.keys)
	if len(msgs) != 2 {
		t.Fatalf("outbox %d", len(msgs))
	}
	a, b := linkRE.FindString(msgs[0].Body), linkRE.FindString(msgs[1].Body)
	if a == "" || a != b {
		t.Fatalf("links %q %q", a, b)
	}
}

func TestRecipientEmailNormalized(t *testing.T) {
	e := setup(t)
	in := e.input(t)
	in.Emails = []string{" Bob@X.com ", "bob@x.com", "carol@y.org"}
	sh, err := e.svc.Create(context.Background(), e.owner, in)
	if err != nil {
		t.Fatal(err)
	}
	if len(sh.Recipients) != 2 || sh.Recipients[0].Email != "bob@x.com" || sh.Recipients[1].Email != "carol@y.org" {
		t.Fatalf("%+v", sh.Recipients)
	}
}

func TestCreateShareValidation(t *testing.T) {
	e := setup(t)
	other := e.user(t, "other@x.com", "")
	otherFile := e.file(t, other, false)
	delFile := e.file(t, e.owner, true)
	many := make([]string, 51)
	for i := range many {
		many[i] = fmt.Sprintf("u%d@x.com", i)
	}
	cases := []struct {
		name        string
		mod         func(*CreateInput)
		field, code string
	}{
		{"no recipients", func(in *CreateInput) { in.Emails = nil }, "emails", "required"},
		{"51 recipients", func(in *CreateInput) { in.Emails = many }, "emails", "too_many"},
		{"bad email", func(in *CreateInput) { in.Emails = []string{"nope"} }, "emails", "invalid"},
		{"no files", func(in *CreateInput) { in.FileIDs = nil }, "file_ids", "required"},
		{"others file", func(in *CreateInput) { in.FileIDs = []uuid.UUID{otherFile} }, "file_ids", "not_found"},
		{"deleted file", func(in *CreateInput) { in.FileIDs = []uuid.UUID{delFile} }, "file_ids", "not_found"},
		{"30 min", func(in *CreateInput) { in.ExpiresAt = e.now.Add(30 * time.Minute) }, "expires_at", "out_of_range"},
		{"no expiry", func(in *CreateInput) { in.ExpiresAt = time.Time{} }, "expires_at", "required"},
		{"31 days", func(in *CreateInput) { in.ExpiresAt = e.now.Add(31 * 24 * time.Hour) }, "expires_at", "out_of_range"},
		{"max views 0", func(in *CreateInput) { z := 0; in.MaxViews = &z }, "max_views", "out_of_range"},
		{"bad ip", func(in *CreateInput) { in.IPAllow = []string{"300.1.1.1"} }, "ip_allow", "invalid"},
		{"long message", func(in *CreateInput) { in.Message = strings.Repeat("好", 2001) }, "message", "too_many"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := e.input(t)
			c.mod(&in)
			_, err := e.svc.Create(context.Background(), e.owner, in)
			var ve *ValidationError
			if !errors.As(err, &ve) || ve.Field != c.field || ve.Code != c.code {
				t.Fatalf("got %v", err)
			}
		})
	}
	if n := count(t, e, `SELECT count(*) FROM shares`); n != 0 {
		t.Fatalf("shares written: %d", n)
	}
}

func TestIPAllowStored(t *testing.T) {
	e := setup(t)
	in := e.input(t)
	in.IPAllow = []string{"10.0.0.0/8", "1.2.3.4", "::1"}
	sh, err := e.svc.Create(context.Background(), e.owner, in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.svc.Get(context.Background(), e.owner.ID, sh.ID)
	if err != nil || len(got.IPAllow) != 3 || got.IPAllow[1].String() != "1.2.3.4/32" || got.IPAllow[2].String() != "::1/128" {
		t.Fatalf("%v %v", got, err)
	}
}

func TestShareTokenStoredHashed(t *testing.T) {
	e := setup(t)
	sh, err := e.svc.Create(context.Background(), e.owner, e.input(t))
	if err != nil {
		t.Fatal(err)
	}
	token := linkRE.FindStringSubmatch(mailtest.Messages(t, e.pool, e.keys)[0].Body)[1]
	var h []byte
	if err := e.pool.QueryRow(context.Background(), `SELECT token_hash FROM shares WHERE id=$1`, sh.ID).Scan(&h); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(token))
	if bytes.Equal(h, []byte(token)) || !bytes.Equal(h, sum[:]) {
		t.Fatal("token_hash is not sha256(token)")
	}
}

func addSession(t *testing.T, e *env, rid uuid.UUID) {
	t.Helper()
	if _, err := e.pool.Exec(context.Background(), `INSERT INTO share_sessions (token_hash,recipient_id,ip,user_agent,expires_at)
		VALUES ($1,$2,'1.1.1.1','ua',now()+interval '1 hour')`, []byte(uuid.New().String()), rid); err != nil {
		t.Fatal(err)
	}
}

func TestRevokeShareDropsSessions(t *testing.T) {
	e := setup(t)
	sh, _ := e.svc.Create(context.Background(), e.owner, e.input(t))
	addSession(t, e, sh.Recipients[0].ID)
	for i := 0; i < 2; i++ { // second call is a no-op success
		if err := e.svc.Revoke(context.Background(), e.owner.ID, sh.ID); err != nil {
			t.Fatal(err)
		}
	}
	if n := count(t, e, `SELECT count(*) FROM share_sessions`); n != 0 {
		t.Fatalf("sessions %d", n)
	}
	got, _ := e.svc.Get(context.Background(), e.owner.ID, sh.ID)
	if got.RevokedAt == nil {
		t.Fatal("not revoked")
	}
}

func TestRevokeRecipientDropsSessions(t *testing.T) {
	e := setup(t)
	in := e.input(t)
	in.Emails = []string{"bob@x.com", "carol@y.org"}
	sh, _ := e.svc.Create(context.Background(), e.owner, in)
	addSession(t, e, sh.Recipients[0].ID)
	addSession(t, e, sh.Recipients[1].ID)
	if err := e.svc.RevokeRecipient(context.Background(), e.owner.ID, sh.ID, sh.Recipients[0].ID); err != nil {
		t.Fatal(err)
	}
	if n := count(t, e, `SELECT count(*) FROM share_sessions`); n != 1 {
		t.Fatalf("sessions %d", n)
	}
	if err := e.svc.RevokeRecipient(context.Background(), e.owner.ID, sh.ID, uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestAddRecipientsSkipsExisting(t *testing.T) {
	e := setup(t)
	sh, _ := e.svc.Create(context.Background(), e.owner, e.input(t))
	added, err := e.svc.AddRecipients(context.Background(), e.owner, sh.ID, []string{"BOB@x.com", "dave@z.com"})
	if err != nil || len(added) != 1 || added[0].Email != "dave@z.com" {
		t.Fatalf("%v %v", added, err)
	}
	msgs := mailtest.Messages(t, e.pool, e.keys)
	if len(msgs) != 2 || msgs[1].To != "dave@z.com" || !linkRE.MatchString(msgs[1].Body) {
		t.Fatalf("%+v", msgs)
	}
	if linkRE.FindString(msgs[0].Body) != linkRE.FindString(msgs[1].Body) {
		t.Fatal("link differs from original invitation")
	}
}

func TestAddRecipientsToRevokedShare(t *testing.T) {
	e := setup(t)
	sh, _ := e.svc.Create(context.Background(), e.owner, e.input(t))
	_ = e.svc.Revoke(context.Background(), e.owner.ID, sh.ID)
	if _, err := e.svc.AddRecipients(context.Background(), e.owner, sh.ID, []string{"d@z.com"}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("got %v", err)
	}
}

func TestAddRecipientsToExpiredShare(t *testing.T) {
	e := setup(t)
	sh, _ := e.svc.Create(context.Background(), e.owner, e.input(t))
	e.now = sh.ExpiresAt
	if _, err := e.svc.AddRecipients(context.Background(), e.owner, sh.ID, []string{"d@z.com"}); !errors.Is(err, ErrExpired) {
		t.Fatalf("got %v", err)
	}
	if n := count(t, e, `SELECT count(*) FROM share_recipients WHERE email = 'd@z.com'`); n != 0 {
		t.Fatalf("recipients %d", n)
	}
}

func TestAddRecipientsLimit(t *testing.T) {
	e := setup(t)
	in := e.input(t)
	in.Emails = nil
	for i := 0; i < 50; i++ {
		in.Emails = append(in.Emails, fmt.Sprintf("u%d@x.com", i))
	}
	sh, err := e.svc.Create(context.Background(), e.owner, in)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.svc.AddRecipients(context.Background(), e.owner, sh.ID, []string{"extra@x.com"})
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Code != "too_many" {
		t.Fatalf("got %v", err)
	}
}

func TestGetOtherOwner404(t *testing.T) {
	e := setup(t)
	sh, _ := e.svc.Create(context.Background(), e.owner, e.input(t))
	other := e.user(t, "o2@x.com", "")
	if _, err := e.svc.Get(context.Background(), other.ID, sh.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get %v", err)
	}
	if err := e.svc.Revoke(context.Background(), other.ID, sh.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoke %v", err)
	}
	if l, _ := e.svc.List(context.Background(), other.ID); len(l) != 0 {
		t.Fatal("list leaks")
	}
	l, _ := e.svc.List(context.Background(), e.owner.ID)
	if len(l) != 1 || l[0].FileCount != 1 || l[0].RecipientCount != 1 {
		t.Fatalf("%+v", l)
	}
}

func TestTokenSealedNotPlaintext(t *testing.T) {
	e := setup(t)
	sh, err := e.svc.Create(context.Background(), e.owner, e.input(t))
	if err != nil {
		t.Fatal(err)
	}
	token := linkRE.FindStringSubmatch(mailtest.Messages(t, e.pool, e.keys)[0].Body)[1]
	var sealed []byte
	if err := e.pool.QueryRow(context.Background(), `SELECT token_sealed FROM shares WHERE id=$1`, sh.ID).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if len(sealed) == 0 || bytes.Contains(sealed, []byte(token)) {
		t.Fatal("token_sealed empty or contains the token")
	}
}

func TestCreateViewOnlyRequiresReadyPreview(t *testing.T) {
	e := setup(t)
	try := func(status string, allow bool) error {
		in := e.input(t)
		in.AllowDownload = allow
		if status != "" {
			if _, err := e.pool.Exec(context.Background(), `INSERT INTO file_previews (file_id, kind, status) VALUES ($1,'pages',$2)`, in.FileIDs[0], status); err != nil {
				t.Fatal(err)
			}
		}
		_, err := e.svc.Create(context.Background(), e.owner, in)
		return err
	}
	for _, c := range []struct {
		status string
		allow  bool
		code   string
	}{
		{"pending", false, "preview_pending"}, {"", false, "preview_pending"},
		{"unsupported", false, "not_previewable"}, {"failed", false, "not_previewable"}, {"too_large", false, "not_previewable"},
		{"ready", false, ""}, {"unsupported", true, ""},
	} {
		err := try(c.status, c.allow)
		var ve *ValidationError
		switch {
		case c.code == "" && err != nil:
			t.Fatalf("%s/%v: %v", c.status, c.allow, err)
		case c.code != "" && (!errors.As(err, &ve) || ve.Field != "file_ids" || ve.Code != c.code):
			t.Fatalf("%s/%v: %v", c.status, c.allow, err)
		}
	}
}
