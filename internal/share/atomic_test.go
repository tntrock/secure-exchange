package share

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tntrock/secure-exchange/internal/mail"
)

// blocked returns a service whose statements time out after 300ms, and locks
// table in SHARE mode (reads pass, writes wait) until the returned unlock is called.
// It shows a write failing midway rolls the whole operation back.
func (e *env) blocked(t *testing.T, table string) (*Service, func()) {
	t.Helper()
	cfg := e.pool.Config().Copy()
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = "300"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	svc := NewService(pool, mail.NewOutbox(pool, e.keys, nil), e.keys, e.svc.baseURL, e.svc.maxDays)
	svc.now = e.svc.now
	tx, err := e.pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(context.Background(), "LOCK TABLE "+table+" IN SHARE MODE"); err != nil {
		t.Fatal(err)
	}
	unlock := func() { tx.Rollback(context.Background()) }
	t.Cleanup(unlock)
	return svc, unlock
}

func TestVerifyCodeAtomic(t *testing.T) {
	for _, table := range []string{"share_otps", "shares", "share_sessions", "share_recipients", "mail_outbox"} {
		t.Run(table, func(t *testing.T) {
			e := setup(t)
			_, tok := e.newShare(t, nil, "bob@x.com")
			code := e.code(t, tok, "bob@x.com")
			svc, unlock := e.blocked(t, table)
			if _, _, err := svc.VerifyCode(context.Background(), tok, "bob@x.com", code, ip1, ""); err == nil || errors.Is(err, ErrBadCode) {
				t.Fatalf("got %v, want a database error", err)
			}
			unlock()
			// nothing was consumed or counted: the same code still opens the share once
			_, a, err := e.svc.VerifyCode(context.Background(), tok, "bob@x.com", code, ip1, "")
			if err != nil || a.Share.ViewCount != 1 {
				t.Fatalf("retry: %v", err)
			}
			if n := mailsTo(t, e, "owner@x.com", "opened"); n != 1 {
				t.Fatalf("first-open mails: %d", n)
			}
		})
	}
	t.Run("wrong code", func(t *testing.T) {
		e := setup(t)
		_, tok := e.newShare(t, nil, "bob@x.com")
		code := e.code(t, tok, "bob@x.com")
		svc, _ := e.blocked(t, "share_otps")
		if _, _, err := svc.VerifyCode(context.Background(), tok, "bob@x.com", wrong(code), ip1, ""); err == nil || errors.Is(err, ErrBadCode) {
			t.Fatalf("got %v, want a database error", err)
		}
	})
}

func TestRequestCodeAtomic(t *testing.T) {
	for _, table := range []string{"share_otps", "mail_outbox"} {
		t.Run(table, func(t *testing.T) {
			e := setup(t)
			_, tok := e.newShare(t, nil, "bob@x.com")
			old := e.code(t, tok, "bob@x.com")
			svc, unlock := e.blocked(t, table)
			if sent, err := svc.RequestCode(context.Background(), tok, "bob@x.com", ip1); sent || err == nil {
				t.Fatalf("got %v %v, want a database error", sent, err)
			}
			unlock()
			if n := count(t, e, `SELECT count(*) FROM share_otps`); n != 1 {
				t.Fatalf("otps: %d", n)
			}
			// the earlier code was not invalidated
			if _, _, err := e.svc.VerifyCode(context.Background(), tok, "bob@x.com", old, ip1, ""); err != nil {
				t.Fatalf("old code: %v", err)
			}
		})
	}
}

func TestCreateAtomic(t *testing.T) {
	for _, table := range []string{"shares", "share_files", "share_recipients", "mail_outbox"} {
		t.Run(table, func(t *testing.T) {
			e := setup(t)
			in := e.input(t)
			svc, unlock := e.blocked(t, table)
			if _, err := svc.Create(context.Background(), e.owner, in); err == nil {
				t.Fatal("created while blocked")
			}
			unlock()
			if n := count(t, e, `SELECT (SELECT count(*) FROM shares) + (SELECT count(*) FROM share_files) + (SELECT count(*) FROM share_recipients) + (SELECT count(*) FROM mail_outbox)`); n != 0 {
				t.Fatalf("partial share left: %d rows", n)
			}
		})
	}
}

func TestOwnerWritesAtomic(t *testing.T) {
	cases := []struct {
		name, table string
		call        func(svc *Service, e *env, sh *Share) error
		check       func(t *testing.T, e *env, sh *Share)
	}{
		{"revoke", "share_sessions",
			func(svc *Service, e *env, sh *Share) error {
				return svc.Revoke(context.Background(), e.owner.ID, sh.ID)
			},
			func(t *testing.T, e *env, sh *Share) {
				if n := count(t, e, `SELECT count(*) FROM shares WHERE revoked_at IS NOT NULL`); n != 0 {
					t.Fatal("share revoked")
				}
			}},
		{"revoke recipient", "share_sessions",
			func(svc *Service, e *env, sh *Share) error {
				return svc.RevokeRecipient(context.Background(), e.owner.ID, sh.ID, sh.Recipients[0].ID)
			},
			func(t *testing.T, e *env, sh *Share) {
				if n := count(t, e, `SELECT count(*) FROM share_recipients WHERE revoked_at IS NOT NULL`); n != 0 {
					t.Fatal("recipient revoked")
				}
			}},
		{"add recipients", "share_recipients",
			func(svc *Service, e *env, sh *Share) error {
				_, err := svc.AddRecipients(context.Background(), e.owner, sh.ID, []string{"carol@x.com"})
				return err
			},
			func(t *testing.T, e *env, sh *Share) {
				if n := count(t, e, `SELECT count(*) FROM share_recipients`); n != 1 {
					t.Fatalf("recipients: %d", n)
				}
			}},
		{"add recipients mail", "mail_outbox",
			func(svc *Service, e *env, sh *Share) error {
				_, err := svc.AddRecipients(context.Background(), e.owner, sh.ID, []string{"carol@x.com"})
				return err
			},
			func(t *testing.T, e *env, sh *Share) {
				if n := count(t, e, `SELECT count(*) FROM share_recipients`); n != 1 {
					t.Fatalf("recipients: %d", n)
				}
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := setup(t)
			sh, _ := e.newShare(t, nil, "bob@x.com")
			sh, err := e.svc.Get(context.Background(), e.owner.ID, sh.ID)
			if err != nil {
				t.Fatal(err)
			}
			svc, unlock := e.blocked(t, c.table)
			if err := c.call(svc, e, sh); err == nil || errors.Is(err, ErrNotFound) {
				t.Fatalf("got %v, want a database error", err)
			}
			unlock()
			c.check(t, e, sh)
		})
	}
}

func TestRecordDownloadAtomic(t *testing.T) {
	for _, table := range []string{"share_downloads", "mail_outbox"} {
		t.Run(table, func(t *testing.T) {
			e := setup(t)
			_, tok := e.newShare(t, nil, "bob@x.com")
			_, a, err := e.svc.VerifyCode(context.Background(), tok, "bob@x.com", e.code(t, tok, "bob@x.com"), ip1, "")
			if err != nil {
				t.Fatal(err)
			}
			svc, unlock := e.blocked(t, table)
			if err := svc.RecordDownload(context.Background(), a, a.Share.Files[0].ID); err == nil {
				t.Fatal("recorded while blocked")
			}
			unlock()
			if n := count(t, e, `SELECT count(*) FROM share_downloads`); n != 0 {
				t.Fatalf("downloads: %d", n)
			}
			// the retry still notifies the owner
			if err := e.svc.RecordDownload(context.Background(), a, a.Share.Files[0].ID); err != nil {
				t.Fatal(err)
			}
			if n := mailsTo(t, e, "owner@x.com", "downloaded"); n != 1 {
				t.Fatalf("download mails: %d", n)
			}
		})
	}
}
