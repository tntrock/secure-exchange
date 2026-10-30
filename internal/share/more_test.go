package share

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/tntrock/secure-exchange/internal/mail/mailtest"
)

func TestLogout(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	_, tok := e.newShare(t, nil, "bob@x.com")
	st, _, err := e.svc.VerifyCode(ctx, tok, "bob@x.com", e.code(t, tok, "bob@x.com"), ip1, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Authorize(ctx, st, ip1); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Logout(ctx, st); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Authorize(ctx, st, ip1); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("after logout: %v", err)
	}
	if err := e.svc.Logout(ctx, "unknown"); err != nil {
		t.Fatalf("unknown token: %v", err)
	}
}

func TestValidationErrorMessage(t *testing.T) {
	var ve *ValidationError
	e := setup(t)
	_, err := e.svc.AddRecipients(context.Background(), e.owner, uuid.New(), []string{"not an address"})
	if !errors.As(err, &ve) || err.Error() != "share: "+ve.Field+": "+ve.Code || ve.Field != "emails" {
		t.Fatalf("got %v", err)
	}
}

func TestCreateTooMany(t *testing.T) {
	e := setup(t)
	for field, mod := range map[string]func(*CreateInput){
		"file_ids": func(in *CreateInput) {
			for len(in.FileIDs) <= maxFiles {
				in.FileIDs = append(in.FileIDs, uuid.New())
			}
		},
		"ip_allow": func(in *CreateInput) {
			for len(in.IPAllow) <= maxIPAllow {
				in.IPAllow = append(in.IPAllow, "10.0.0.1")
			}
		},
	} {
		in := e.input(t)
		mod(&in)
		var ve *ValidationError
		if _, err := e.svc.Create(context.Background(), e.owner, in); !errors.As(err, &ve) || ve.Field != field || ve.Code != "too_many" {
			t.Errorf("%s: %v", field, err)
		}
	}
}

func TestSenderNameFallsBackToEmail(t *testing.T) {
	e := setup(t)
	e.owner.DisplayName = ""
	e.newShare(t, nil, "bob@x.com")
	msgs := mailtest.Messages(t, e.pool, e.keys)
	if !strings.Contains(msgs[len(msgs)-1].Body, "owner@x.com 與您分享了檔案") {
		t.Fatalf("invitation: %s", msgs[len(msgs)-1].Body)
	}
}

func TestInvalidEmailsAtRecipientEndpoints(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	_, tok := e.newShare(t, nil, "bob@x.com")
	if sent, err := e.svc.RequestCode(ctx, tok, "Bob <bob@x.com>", ip1); sent || err != nil {
		t.Fatalf("request: %v %v", sent, err)
	}
	if _, _, err := e.svc.VerifyCode(ctx, tok, "Bob <bob@x.com>", "123456", ip1, ""); !errors.Is(err, ErrBadCode) {
		t.Fatalf("verify: %v", err)
	}
	if _, _, err := e.svc.VerifyCode(ctx, "bad-token", "bob@x.com", "123456", ip1, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("verify bad token: %v", err)
	}
	if _, err := e.svc.RequestCode(ctx, "bad-token", "bob@x.com", ip1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("request bad token: %v", err)
	}
}

func TestAddRecipientsUnreadableToken(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	sh, _ := e.newShare(t, nil, "bob@x.com")
	if _, err := e.pool.Exec(ctx, `UPDATE shares SET token_sealed = 'x' WHERE id = $1`, sh.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AddRecipients(ctx, e.owner, sh.ID, []string{"carol@x.com"}); err == nil {
		t.Fatal("added recipients without a readable link token")
	}
	if n := count(t, e, `SELECT count(*) FROM share_recipients WHERE share_id = $1`, sh.ID); n != 1 {
		t.Fatalf("recipients: %d", n)
	}
}

// Every service call surfaces a database error rather than a domain answer.
func TestCanceledContext(t *testing.T) {
	e := setup(t)
	sh, tok := e.newShare(t, nil, "bob@x.com")
	st, a, err := e.svc.VerifyCode(context.Background(), tok, "bob@x.com", e.code(t, tok, "bob@x.com"), ip1, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := map[string]func() error{
		"Landing":         func() error { _, err := e.svc.Landing(ctx, tok, ip1); return err },
		"RequestCode":     func() error { _, err := e.svc.RequestCode(ctx, tok, "bob@x.com", ip1); return err },
		"VerifyCode":      func() error { _, _, err := e.svc.VerifyCode(ctx, tok, "bob@x.com", "123456", ip1, ""); return err },
		"Authorize":       func() error { _, err := e.svc.Authorize(ctx, st, ip1); return err },
		"RecordDownload":  func() error { return e.svc.RecordDownload(ctx, a, a.Share.Files[0].ID) },
		"Logout":          func() error { return e.svc.Logout(ctx, st) },
		"Create":          func() error { _, err := e.svc.Create(ctx, e.owner, e.input(t)); return err },
		"List":            func() error { _, err := e.svc.List(ctx, e.owner.ID); return err },
		"Get":             func() error { _, err := e.svc.Get(ctx, e.owner.ID, sh.ID); return err },
		"Revoke":          func() error { return e.svc.Revoke(ctx, e.owner.ID, sh.ID) },
		"RevokeRecipient": func() error { return e.svc.RevokeRecipient(ctx, e.owner.ID, sh.ID, a.Recipient.ID) },
		"AddRecipients":   func() error { _, err := e.svc.AddRecipients(ctx, e.owner, sh.ID, []string{"carol@x.com"}); return err },
	}
	for name, call := range calls {
		err := call()
		var ve *ValidationError
		if err == nil || errors.As(err, &ve) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrBadCode) {
			t.Errorf("%s: got %v, want a context error", name, err)
		}
	}
	// nothing changed
	if _, err := e.svc.Authorize(context.Background(), st, ip1); err != nil {
		t.Fatalf("session lost: %v", err)
	}
}
