package mail

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tntrock/secure-exchange/internal/config"
	"github.com/tntrock/secure-exchange/internal/db/testdb"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
)

func TestValidAddress(t *testing.T) {
	if a, ok := ValidAddress(" Bob@Example.COM "); !ok || a != "bob@example.com" {
		t.Fatalf("got %q %v", a, ok)
	}
	for _, s := range []string{"Bob <bob@x.com>", "a@b.com\r\nBcc: x@y.com", "x", strings.Repeat("a", 250) + "@b.com"} {
		if _, ok := ValidAddress(s); ok {
			t.Errorf("%q accepted", s)
		}
	}
}

func newOutbox(t *testing.T, s Sender) (*Outbox, func(string) any) {
	t.Helper()
	pool := testdb.New(t)
	keys, err := sxcrypto.ParseKeyring("1:"+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), 1)
	if err != nil {
		t.Fatal(err)
	}
	o := NewOutbox(pool, keys, s)
	return o, func(col string) any {
		var v any
		if err := pool.QueryRow(context.Background(), "SELECT "+col+" FROM mail_outbox").Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
}

func TestOutboxSealsBody(t *testing.T) {
	rec := &Recorder{}
	o, col := newOutbox(t, rec)
	ctx := context.Background()
	if err := o.Enqueue(ctx, o.pool, Message{To: "a@b.com", Subject: "s", Body: "CODE-123456"}); err != nil {
		t.Fatal(err)
	}
	if b := col("body_sealed").([]byte); bytes.Contains(b, []byte("CODE-123456")) {
		t.Fatal("body stored in plaintext")
	}
	if n, err := o.runOnce(ctx); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if len(rec.Sent) != 1 || !strings.Contains(rec.Sent[0].Body, "CODE-123456") || rec.Sent[0].To != "a@b.com" {
		t.Fatalf("sent %+v", rec.Sent)
	}
	if col("sent_at") == nil {
		t.Fatal("sent_at not set")
	}
}

type failSender struct{}

func (failSender) Send(context.Context, Message) error { return errors.New("boom") }

func TestOutboxRetryBackoff(t *testing.T) {
	o, col := newOutbox(t, failSender{})
	ctx := context.Background()
	if err := o.Enqueue(ctx, o.pool, Message{To: "a@b.com", Subject: "s", Body: "b"}); err != nil {
		t.Fatal(err)
	}
	if n, err := o.runOnce(ctx); err != nil || n != 0 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if col("attempts").(int32) != 1 || col("last_error") == "" {
		t.Fatalf("attempts=%v err=%v", col("attempts"), col("last_error"))
	}
	if d := time.Until(col("next_attempt_at").(time.Time)); d < time.Minute || d > 3*time.Minute {
		t.Fatalf("next attempt in %v, want ~2m", d)
	}
	// not due: a succeeding sender must not be called
	rec := &Recorder{}
	o.sender = rec
	if _, err := o.runOnce(ctx); err != nil || len(rec.Sent) != 0 {
		t.Fatalf("resent early: %v %v", err, rec.Sent)
	}
}

func TestOutboxRejectsHeaderInjection(t *testing.T) {
	o, _ := newOutbox(t, &Recorder{})
	ctx := context.Background()
	for _, m := range []Message{{To: "a@b.com\nBcc: x@y.com", Subject: "s"}, {To: "a@b.com", Subject: "s\nBcc: x"}} {
		if err := o.Enqueue(ctx, o.pool, m); err == nil {
			t.Errorf("%+v accepted", m)
		}
	}
	var n int
	if err := o.pool.QueryRow(ctx, `SELECT count(*) FROM mail_outbox`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("rows=%d %v", n, err)
	}
}

func TestSMTPAgainstMailpit(t *testing.T) {
	addr := os.Getenv("SX_TEST_SMTP_ADDR")
	if addr == "" {
		t.Skip("SX_TEST_SMTP_ADDR not set")
	}
	var host string
	var port int
	fmt.Sscanf(strings.Replace(addr, ":", " ", 1), "%s %d", &host, &port)
	s := NewSMTP(config.SMTPConfig{Host: host, Port: port, From: "sx@example.com", TLS: "none"})
	subj := fmt.Sprintf("[secure-exchange] 測試 / test %d", time.Now().UnixNano())
	if err := s.Send(context.Background(), Message{To: "bob@example.com", Subject: subj, Body: "內文 body"}); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get("http://localhost:58025/api/v1/messages")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct{ Messages []struct{ Subject string } }
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	for _, m := range out.Messages {
		if m.Subject == subj {
			return
		}
	}
	t.Fatalf("subject %q not found in mailpit", subj)
}

func TestSMTPNoneRefusesRemoteHost(t *testing.T) {
	s := NewSMTP(config.SMTPConfig{Host: "smtp.example.com", Port: 25, From: "a@b.com", TLS: "none"})
	if err := s.Send(context.Background(), Message{To: "x@y.com", Subject: "s"}); err == nil {
		t.Fatal("none mode allowed for remote host")
	}
}
