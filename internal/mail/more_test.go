package mail

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tntrock/secure-exchange/internal/config"
)

func TestTemplates(t *testing.T) {
	exp := time.Date(2026, 1, 2, 3, 4, 0, 0, time.FixedZone("x", 8*3600))
	cases := []struct {
		name          string
		subj, body    string
		subjHas, want []string
		wantNot       []string
	}{
		{name: "invitation with message", subjHas: []string{"[secure-exchange]", "securely shared"},
			want: []string{"Alice", "https://sx/s/tok", "附言：\nhello", "Message:\nhello", "2026-01-01 19:04 UTC", sep}},
		{name: "invitation without message", subjHas: []string{"securely shared"},
			want: []string{"Alice", "https://sx/s/tok"}, wantNot: []string{"附言", "Message:"}},
		{name: "otp", subjHas: []string{"verification code"}, want: []string{"您的驗證碼是：123456", "Your verification code is: 123456"}},
		{name: "first open", subjHas: []string{"opened your share"}, want: []string{"bob@x.com 已首次開啟", "bob@x.com opened", "https://sx/s/tok"}},
		{name: "download", subjHas: []string{"downloaded a file"}, want: []string{"「a.pdf」", `"a.pdf"`, "bob@x.com"}},
	}
	cases[0].subj, cases[0].body = Invitation("https://sx/s/tok", "Alice", "hello", exp)
	cases[1].subj, cases[1].body = Invitation("https://sx/s/tok", "Alice", "", exp)
	cases[2].subj, cases[2].body = OTPCode("123456")
	cases[3].subj, cases[3].body = NotifyFirstOpen("bob@x.com", "https://sx/s/tok")
	cases[4].subj, cases[4].body = NotifyDownload("bob@x.com", "a.pdf", "https://sx/s/tok")
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if strings.ContainsAny(c.subj, "\r\n") || !strings.HasPrefix(c.subj, "[secure-exchange] ") {
				t.Fatalf("subject %q", c.subj)
			}
			for _, s := range c.subjHas {
				if !strings.Contains(c.subj, s) {
					t.Errorf("subject %q lacks %q", c.subj, s)
				}
			}
			for _, s := range c.want {
				if !strings.Contains(c.body, s) {
					t.Errorf("body lacks %q:\n%s", s, c.body)
				}
			}
			for _, s := range c.wantNot {
				if strings.Contains(c.body, s) {
					t.Errorf("body has %q", s)
				}
			}
		})
	}
}

func TestOutboxRunDeliversOnWakeAndStops(t *testing.T) {
	rec := &Recorder{}
	o, col := newOutbox(t, rec)
	sent := func() int {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		return len(rec.Sent)
	}
	waitSent := func(n int, msg string) {
		deadline := time.Now().Add(4 * time.Second) // well under the 5s ticker
		for sent() != n {
			if time.Now().After(deadline) {
				t.Fatal(msg)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	// A message queued before Run is delivered by Run's initial pass; seeing it sent proves
	// that pass already selected its rows, so the second message can only come from the wake.
	if err := o.Enqueue(context.Background(), o.pool, Message{To: "first@b.com", Subject: "s", Body: "b"}); err != nil {
		t.Fatal(err)
	}
	<-o.wake // drop its wake: only the second Enqueue may wake Run
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { o.Run(ctx); close(done) }()
	waitSent(1, "initial pass did not deliver")

	if err := o.Enqueue(context.Background(), o.pool, Message{To: "a@b.com", Subject: "s", Body: "b"}); err != nil {
		t.Fatal(err)
	}
	waitSent(2, "enqueued mail not delivered after wake")
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if rec.Sent[1].To != "a@b.com" {
		t.Fatalf("second delivery to %q", rec.Sent[1].To)
	}
	if n := col("count(*) FILTER (WHERE sent_at IS NULL)"); n != int64(0) {
		t.Fatalf("%v rows without sent_at", n)
	}
}

func TestOutboxUnsealFailureIsRetried(t *testing.T) {
	rec := &Recorder{}
	o, col := newOutbox(t, rec)
	ctx := context.Background()
	if _, err := o.pool.Exec(ctx, `INSERT INTO mail_outbox (id, to_addr, body_sealed) VALUES ($1,'a@b.com','garbage')`, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if n, err := o.runOnce(ctx); err != nil || n != 0 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if len(rec.Sent) != 0 || !strings.Contains(col("last_error").(string), "unseal") || col("attempts").(int32) != 1 {
		t.Fatalf("sent=%v last_error=%v attempts=%v", rec.Sent, col("last_error"), col("attempts"))
	}
}

func TestOutboxCanceledContext(t *testing.T) {
	o, _ := newOutbox(t, &Recorder{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := o.runOnce(ctx); err == nil {
		t.Fatal("runOnce on a canceled context succeeded")
	}
	if err := o.Enqueue(ctx, o.pool, Message{To: "a@b.com", Subject: "s"}); err == nil {
		t.Fatal("Enqueue on a canceled context succeeded")
	}
}

// fakeSMTP serves one plain SMTP session; replies maps a command prefix (upper case) to its reply.
func fakeSMTP(t *testing.T, replies map[string]string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		fmt.Fprint(c, "220 hi\r\n")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			up := strings.ToUpper(line)
			reply := "250 ok"
			for p, rep := range replies {
				if strings.HasPrefix(up, p) {
					reply = rep
				}
			}
			fmt.Fprint(c, reply+"\r\n")
			if strings.HasPrefix(up, "DATA") && strings.HasPrefix(reply, "354") {
				for {
					l, err := r.ReadString('\n')
					if err != nil || l == ".\r\n" {
						break
					}
				}
				fmt.Fprint(c, replies["."]+"\r\n")
			}
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestSMTPSendErrors(t *testing.T) {
	msg := Message{To: "b@example.com", Subject: "s", Body: "b"}
	cfg := func(port int, mut func(*config.SMTPConfig)) config.SMTPConfig {
		c := config.SMTPConfig{Host: "127.0.0.1", Port: port, From: "sx@example.com", TLS: "none"}
		if mut != nil {
			mut(&c)
		}
		return c
	}
	closed := func() int { // a port nothing listens on
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		p := ln.Addr().(*net.TCPAddr).Port
		ln.Close()
		return p
	}
	cases := []struct {
		name    string
		port    func() int
		mut     func(*config.SMTPConfig)
		msg     Message
		wantErr string
	}{
		{name: "header injection", port: closed, msg: Message{To: "b@example.com\r\nBcc: x@y.com", Subject: "s"}, wantErr: "CR/LF"},
		{name: "bad from", port: closed, mut: func(c *config.SMTPConfig) { c.From = "not an address" }, wantErr: "bad From"},
		{name: "unknown tls mode", port: closed, mut: func(c *config.SMTPConfig) { c.TLS = "ssl3" }, wantErr: "unknown TLS mode"},
		{name: "connection refused", port: closed, wantErr: "refused"},
		{name: "starttls unsupported", port: func() int { return fakeSMTP(t, map[string]string{"STARTTLS": "502 no"}) },
			mut: func(c *config.SMTPConfig) { c.TLS = "starttls" }, wantErr: "502"},
		{name: "tls handshake fails", port: func() int { return fakeSMTP(t, nil) },
			mut: func(c *config.SMTPConfig) { c.TLS = "tls" }, wantErr: "tls"},
		{name: "auth rejected", port: func() int { return fakeSMTP(t, map[string]string{"AUTH": "535 bad credentials"}) },
			mut: func(c *config.SMTPConfig) { c.Username, c.Password = "u", "p" }, wantErr: "535"},
		{name: "sender rejected", port: func() int { return fakeSMTP(t, map[string]string{"MAIL": "550 no sender"}) }, wantErr: "550"},
		{name: "recipient rejected", port: func() int { return fakeSMTP(t, map[string]string{"RCPT": "550 no such user"}) }, wantErr: "no such user"},
		{name: "data refused", port: func() int { return fakeSMTP(t, map[string]string{"DATA": "554 nope"}) }, wantErr: "554"},
		{name: "message rejected", port: func() int { return fakeSMTP(t, map[string]string{"DATA": "354 go", ".": "552 too big"}) }, wantErr: "552"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := msg
			if c.msg.To != "" {
				m = c.msg
			}
			err := NewSMTP(cfg(c.port(), c.mut)).Send(context.Background(), m)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(c.wantErr)) {
				t.Fatalf("err = %v, want containing %q", err, c.wantErr)
			}
		})
	}
}
