package mail

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/tntrock/secure-exchange/internal/config"
)

type cancelAfterFirst struct {
	cancel context.CancelFunc
	rec    Recorder
}

func (c *cancelAfterFirst) Send(ctx context.Context, m Message) error {
	err := c.rec.Send(ctx, m)
	c.cancel()
	return err
}

func TestOutboxShutdownKeepsSentAt(t *testing.T) {
	cs := &cancelAfterFirst{}
	o, _ := newOutbox(t, cs)
	bg := context.Background()
	for _, s := range []string{"one", "two"} {
		if err := o.Enqueue(bg, o.pool, Message{To: "a@b.com", Subject: s, Body: "b"}); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(bg)
	cs.cancel = cancel
	if n, err := o.runOnce(ctx); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	var sentRows int
	if err := o.pool.QueryRow(bg, `SELECT count(*) FROM mail_outbox WHERE sent_at IS NOT NULL`).Scan(&sentRows); err != nil || sentRows != 1 {
		t.Fatalf("sent rows=%d %v", sentRows, err)
	}
	cs.cancel = func() {}
	if n, err := o.runOnce(bg); err != nil || n != 1 || len(cs.rec.Sent) != 2 {
		t.Fatalf("second run n=%d err=%v total sent=%d, want 1 nil 2", n, err, len(cs.rec.Sent))
	}
}

type cjkErrSender struct{}

func (cjkErrSender) Send(context.Context, Message) error {
	return errors.New(strings.Repeat("錯", 200)) // 600 bytes
}

func TestOutboxLastErrorUTF8(t *testing.T) {
	o, col := newOutbox(t, cjkErrSender{})
	ctx := context.Background()
	if err := o.Enqueue(ctx, o.pool, Message{To: "a@b.com", Subject: "s", Body: "b"}); err != nil {
		t.Fatal(err)
	}
	if _, err := o.runOnce(ctx); err != nil {
		t.Fatal(err)
	}
	le := col("last_error").(string)
	if col("attempts").(int32) != 1 || len(le) > 500 || !utf8.ValidString(le) || le == "" {
		t.Fatalf("attempts=%v len=%d valid=%v", col("attempts"), len(le), utf8.ValidString(le))
	}
}

type nulErrSender struct{}

func (nulErrSender) Send(context.Context, Message) error {
	return errors.New("bad" + string(rune(0)) + "reply")
}

func TestOutboxLastErrorStripsNUL(t *testing.T) {
	o, col := newOutbox(t, nulErrSender{})
	ctx := context.Background()
	if err := o.Enqueue(ctx, o.pool, Message{To: "a@b.com", Subject: "s", Body: "b"}); err != nil {
		t.Fatal(err)
	}
	if _, err := o.runOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if le := col("last_error"); le != "badreply" || col("attempts").(int32) != 1 {
		t.Fatalf("last_error=%q attempts=%v", le, col("attempts"))
	}
}

// A server that drops the connection right after accepting DATA must not make Send fail.
func TestSMTPQuitFailureIgnored(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
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
			if strings.HasPrefix(strings.ToUpper(line), "DATA") {
				fmt.Fprint(c, "354 go\r\n")
				for {
					l, err := r.ReadString('\n')
					if err != nil || l == ".\r\n" {
						break
					}
				}
				fmt.Fprint(c, "250 queued\r\n")
				return // close before QUIT
			}
			fmt.Fprint(c, "250 ok\r\n")
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	s := NewSMTP(config.SMTPConfig{Host: "127.0.0.1", Port: port, From: "sx@example.com", TLS: "none"})
	if err := s.Send(context.Background(), Message{To: "b@example.com", Subject: "s", Body: "b"}); err != nil {
		t.Fatalf("Send failed after DATA accepted: %v", err)
	}
}
