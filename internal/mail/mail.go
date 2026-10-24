// Package mail sends plain-text email via SMTP and queues it in a sealed PostgreSQL outbox.
package mail

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tntrock/secure-exchange/internal/config"
)

type Message struct{ To, Subject, Body string }

type Sender interface {
	Send(ctx context.Context, m Message) error
}

// Recorder is a Sender for tests: it only records.
type Recorder struct {
	mu   sync.Mutex
	Sent []Message
}

func (r *Recorder) Send(_ context.Context, m Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Sent = append(r.Sent, m)
	return nil
}

// ValidAddress trims and lowercases s and reports whether it is a bare, single email address.
func ValidAddress(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || len(s) > 254 || strings.ContainsAny(s, "\r\n") {
		return "", false
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Name != "" || a.Address != s {
		return "", false
	}
	return s, true
}

type SMTP struct{ cfg config.SMTPConfig }

func NewSMTP(cfg config.SMTPConfig) *SMTP { return &SMTP{cfg: cfg} }

func (s *SMTP) Send(ctx context.Context, m Message) error {
	if strings.ContainsAny(m.To+m.Subject, "\r\n") {
		return errors.New("mail: CR/LF in header")
	}
	from, err := mail.ParseAddress(s.cfg.From)
	if err != nil {
		return fmt.Errorf("mail: bad From: %w", err)
	}
	switch s.cfg.TLS {
	case "starttls", "tls":
	case "none":
		if h := s.cfg.Host; h != "localhost" && h != "127.0.0.1" && h != "mailpit" {
			return fmt.Errorf("mail: TLS none is only allowed for local hosts, not %q", h)
		}
	default:
		return fmt.Errorf("mail: unknown TLS mode %q", s.cfg.TLS)
	}

	addr := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))
	d := net.Dialer{Timeout: 15 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(60 * time.Second))
	tlsCfg := &tls.Config{ServerName: s.cfg.Host, MinVersion: tls.VersionTLS12}
	if s.cfg.TLS == "tls" {
		conn = tls.Client(conn, tlsCfg)
	}
	c, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		return err
	}
	defer c.Close()
	if s.cfg.TLS == "starttls" {
		if err := c.StartTLS(tlsCfg); err != nil {
			return err
		}
	}
	if s.cfg.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)); err != nil {
			return err
		}
	}
	if err := c.Mail(from.Address); err != nil {
		return err
	}
	if err := c.Rcpt(m.To); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(s.render(from.Address, m)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func (s *SMTP) render(from string, m Message) []byte {
	id := make([]byte, 16)
	rand.Read(id)
	domain := from[strings.LastIndex(from, "@")+1:]
	h := []string{
		"From: " + s.cfg.From,
		"To: " + m.To,
		"Subject: " + mime.QEncoding.Encode("utf-8", m.Subject),
		"Date: " + time.Now().Format(time.RFC1123Z),
		"Message-ID: <" + hex.EncodeToString(id) + "@" + domain + ">",
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"Content-Transfer-Encoding: 8bit",
	}
	body := strings.ReplaceAll(strings.ReplaceAll(m.Body, "\r\n", "\n"), "\n", "\r\n")
	return []byte(strings.Join(h, "\r\n") + "\r\n\r\n" + body)
}
