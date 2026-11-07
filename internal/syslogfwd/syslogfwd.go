// Package syslogfwd forwards audit rows to a syslog server (RFC 5424) and
// tracks progress in the syslog_cursor table, so nothing is lost across
// outages or restarts (delivery is at least once).
package syslogfwd

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/config"
)

const (
	lockKey      = 7462 // audit.Append uses 7461
	writeTimeout = 10 * time.Second
	// facility 13 (log audit): severity 6 (info) or 4 (warning)
	priOK, priFail = 13*8 + 6, 13*8 + 4
)

// Format renders e as one RFC 5424 message without transport framing.
func Format(e audit.Entry, host string) []byte {
	if host == "" {
		host = "-"
	}
	pri := priOK
	if e.Event.Result != "ok" {
		pri = priFail
	}
	ev := e.Event
	body, _ := json.Marshal(struct {
		ID         int64          `json:"id"`
		At         string         `json:"at"`
		ActorType  string         `json:"actor_type"`
		ActorID    string         `json:"actor_id"`
		IP         string         `json:"ip"`
		UserAgent  string         `json:"user_agent"`
		Action     string         `json:"action"`
		TargetType string         `json:"target_type"`
		TargetID   string         `json:"target_id"`
		Result     string         `json:"result"`
		Detail     map[string]any `json:"detail"`
		PrevHash   string         `json:"prev_hash"`
		Hash       string         `json:"hash"`
	}{e.ID, e.At.UTC().Format(time.RFC3339Nano), ev.ActorType, ev.ActorID, ev.IP, ev.UserAgent, ev.Action,
		ev.TargetType, ev.TargetID, ev.Result, ev.Detail, hex.EncodeToString(e.PrevHash), hex.EncodeToString(e.Hash)})
	var b bytes.Buffer
	b.WriteString("<" + strconv.Itoa(pri) + ">1 ")
	// RFC 5424 allows at most 6 fractional digits; audit times are microsecond-truncated
	b.WriteString(e.At.UTC().Format("2006-01-02T15:04:05.999999Z07:00"))
	msgID := ev.Action
	if msgID == "" {
		msgID = "-"
	} else if len(msgID) > 32 { // RFC 5424 MSGID limit
		msgID = msgID[:32]
	}
	b.WriteString(" " + host + " secure-exchange - " + msgID + " - ")
	b.Write(body)
	return b.Bytes()
}

// Forwarder ships audit rows past syslog_cursor.last_id to Cfg.Addr.
type Forwarder struct {
	Pool     *pgxpool.Pool
	Cfg      config.SyslogConfig
	Host     string
	Interval time.Duration // idle poll, default 2s
	Retry    time.Duration // wait after an error, default 10s
	Batch    int           // rows per step, default 500

	conn net.Conn
}

func orDefault[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}
	return v
}

// Run steps until ctx is done: again at once after a full batch, after
// Interval when caught up and after Retry on an error.
func (f *Forwarder) Run(ctx context.Context) {
	defer f.close()
	for {
		n, err := f.Step(ctx)
		wait := orDefault(f.Interval, 2*time.Second)
		switch {
		case err != nil:
			slog.Warn("syslog forward", "err", err)
			wait = orDefault(f.Retry, 10*time.Second)
		case n == orDefault(f.Batch, 500):
			wait = 0
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// Step sends one batch and advances the cursor. It returns (0, nil) when
// another process holds the forwarder lock.
func (f *Forwarder) Step(ctx context.Context) (int, error) {
	tx, err := f.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, lockKey).Scan(&ok); err != nil {
		return 0, err
	}
	if !ok {
		return 0, tx.Commit(ctx)
	}
	var last int64
	if err := tx.QueryRow(ctx, `SELECT last_id FROM syslog_cursor WHERE id = 1 FOR UPDATE`).Scan(&last); err != nil {
		return 0, err
	}
	rows, err := audit.After(ctx, tx, last, orDefault(f.Batch, 500))
	if err != nil || len(rows) == 0 {
		return 0, err
	}
	if err := f.send(ctx, rows); err != nil {
		f.close()
		_ = tx.Rollback(ctx)
		// WithoutCancel: still record a failure caused by shutdown mid-dial
		_, dbErr := f.Pool.Exec(context.WithoutCancel(ctx), `UPDATE syslog_cursor SET failing_since = COALESCE(failing_since, now()), last_error = $1 WHERE id = 1`, err.Error())
		return 0, errors.Join(err, dbErr)
	}
	if _, err := tx.Exec(ctx, `UPDATE syslog_cursor SET last_id = $1, last_ok_at = now(), failing_since = NULL, last_error = '' WHERE id = 1`,
		rows[len(rows)-1].ID); err != nil {
		return 0, err
	}
	return len(rows), tx.Commit(ctx)
}

func (f *Forwarder) send(ctx context.Context, rows []audit.Entry) error {
	// A peer that closed (e.g. a restarted syslog server) still accepts writes into
	// our send buffer, which would lose the batch silently; probe before reusing.
	if f.conn != nil && f.Cfg.Transport != "udp" && !alive(f.conn) {
		f.close()
	}
	if f.conn == nil {
		c, err := f.dial(ctx)
		if err != nil {
			return err
		}
		f.conn = c
	}
	if err := f.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}
	if f.Cfg.Transport == "udp" {
		for _, e := range rows {
			if _, err := f.conn.Write(Format(e, f.Host)); err != nil {
				return err
			}
		}
		return nil
	}
	var b bytes.Buffer // RFC 6587 octet counting: "LEN SP MSG"
	for _, e := range rows {
		m := Format(e, f.Host)
		b.WriteString(strconv.Itoa(len(m)) + " ")
		b.Write(m)
	}
	_, err := f.conn.Write(b.Bytes())
	return err
}

func (f *Forwarder) dial(ctx context.Context) (net.Conn, error) {
	d := &net.Dialer{Timeout: writeTimeout}
	switch f.Cfg.Transport {
	case "udp", "tcp":
		return d.DialContext(ctx, f.Cfg.Transport, f.Cfg.Addr)
	}
	host, _, err := net.SplitHostPort(f.Cfg.Addr)
	if err != nil {
		return nil, err
	}
	tc := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if f.Cfg.CAFile != "" {
		if tc.RootCAs, err = config.CertPool(f.Cfg.CAFile); err != nil {
			return nil, err
		}
	}
	return (&tls.Dialer{NetDialer: d, Config: tc}).DialContext(ctx, "tcp", f.Cfg.Addr)
}

func (f *Forwarder) close() {
	if f.conn != nil {
		_ = f.conn.Close()
		f.conn = nil
	}
}

// Status is the forwarder health shown to admins.
type Status struct {
	Enabled      bool       `json:"enabled"`
	Pending      int64      `json:"pending"`
	LastOKAt     *time.Time `json:"last_ok_at"`
	FailingSince *time.Time `json:"failing_since"`
	LastError    string     `json:"last_error"`
	Alert        bool       `json:"alert"`
}

// GetStatus reads syslog_cursor; Alert means failing for over 15 minutes.
func GetStatus(ctx context.Context, pool *pgxpool.Pool, enabled bool, now time.Time) (Status, error) {
	s := Status{Enabled: enabled}
	err := pool.QueryRow(ctx, `SELECT COALESCE((SELECT max(id) FROM audit_log), 0) - last_id, last_ok_at, failing_since, last_error
		FROM syslog_cursor WHERE id = 1`).Scan(&s.Pending, &s.LastOKAt, &s.FailingSince, &s.LastError)
	s.Alert = enabled && s.FailingSince != nil && now.Sub(*s.FailingSince) > 15*time.Minute
	return s, err
}

// alive reports whether c is still open: a short read must time out, since the
// server never sends; EOF, a reset or unexpected data all mean redial.
func alive(c net.Conn) bool {
	if c.SetReadDeadline(time.Now().Add(time.Millisecond)) != nil {
		return false
	}
	_, err := c.Read(make([]byte, 1))
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout() && c.SetReadDeadline(time.Time{}) == nil
}
