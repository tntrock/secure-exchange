// Package audit is an append-only, SHA-256 hash-chained audit log.
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	ActLoginOK     = "auth.login.ok"
	ActLoginFail   = "auth.login.fail"
	ActLogout      = "auth.logout"
	ActTOTPEnable  = "auth.totp.enable"
	ActUpload      = "file.upload"
	ActDownload    = "file.download"
	ActDelete      = "file.delete"
	ActKeyRotate   = "crypto.rotate"
	ActFileView    = "file.view"
	ActTraceLookup = "trace.lookup"

	ActShareCreate          = "share.create"
	ActShareRevoke          = "share.revoke"
	ActShareRecipientAdd    = "share.recipient.add"
	ActShareRecipientRevoke = "share.recipient.revoke"
	ActShareOTPRequest      = "share.otp.request"
	ActShareOTPVerify       = "share.otp.verify"
)

const lockKey = 7461

type Event struct {
	ActorType, ActorID, IP, UserAgent, Action, TargetType, TargetID, Result string
	Detail                                                                  map[string]any
}

type Entry struct {
	ID       int64
	At       time.Time
	Event    Event
	PrevHash []byte
	Hash     []byte
}

type Filter struct {
	ActorID, Action string
	Since, Until    time.Time
	Limit           int
}

type Log struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *Log { return &Log{pool: pool} }

// canonical is the hashed form: fixed field order, detail with sorted keys.
func canonical(at time.Time, e Event, detail []byte) []byte {
	b, _ := json.Marshal(struct {
		At         string          `json:"at"`
		ActorType  string          `json:"actor_type"`
		ActorID    string          `json:"actor_id"`
		IP         string          `json:"ip"`
		UserAgent  string          `json:"user_agent"`
		Action     string          `json:"action"`
		TargetType string          `json:"target_type"`
		TargetID   string          `json:"target_id"`
		Result     string          `json:"result"`
		Detail     json.RawMessage `json:"detail"`
	}{at.UTC().Format(time.RFC3339Nano), e.ActorType, e.ActorID, e.IP, e.UserAgent, e.Action, e.TargetType, e.TargetID, e.Result, detail})
	return b
}

// canonDetail normalizes JSON (as stored in jsonb or given by callers) to sorted-key compact form.
func canonDetail(raw []byte) ([]byte, error) {
	m := map[string]any{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, err
		}
	}
	if m == nil {
		m = map[string]any{}
	}
	return json.Marshal(m)
}

func chain(prev []byte, canon []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	h.Write(canon)
	return h.Sum(nil)
}

func (l *Log) Append(ctx context.Context, e Event) error {
	raw, err := json.Marshal(e.Detail) // nil map -> null -> {}
	if err != nil {
		return err
	}
	detail, err := canonDetail(raw)
	if err != nil {
		return err
	}
	tx, err := l.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockKey); err != nil {
		return err
	}
	prev := make([]byte, 32)
	err = tx.QueryRow(ctx, `SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&prev)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	hash := chain(prev, canonical(at, e, detail))
	if _, err := tx.Exec(ctx, `INSERT INTO audit_log
		(at, actor_type, actor_id, ip, user_agent, action, target_type, target_id, result, detail, prev_hash, hash)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		at, e.ActorType, e.ActorID, e.IP, e.UserAgent, e.Action, e.TargetType, e.TargetID, e.Result, detail, prev, hash); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

const cols = `id, at, actor_type, actor_id, ip, user_agent, action, target_type, target_id, result, detail, prev_hash, hash`

func scan(rows pgx.Rows) (Entry, error) {
	var en Entry
	var raw []byte
	e := &en.Event
	if err := rows.Scan(&en.ID, &en.At, &e.ActorType, &e.ActorID, &e.IP, &e.UserAgent, &e.Action,
		&e.TargetType, &e.TargetID, &e.Result, &raw, &en.PrevHash, &en.Hash); err != nil {
		return en, err
	}
	en.At = en.At.UTC()
	return en, json.Unmarshal(raw, &e.Detail)
}

// Verify recomputes the chain in id order; returns the first bad id, or 0 if intact.
func (l *Log) Verify(ctx context.Context) (int64, error) {
	rows, err := l.pool.Query(ctx, `SELECT `+cols+` FROM audit_log ORDER BY id`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	prev := make([]byte, 32)
	for rows.Next() {
		en, err := scan(rows)
		if err != nil {
			return 0, err
		}
		detail, err := json.Marshal(en.Event.Detail)
		if err != nil {
			return 0, err
		}
		if !bytes.Equal(en.PrevHash, prev) || !bytes.Equal(en.Hash, chain(prev, canonical(en.At, en.Event, detail))) {
			return en.ID, nil
		}
		prev = en.Hash
	}
	return 0, rows.Err()
}

func (l *Log) List(ctx context.Context, f Filter) ([]Entry, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	// zero Since/Until are passed as NULL (no bound).
	var since, until *time.Time
	if !f.Since.IsZero() {
		since = &f.Since
	}
	if !f.Until.IsZero() {
		until = &f.Until
	}
	rows, err := l.pool.Query(ctx, `SELECT `+cols+` FROM audit_log
		WHERE ($1 = '' OR actor_id = $1) AND ($2 = '' OR action = $2)
		AND ($3::timestamptz IS NULL OR at >= $3) AND ($4::timestamptz IS NULL OR at < $4)
		ORDER BY id DESC LIMIT $5`, f.ActorID, f.Action, since, until, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		en, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, en)
	}
	return out, rows.Err()
}
