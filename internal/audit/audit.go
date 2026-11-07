// Package audit is an append-only, SHA-256 hash-chained audit log.
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
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

	ActRequestCreate     = "request.create"
	ActRequestRevoke     = "request.revoke"
	ActRequestOTPRequest = "request.otp.request"
	ActRequestOTPVerify  = "request.otp.verify"
	ActFileScan          = "file.scan"

	ActVendorCreate   = "vendor.create"
	ActVendorApprove  = "vendor.approve"
	ActVendorReject   = "vendor.reject"
	ActVendorDisable  = "vendor.disable"
	ActVendorEnable   = "vendor.enable"
	ActVendorExpiry   = "vendor.expiry"
	ActVendorReinvite = "vendor.reinvite"
	ActVendorActivate = "vendor.activate"

	ActUserCreate    = "user.create"
	ActUserDisable   = "user.disable"
	ActUserEnable    = "user.enable"
	ActUserRole      = "user.role"
	ActUserTOTPReset = "user.totp_reset"
	ActUserReinvite  = "user.reinvite"
	ActUserActivate  = "user.activate"

	ActAuditExport = "audit.export"
	ActAuditVerify = "audit.verify"
	ActNotifyPrefs = "user.notify_prefs"

	ActRulesUpdate     = "rules.update"
	ActRetentionDelete = "file.retention_delete"
)

const lockKey = 7461

type Event struct {
	ActorType, ActorID, IP, UserAgent, Action, TargetType, TargetID, Result string
	Detail                                                                  map[string]any
}

type Entry struct {
	ID         int64
	At         time.Time
	Event      Event
	PrevHash   []byte
	Hash       []byte
	ActorLabel string
}

type Filter struct {
	Actor, ActionPrefix, Target string
	Since, Until                time.Time
	BeforeID                    int64
	Limit                       int
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

const (
	selectCols = `a.id, a.at, a.actor_type, a.actor_id, a.ip, a.user_agent, a.action, a.target_type, a.target_id, a.result, a.detail, a.prev_hash, a.hash,
		COALESCE(u.email, sr.email, ru.email, '')`
	fromJoins = ` FROM audit_log a
		LEFT JOIN users u ON u.id::text = a.actor_id
		LEFT JOIN share_recipients sr ON sr.id::text = a.actor_id
		LEFT JOIN request_uploaders ru ON ru.id::text = a.actor_id`
)

func scan(rows pgx.Rows) (Entry, error) {
	var en Entry
	var raw []byte
	e := &en.Event
	if err := rows.Scan(&en.ID, &en.At, &e.ActorType, &e.ActorID, &e.IP, &e.UserAgent, &e.Action,
		&e.TargetType, &e.TargetID, &e.Result, &raw, &en.PrevHash, &en.Hash, &en.ActorLabel); err != nil {
		return en, err
	}
	en.At = en.At.UTC()
	return en, json.Unmarshal(raw, &e.Detail)
}

// Verify recomputes the chain in id order; returns rows checked and the first bad id (0 if intact).
func (l *Log) Verify(ctx context.Context) (checked, badID int64, err error) {
	rows, err := l.pool.Query(ctx, `SELECT `+selectCols+fromJoins+` ORDER BY a.id`)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	prev := make([]byte, 32)
	for rows.Next() {
		en, err := scan(rows)
		if err != nil {
			return checked, 0, err
		}
		checked++
		detail, err := json.Marshal(en.Event.Detail)
		if err != nil {
			return checked, 0, err
		}
		if !bytes.Equal(en.PrevHash, prev) || !bytes.Equal(en.Hash, chain(prev, canonical(en.At, en.Event, detail))) {
			return checked, en.ID, nil
		}
		prev = en.Hash
	}
	return checked, 0, rows.Err()
}

// where builds the shared filter predicate (BeforeID/Limit are handled by callers).
func where(f Filter) (string, []any) {
	var conds []string
	var args []any
	add := func(cond string, v any) {
		args = append(args, v)
		conds = append(conds, strings.ReplaceAll(cond, "$n", "$"+strconv.Itoa(len(args))))
	}
	if f.Actor != "" {
		// ponytail: actor email filter seq-scans; resolve email→ids first if audit_log grows past ~10M rows
		add(`(a.actor_id = $n OR lower(COALESCE(u.email, sr.email, ru.email, a.actor_id)) = lower($n))`, f.Actor)
	}
	if f.ActionPrefix != "" {
		add(`starts_with(a.action, $n)`, f.ActionPrefix)
	}
	if f.Target != "" {
		add(`(a.target_id = $n OR a.detail->>'share_id' = $n)`, f.Target)
	}
	if !f.Since.IsZero() {
		add(`a.at >= $n`, f.Since)
	}
	if !f.Until.IsZero() {
		add(`a.at < $n`, f.Until)
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

func collect(rows pgx.Rows, fn func(Entry) error) error {
	defer rows.Close()
	for rows.Next() {
		en, err := scan(rows)
		if err != nil {
			return err
		}
		if err := fn(en); err != nil {
			return err
		}
	}
	return rows.Err()
}

// List returns entries newest first; nextBeforeID is 0 when there is no further page.
func (l *Log) List(ctx context.Context, f Filter) (out []Entry, nextBeforeID int64, err error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	if f.Limit > 500 {
		f.Limit = 500
	}
	w, args := where(f)
	if f.BeforeID > 0 {
		args = append(args, f.BeforeID)
		if w == "" {
			w = " WHERE"
		} else {
			w += " AND"
		}
		w += " a.id < $" + strconv.Itoa(len(args))
	}
	args = append(args, f.Limit+1)
	rows, err := l.pool.Query(ctx, `SELECT `+selectCols+fromJoins+w+` ORDER BY a.id DESC LIMIT $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	if err := collect(rows, func(en Entry) error { out = append(out, en); return nil }); err != nil {
		return nil, 0, err
	}
	if len(out) > f.Limit {
		out = out[:f.Limit]
		nextBeforeID = out[len(out)-1].ID
	}
	return out, nextBeforeID, nil
}

// Each streams matching entries in ascending id order, ignoring BeforeID and Limit.
func (l *Log) Each(ctx context.Context, f Filter, fn func(Entry) error) error {
	w, args := where(f)
	rows, err := l.pool.Query(ctx, `SELECT `+selectCols+fromJoins+w+` ORDER BY a.id`, args...)
	if err != nil {
		return err
	}
	return collect(rows, fn)
}

// Querier is satisfied by *pgxpool.Pool and pgx.Tx.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// After returns up to limit entries with id > afterID, ascending.
func After(ctx context.Context, q Querier, afterID int64, limit int) ([]Entry, error) {
	rows, err := q.Query(ctx, `SELECT `+selectCols+fromJoins+` WHERE a.id > $1 ORDER BY a.id LIMIT $2`, afterID, limit)
	if err != nil {
		return nil, err
	}
	var out []Entry
	err = collect(rows, func(en Entry) error { out = append(out, en); return nil })
	return out, err
}
