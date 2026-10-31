package intake

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/tntrock/secure-exchange/internal/mail"
)

const (
	otpTTL      = 10 * time.Minute
	otpAttempts = 5
	otpsPerHour = 10
	otpsPerDay  = 20
	sessionTTL  = 24 * time.Hour // uploads of large files take hours
)

// Access is a verified uploader's view of one request.
type Access struct {
	Request  *Request
	Uploader Uploader
}

// Querier is satisfied by pgx.Tx and *pgxpool.Pool.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type ctxKey struct{}

func WithAccess(ctx context.Context, a *Access) context.Context {
	return context.WithValue(ctx, ctxKey{}, a)
}

// AccessFrom returns the Access carried by ctx, or nil.
func AccessFrom(ctx context.Context) *Access {
	a, _ := ctx.Value(ctxKey{}).(*Access)
	return a
}

// check reports whether r may be served now.
func (s *Service) check(r *Request) error {
	if r.RevokedAt != nil || !s.now().Before(r.ExpiresAt) {
		return ErrGone
	}
	return nil
}

func hashString(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func otpHash(id uuid.UUID, code string) []byte {
	h := sha256.Sum256(append(id[:], code...))
	return h[:]
}

// Landing finds the request behind a link token and checks it may be served.
// Only ExpiresAt, Message, OwnerName and the limits are meant for the uploader.
// The address is unused: upload requests have no IP allow list.
func (s *Service) Landing(ctx context.Context, token string, _ netip.Addr) (*Request, error) {
	r, err := scanRequest(s.pool.QueryRow(ctx, `SELECT `+requestCols+` FROM upload_requests r JOIN users u ON u.id = r.owner_id
		WHERE r.token_hash = $1`, hashString(token)))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := s.check(r); err != nil {
		return nil, err
	}
	return r, nil
}

// RequestCode mails a fresh code if email is listed on the request; otherwise it does nothing.
// sent reports which happened, for the audit log only: callers must answer both cases alike.
func (s *Service) RequestCode(ctx context.Context, token, email string, ip netip.Addr) (sent bool, err error) {
	r, err := s.Landing(ctx, token, ip)
	if err != nil {
		return false, err
	}
	email, ok := mail.ValidAddress(email)
	if !ok {
		return false, nil
	}
	var uid uuid.UUID
	err = s.pool.QueryRow(ctx, `SELECT id FROM request_uploaders WHERE request_id = $1 AND lower(email) = $2`, r.ID, email).Scan(&uid)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// backstop against guessing by requesting code after code; the HTTP rate limit is the main guard
	var lastHour, lastDay int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE created_at > now() - interval '1 hour'), count(*)
		FROM request_otps WHERE uploader_id = $1 AND created_at > now() - interval '24 hours'`, uid).Scan(&lastHour, &lastDay); err != nil {
		return false, err
	}
	if lastHour >= otpsPerHour || lastDay >= otpsPerDay {
		return false, nil
	}
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return false, err
	}
	code := fmt.Sprintf("%06d", n.Int64())
	id := uuid.New()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE request_otps SET used_at = now() WHERE uploader_id = $1 AND used_at IS NULL`, uid); err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO request_otps (id, uploader_id, code_hash, expires_at) VALUES ($1,$2,$3,$4)`,
		id, uid, otpHash(id, code), s.now().Add(otpTTL)); err != nil {
		return false, err
	}
	subject, body := mail.OTPCode(code)
	if err := s.outbox.Enqueue(ctx, tx, mail.Message{To: email, Subject: subject, Body: body}); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

// VerifyCode consumes an uploader's code and opens a session lasting 24 hours or until the request ends.
// Unknown addresses and missing, expired, exhausted or wrong codes all return ErrBadCode.
// ua must already be length-capped by the caller (httpapi.UserAgent).
func (s *Service) VerifyCode(ctx context.Context, token, email, code string, ip netip.Addr, ua string) (string, *Access, error) {
	r, err := s.Landing(ctx, token, ip)
	if err != nil {
		return "", nil, err
	}
	email, ok := mail.ValidAddress(email)
	if !ok {
		return "", nil, ErrBadCode
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", nil, err
	}
	defer tx.Rollback(ctx)
	var otpID uuid.UUID
	var hash []byte
	var attempts int
	u := Uploader{}
	err = tx.QueryRow(ctx, `SELECT o.id, o.code_hash, o.attempts, q.id, q.email
		FROM request_otps o JOIN request_uploaders q ON q.id = o.uploader_id
		WHERE q.request_id = $1 AND lower(q.email) = $2 AND o.used_at IS NULL AND o.expires_at > $3
		ORDER BY o.created_at DESC LIMIT 1 FOR UPDATE OF o`, r.ID, email, s.now()).
		Scan(&otpID, &hash, &attempts, &u.ID, &u.Email)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil, ErrBadCode
	}
	if err != nil {
		return "", nil, err
	}
	if attempts >= otpAttempts {
		return "", nil, ErrBadCode
	}
	if subtle.ConstantTimeCompare(hash, otpHash(otpID, code)) != 1 {
		if _, err := tx.Exec(ctx, `UPDATE request_otps SET attempts = attempts + 1 WHERE id = $1`, otpID); err != nil {
			return "", nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return "", nil, err
		}
		return "", nil, ErrBadCode
	}
	if _, err := tx.Exec(ctx, `UPDATE request_otps SET used_at = now() WHERE id = $1`, otpID); err != nil {
		return "", nil, err
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	session := base64.RawURLEncoding.EncodeToString(b)
	expires := s.now().Add(sessionTTL)
	if r.ExpiresAt.Before(expires) {
		expires = r.ExpiresAt
	}
	if _, err := tx.Exec(ctx, `INSERT INTO request_sessions (token_hash, uploader_id, ip, user_agent, expires_at) VALUES ($1,$2,$3,$4,$5)`,
		hashString(session), u.ID, ip.String(), ua, expires); err != nil {
		return "", nil, err
	}
	if err := tx.QueryRow(ctx, `UPDATE request_uploaders SET first_opened_at = coalesce(first_opened_at, now()), last_access_at = now()
		WHERE id = $1 RETURNING first_opened_at, last_access_at`, u.ID).Scan(&u.FirstOpenedAt, &u.LastAccessAt); err != nil {
		return "", nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", nil, err
	}
	return session, &Access{Request: r, Uploader: u}, nil
}

// Authorize resolves an uploader session and rechecks the request on every call.
func (s *Service) Authorize(ctx context.Context, sessionToken string, _ netip.Addr) (*Access, error) {
	var requestID uuid.UUID
	var expires time.Time
	u := Uploader{}
	err := s.pool.QueryRow(ctx, `SELECT q.request_id, ss.expires_at, q.id, q.email, q.first_opened_at, q.last_access_at
		FROM request_sessions ss JOIN request_uploaders q ON q.id = ss.uploader_id WHERE ss.token_hash = $1`, hashString(sessionToken)).
		Scan(&requestID, &expires, &u.ID, &u.Email, &u.FirstOpenedAt, &u.LastAccessAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUnauthorized
	}
	if err != nil {
		return nil, err
	}
	r, err := scanRequest(s.pool.QueryRow(ctx, `SELECT `+requestCols+` FROM upload_requests r JOIN users u ON u.id = r.owner_id WHERE r.id = $1`, requestID))
	if err != nil {
		return nil, err // the session's FK cascade means the request exists
	}
	// the request first: a session never outlives it, so ErrGone would otherwise be unreachable by the clock
	if err := s.check(r); err != nil {
		return nil, err
	}
	if !s.now().Before(expires) {
		return nil, ErrUnauthorized
	}
	if _, err := s.pool.Exec(ctx, `UPDATE request_uploaders SET last_access_at = now()
		WHERE id = $1 AND (last_access_at IS NULL OR last_access_at < now() - interval '1 minute')`, u.ID); err != nil {
		return nil, err
	}
	return &Access{Request: r, Uploader: u}, nil
}

// Logout ends an uploader session; an unknown token is not an error.
func (s *Service) Logout(ctx context.Context, sessionToken string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM request_sessions WHERE token_hash = $1`, hashString(sessionToken))
	return err
}

// Usage counts the files received for a request (deleted ones included) plus uploads in progress, and their bytes.
func Usage(ctx context.Context, q Querier, requestID uuid.UUID) (files int, bytes int64, err error) {
	err = q.QueryRow(ctx, `SELECT count(*), COALESCE(sum(size),0) FROM (
		SELECT size FROM files WHERE request_id = $1
		UNION ALL SELECT size FROM uploads WHERE request_id = $1) t`, requestID).Scan(&files, &bytes)
	return files, bytes, err
}

// CheckUpload locks the request row (SELECT ... FOR UPDATE inside tx) and refuses a new upload of
// size bytes named name. The caller inserts its uploads row in the same tx, so concurrent
// uploads of one request are counted one after another.
func CheckUpload(ctx context.Context, tx pgx.Tx, a *Access, name string, size int64) error {
	r := a.Request
	if len(r.AllowedExts) > 0 && !slices.Contains(r.AllowedExts, strings.TrimPrefix(strings.ToLower(filepath.Ext(name)), ".")) {
		return ErrExtNotAllowed
	}
	if _, err := tx.Exec(ctx, `SELECT 1 FROM upload_requests WHERE id = $1 FOR UPDATE`, r.ID); err != nil {
		return err
	}
	files, bytes, err := Usage(ctx, tx, r.ID)
	if err != nil {
		return err
	}
	if files >= r.MaxFiles {
		return ErrTooManyFiles
	}
	if bytes+size > r.MaxTotalBytes {
		return ErrQuotaExceeded
	}
	return nil
}
