// Package intake implements upload requests: a staff member asks a list of email addresses to send files.
package intake

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/mail"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
)

const (
	maxUploaders = 50
	maxFilesCap  = 1000
	maxBytesCap  = int64(1) << 50
	maxExts      = 50
	maxMessage   = 2000
)

var (
	ErrNotFound      = errors.New("intake: not found")
	ErrGone          = errors.New("intake: revoked or expired")
	ErrBadCode       = errors.New("intake: invalid verification code")
	ErrUnauthorized  = errors.New("intake: no valid uploader session")
	ErrExtNotAllowed = errors.New("intake: file type not allowed")
	ErrTooManyFiles  = errors.New("intake: file count limit reached")
	ErrQuotaExceeded = errors.New("intake: total size limit exceeded")
)

// ValidationError names the offending JSON field and a machine-readable code
// (required, too_many, invalid, out_of_range).
type ValidationError struct{ Field, Code string }

func (e *ValidationError) Error() string { return "intake: " + e.Field + ": " + e.Code }

type Request struct {
	ID, OwnerID           uuid.UUID
	OwnerName, OwnerEmail string // OwnerName is the display name, or the email when empty
	Message               string
	ExpiresAt             time.Time
	MaxFiles              int
	MaxTotalBytes         int64
	AllowedExts           []string // lower-case, no dot; empty = any
	RevokedAt             *time.Time
	CreatedAt             time.Time
	FileCount             int   // files received (deleted ones included)
	TotalBytes            int64 // their sizes
	UploaderCount         int
	Uploaders             []Uploader // filled by Get only
	URL                   string     // baseURL + "/r/" + token; filled by Get only
}

type Uploader struct {
	ID                          uuid.UUID
	Email                       string
	FirstOpenedAt, LastAccessAt *time.Time
}

type CreateInput struct {
	Emails        []string
	ExpiresAt     time.Time
	MaxFiles      int
	MaxTotalBytes int64
	AllowedExts   []string
	Message       string
}

type Service struct {
	pool    *pgxpool.Pool
	outbox  *mail.Outbox
	keys    *sxcrypto.Keyring
	baseURL string
	maxDays int
	now     func() time.Time
}

func NewService(pool *pgxpool.Pool, outbox *mail.Outbox, keys *sxcrypto.Keyring, baseURL string, maxDays int) *Service {
	return &Service{pool: pool, outbox: outbox, keys: keys, baseURL: baseURL, maxDays: maxDays, now: time.Now}
}

func invalid(field, code string) error { return &ValidationError{field, code} }

// normEmails normalizes and de-duplicates addresses (order kept).
func normEmails(in []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, s := range in {
		a, ok := mail.ValidAddress(s)
		if !ok {
			return nil, invalid("emails", "invalid")
		}
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil, invalid("emails", "required")
	}
	if len(out) > maxUploaders {
		return nil, invalid("emails", "too_many")
	}
	return out, nil
}

var extRE = regexp.MustCompile(`^[a-z0-9]{1,10}$`)

// normExts trims, lower-cases, strips one leading dot, validates and de-duplicates (order kept).
// The result is never nil: the column is NOT NULL.
func normExts(in []string) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	for _, s := range in {
		e := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), ".")
		if !extRE.MatchString(e) {
			return nil, invalid("allowed_exts", "invalid")
		}
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	if len(out) > maxExts {
		return nil, invalid("allowed_exts", "too_many")
	}
	return out, nil
}

func (s *Service) Create(ctx context.Context, owner *auth.User, in CreateInput) (*Request, error) {
	emails, err := normEmails(in.Emails)
	if err != nil {
		return nil, err
	}
	if in.ExpiresAt.IsZero() {
		return nil, invalid("expires_at", "required")
	}
	now := s.now()
	if in.ExpiresAt.Before(now.Add(time.Hour)) || in.ExpiresAt.After(now.AddDate(0, 0, s.maxDays)) {
		return nil, invalid("expires_at", "out_of_range")
	}
	if in.MaxFiles < 1 || in.MaxFiles > maxFilesCap {
		return nil, invalid("max_files", "out_of_range")
	}
	if in.MaxTotalBytes < 1 || in.MaxTotalBytes > maxBytesCap {
		return nil, invalid("max_total_bytes", "out_of_range")
	}
	exts, err := normExts(in.AllowedExts)
	if err != nil {
		return nil, err
	}
	if utf8.RuneCountInString(in.Message) > maxMessage {
		return nil, invalid("message", "too_many")
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, err
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	hash := sha256.Sum256([]byte(token))
	id := uuid.New()
	sealed, err := s.keys.Seal([]byte(token), []byte("requesttoken:"+id.String()))
	if err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO upload_requests (id, owner_id, token_hash, token_sealed, message, expires_at, max_files, max_total_bytes, allowed_exts)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, id, owner.ID, hash[:], sealed, in.Message, in.ExpiresAt, in.MaxFiles, in.MaxTotalBytes, exts); err != nil {
		return nil, err
	}
	name := owner.DisplayName
	if name == "" {
		name = owner.Email
	}
	subject, body := mail.UploadInvitation(s.baseURL+"/r/"+token, name, in.Message, in.ExpiresAt)
	for _, e := range emails {
		if _, err := tx.Exec(ctx, `INSERT INTO request_uploaders (id, request_id, email) VALUES ($1,$2,$3)`, uuid.New(), id, e); err != nil {
			return nil, err
		}
		if err := s.outbox.Enqueue(ctx, tx, mail.Message{To: e, Subject: subject, Body: body}); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.Get(ctx, owner.ID, id)
}

const requestCols = `r.id, r.owner_id, CASE WHEN u.display_name = '' THEN u.email ELSE u.display_name END, u.email,
	r.message, r.expires_at, r.max_files, r.max_total_bytes, r.allowed_exts, r.revoked_at, r.created_at,
	(SELECT count(*) FROM files f WHERE f.request_id = r.id), (SELECT COALESCE(sum(f.size),0) FROM files f WHERE f.request_id = r.id),
	(SELECT count(*) FROM request_uploaders q WHERE q.request_id = r.id)`

func (r *Request) dests() []any {
	return []any{&r.ID, &r.OwnerID, &r.OwnerName, &r.OwnerEmail, &r.Message, &r.ExpiresAt, &r.MaxFiles, &r.MaxTotalBytes,
		&r.AllowedExts, &r.RevokedAt, &r.CreatedAt, &r.FileCount, &r.TotalBytes, &r.UploaderCount}
}

func scanRequest(row pgx.Row) (*Request, error) {
	r := &Request{}
	return r, row.Scan(r.dests()...)
}

// List returns the owner's requests, newest first, without Uploaders/URL.
func (s *Service) List(ctx context.Context, ownerID uuid.UUID) ([]Request, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+requestCols+` FROM upload_requests r JOIN users u ON u.id = r.owner_id
		WHERE r.owner_id = $1 ORDER BY r.created_at DESC`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Request
	for rows.Next() {
		r, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// Get returns one of the owner's requests with its uploaders and link.
func (s *Service) Get(ctx context.Context, ownerID, id uuid.UUID) (*Request, error) {
	var sealed []byte
	r := &Request{}
	err := s.pool.QueryRow(ctx, `SELECT `+requestCols+`, r.token_sealed FROM upload_requests r JOIN users u ON u.id = r.owner_id
		WHERE r.id = $1 AND r.owner_id = $2`, id, ownerID).Scan(append(r.dests(), &sealed)...)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	tok, err := s.keys.Open(sealed, []byte("requesttoken:"+id.String()))
	if err != nil {
		return nil, err
	}
	r.URL = s.baseURL + "/r/" + string(tok)
	rows, err := s.pool.Query(ctx, `SELECT id, email, first_opened_at, last_access_at FROM request_uploaders
		WHERE request_id = $1 ORDER BY created_at, email`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var u Uploader
		if err := rows.Scan(&u.ID, &u.Email, &u.FirstOpenedAt, &u.LastAccessAt); err != nil {
			return nil, err
		}
		r.Uploaders = append(r.Uploaders, u)
	}
	return r, rows.Err()
}

// Revoke is idempotent. Sessions are left alone: Authorize rechecks the request on every call.
func (s *Service) Revoke(ctx context.Context, ownerID, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `UPDATE upload_requests SET revoked_at = coalesce(revoked_at, now()) WHERE id = $1 AND owner_id = $2`, id, ownerID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
