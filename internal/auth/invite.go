package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	maxPassword = 256 // bytes
	inviteTTL   = "7 days"
)

// ErrInviteGone: the invitation is unknown, used, expired or replaced by a newer one.
var ErrInviteGone = errors.New("auth: invitation used, expired or replaced")

// Querier is satisfied by pgx.Tx and *pgxpool.Pool.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func hashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// CreateInvite stores a 7-day invitation for the user; a newer invitation voids older ones (see InviteUser).
func CreateInvite(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (string, time.Time, error) {
	b := make([]byte, 32)
	rand.Read(b) // never fails (Go ≥ 1.24)
	token := base64.RawURLEncoding.EncodeToString(b)
	var expires time.Time
	err := tx.QueryRow(ctx, `INSERT INTO account_invites (token_hash, user_id, expires_at) VALUES ($1,$2, now() + interval '`+inviteTTL+`')
		RETURNING expires_at`, hashToken(token), userID).Scan(&expires)
	return token, expires, err
}

// InviteUser returns the user behind an unused, unexpired invitation that is the newest for that user.
func InviteUser(ctx context.Context, q Querier, token string) (uuid.UUID, error) {
	var id uuid.UUID
	err := q.QueryRow(ctx, `SELECT i.user_id FROM account_invites i WHERE i.token_hash = $1 AND i.used_at IS NULL AND i.expires_at > now()
		AND NOT EXISTS (SELECT 1 FROM account_invites n WHERE n.user_id = i.user_id AND n.created_at > i.created_at)`, hashToken(token)).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrInviteGone
	}
	return id, err
}

// ConsumeInvite marks the invitation used; ErrInviteGone when it already was (or never existed).
func ConsumeInvite(ctx context.Context, tx pgx.Tx, token string) error {
	tag, err := tx.Exec(ctx, `UPDATE account_invites SET used_at = now() WHERE token_hash = $1 AND used_at IS NULL`, hashToken(token))
	if err == nil && tag.RowsAffected() == 0 {
		return ErrInviteGone
	}
	return err
}

// ValidPassword returns "" when pw is acceptable, else "too_short" (< 12 runes) or "invalid" (> 256 bytes).
func ValidPassword(pw string) string {
	switch {
	case utf8.RuneCountInString(pw) < minPwLen:
		return "too_short"
	case len(pw) > maxPassword:
		return "invalid"
	}
	return ""
}
