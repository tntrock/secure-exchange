package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Session struct {
	UserID    uuid.UUID
	MFAPassed bool
	ExpiresAt time.Time
}

// Sessions stores server-side sessions keyed by SHA-256 of the bearer token.
type Sessions struct{ pool *pgxpool.Pool }

func NewSessions(pool *pgxpool.Pool) *Sessions { return &Sessions{pool} }

func tokenHash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// Create returns a new 256-bit base64url token; only its hash is stored.
// ponytail: expired rows are never purged; add a periodic DELETE when the table grows.
func (s *Sessions) Create(ctx context.Context, userID uuid.UUID, mfaPassed bool, ip, ua string, ttl time.Duration) (string, error) {
	b := make([]byte, 32)
	rand.Read(b) // never fails (Go ≥ 1.24)
	token := base64.RawURLEncoding.EncodeToString(b)
	_, err := s.pool.Exec(ctx, `INSERT INTO sessions (token_hash, user_id, mfa_passed, ip, user_agent, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6)`, tokenHash(token), userID, mfaPassed, ip, ua, time.Now().Add(ttl))
	if err != nil {
		return "", err
	}
	return token, nil
}

// Lookup returns the unexpired session for token, or ErrNotFound.
func (s *Sessions) Lookup(ctx context.Context, token string) (*Session, error) {
	se := &Session{}
	err := s.pool.QueryRow(ctx, `SELECT user_id, mfa_passed, expires_at FROM sessions WHERE token_hash=$1 AND expires_at > now()`,
		tokenHash(token)).Scan(&se.UserID, &se.MFAPassed, &se.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return se, err
}

func (s *Sessions) MarkMFA(ctx context.Context, token string) error {
	_, err := s.pool.Exec(ctx, `UPDATE sessions SET mfa_passed=true WHERE token_hash=$1`, tokenHash(token))
	return err
}

func (s *Sessions) Revoke(ctx context.Context, token string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash=$1`, tokenHash(token))
	return err
}

func (s *Sessions) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE user_id=$1`, userID)
	return err
}
