package auth

import (
	"context"
	"errors"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tntrock/secure-exchange/internal/sxcrypto"
)

type User struct {
	ID                                   uuid.UUID
	Email, DisplayName, Role, AuthSource string
	PasswordHash                         string
	TOTPEnabled, Disabled                bool
}

type Users struct {
	pool *pgxpool.Pool
	keys *sxcrypto.Keyring
}

func NewUsers(pool *pgxpool.Pool, keys *sxcrypto.Keyring) *Users { return &Users{pool, keys} }

const userCols = `id, email, display_name, role, auth_source, coalesce(password_hash,''), totp_enabled, disabled`

func scanUser(row pgx.Row) (*User, error) {
	u := &User{}
	err := row.Scan(&u.ID, &u.Email, &u.DisplayName, &u.Role, &u.AuthSource, &u.PasswordHash, &u.TOTPEnabled, &u.Disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

func (s *Users) Create(ctx context.Context, email, displayName, role, password string) (*User, error) {
	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	id := uuid.New()
	_, err = s.pool.Exec(ctx, `INSERT INTO users (id, email, display_name, role, password_hash) VALUES ($1,$2,$3,$4,$5)`,
		id, email, displayName, role, hash)
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		return nil, ErrEmailTaken
	}
	if err != nil {
		return nil, err
	}
	return s.ByID(ctx, id)
}

func (s *Users) ByEmail(ctx context.Context, email string) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE lower(email)=lower($1)`, email))
}

func (s *Users) ByID(ctx context.Context, id uuid.UUID) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id=$1`, id))
}

// EnsureInitialAdmin creates an admin only when no users exist and both values
// are set; with no users and no values it logs a warning.
func (s *Users) EnsureInitialAdmin(ctx context.Context, email, password string) error {
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil || n > 0 {
		return err
	}
	if email == "" || password == "" {
		slog.Warn("no users exist and SX_INIT_ADMIN_EMAIL / SX_INIT_ADMIN_PASSWORD are not set: nobody can log in")
		return nil
	}
	_, err := s.Create(ctx, email, "Administrator", "admin", password)
	if errors.Is(err, ErrEmailTaken) { // lost a startup race with another instance
		return nil
	}
	return err
}
