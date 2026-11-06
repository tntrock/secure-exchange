// Package account is the admin view of every account: listing, inviting local staff and admins, disabling,
// role changes, TOTP resets, and the staff invitation (activation) flow.
package account

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/mail"
	"github.com/tntrock/secure-exchange/internal/rules"
	"github.com/tntrock/secure-exchange/internal/vendor"
)

const maxName = 100

var (
	ErrNotFound     = errors.New("account: not found")
	ErrEmailTaken   = errors.New("account: email taken")
	ErrState        = errors.New("account: not allowed in the account's current state")
	ErrLastAdmin    = errors.New("account: last usable local admin")
	ErrInviteGone   = auth.ErrInviteGone
	ErrBadCode      = errors.New("account: invalid TOTP code")
	ErrTOTPRequired = errors.New("account: TOTP code required")
	ErrExternal     = errors.New("account: externally managed account")
)

// ValidationError names the offending JSON field and a code (required, invalid, out_of_range, too_short).
type ValidationError struct{ Field, Code string }

func (e *ValidationError) Error() string { return "account: " + e.Field + ": " + e.Code }

func invalid(field, code string) error { return &ValidationError{field, code} }

type Account struct {
	ID                                           uuid.UUID
	Email, DisplayName, Role, AuthSource, Status string // status: invited | active | disabled (vendors: vendor.StatusOf values)
	TOTPEnabled                                  bool
	LastLoginAt, CreatedAt                       *time.Time
}

type CreateInput struct{ Email, DisplayName, Role string } // role: staff | admin

type Service struct {
	pool     *pgxpool.Pool
	users    *auth.Users
	sessions *auth.Sessions
	outbox   *mail.Outbox
	rules    *rules.Service
	baseURL  string
}

func New(pool *pgxpool.Pool, users *auth.Users, sessions *auth.Sessions, outbox *mail.Outbox, rules *rules.Service, baseURL string) *Service {
	return &Service{pool: pool, users: users, sessions: sessions, outbox: outbox, rules: rules, baseURL: baseURL}
}

const accountCols = `id, email, display_name, role, auth_source, disabled, password_hash IS NOT NULL, approval, expires_at,
	totp_enabled, last_login_at, created_at FROM users`

func scanAccount(row pgx.Row) (*Account, error) {
	a := &Account{}
	var approval string
	var disabled, hasPW bool
	var expires, created *time.Time
	err := row.Scan(&a.ID, &a.Email, &a.DisplayName, &a.Role, &a.AuthSource, &disabled, &hasPW, &approval, &expires,
		&a.TOTPEnabled, &a.LastLoginAt, &created)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	a.CreatedAt = created
	switch {
	case a.Role == "vendor":
		exp := time.Now().AddDate(100, 0, 0) // vendors always have one; be safe
		if expires != nil {
			exp = *expires
		}
		a.Status = vendor.StatusOf(approval, disabled, exp, hasPW && a.TOTPEnabled)
	case disabled:
		a.Status = "disabled"
	case !hasPW && a.AuthSource == "local": // external accounts never hold a local password
		a.Status = "invited"
	default:
		a.Status = "active"
	}
	return a, nil
}

func (s *Service) get(ctx context.Context, id uuid.UUID) (*Account, error) {
	return scanAccount(s.pool.QueryRow(ctx, `SELECT `+accountCols+` WHERE id = $1`, id))
}

// List returns every account, newest first.
func (s *Service) List(ctx context.Context) ([]Account, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+accountCols+` ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Account{}
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

func name(u *auth.User) string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.Email
}

func validRole(r string) bool { return r == "staff" || r == "admin" }

// invite stores a fresh invitation (the only one created in tx) and queues its mail. Mail goes to a
// staff/admin activation link or, for vendors, the vendor invitation link.
func (s *Service) invite(ctx context.Context, tx pgx.Tx, id uuid.UUID, email, role, inviter string) error {
	token, expires, err := auth.CreateInvite(ctx, tx, id)
	if err != nil {
		return err
	}
	var subject, body string
	if role == "vendor" {
		subject, body = mail.VendorInvitation(s.baseURL+"/invite/"+token, inviter, expires)
	} else {
		subject, body = mail.StaffInvitation(s.baseURL+"/activate/"+token, inviter, expires)
	}
	return s.outbox.Enqueue(ctx, tx, mail.Message{To: email, Subject: subject, Body: body})
}

// Create adds a local staff or admin account without a password and mails the activation link.
func (s *Service) Create(ctx context.Context, by *auth.User, in CreateInput) (*Account, error) {
	if !validRole(in.Role) {
		return nil, invalid("role", "invalid")
	}
	if strings.TrimSpace(in.Email) == "" {
		return nil, invalid("email", "required")
	}
	email, ok := mail.ValidAddress(in.Email)
	if !ok {
		return nil, invalid("email", "invalid")
	}
	display := strings.TrimSpace(in.DisplayName)
	if utf8.RuneCountInString(display) > maxName {
		return nil, invalid("display_name", "out_of_range")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	id := uuid.New()
	_, err = tx.Exec(ctx, `INSERT INTO users (id, email, display_name, role, created_by) VALUES ($1,$2,$3,$4,$5)`, id, email, display, in.Role, by.ID)
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		return nil, ErrEmailTaken
	}
	if err != nil {
		return nil, err
	}
	if err := s.invite(ctx, tx, id, email, in.Role, name(by)); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.get(ctx, id)
}

// Reinvite mails a fresh activation link to a staff/admin account still in status invited. Older links stop
// working and the pending TOTP secret is dropped, so a secret scanned from an older link is useless.
func (s *Service) Reinvite(ctx context.Context, by *auth.User, id uuid.UUID) error {
	a, err := s.get(ctx, id)
	if err != nil {
		return err
	}
	if a.Role == "vendor" || a.AuthSource != "local" || a.Status != "invited" {
		return ErrState
	}
	raceHook()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE users SET totp_secret_sealed = NULL WHERE id = $1 AND password_hash IS NULL`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 { // activated meanwhile
		return ErrState
	}
	if err := s.invite(ctx, tx, id, a.Email, a.Role, name(by)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// guardLastAdmin locks every usable local admin (ordered, so concurrent changes serialise) and returns
// ErrLastAdmin when id is the only one. Call it inside the tx that then changes the account.
func guardLastAdmin(ctx context.Context, tx pgx.Tx, id uuid.UUID) error {
	rows, err := tx.Query(ctx, `SELECT id FROM users WHERE role = 'admin' AND auth_source = 'local' AND NOT disabled
		AND password_hash IS NOT NULL ORDER BY id FOR UPDATE`)
	if err != nil {
		return err
	}
	admins, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	if len(admins) == 1 && admins[0] == id {
		return ErrLastAdmin
	}
	return nil
}

// SetDisabled turns any account off or on; disabling also ends its sessions and may not remove the last
// usable local admin.
func (s *Service) SetDisabled(ctx context.Context, id uuid.UUID, disabled bool) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if disabled {
		if err := guardLastAdmin(ctx, tx, id); err != nil {
			return err
		}
	}
	tag, err := tx.Exec(ctx, `UPDATE users SET disabled = $2 WHERE id = $1`, id, disabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if disabled {
		if _, err := tx.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, id); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// SetRole switches a local account between staff and admin; demoting the last usable local admin is refused.
func (s *Service) SetRole(ctx context.Context, id uuid.UUID, role string) error {
	if !validRole(role) {
		return invalid("role", "invalid")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if role == "staff" {
		if err := guardLastAdmin(ctx, tx, id); err != nil {
			return err
		}
	}
	var cur, source string
	err = tx.QueryRow(ctx, `SELECT role, auth_source FROM users WHERE id = $1 FOR UPDATE`, id).Scan(&cur, &source)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	switch {
	case cur == "vendor":
		return ErrState
	case source != "local":
		return ErrExternal
	}
	if _, err := tx.Exec(ctx, `UPDATE users SET role = $2 WHERE id = $1`, id, role); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ResetTOTP drops the account's second factor and sessions. A local staff/admin keeps the password; a vendor
// loses password and TOTP and gets a fresh invitation (status invited again), as vendors cannot log in without TOTP.
func (s *Service) ResetTOTP(ctx context.Context, by *auth.User, id uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var email, role, source, approval string
	var enabled bool
	err = tx.QueryRow(ctx, `SELECT email, role, auth_source, approval, totp_enabled FROM users WHERE id = $1 FOR UPDATE`, id).
		Scan(&email, &role, &source, &approval, &enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if source != "local" {
		return ErrExternal
	}
	if !enabled || approval != "approved" {
		return ErrState
	}
	pw := ""
	if role == "vendor" {
		pw = ", password_hash = NULL"
	}
	if _, err := tx.Exec(ctx, `UPDATE users SET totp_enabled = false, totp_secret_sealed = NULL, totp_last_step = 0`+pw+` WHERE id = $1`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, id); err != nil {
		return err
	}
	if role == "vendor" {
		if err := s.invite(ctx, tx, id, email, role, name(by)); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// validInvite returns the staff/admin account behind an unused, unexpired, newest invitation; vendor tokens are refused.
func (s *Service) validInvite(ctx context.Context, token string) (*Account, error) {
	id, err := auth.InviteUser(ctx, s.pool, token)
	if err != nil {
		return nil, err
	}
	a, err := s.get(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrInviteGone
	}
	if err != nil {
		return nil, err
	}
	if a.Role == "vendor" || a.AuthSource != "local" || a.Status != "invited" {
		return nil, ErrInviteGone
	}
	return a, nil
}

// InviteInfo returns the invited address and, when site rules force TOTP, the enrolment URL. A pending secret
// is reused, so reloading the page shows the same QR code and cannot swap the secret under an activation.
func (s *Service) InviteInfo(ctx context.Context, token string) (email string, totpRequired bool, otpauthURL string, err error) {
	a, err := s.validInvite(ctx, token)
	if err != nil {
		return "", false, "", err
	}
	rl, err := s.rules.Get(ctx)
	if err != nil || !rl.ForceTOTP {
		return a.Email, false, "", err
	}
	otpauthURL, err = s.users.PendingTOTP(ctx, a.ID)
	if err == nil && otpauthURL == "" {
		otpauthURL, err = s.users.BeginTOTP(ctx, a.ID)
	}
	if errors.Is(err, auth.ErrTOTPAlreadyEnabled) {
		return "", false, "", ErrInviteGone
	}
	return a.Email, true, otpauthURL, err
}

// Activate sets the password (and turns TOTP on when site rules force it), consuming the invitation.
// With ErrBadCode or ErrTOTPRequired the account id is still returned, for the audit log.
func (s *Service) Activate(ctx context.Context, token, password, code string) (uuid.UUID, error) {
	a, err := s.validInvite(ctx, token)
	if err != nil {
		return uuid.Nil, err
	}
	if c := auth.ValidPassword(password); c != "" {
		return uuid.Nil, invalid("password", c)
	}
	rl, err := s.rules.Get(ctx) // before the tx: never use a pool helper while holding one
	if err != nil {
		return uuid.Nil, err
	}
	force := rl.ForceTOTP
	var sealed []byte // the secret the code is checked against; only that one may be enabled
	if force {
		if code == "" {
			return a.ID, ErrTOTPRequired
		}
		if err := s.pool.QueryRow(ctx, `SELECT totp_secret_sealed FROM users WHERE id = $1`, a.ID).Scan(&sealed); err != nil {
			return uuid.Nil, err
		}
		if !s.users.CheckTOTP(ctx, a.ID, code) {
			return a.ID, ErrBadCode
		}
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return uuid.Nil, err
	}
	raceHook()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE users SET password_hash = $2, totp_enabled = $3 WHERE id = $1 AND password_hash IS NULL AND NOT disabled
		AND (NOT $3 OR totp_secret_sealed = $4)`, a.ID, hash, force, sealed)
	if err != nil {
		return uuid.Nil, err
	}
	if tag.RowsAffected() == 0 {
		return uuid.Nil, ErrInviteGone
	}
	// the UPDATE above holds the row lock that Reinvite also takes, so a newer invitation is now visible here
	if id, err := auth.InviteUser(ctx, tx, token); err != nil || id != a.ID {
		return uuid.Nil, ErrInviteGone
	}
	if err := auth.ConsumeInvite(ctx, tx, token); err != nil { // consumed concurrently
		return uuid.Nil, err
	}
	return a.ID, tx.Commit(ctx)
}

// raceHook lets tests run a concurrent change between a pre-check and its transaction.
var raceHook = func() {}
