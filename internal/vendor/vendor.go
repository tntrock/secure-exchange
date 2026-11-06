// Package vendor manages vendor accounts: external people with a password and mandatory TOTP,
// created by staff (subject to SX_VENDOR_CREATION), invited by email and expiring on a set date.
package vendor

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
)

const (
	maxName = 100
	maxDays = 1095
)

var (
	ErrNotFound   = errors.New("vendor: not found")
	ErrForbidden  = errors.New("vendor: forbidden")
	ErrEmailTaken = errors.New("vendor: email taken")
	ErrInviteGone = auth.ErrInviteGone
	ErrBadCode    = errors.New("vendor: invalid TOTP code")
	ErrState      = errors.New("vendor: not allowed in the account's current status")
)

// ValidationError names the offending JSON field and a code (required, invalid, out_of_range, too_short).
type ValidationError struct{ Field, Code string }

func (e *ValidationError) Error() string { return "vendor: " + e.Field + ": " + e.Code }

func invalid(field, code string) error { return &ValidationError{field, code} }

type Vendor struct {
	ID                 uuid.UUID
	Email, DisplayName string
	Org                string // "" when none
	Status             string // pending | rejected | invited | active | disabled | expired
	ExpiresAt          time.Time
	CreatedByID        *uuid.UUID
	CreatedByName      string
	CreatedAt          time.Time
}

type CreateInput struct {
	Email, DisplayName, Org string
	ExpiresAt               time.Time
}

type Service struct {
	pool     *pgxpool.Pool
	users    *auth.Users
	sessions *auth.Sessions
	outbox   *mail.Outbox
	baseURL  string
	mode     string // staff | approval | admin
	rules    *rules.Service
}

func NewService(pool *pgxpool.Pool, users *auth.Users, sessions *auth.Sessions, outbox *mail.Outbox, baseURL, mode string, rules *rules.Service) *Service {
	return &Service{pool: pool, users: users, sessions: sessions, outbox: outbox, baseURL: baseURL, mode: mode, rules: rules}
}

const vendorCols = `u.id, u.email, u.display_name, coalesce(o.name,''), u.approval, u.disabled, u.expires_at,
	coalesce(u.password_hash,'') <> '' AND u.totp_enabled, u.created_by, coalesce(nullif(c.display_name,''), c.email, ''), u.created_at
	FROM users u LEFT JOIN vendor_orgs o ON o.id = u.vendor_org_id LEFT JOIN users c ON c.id = u.created_by
	WHERE u.role = 'vendor'`

func scanVendor(row pgx.Row) (*Vendor, error) {
	v := &Vendor{}
	var approval string
	var disabled, enrolled bool
	err := row.Scan(&v.ID, &v.Email, &v.DisplayName, &v.Org, &approval, &disabled, &v.ExpiresAt, &enrolled, &v.CreatedByID, &v.CreatedByName, &v.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	switch {
	case approval != "approved":
		v.Status = approval
	case disabled:
		v.Status = "disabled"
	case !time.Now().Before(v.ExpiresAt):
		v.Status = "expired"
	case !enrolled:
		v.Status = "invited"
	default:
		v.Status = "active"
	}
	return v, nil
}

func (s *Service) get(ctx context.Context, id uuid.UUID) (*Vendor, error) {
	return scanVendor(s.pool.QueryRow(ctx, `SELECT `+vendorCols+` AND u.id = $1`, id))
}

// List returns every vendor, newest first; activeOnly keeps those with status "active".
func (s *Service) List(ctx context.Context, activeOnly bool) ([]Vendor, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+vendorCols+` ORDER BY u.created_at DESC, u.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Vendor{}
	for rows.Next() {
		v, err := scanVendor(rows)
		if err != nil {
			return nil, err
		}
		if !activeOnly || v.Status == "active" {
			out = append(out, *v)
		}
	}
	return out, rows.Err()
}

func checkExpiry(at time.Time) error {
	if at.IsZero() {
		return invalid("expires_at", "required")
	}
	now := time.Now()
	if at.Before(now.AddDate(0, 0, 1)) || at.After(now.AddDate(0, 0, maxDays)) {
		return invalid("expires_at", "out_of_range")
	}
	return nil
}

func name(u *auth.User) string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.Email
}

func (s *Service) Create(ctx context.Context, by *auth.User, in CreateInput) (*Vendor, error) {
	isAdmin := by.Role == "admin"
	if s.mode == "admin" && !isAdmin {
		return nil, ErrForbidden
	}
	if strings.TrimSpace(in.Email) == "" {
		return nil, invalid("email", "required")
	}
	email, ok := mail.ValidAddress(in.Email)
	if !ok {
		return nil, invalid("email", "invalid")
	}
	rl, err := s.rules.Get(ctx)
	if err != nil {
		return nil, err
	}
	if !rl.DomainAllowed(email) {
		return nil, invalid("email", "domain_blocked")
	}
	display, org := strings.TrimSpace(in.DisplayName), strings.TrimSpace(in.Org)
	if display == "" {
		return nil, invalid("display_name", "required")
	}
	if utf8.RuneCountInString(display) > maxName {
		return nil, invalid("display_name", "out_of_range")
	}
	if utf8.RuneCountInString(org) > maxName {
		return nil, invalid("org", "out_of_range")
	}
	if err := checkExpiry(in.ExpiresAt); err != nil {
		return nil, err
	}
	approval := "approved"
	if s.mode == "approval" && !isAdmin {
		approval = "pending"
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var orgID *uuid.UUID
	if org != "" {
		if _, err := tx.Exec(ctx, `INSERT INTO vendor_orgs (id, name) VALUES ($1,$2) ON CONFLICT ((lower(name))) DO NOTHING`, uuid.New(), org); err != nil {
			return nil, err
		}
		orgID = new(uuid.UUID)
		if err := tx.QueryRow(ctx, `SELECT id FROM vendor_orgs WHERE lower(name) = lower($1)`, org).Scan(orgID); err != nil {
			return nil, err
		}
	}
	id := uuid.New()
	_, err = tx.Exec(ctx, `INSERT INTO users (id, email, display_name, role, vendor_org_id, created_by, expires_at, approval)
		VALUES ($1,$2,$3,'vendor',$4,$5,$6,$7)`, id, email, display, orgID, by.ID, in.ExpiresAt, approval)
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		return nil, ErrEmailTaken
	}
	if err != nil {
		return nil, err
	}
	if approval == "approved" {
		err = s.invite(ctx, tx, id, email, name(by))
	} else {
		err = s.askAdmins(ctx, tx, email, name(by))
	}
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.get(ctx, id)
}

// askAdmins mails every active admin that a vendor awaits approval.
func (s *Service) askAdmins(ctx context.Context, tx pgx.Tx, vendorEmail, creator string) error {
	rows, err := tx.Query(ctx, `SELECT email FROM users WHERE role = 'admin' AND NOT disabled AND approval = 'approved'
		AND (expires_at IS NULL OR expires_at > now())`)
	if err != nil {
		return err
	}
	admins, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	subject, body := mail.VendorApprovalNeeded(vendorEmail, creator, s.baseURL+"/vendors")
	for _, a := range admins {
		if err := s.outbox.Enqueue(ctx, tx, mail.Message{To: a, Subject: subject, Body: body}); err != nil {
			return err
		}
	}
	return nil
}

// invite stores a 7-day invitation and mails its link. A newer invitation voids older ones (see validInvite).
func (s *Service) invite(ctx context.Context, tx pgx.Tx, id uuid.UUID, email, inviter string) error {
	token, expires, err := auth.CreateInvite(ctx, tx, id)
	if err != nil {
		return err
	}
	subject, body := mail.VendorInvitation(s.baseURL+"/invite/"+token, inviter, expires)
	return s.outbox.Enqueue(ctx, tx, mail.Message{To: email, Subject: subject, Body: body})
}

// pending loads a pending vendor for an admin decision.
func (s *Service) pending(ctx context.Context, by *auth.User, id uuid.UUID) (*Vendor, error) {
	if by.Role != "admin" {
		return nil, ErrForbidden
	}
	v, err := s.get(ctx, id)
	if err != nil {
		return nil, err
	}
	if v.Status != "pending" {
		return nil, ErrState
	}
	return v, nil
}

func (s *Service) Approve(ctx context.Context, by *auth.User, id uuid.UUID) error {
	v, err := s.pending(ctx, by, id)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE users SET approval = 'approved' WHERE id = $1 AND approval = 'pending'`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 { // decided concurrently
		return ErrState
	}
	if err := s.invite(ctx, tx, id, v.Email, v.CreatedByName); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) Reject(ctx context.Context, by *auth.User, id uuid.UUID) error {
	if _, err := s.pending(ctx, by, id); err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `UPDATE users SET approval = 'rejected' WHERE id = $1 AND approval = 'pending'`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrState
	}
	return err
}

// manageable loads a vendor that by created or by is an admin.
func (s *Service) manageable(ctx context.Context, by *auth.User, id uuid.UUID) (*Vendor, error) {
	v, err := s.get(ctx, id)
	if err != nil {
		return nil, err
	}
	if by.Role != "admin" && (v.CreatedByID == nil || *v.CreatedByID != by.ID) {
		return nil, ErrForbidden
	}
	return v, nil
}

// SetDisabled turns the account off or on; disabling also ends every session of the vendor.
func (s *Service) SetDisabled(ctx context.Context, by *auth.User, id uuid.UUID, disabled bool) error {
	if _, err := s.manageable(ctx, by, id); err != nil {
		return err
	}
	if _, err := s.pool.Exec(ctx, `UPDATE users SET disabled = $2 WHERE id = $1`, id, disabled); err != nil {
		return err
	}
	if disabled {
		return s.sessions.RevokeAllForUser(ctx, id)
	}
	return nil
}

func (s *Service) SetExpiry(ctx context.Context, by *auth.User, id uuid.UUID, at time.Time) error {
	if _, err := s.manageable(ctx, by, id); err != nil {
		return err
	}
	if err := checkExpiry(at); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `UPDATE users SET expires_at = $2 WHERE id = $1`, id, at)
	return err
}

// Reinvite mails a fresh invitation to a vendor still in status invited; older links stop working, and the
// pending TOTP secret is dropped so whoever scanned it from an older link cannot use it after activation.
func (s *Service) Reinvite(ctx context.Context, by *auth.User, id uuid.UUID) error {
	v, err := s.manageable(ctx, by, id)
	if err != nil {
		return err
	}
	if v.Status != "invited" {
		return ErrState
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE users SET totp_secret_sealed = NULL WHERE id = $1 AND NOT totp_enabled`, id); err != nil {
		return err
	}
	if err := s.invite(ctx, tx, id, v.Email, v.CreatedByName); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// validInvite returns the vendor behind an unused, unexpired invitation that is the newest for a vendor in status invited.
func (s *Service) validInvite(ctx context.Context, token string) (*Vendor, error) {
	id, err := auth.InviteUser(ctx, s.pool, token)
	if err != nil {
		return nil, err
	}
	v, err := s.get(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrInviteGone
	}
	if err != nil {
		return nil, err
	}
	if v.Status != "invited" {
		return nil, ErrInviteGone
	}
	return v, nil
}

// InviteInfo starts TOTP enrolment for the invitation. A pending secret is reused, so reloading the page
// shows the same QR code and cannot swap the secret under an activation in flight.
func (s *Service) InviteInfo(ctx context.Context, token string) (email, otpauthURL string, err error) {
	v, err := s.validInvite(ctx, token)
	if err != nil {
		return "", "", err
	}
	otpauthURL, err = s.users.PendingTOTP(ctx, v.ID)
	if err == nil && otpauthURL == "" {
		otpauthURL, err = s.users.BeginTOTP(ctx, v.ID)
	}
	if errors.Is(err, auth.ErrTOTPAlreadyEnabled) {
		return "", "", ErrInviteGone
	}
	return v.Email, otpauthURL, err
}

// Activate sets the password and turns TOTP on, consuming the invitation. A wrong code changes nothing
// but the TOTP replay step; with ErrBadCode the vendor id is still returned, for the audit log.
func (s *Service) Activate(ctx context.Context, token, password, code string) (uuid.UUID, error) {
	v, err := s.validInvite(ctx, token)
	if err != nil {
		return uuid.Nil, err
	}
	if code := auth.ValidPassword(password); code != "" {
		return uuid.Nil, invalid("password", code)
	}
	var sealed []byte // the secret the code is checked against; only that one may be enabled
	if err := s.pool.QueryRow(ctx, `SELECT totp_secret_sealed FROM users WHERE id = $1`, v.ID).Scan(&sealed); err != nil {
		return uuid.Nil, err
	}
	if !s.users.CheckTOTP(ctx, v.ID, code) {
		return v.ID, ErrBadCode
	}
	afterCodeCheck()
	hash, err := auth.HashPassword(password)
	if err != nil {
		return uuid.Nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE users SET password_hash = $2, totp_enabled = true WHERE id = $1 AND NOT totp_enabled AND totp_secret_sealed = $3`, v.ID, hash, sealed)
	if err != nil {
		return uuid.Nil, err
	}
	if tag.RowsAffected() == 0 {
		return uuid.Nil, ErrInviteGone
	}
	if err := auth.ConsumeInvite(ctx, tx, token); err != nil { // consumed concurrently
		return uuid.Nil, err
	}
	return v.ID, tx.Commit(ctx)
}

// afterCodeCheck lets tests run a concurrent request between the code check and the enabling update.
var afterCodeCheck = func() {}
