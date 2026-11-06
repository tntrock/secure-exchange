package share

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
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/tntrock/secure-exchange/internal/mail"
	"github.com/tntrock/secure-exchange/internal/rules"
)

const (
	otpTTL      = 10 * time.Minute
	otpAttempts = 5
	otpsPerHour = 10
	otpsPerDay  = 20
	sessionTTL  = time.Hour
)

var (
	ErrGone          = errors.New("share: revoked or expired")
	ErrIPDenied      = errors.New("share: source address not allowed")
	ErrBadCode       = errors.New("share: invalid verification code")
	ErrViewLimit     = errors.New("share: view limit reached")
	ErrUnauthorized  = errors.New("share: no valid recipient session")
	ErrDomainBlocked = errors.New("share: recipient domain not allowed")
)

// Access is a verified recipient's view of one share.
type Access struct {
	Share       *Share
	Recipient   Recipient
	SessionHash []byte // sha256 of the share session token; for a vendor, vendorViewKey of the login session
}

func ipAllowed(list []netip.Prefix, ip netip.Addr) bool {
	if len(list) == 0 {
		return true
	}
	ip = ip.Unmap()
	for _, p := range list {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// enforce applies the current admin rules to a loaded share: a download ban and forced watermark override
// the share's own settings, and a non-empty email must be on an allowed domain.
func (s *Service) enforce(ctx context.Context, sh *Share, email string) error {
	r, err := s.rules.Get(ctx)
	if err != nil {
		return err
	}
	return applyRules(r, sh, email)
}

// enforceTx is enforce for callers holding a tx: reading through it avoids taking a second pool connection,
// which under concurrency can starve the pool while every tx waits for one.
func (s *Service) enforceTx(ctx context.Context, tx pgx.Tx, sh *Share, email string) error {
	r, err := s.rules.GetTx(ctx, tx)
	if err != nil {
		return err
	}
	return applyRules(r, sh, email)
}

func applyRules(r rules.Rules, sh *Share, email string) error {
	sh.AllowDownload = sh.AllowDownload && !r.ForbidDownload
	sh.Watermark = sh.Watermark || r.ForceWatermark
	if email != "" && !r.DomainAllowed(email) {
		return ErrDomainBlocked
	}
	return nil
}

// check reports whether sh may be served now to ip. The allow list itself is never revealed.
func (s *Service) check(sh *Share, ip netip.Addr) error {
	if sh.RevokedAt != nil || !s.now().Before(sh.ExpiresAt) {
		return ErrGone
	}
	if !ipAllowed(sh.IPAllow, ip) {
		return ErrIPDenied
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

func (s *Service) shareURL(sh *Share) string { return s.baseURL + "/shares/" + sh.ID.String() }

// Landing finds the share behind a link token and checks it may be served to ip.
// Only ExpiresAt, Message and OwnerName are meant for the recipient.
func (s *Service) Landing(ctx context.Context, token string, ip netip.Addr) (*Share, error) {
	sh, err := scanShare(s.pool.QueryRow(ctx, `SELECT `+shareCols+` FROM shares s JOIN users u ON u.id = s.owner_id
		WHERE s.token_hash = $1`, hashString(token)))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := s.check(sh, ip); err != nil {
		return nil, err
	}
	if err := s.enforce(ctx, sh, ""); err != nil {
		return nil, err
	}
	return sh, nil
}

// RequestCode mails a fresh code if email is an active recipient; otherwise it does nothing.
// sent reports which happened, for the audit log only: callers must answer both cases alike.
func (s *Service) RequestCode(ctx context.Context, token, email string, ip netip.Addr) (sent bool, err error) {
	sh, err := s.Landing(ctx, token, ip)
	if err != nil {
		return false, err
	}
	email, ok := mail.ValidAddress(email)
	if !ok {
		return false, nil
	}
	// the domain rule is deliberately not applied here: the recipient gets a code and learns the reason at VerifyCode
	var rid uuid.UUID
	err = s.pool.QueryRow(ctx, `SELECT id FROM share_recipients WHERE share_id = $1 AND lower(email) = $2 AND revoked_at IS NULL AND vendor_id IS NULL`,
		sh.ID, email).Scan(&rid)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// backstop against guessing by requesting code after code; the HTTP rate limit is the main guard
	var lastHour, lastDay int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE created_at > now() - interval '1 hour'), count(*)
		FROM share_otps WHERE recipient_id = $1 AND created_at > now() - interval '24 hours'`, rid).Scan(&lastHour, &lastDay); err != nil {
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
	if _, err := tx.Exec(ctx, `UPDATE share_otps SET used_at = now() WHERE recipient_id = $1 AND used_at IS NULL`, rid); err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO share_otps (id, recipient_id, code_hash, expires_at) VALUES ($1,$2,$3,$4)`,
		id, rid, otpHash(id, code), s.now().Add(otpTTL)); err != nil {
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

// VerifyCode consumes a recipient's code, counts a view and opens a one-hour session.
// Unknown addresses and missing, expired, exhausted or wrong codes all return ErrBadCode.
// ua must already be length-capped by the caller (httpapi.UserAgent).
func (s *Service) VerifyCode(ctx context.Context, token, email, code string, ip netip.Addr, ua string) (string, *Access, error) {
	sh, err := s.Landing(ctx, token, ip)
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
	r := Recipient{}
	err = tx.QueryRow(ctx, `SELECT o.id, o.code_hash, o.attempts, r.id, r.email, r.first_opened_at
		FROM share_otps o JOIN share_recipients r ON r.id = o.recipient_id
		WHERE r.share_id = $1 AND lower(r.email) = $2 AND r.revoked_at IS NULL AND r.vendor_id IS NULL AND o.used_at IS NULL AND o.expires_at > $3
		ORDER BY o.created_at DESC LIMIT 1 FOR UPDATE OF o`, sh.ID, email, s.now()).
		Scan(&otpID, &hash, &attempts, &r.ID, &r.Email, &r.FirstOpenedAt)
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
		if _, err := tx.Exec(ctx, `UPDATE share_otps SET attempts = attempts + 1 WHERE id = $1`, otpID); err != nil {
			return "", nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return "", nil, err
		}
		return "", nil, ErrBadCode
	}
	// only after a valid code, so the domain policy is not disclosed to someone without one
	if err := s.enforceTx(ctx, tx, sh, email); err != nil {
		return "", nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE share_otps SET used_at = now() WHERE id = $1`, otpID); err != nil {
		return "", nil, err
	}
	if err := s.countView(ctx, tx, sh); err != nil {
		return "", nil, err
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	session := base64.RawURLEncoding.EncodeToString(b)
	if _, err := tx.Exec(ctx, `INSERT INTO share_sessions (token_hash, recipient_id, ip, user_agent, expires_at) VALUES ($1,$2,$3,$4,$5)`,
		hashString(session), r.ID, ip.String(), ua, s.now().Add(sessionTTL)); err != nil {
		return "", nil, err
	}
	if err := s.opened(ctx, tx, sh, &r); err != nil {
		return "", nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", nil, err
	}
	if err := s.loadFiles(ctx, sh); err != nil {
		return "", nil, err
	}
	return session, &Access{Share: sh, Recipient: r, SessionHash: hashString(session)}, nil
}

// countView spends one of sh's views in tx: ErrViewLimit when none are left, ErrGone if the share
// was revoked or expired meanwhile.
func (s *Service) countView(ctx context.Context, tx pgx.Tx, sh *Share) error {
	err := tx.QueryRow(ctx, `UPDATE shares SET view_count = view_count + 1 WHERE id = $1 AND (max_views IS NULL OR view_count < max_views)
		AND revoked_at IS NULL AND expires_at > $2 RETURNING view_count`, sh.ID, s.now()).Scan(&sh.ViewCount)
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	var gone bool
	if err := tx.QueryRow(ctx, `SELECT revoked_at IS NOT NULL OR expires_at <= $2 FROM shares WHERE id = $1`, sh.ID, s.now()).Scan(&gone); err != nil {
		return err
	}
	if gone {
		return ErrGone
	}
	return ErrViewLimit
}

// opened stamps r's last access in tx, and its first open, which the owner is told about once.
func (s *Service) opened(ctx context.Context, tx pgx.Tx, sh *Share, r *Recipient) error {
	tag, err := tx.Exec(ctx, `UPDATE share_recipients SET first_opened_at = now() WHERE id = $1 AND first_opened_at IS NULL`, r.ID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		subject, body := mail.NotifyFirstOpen(r.Email, s.shareURL(sh))
		if err := s.outbox.Enqueue(ctx, tx, mail.Message{To: sh.OwnerEmail, Subject: subject, Body: body}); err != nil {
			return err
		}
	}
	return tx.QueryRow(ctx, `UPDATE share_recipients SET last_access_at = now() WHERE id = $1 RETURNING first_opened_at, last_access_at`, r.ID).
		Scan(&r.FirstOpenedAt, &r.LastAccessAt)
}

// vendorViewKey derives a per-share key from a vendor's login session: one login spans many shares, but
// view_traces dedupe on (session_hash, file_id), so a file seen through two shares needs two keys.
func vendorViewKey(sessionHash []byte, shareID uuid.UUID) []byte {
	h := sha256.Sum256(append(append([]byte{}, sessionHash...), shareID[:]...))
	return h[:]
}

// VendorAccess is Authorize for a signed-in vendor, on every request: the vendor must be a non-revoked
// recipient of the share (else ErrNotFound, so other shares' existence is not revealed), then the share
// checks apply. The first call per (sessionHash, share) counts a view under max_views and stamps the open.
func (s *Service) VendorAccess(ctx context.Context, vendorID, shareID uuid.UUID, sessionHash []byte, ip netip.Addr) (*Access, error) {
	sessionHash = vendorViewKey(sessionHash, shareID)
	r := Recipient{VendorID: &vendorID}
	err := s.pool.QueryRow(ctx, `SELECT id, email, first_opened_at, last_access_at FROM share_recipients
		WHERE share_id = $1 AND vendor_id = $2 AND revoked_at IS NULL`, shareID, vendorID).Scan(&r.ID, &r.Email, &r.FirstOpenedAt, &r.LastAccessAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	sh, err := scanShare(s.pool.QueryRow(ctx, `SELECT `+shareCols+` FROM shares s JOIN users u ON u.id = s.owner_id WHERE s.id = $1`, shareID))
	if err != nil {
		return nil, err // the recipient row's FK means the share exists
	}
	if err := s.check(sh, ip); err != nil {
		return nil, err
	}
	if err := s.enforce(ctx, sh, r.Email); err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	// a concurrent first call by the same session waits on this row's key, then sees it taken
	tag, err := tx.Exec(ctx, `INSERT INTO vendor_share_views (session_hash, share_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, sessionHash, shareID)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 1 {
		if err := s.countView(ctx, tx, sh); err != nil {
			return nil, err
		}
		err = s.opened(ctx, tx, sh, &r)
	} else {
		_, err = tx.Exec(ctx, `UPDATE share_recipients SET last_access_at = now()
			WHERE id = $1 AND (last_access_at IS NULL OR last_access_at < now() - interval '1 minute')`, r.ID)
	}
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	if err := s.loadFiles(ctx, sh); err != nil {
		return nil, err
	}
	return &Access{Share: sh, Recipient: r, SessionHash: sessionHash}, nil
}

// Authorize resolves a recipient session and rechecks the recipient and share on every call.
func (s *Service) Authorize(ctx context.Context, sessionToken string, ip netip.Addr) (*Access, error) {
	var shareID uuid.UUID
	var expires time.Time
	r := Recipient{}
	err := s.pool.QueryRow(ctx, `SELECT r.share_id, ss.expires_at, r.id, r.email, r.revoked_at, r.first_opened_at, r.last_access_at
		FROM share_sessions ss JOIN share_recipients r ON r.id = ss.recipient_id WHERE ss.token_hash = $1`, hashString(sessionToken)).
		Scan(&shareID, &expires, &r.ID, &r.Email, &r.RevokedAt, &r.FirstOpenedAt, &r.LastAccessAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUnauthorized
	}
	if err != nil {
		return nil, err
	}
	if !s.now().Before(expires) || r.RevokedAt != nil {
		return nil, ErrUnauthorized
	}
	sh, err := scanShare(s.pool.QueryRow(ctx, `SELECT `+shareCols+` FROM shares s JOIN users u ON u.id = s.owner_id WHERE s.id = $1`, shareID))
	if err != nil {
		return nil, err // the session's FK cascade means the share exists
	}
	if err := s.check(sh, ip); err != nil {
		return nil, err
	}
	if err := s.enforce(ctx, sh, r.Email); err != nil {
		return nil, err
	}
	if err := s.loadFiles(ctx, sh); err != nil {
		return nil, err
	}
	if _, err := s.pool.Exec(ctx, `UPDATE share_recipients SET last_access_at = now()
		WHERE id = $1 AND (last_access_at IS NULL OR last_access_at < now() - interval '1 minute')`, r.ID); err != nil {
		return nil, err
	}
	return &Access{Share: sh, Recipient: r, SessionHash: hashString(sessionToken)}, nil
}

// RecordDownload notes a recipient's first download of a file and tells the owner once per file.
func (s *Service) RecordDownload(ctx context.Context, a *Access, fileID uuid.UUID) error {
	var file *ShareFile
	for i := range a.Share.Files {
		if a.Share.Files[i].ID == fileID {
			file = &a.Share.Files[i]
		}
	}
	if file == nil {
		return ErrNotFound
	}
	if file.Deleted {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `INSERT INTO share_downloads (recipient_id, file_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, a.Recipient.ID, fileID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		subject, body := mail.NotifyDownload(a.Recipient.Email, file.Name, s.shareURL(a.Share))
		if err := s.outbox.Enqueue(ctx, tx, mail.Message{To: a.Share.OwnerEmail, Subject: subject, Body: body}); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// Logout ends a recipient session; an unknown token is not an error.
func (s *Service) Logout(ctx context.Context, sessionToken string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM share_sessions WHERE token_hash = $1`, hashString(sessionToken))
	return err
}
