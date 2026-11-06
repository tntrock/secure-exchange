// Package share implements one-time shares: a staff member's files offered to a list of email recipients.
package share

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/mail"
	"github.com/tntrock/secure-exchange/internal/rules"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
)

const (
	maxRecipients = 50
	maxFiles      = 100
	maxIPAllow    = 20
	maxMessage    = 2000
	maxViewsCap   = 10000
)

var (
	ErrNotFound = errors.New("share: not found")
	ErrRevoked  = errors.New("share: revoked")
	ErrExpired  = errors.New("share: expired")
)

// ValidationError names the offending JSON field and a machine-readable code
// (required, too_many, invalid, not_found, out_of_range).
type ValidationError struct{ Field, Code string }

func (e *ValidationError) Error() string { return "share: " + e.Field + ": " + e.Code }

type Share struct {
	ID, OwnerID    uuid.UUID
	OwnerName      string
	OwnerEmail     string
	FileCount      int
	RecipientCount int
	Message        string
	AllowDownload  bool
	Watermark      bool
	ExpiresAt      time.Time
	MaxViews       *int
	ViewCount      int
	IPAllow        []netip.Prefix
	RevokedAt      *time.Time
	CreatedAt      time.Time
	Files          []ShareFile
	Recipients     []Recipient
}

type ShareFile struct {
	ID      uuid.UUID
	Name    string
	Size    int64
	Deleted bool
}

type Recipient struct {
	ID                                     uuid.UUID
	Email                                  string
	RevokedAt, FirstOpenedAt, LastAccessAt *time.Time
	VendorID                               *uuid.UUID // set for a vendor account recipient
}

type CreateInput struct {
	FileIDs       []uuid.UUID
	Emails        []string
	AllowDownload bool
	Watermark     bool
	ExpiresAt     time.Time
	MaxViews      *int
	IPAllow       []string
	Message       string
	VendorIDs     []uuid.UUID
}

type Service struct {
	pool    *pgxpool.Pool
	outbox  *mail.Outbox
	keys    *sxcrypto.Keyring
	users   *auth.Users
	baseURL string
	rules   *rules.Service
	now     func() time.Time
}

func NewService(pool *pgxpool.Pool, outbox *mail.Outbox, keys *sxcrypto.Keyring, baseURL string, rules *rules.Service) *Service {
	return &Service{pool: pool, outbox: outbox, keys: keys, users: auth.NewUsers(pool, keys), baseURL: baseURL, rules: rules, now: time.Now}
}

func invalid(field, code string) error { return &ValidationError{field, code} }

// recipients validates a recipient list: addresses plus vendor accounts, at least one and at most 50 in all.
// Every vendor must be an Active vendor account; an address that is also a listed vendor's is dropped,
// the vendor row covers it.
func (s *Service) recipients(ctx context.Context, emails []string, vendorIDs []uuid.UUID) ([]string, []*auth.User, error) {
	emails, err := normEmails(emails)
	if err != nil {
		return nil, nil, err
	}
	vendorIDs = dedupIDs(vendorIDs)
	if len(vendorIDs) > maxRecipients {
		return nil, nil, invalid("recipients", "too_many")
	}
	vendors := make([]*auth.User, 0, len(vendorIDs))
	covered := map[string]bool{}
	for _, id := range vendorIDs {
		u, err := s.users.ByID(ctx, id)
		if errors.Is(err, auth.ErrNotFound) || err == nil && (u.Role != "vendor" || !u.Active(s.now())) {
			return nil, nil, invalid("vendor_ids", "not_found")
		}
		if err != nil {
			return nil, nil, err
		}
		vendors = append(vendors, u)
		covered[strings.ToLower(u.Email)] = true
	}
	emails = slices.DeleteFunc(emails, func(e string) bool { return covered[e] })
	rl, err := s.rules.Get(ctx)
	if err != nil {
		return nil, nil, err
	}
	if slices.ContainsFunc(emails, func(e string) bool { return !rl.DomainAllowed(e) }) {
		return nil, nil, invalid("emails", "domain_blocked")
	}
	if slices.ContainsFunc(vendors, func(v *auth.User) bool { return !rl.DomainAllowed(v.Email) }) {
		return nil, nil, invalid("vendor_ids", "domain_blocked")
	}
	switch n := len(emails) + len(vendors); {
	case n == 0:
		return nil, nil, invalid("recipients", "required")
	case n > maxRecipients:
		return nil, nil, invalid("recipients", "too_many")
	}
	return emails, vendors, nil
}

// addRecipients inserts recipient rows, skipping any already on the share, and queues each new one its
// invitation: the link for an address, a pointer to the signed-in list for a vendor.
func (s *Service) addRecipients(ctx context.Context, tx pgx.Tx, shareID uuid.UUID, emails []string, vendors []*auth.User,
	link, sender, message string, expires time.Time) ([]Recipient, error) {
	rows := make([]Recipient, 0, len(emails)+len(vendors))
	for _, e := range emails {
		rows = append(rows, Recipient{ID: uuid.New(), Email: e})
	}
	for _, v := range vendors {
		rows = append(rows, Recipient{ID: uuid.New(), Email: v.Email, VendorID: &v.ID})
	}
	subject, body := mail.Invitation(link, sender, message, expires)
	vSubject, vBody := mail.VendorShared(s.baseURL+"/vendor/shares", sender, message, expires)
	var added []Recipient
	for _, r := range rows {
		tag, err := tx.Exec(ctx, `INSERT INTO share_recipients (id, share_id, email, vendor_id) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
			r.ID, shareID, r.Email, r.VendorID)
		if err != nil {
			return nil, err
		}
		if tag.RowsAffected() == 0 && r.VendorID != nil {
			// the vendor's address is already a live email recipient: that row becomes the vendor's,
			// keeping its id and history; its email sessions end, as codes no longer reach it.
			// A revoked row stays revoked, as for a re-added email.
			err := tx.QueryRow(ctx, `UPDATE share_recipients SET vendor_id = $3
				WHERE share_id = $1 AND lower(email) = lower($2) AND vendor_id IS NULL AND revoked_at IS NULL RETURNING id`,
				shareID, r.Email, r.VendorID).Scan(&r.ID)
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if _, err := tx.Exec(ctx, `DELETE FROM share_sessions WHERE recipient_id = $1`, r.ID); err != nil {
				return nil, err
			}
		} else if tag.RowsAffected() == 0 {
			continue
		}
		added = append(added, r)
		m := mail.Message{To: r.Email, Subject: subject, Body: body}
		if r.VendorID != nil {
			m.Subject, m.Body = vSubject, vBody
		}
		if err := s.outbox.Enqueue(ctx, tx, m); err != nil {
			return nil, err
		}
	}
	return added, nil
}

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
	if len(out) > maxRecipients {
		return nil, invalid("emails", "too_many")
	}
	return out, nil
}

func parseIPs(in []string) ([]netip.Prefix, error) {
	out, err := rules.ParsePrefixes(in, maxIPAllow)
	switch {
	case errors.Is(err, rules.ErrTooMany):
		return nil, invalid("ip_allow", "too_many")
	case err != nil:
		return nil, invalid("ip_allow", "invalid")
	}
	return out, nil
}

func (s *Service) Create(ctx context.Context, owner *auth.User, in CreateInput) (*Share, error) {
	emails, vendors, err := s.recipients(ctx, in.Emails, in.VendorIDs)
	if err != nil {
		return nil, err
	}
	fileIDs := dedupIDs(in.FileIDs)
	if len(fileIDs) == 0 {
		return nil, invalid("file_ids", "required")
	}
	if len(fileIDs) > maxFiles {
		return nil, invalid("file_ids", "too_many")
	}
	if in.ExpiresAt.IsZero() {
		return nil, invalid("expires_at", "required")
	}
	now := s.now()
	rl, err := s.rules.Get(ctx)
	if err != nil {
		return nil, err
	}
	if in.AllowDownload && rl.ForbidDownload {
		return nil, invalid("allow_download", "locked")
	}
	if !in.Watermark && rl.ForceWatermark {
		return nil, invalid("watermark", "locked")
	}
	if in.ExpiresAt.Before(now.Add(time.Hour)) || in.ExpiresAt.After(now.AddDate(0, 0, rl.ShareMaxDays)) {
		return nil, invalid("expires_at", "out_of_range")
	}
	if in.MaxViews != nil && (*in.MaxViews < 1 || *in.MaxViews > maxViewsCap) {
		return nil, invalid("max_views", "out_of_range")
	}
	ips, err := parseIPs(in.IPAllow)
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

	sealed, err := s.keys.Seal([]byte(token), []byte("sharetoken:"+id.String()))
	if err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM (SELECT id FROM files WHERE id = ANY($1) AND owner_id = $2 AND deleted_at IS NULL FOR SHARE) f`, fileIDs, owner.ID).Scan(&n); err != nil {
		return nil, err
	}
	if n != len(fileIDs) {
		return nil, invalid("file_ids", "not_found")
	}
	if rl.MaxShareBytes > 0 {
		var total int64
		if err := tx.QueryRow(ctx, `SELECT coalesce(sum(size),0)::bigint FROM files WHERE id = ANY($1)`, fileIDs).Scan(&total); err != nil {
			return nil, err
		}
		if total > rl.MaxShareBytes {
			return nil, invalid("file_ids", "too_large")
		}
	}
	var unscanned int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM files WHERE id = ANY($1) AND scan_status NOT IN ('none','clean','skipped')`, fileIDs).Scan(&unscanned); err != nil {
		return nil, err
	}
	if unscanned > 0 {
		return nil, invalid("file_ids", "not_scanned")
	}
	if !in.AllowDownload {
		// missing preview row counts as pending
		var pending, bad int
		if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE p.status IS NULL OR p.status = 'pending'),
				count(*) FILTER (WHERE p.status IN ('failed','unsupported','too_large'))
			FROM unnest($1::uuid[]) u(id) LEFT JOIN file_previews p ON p.file_id = u.id`, fileIDs).Scan(&pending, &bad); err != nil {
			return nil, err
		}
		if bad > 0 {
			return nil, invalid("file_ids", "not_previewable")
		}
		if pending > 0 {
			return nil, invalid("file_ids", "preview_pending")
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO shares (id, owner_id, token_hash, token_sealed, message, allow_download, watermark, expires_at, max_views, ip_allow)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, id, owner.ID, hash[:], sealed, in.Message, in.AllowDownload, in.Watermark, in.ExpiresAt, in.MaxViews, ips); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO share_files (share_id, file_id) SELECT $1, unnest($2::uuid[])`, id, fileIDs); err != nil {
		return nil, err
	}
	if _, err := s.addRecipients(ctx, tx, id, emails, vendors, s.baseURL+"/s/"+token, senderName(owner), in.Message, in.ExpiresAt); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.Get(ctx, owner.ID, id)
}

func senderName(u *auth.User) string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.Email
}

func dedupIDs(in []uuid.UUID) []uuid.UUID {
	seen := map[uuid.UUID]bool{}
	var out []uuid.UUID
	for _, id := range in {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

const shareCols = `s.id, s.owner_id, CASE WHEN u.display_name = '' THEN u.email ELSE u.display_name END, u.email,
	(SELECT count(*) FROM share_files f WHERE f.share_id = s.id), (SELECT count(*) FROM share_recipients r WHERE r.share_id = s.id),
	s.message, s.allow_download, s.watermark, s.expires_at, s.max_views, s.view_count, s.ip_allow, s.revoked_at, s.created_at`

func scanShare(row pgx.Row) (*Share, error) {
	sh := &Share{}
	err := row.Scan(&sh.ID, &sh.OwnerID, &sh.OwnerName, &sh.OwnerEmail, &sh.FileCount, &sh.RecipientCount, &sh.Message,
		&sh.AllowDownload, &sh.Watermark, &sh.ExpiresAt, &sh.MaxViews, &sh.ViewCount, &sh.IPAllow, &sh.RevokedAt, &sh.CreatedAt)
	return sh, err
}

// List returns the owner's shares, newest first, without Files/Recipients.
func (s *Service) List(ctx context.Context, ownerID uuid.UUID) ([]Share, error) {
	return s.list(ctx, `WHERE s.owner_id = $1 ORDER BY s.created_at DESC`, ownerID)
}

// VendorShares lists live shares (not revoked/expired) where vendorID is a non-revoked recipient, newest first.
func (s *Service) VendorShares(ctx context.Context, vendorID uuid.UUID) ([]Share, error) {
	return s.list(ctx, `JOIN share_recipients r ON r.share_id = s.id
		WHERE r.vendor_id = $1 AND r.revoked_at IS NULL AND s.revoked_at IS NULL AND s.expires_at > $2
		ORDER BY s.created_at DESC`, vendorID, s.now())
}

func (s *Service) list(ctx context.Context, where string, args ...any) ([]Share, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+shareCols+` FROM shares s JOIN users u ON u.id = s.owner_id `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Share
	for rows.Next() {
		sh, err := scanShare(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *sh)
	}
	return out, rows.Err()
}

func (s *Service) Get(ctx context.Context, ownerID, id uuid.UUID) (*Share, error) {
	sh, err := scanShare(s.pool.QueryRow(ctx, `SELECT `+shareCols+` FROM shares s JOIN users u ON u.id = s.owner_id
		WHERE s.id = $1 AND s.owner_id = $2`, id, ownerID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := s.loadFiles(ctx, sh); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT id, email, revoked_at, first_opened_at, last_access_at, vendor_id FROM share_recipients
		WHERE share_id = $1 ORDER BY created_at, email`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r Recipient
		if err := rows.Scan(&r.ID, &r.Email, &r.RevokedAt, &r.FirstOpenedAt, &r.LastAccessAt, &r.VendorID); err != nil {
			return nil, err
		}
		sh.Recipients = append(sh.Recipients, r)
	}
	return sh, rows.Err()
}

// loadFiles fills sh.Files, flagging files deleted since the share was made.
func (s *Service) loadFiles(ctx context.Context, sh *Share) error {
	rows, err := s.pool.Query(ctx, `SELECT f.id, f.name, f.size, f.deleted_at IS NOT NULL FROM share_files sf JOIN files f ON f.id = sf.file_id
		WHERE sf.share_id = $1 ORDER BY f.name, f.id`, sh.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var f ShareFile
		if err := rows.Scan(&f.ID, &f.Name, &f.Size, &f.Deleted); err != nil {
			return err
		}
		sh.Files = append(sh.Files, f)
	}
	return rows.Err()
}

// Revoke is idempotent; it also drops every recipient session of the share.
func (s *Service) Revoke(ctx context.Context, ownerID, id uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE shares SET revoked_at = coalesce(revoked_at, now()) WHERE id = $1 AND owner_id = $2`, id, ownerID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx, `DELETE FROM share_sessions WHERE recipient_id IN (SELECT id FROM share_recipients WHERE share_id = $1)`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) RevokeRecipient(ctx context.Context, ownerID, shareID, recipientID uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE share_recipients r SET revoked_at = coalesce(r.revoked_at, now())
		FROM shares s WHERE r.id = $1 AND r.share_id = $2 AND s.id = r.share_id AND s.owner_id = $3`, recipientID, shareID, ownerID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx, `DELETE FROM share_sessions WHERE recipient_id = $1`, recipientID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// AddRecipients adds addresses and vendor accounts not already on the share and returns the new ones.
// Each new recipient is sent the same invitation as the original ones.
func (s *Service) AddRecipients(ctx context.Context, owner *auth.User, shareID uuid.UUID, emails []string, vendorIDs []uuid.UUID) ([]Recipient, error) {
	emails, vendors, err := s.recipients(ctx, emails, vendorIDs)
	if err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var revoked *time.Time
	var sealed []byte
	var expires time.Time
	var message string
	// FOR UPDATE serializes concurrent adds so the 50 cap holds
	err = tx.QueryRow(ctx, `SELECT revoked_at, token_sealed, expires_at, message FROM shares WHERE id = $1 AND owner_id = $2 FOR UPDATE`,
		shareID, owner.ID).Scan(&revoked, &sealed, &expires, &message)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if revoked != nil {
		return nil, ErrRevoked
	}
	if !s.now().Before(expires) {
		return nil, ErrExpired
	}
	tok, err := s.keys.Open(sealed, []byte("sharetoken:"+shareID.String()))
	if err != nil {
		return nil, err
	}
	added, err := s.addRecipients(ctx, tx, shareID, emails, vendors, s.baseURL+"/s/"+string(tok), senderName(owner), message, expires)
	if err != nil {
		return nil, err
	}
	var total int // counted after adding: a converted row is not a new one
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM share_recipients WHERE share_id = $1`, shareID).Scan(&total); err != nil {
		return nil, err
	}
	if total > maxRecipients {
		return nil, invalid("recipients", "too_many")
	}
	return added, tx.Commit(ctx)
}
