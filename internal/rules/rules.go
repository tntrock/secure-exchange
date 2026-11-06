// Package rules holds the admin-enforced site rules (a single site_rules row) and their matchers.
package rules

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"path"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	maxDomains = 200
	maxExts    = 200
	maxIPs     = 100
)

type Rules struct {
	ForceWatermark   bool           `json:"force_watermark"`
	ForbidDownload   bool           `json:"forbid_download"`
	ShareMaxDays     int            `json:"share_max_days"`     // 1..365
	ShareDefaultDays int            `json:"share_default_days"` // 1..ShareMaxDays
	MaxFileBytes     int64          `json:"max_file_bytes"`     // 0 = only the SX_MAX_FILE_SIZE cap
	MaxShareBytes    int64          `json:"max_share_bytes"`    // 0 = unlimited
	DomainBlock      []string       `json:"domain_block"`
	DomainAllow      []string       `json:"domain_allow"`
	ExternalIPAllow  []netip.Prefix `json:"external_ip_allow"`
	UploadExts       []string       `json:"upload_exts"`      // lowercase, no dot; empty = any
	UploadMaxBytes   int64          `json:"upload_max_bytes"` // 0 = unlimited
	QuotaBytes       int64          `json:"quota_bytes"`      // 0 = unlimited
	RetentionDays    int            `json:"retention_days"`   // 0 = never
}

// ValidationError names the offending JSON field and a machine-readable code (invalid, too_many, out_of_range).
type ValidationError struct{ Field, Code string }

func (e *ValidationError) Error() string { return "rules: " + e.Field + " " + e.Code }

// Sentinels returned by ParsePrefixes; callers map them to their own field names.
var (
	ErrTooMany = errors.New("rules: too many")
	ErrInvalid = errors.New("rules: invalid")
)

type Service struct {
	pool        *pgxpool.Pool
	hardMaxFile int64
}

func New(pool *pgxpool.Pool, hardMaxFile int64) *Service {
	return &Service{pool: pool, hardMaxFile: hardMaxFile}
}

func (s *Service) HardMaxFile() int64 { return s.hardMaxFile }

const cols = `force_watermark, forbid_download, share_max_days, share_default_days, max_file_bytes, max_share_bytes,
	domain_block, domain_allow, external_ip_allow, upload_exts, upload_max_bytes, quota_bytes, retention_days`

type queryRower interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func scan(ctx context.Context, q queryRower, suffix string) (Rules, error) {
	var r Rules
	err := q.QueryRow(ctx, `SELECT `+cols+` FROM site_rules WHERE id=1`+suffix).Scan(
		&r.ForceWatermark, &r.ForbidDownload, &r.ShareMaxDays, &r.ShareDefaultDays, &r.MaxFileBytes, &r.MaxShareBytes,
		&r.DomainBlock, &r.DomainAllow, &r.ExternalIPAllow, &r.UploadExts, &r.UploadMaxBytes, &r.QuotaBytes, &r.RetentionDays)
	return r, err
}

// Seed inserts the initial row (default share_max_days from config) unless one exists.
func (s *Service) Seed(ctx context.Context, shareMaxDays int) error {
	if shareMaxDays < 1 || shareMaxDays > 365 {
		return fmt.Errorf("rules: seed share_max_days %d out of range 1..365", shareMaxDays)
	}
	if _, err := s.pool.Exec(ctx, `INSERT INTO site_rules (id, share_max_days, share_default_days) VALUES (1, $1, $2)
		ON CONFLICT (id) DO NOTHING`, shareMaxDays, min(7, shareMaxDays)); err != nil {
		return err
	}
	r, err := s.Get(ctx)
	if err != nil {
		return err
	}
	if r.ShareMaxDays != shareMaxDays {
		slog.Warn("stored share_max_days differs from configured value; keeping stored", "stored", r.ShareMaxDays, "configured", shareMaxDays)
	}
	return nil
}

func (s *Service) Get(ctx context.Context) (Rules, error) { return scan(ctx, s.pool, "") }

// Update validates and normalises r, stores it and returns the previous rules (before) read under FOR UPDATE.
func (s *Service) Update(ctx context.Context, tx pgx.Tx, r Rules) (Rules, error) {
	before, err := scan(ctx, tx, " FOR UPDATE")
	if err != nil {
		return Rules{}, err
	}
	if err := s.normalise(&r); err != nil {
		return before, err
	}
	_, err = tx.Exec(ctx, `UPDATE site_rules SET force_watermark=$1, forbid_download=$2, share_max_days=$3, share_default_days=$4,
		max_file_bytes=$5, max_share_bytes=$6, domain_block=$7, domain_allow=$8, external_ip_allow=$9, upload_exts=$10,
		upload_max_bytes=$11, quota_bytes=$12, retention_days=$13, updated_at=now() WHERE id=1`,
		r.ForceWatermark, r.ForbidDownload, r.ShareMaxDays, r.ShareDefaultDays, r.MaxFileBytes, r.MaxShareBytes,
		r.DomainBlock, r.DomainAllow, r.ExternalIPAllow, r.UploadExts, r.UploadMaxBytes, r.QuotaBytes, r.RetentionDays)
	return before, err
}

func (s *Service) normalise(r *Rules) error {
	bad := func(f, c string) error { return &ValidationError{f, c} }
	if r.ShareMaxDays < 1 || r.ShareMaxDays > 365 {
		return bad("share_max_days", "out_of_range")
	}
	if r.ShareDefaultDays < 1 || r.ShareDefaultDays > r.ShareMaxDays {
		return bad("share_default_days", "out_of_range")
	}
	if r.MaxFileBytes < 0 || r.MaxFileBytes > s.hardMaxFile {
		return bad("max_file_bytes", "out_of_range")
	}
	if r.MaxShareBytes < 0 {
		return bad("max_share_bytes", "out_of_range")
	}
	if r.UploadMaxBytes < 0 {
		return bad("upload_max_bytes", "out_of_range")
	}
	if r.QuotaBytes < 0 {
		return bad("quota_bytes", "out_of_range")
	}
	if r.RetentionDays < 0 || r.RetentionDays > 3650 {
		return bad("retention_days", "out_of_range")
	}
	var err error
	if r.DomainBlock, err = normList("domain_block", r.DomainBlock, maxDomains, validDomain); err != nil {
		return err
	}
	if r.DomainAllow, err = normList("domain_allow", r.DomainAllow, maxDomains, validDomain); err != nil {
		return err
	}
	exts := make([]string, len(r.UploadExts))
	for i, e := range r.UploadExts {
		exts[i] = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(e)), ".")
	}
	if r.UploadExts, err = normList("upload_exts", exts, maxExts, validExt); err != nil {
		return err
	}
	if len(r.ExternalIPAllow) > maxIPs {
		return bad("external_ip_allow", "too_many")
	}
	ips := make([]netip.Prefix, 0, len(r.ExternalIPAllow))
	for _, p := range r.ExternalIPAllow {
		if !p.IsValid() {
			return bad("external_ip_allow", "invalid")
		}
		if c := canonPrefix(p); !slices.Contains(ips, c) {
			ips = append(ips, c)
		}
	}
	r.ExternalIPAllow = ips
	return nil
}

// normList trims, lowercases, validates and dedups; the result is never nil (NOT NULL columns).
func normList(field string, in []string, limit int, valid func(string) bool) ([]string, error) {
	if len(in) > limit {
		return nil, &ValidationError{field, "too_many"}
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if !valid(s) {
			return nil, &ValidationError{field, "invalid"}
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out, nil
}

func validDomain(d string) bool {
	if len(d) == 0 || len(d) > 253 || !strings.Contains(d, ".") {
		return false
	}
	for _, c := range d {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

func validExt(e string) bool {
	if len(e) < 1 || len(e) > 16 {
		return false
	}
	for _, c := range e {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func domainMatch(list []string, d string) bool {
	for _, x := range list {
		if d == x || strings.HasSuffix(d, "."+x) {
			return true
		}
	}
	return false
}

// DomainAllowed reports whether the email's domain passes the block and allow lists (subdomains match).
func (r Rules) DomainAllowed(email string) bool {
	d := strings.ToLower(email[strings.LastIndex(email, "@")+1:])
	if domainMatch(r.DomainBlock, d) {
		return false
	}
	return len(r.DomainAllow) == 0 || domainMatch(r.DomainAllow, d)
}

// IPAllowed: an empty list allows every address.
func (r Rules) IPAllowed(ip netip.Addr) bool {
	if len(r.ExternalIPAllow) == 0 {
		return true
	}
	ip = ip.Unmap()
	return slices.ContainsFunc(r.ExternalIPAllow, func(p netip.Prefix) bool { return p.Contains(ip) })
}

// ExtAllowed: an empty list allows every file name.
func (r Rules) ExtAllowed(name string) bool {
	if len(r.UploadExts) == 0 {
		return true
	}
	return slices.Contains(r.UploadExts, strings.ToLower(strings.TrimPrefix(path.Ext(name), ".")))
}

// ParsePrefixes parses bare IPs or CIDRs into masked prefixes; errors are ErrTooMany / ErrInvalid.
func ParsePrefixes(ss []string, limit int) ([]netip.Prefix, error) {
	if len(ss) > limit {
		return nil, fmt.Errorf("%w (max %d)", ErrTooMany, limit)
	}
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, aerr := netip.ParseAddr(s)
			if aerr != nil {
				return nil, ErrInvalid
			}
			a = a.Unmap()
			p = netip.PrefixFrom(a, a.BitLen())
		}
		out = append(out, canonPrefix(p))
	}
	return out, nil
}

// canonPrefix maps ::ffff:a.b.c.d/n to the v4 prefix /n-96 and masks host bits (cidr columns reject them).
func canonPrefix(p netip.Prefix) netip.Prefix {
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p.Masked()
}

// GetTx reads the stored rules inside tx (e.g. the normalised result of an Update not yet committed).
func (s *Service) GetTx(ctx context.Context, tx pgx.Tx) (Rules, error) { return scan(ctx, tx, "") }
