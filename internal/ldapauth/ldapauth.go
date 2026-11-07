// Package ldapauth authenticates users against AD/LDAP: the user's DN is found
// with a service account, then the password is checked by binding as the user.
// Connections are always encrypted (ldaps:// or ldap:// with StartTLS).
package ldapauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/tntrock/secure-exchange/internal/config"
)

var (
	ErrInvalidCredentials = errors.New("ldap: invalid credentials")
	ErrDisabled           = errors.New("ldap: account disabled")
	ErrNoEmail            = errors.New("ldap: account has no email")
	ErrGone               = errors.New("ldap: account missing or disabled")
	// ErrUnavailable wraps every network, TLS or directory-side failure.
	ErrUnavailable = errors.New("ldap: directory unavailable")
	// ErrCertificate additionally marks an ErrUnavailable caused by an untrusted
	// server certificate (wrong or missing SX_LDAP_CA).
	ErrCertificate = errors.New("ldapauth: server certificate not trusted")
)

// timeout bounds every LDAP network operation; a var so tests can shorten it.
var timeout = 10 * time.Second

// inChain is AD's LDAP_MATCHING_RULE_IN_CHAIN (nested group membership).
const inChain = "1.2.840.113556.1.4.1941"

type Identity struct {
	ExternalID, Email, Name string
	Admin                   bool
}

type conn interface {
	Bind(user, pw string) error
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
	Close() error
}

type Directory struct {
	cfg  config.LDAPConfig
	dial func(ctx context.Context) (conn, error)
}

// New prepares a Directory; it does not connect.
func New(cfg config.LDAPConfig) (*Directory, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, err
	}
	tc, err := tlsConfig(cfg, u.Hostname())
	if err != nil {
		return nil, err
	}
	return &Directory{cfg: cfg, dial: func(context.Context) (conn, error) {
		c, err := ldap.DialURL(cfg.URL, ldap.DialWithTLSConfig(tc), ldap.DialWithDialer(&net.Dialer{Timeout: timeout}))
		if err != nil {
			return nil, err
		}
		c.SetTimeout(timeout)
		if u.Scheme == "ldap" { // never bind in plaintext
			if err := c.StartTLS(tc); err != nil {
				_ = c.Close()
				return nil, err
			}
		}
		return c, nil
	}}, nil
}

func tlsConfig(cfg config.LDAPConfig, host string) (*tls.Config, error) {
	tc := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.TLSInsecure} // #nosec G402 -- opt-in SX_LDAP_TLS_INSECURE, warned at startup
	if cfg.CAFile != "" {
		p, err := config.CertPool(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		tc.RootCAs = p
	}
	return tc, nil
}

func unavailable(err error) error { return fmt.Errorf("%w: %w", ErrUnavailable, err) }

// dialFailed wraps a connect/handshake/StartTLS failure, marking certificate
// verification failures with ErrCertificate too.
func dialFailed(err error) error {
	if !isCertError(err) {
		return unavailable(err)
	}
	return fmt.Errorf("%w: %w: %w", ErrUnavailable, ErrCertificate, err)
}

func isCertError(err error) bool {
	var (
		cve *tls.CertificateVerificationError
		ua  x509.UnknownAuthorityError
		he  x509.HostnameError
		ci  x509.CertificateInvalidError
	)
	if errors.As(err, &cve) || errors.As(err, &ua) || errors.As(err, &he) || errors.As(err, &ci) {
		return true
	}
	// go-ldap's StartTLS flattens the handshake error with %v
	s := err.Error()
	return strings.Contains(s, "x509:") || strings.Contains(s, "failed to verify certificate")
}

// session dials, binds as the service account and runs fn.
func (d *Directory) session(ctx context.Context, fn func(conn) error) error {
	c, err := d.dial(ctx)
	if err != nil {
		return dialFailed(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Bind(d.cfg.BindDN, d.cfg.BindPassword); err != nil {
		return unavailable(err) // a rejected service account is a misconfiguration
	}
	return fn(c)
}

// find returns the single entry matching filter under the base DN, or nil.
func (d *Directory) find(c conn, filter string) (*ldap.Entry, error) {
	r, err := c.Search(ldap.NewSearchRequest(d.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, int(timeout.Seconds()), false,
		filter, []string{d.cfg.IDAttr, d.cfg.EmailAttr, d.cfg.NameAttr, "userPrincipalName", "userAccountControl", "memberOf"}, nil))
	if err != nil {
		return nil, unavailable(err)
	}
	if len(r.Entries) != 1 {
		return nil, nil
	}
	return r.Entries[0], nil
}

// identity reads e; c must still be bound as the service account.
func (d *Directory) identity(c conn, e *ldap.Entry) (Identity, error) {
	raw := e.GetEqualFoldRawAttributeValue(d.cfg.IDAttr)
	if len(raw) == 0 {
		return Identity{}, unavailable(fmt.Errorf("%s has no %s attribute", e.DN, d.cfg.IDAttr))
	}
	id := Identity{ExternalID: hex.EncodeToString(raw), Email: e.GetEqualFoldAttributeValue(d.cfg.EmailAttr), Name: e.GetEqualFoldAttributeValue(d.cfg.NameAttr)}
	if id.Email == "" {
		id.Email = e.GetEqualFoldAttributeValue("userPrincipalName")
	}
	g := d.cfg.AdminGroup
	if g == "" {
		return id, nil
	}
	for _, m := range e.GetEqualFoldAttributeValues("memberOf") {
		if strings.EqualFold(m, g) {
			id.Admin = true
			return id, nil
		}
	}
	r, err := c.Search(ldap.NewSearchRequest(e.DN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, int(timeout.Seconds()), false,
		"(memberOf:"+inChain+":="+ldap.EscapeFilter(g)+")", []string{"1.1"}, nil))
	var le *ldap.Error
	switch {
	case err == nil:
		id.Admin = len(r.Entries) > 0
	case errors.As(err, &le) && le.ResultCode != ldap.ErrorNetwork:
		// the server lacks the in-chain rule (non-AD): direct membership only
	default:
		return Identity{}, unavailable(err)
	}
	return id, nil
}

// disabled reports AD's ACCOUNTDISABLE bit; a missing attribute (non-AD) is enabled.
func disabled(e *ldap.Entry) bool {
	n, _ := strconv.ParseInt(e.GetEqualFoldAttributeValue("userAccountControl"), 10, 64)
	return n&2 != 0
}

// Authenticate checks username and password and returns the account.
func (d *Directory) Authenticate(ctx context.Context, username, password string) (Identity, error) {
	if password == "" { // would be an unauthenticated bind, which "succeeds"
		return Identity{}, ErrInvalidCredentials
	}
	var id Identity
	err := d.session(ctx, func(c conn) error {
		e, err := d.find(c, strings.ReplaceAll(d.cfg.UserFilter, "{username}", ldap.EscapeFilter(username)))
		if err != nil {
			return err
		}
		if e == nil {
			return ErrInvalidCredentials
		}
		if id, err = d.identity(c, e); err != nil {
			return err
		}
		if err := c.Bind(e.DN, password); err != nil {
			if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
				return ErrInvalidCredentials
			}
			return unavailable(err)
		}
		if disabled(e) {
			return ErrDisabled
		}
		if id.Email == "" {
			return ErrNoEmail
		}
		return nil
	})
	if err != nil {
		return Identity{}, err
	}
	return id, nil
}

// Lookup re-reads the account with the given external id (session re-check).
// A missing or disabled account is ErrGone.
func (d *Directory) Lookup(ctx context.Context, externalID string) (Identity, error) {
	raw, err := hex.DecodeString(externalID)
	if err != nil || len(raw) == 0 {
		return Identity{}, ErrGone
	}
	var f strings.Builder
	for _, b := range raw {
		fmt.Fprintf(&f, `\%02x`, b)
	}
	var id Identity
	err = d.session(ctx, func(c conn) error {
		e, err := d.find(c, "("+d.cfg.IDAttr+"="+f.String()+")")
		if err != nil {
			return err
		}
		if e == nil || disabled(e) {
			return ErrGone
		}
		id, err = d.identity(c, e)
		return err
	})
	if err != nil {
		return Identity{}, err
	}
	return id, nil
}
