// Package config loads settings from SX_-prefixed environment variables.
package config

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/mail"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type S3Config struct {
	Endpoint, Bucket, AccessKey, SecretKey, Region string
	UseSSL                                         bool
}

type SMTPConfig struct {
	Host               string
	Port               int
	Username, Password string
	From               string
	TLS                string // "starttls", "tls" or "none"
}

// SyslogConfig is the audit forwarder target; an empty Addr disables it.
type SyslogConfig struct {
	Addr, Transport, CAFile string // Transport: "udp", "tcp" or "tls"
}

// LDAPConfig is the AD/LDAP login directory; an empty URL disables it.
type LDAPConfig struct {
	URL, CAFile, BindDN, BindPassword, BaseDN string
	UserFilter, IDAttr, EmailAttr, NameAttr   string
	AdminGroup                                string
	TLSInsecure                               bool // skip certificate verification (SX_LDAP_TLS_INSECURE)
}

// OIDCConfig is the OpenID Connect login; an empty Issuer disables it.
type OIDCConfig struct {
	Issuer, ClientID, ClientSecret, Scopes string
	AdminClaim, AdminValue                 string
	ButtonText, CAFile                     string
}

type PreviewConfig struct {
	MaxBytes, MaxVideoBytes        int64
	MaxPages, MaxVideoSeconds, DPI int
}

type MarkConfig struct {
	MaxBytes  int64
	MaxPixels int
	Policy    string // "warn" or "block"
}

type ScanConfig struct {
	ClamdAddr string
	MaxBytes  int64
}

type Config struct {
	Listen            string
	BaseURL           string
	DatabaseURL       string
	MasterKeys        string
	ActiveKeyID       int
	Storage           string // "local" or "s3"
	StorageDir        string
	StagingDir        string
	S3                S3Config
	TrustedProxies    []netip.Prefix
	MaxFileSize       int64
	SessionTTL        time.Duration
	InitAdminEmail    string
	InitAdminPassword string
	SMTP              SMTPConfig
	Syslog            SyslogConfig
	LDAP              LDAPConfig
	OIDC              OIDCConfig
	ShareMaxDays      int
	Preview           PreviewConfig
	Mark              MarkConfig
	Scan              ScanConfig
	WorkerTmp         string
	FontFile          string // drawtext font for video watermarks
	VendorCreation    string // web only: "staff", "approval" or "admin"
}

// Load reads configuration via getenv (e.g. os.Getenv). All problems are
// reported together.
func Load(getenv func(string) string) (*Config, error) { return load(getenv, false) }

// LoadWorker is Load for the preview worker: it checks only what the worker uses
// (database, master keys, base URL, storage, preview and scan limits, SX_WORKER_TMP), not the web
// server, SMTP or syslog settings.
func LoadWorker(getenv func(string) string) (*Config, error) { return load(getenv, true) }

func load(getenv func(string) string, worker bool) (*Config, error) {
	var errs []error
	get := func(k, def string) string {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			return v
		}
		return def
	}
	req := func(k string) string {
		v := get(k, "")
		if v == "" {
			errs = append(errs, fmt.Errorf("%s is required", k))
		}
		return v
	}
	bad := func(k string, err error) { errs = append(errs, fmt.Errorf("%s: %w", k, err)) }
	web := req // required by the web server only
	if worker {
		web = func(k string) string { return get(k, "") }
	}

	c := &Config{
		Listen:            get("SX_LISTEN", ":8080"),
		BaseURL:           req("SX_BASE_URL"),
		DatabaseURL:       req("SX_DATABASE_URL"),
		MasterKeys:        req("SX_MASTER_KEYS"),
		Storage:           get("SX_STORAGE", "local"),
		StorageDir:        get("SX_STORAGE_DIR", "/data/blobs"),
		StagingDir:        get("SX_STAGING_DIR", "/data/staging"),
		MaxFileSize:       500 << 30,
		SessionTTL:        12 * time.Hour,
		InitAdminEmail:    get("SX_INIT_ADMIN_EMAIL", ""),
		InitAdminPassword: get("SX_INIT_ADMIN_PASSWORD", ""),
		ShareMaxDays:      30,
		VendorCreation:    get("SX_VENDOR_CREATION", "approval"),
		WorkerTmp:         get("SX_WORKER_TMP", "/work"),
		FontFile:          get("SX_FONT_FILE", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
		// input + rendered output must fit the 4 GiB /work tmpfs (see .env.example)
		Preview: PreviewConfig{MaxBytes: 1 << 30, MaxPages: 500, MaxVideoBytes: 3 << 29, MaxVideoSeconds: 7200, DPI: 110},
		Mark:    MarkConfig{MaxBytes: 256 << 20, MaxPixels: 50_000_000, Policy: "warn"},
		Scan:    ScanConfig{ClamdAddr: get("SX_CLAMD_ADDR", "clamav:3310"), MaxBytes: 1 << 30},
		SMTP: SMTPConfig{
			Host:     web("SX_SMTP_HOST"),
			Port:     587,
			Username: get("SX_SMTP_USERNAME", ""),
			Password: get("SX_SMTP_PASSWORD", ""),
			From:     web("SX_SMTP_FROM"),
			TLS:      get("SX_SMTP_TLS", "starttls"),
		},
		Syslog: SyslogConfig{Addr: get("SX_SYSLOG_ADDR", ""), Transport: get("SX_SYSLOG_TRANSPORT", "tls"), CAFile: get("SX_SYSLOG_CA", "")},
		LDAP: LDAPConfig{
			URL:          get("SX_LDAP_URL", ""),
			CAFile:       get("SX_LDAP_CA", ""),
			BindDN:       get("SX_LDAP_BIND_DN", ""),
			BindPassword: getenv("SX_LDAP_BIND_PASSWORD"), // untrimmed: spaces may be part of the password,
			BaseDN:       get("SX_LDAP_BASE_DN", ""),
			UserFilter:   get("SX_LDAP_USER_FILTER", "(&(objectClass=user)(|(sAMAccountName={username})(userPrincipalName={username})))"),
			IDAttr:       get("SX_LDAP_ID_ATTR", "objectGUID"),
			EmailAttr:    get("SX_LDAP_EMAIL_ATTR", "mail"),
			NameAttr:     get("SX_LDAP_NAME_ATTR", "displayName"),
			AdminGroup:   get("SX_LDAP_ADMIN_GROUP", ""),
		},
		OIDC: OIDCConfig{
			Issuer:       get("SX_OIDC_ISSUER", ""),
			ClientID:     get("SX_OIDC_CLIENT_ID", ""),
			ClientSecret: getenv("SX_OIDC_CLIENT_SECRET"), // untrimmed, like SX_LDAP_BIND_PASSWORD
			Scopes:       withOpenID(get("SX_OIDC_SCOPES", "openid profile email")),
			AdminClaim:   get("SX_OIDC_ADMIN_CLAIM", "groups"),
			AdminValue:   get("SX_OIDC_ADMIN_VALUE", ""),
			ButtonText:   get("SX_OIDC_BUTTON_TEXT", ""),
			CAFile:       get("SX_OIDC_CA", ""),
		},
		S3: S3Config{
			Endpoint:  get("SX_S3_ENDPOINT", ""),
			Bucket:    get("SX_S3_BUCKET", ""),
			AccessKey: get("SX_S3_ACCESS_KEY", ""),
			SecretKey: get("SX_S3_SECRET_KEY", ""),
			Region:    get("SX_S3_REGION", ""),
		},
	}

	if s := req("SX_ACTIVE_KEY_ID"); s != "" {
		if n, err := strconv.ParseUint(s, 10, 31); err != nil || n == 0 {
			bad("SX_ACTIVE_KEY_ID", errors.New("must be an integer from 1 to 2147483647"))
		} else {
			c.ActiveKeyID = int(n)
		}
	}
	if s := get("SX_S3_USE_SSL", ""); s != "" {
		b, err := strconv.ParseBool(s)
		if err != nil {
			bad("SX_S3_USE_SSL", err)
		}
		c.S3.UseSSL = b
	}
	posInt := func(k string, dst *int) {
		if s := get(k, ""); s != "" {
			if n, err := strconv.ParseInt(s, 10, 31); err != nil || n <= 0 {
				bad(k, errors.New("must be a positive integer"))
			} else {
				*dst = int(n)
			}
		}
	}
	posInt64 := func(k string, dst *int64) {
		if s := get(k, ""); s != "" {
			if n, err := strconv.ParseInt(s, 10, 64); err != nil || n <= 0 {
				bad(k, errors.New("must be a positive integer"))
			} else {
				*dst = n
			}
		}
	}
	posInt64("SX_PREVIEW_MAX_BYTES", &c.Preview.MaxBytes)
	posInt("SX_PREVIEW_MAX_PAGES", &c.Preview.MaxPages)
	posInt64("SX_PREVIEW_MAX_VIDEO_BYTES", &c.Preview.MaxVideoBytes)
	posInt("SX_PREVIEW_MAX_VIDEO_SECONDS", &c.Preview.MaxVideoSeconds)
	posInt("SX_RENDER_DPI", &c.Preview.DPI)
	posInt64("SX_MARK_MAX_BYTES", &c.Mark.MaxBytes)
	posInt("SX_MARK_MAX_PIXELS", &c.Mark.MaxPixels)
	if s := get("SX_SCAN_MAX_BYTES", ""); s != "" {
		if n, err := strconv.ParseInt(s, 10, 64); err != nil || n < 1 || n > 4000<<20 {
			bad("SX_SCAN_MAX_BYTES", errors.New("must be an integer from 1 to 4194304000"))
		} else {
			c.Scan.MaxBytes = n
		}
	}
	switch c.Mark.Policy = get("SX_UNMARKABLE_POLICY", c.Mark.Policy); c.Mark.Policy {
	case "warn", "block":
	default:
		bad("SX_UNMARKABLE_POLICY", fmt.Errorf("%q must be warn or block", c.Mark.Policy))
	}
	if !worker {
		if s := get("SX_MAX_FILE_SIZE", ""); s != "" {
			if n, err := strconv.ParseInt(s, 10, 64); err != nil || n <= 0 {
				bad("SX_MAX_FILE_SIZE", errors.New("must be a positive integer"))
			} else {
				c.MaxFileSize = n
			}
		}
		if s := get("SX_SESSION_TTL", ""); s != "" {
			if d, err := time.ParseDuration(s); err != nil || d <= 0 {
				bad("SX_SESSION_TTL", errors.New("must be a positive duration"))
			} else {
				c.SessionTTL = d
			}
		}
		for _, p := range strings.Split(get("SX_TRUSTED_PROXIES", ""), ",") {
			if p = strings.TrimSpace(p); p == "" {
				continue
			}
			pf, err := netip.ParsePrefix(p)
			if err != nil {
				bad("SX_TRUSTED_PROXIES", err)
				continue
			}
			c.TrustedProxies = append(c.TrustedProxies, pf)
		}
		if s := get("SX_SMTP_PORT", ""); s != "" {
			if n, err := strconv.ParseUint(s, 10, 16); err != nil || n == 0 {
				bad("SX_SMTP_PORT", errors.New("must be an integer from 1 to 65535"))
			} else {
				c.SMTP.Port = int(n)
			}
		}
		if s := get("SX_SHARE_MAX_DAYS", ""); s != "" {
			if n, err := strconv.Atoi(s); err != nil || n < 1 || n > 365 {
				bad("SX_SHARE_MAX_DAYS", errors.New("must be an integer from 1 to 365"))
			} else {
				c.ShareMaxDays = n
			}
		}
		if c.SMTP.From != "" {
			if _, err := mail.ParseAddress(c.SMTP.From); err != nil {
				bad("SX_SMTP_FROM", err)
			}
		}
		switch c.VendorCreation {
		case "staff", "approval", "admin":
		default:
			bad("SX_VENDOR_CREATION", fmt.Errorf("%q must be staff, approval or admin", c.VendorCreation))
		}
		switch c.Syslog.Transport {
		case "udp", "tcp", "tls":
		default:
			bad("SX_SYSLOG_TRANSPORT", fmt.Errorf("%q must be udp, tcp or tls", c.Syslog.Transport))
		}
		if c.Syslog.CAFile != "" {
			if c.Syslog.Transport != "tls" {
				bad("SX_SYSLOG_CA", errors.New("only used with SX_SYSLOG_TRANSPORT=tls"))
			} else if _, err := CertPool(c.Syslog.CAFile); err != nil {
				bad("SX_SYSLOG_CA", err)
			}
		}
		if c.LDAP.URL != "" {
			if u, err := url.Parse(c.LDAP.URL); err != nil || (u.Scheme != "ldaps" && u.Scheme != "ldap") || u.Host == "" {
				bad("SX_LDAP_URL", fmt.Errorf("%q must be ldaps://host[:port] or ldap://host[:port]", c.LDAP.URL))
			}
			for _, kv := range [][2]string{{"SX_LDAP_BIND_DN", c.LDAP.BindDN}, {"SX_LDAP_BIND_PASSWORD", c.LDAP.BindPassword}, {"SX_LDAP_BASE_DN", c.LDAP.BaseDN}} {
				if kv[1] == "" {
					errs = append(errs, fmt.Errorf("%s is required when SX_LDAP_URL is set", kv[0]))
				}
			}
			if !strings.Contains(c.LDAP.UserFilter, "{username}") {
				bad("SX_LDAP_USER_FILTER", errors.New("must contain {username}"))
			}
			if c.LDAP.CAFile != "" {
				if _, err := CertPool(c.LDAP.CAFile); err != nil {
					bad("SX_LDAP_CA", err)
				}
			}
			if s := get("SX_LDAP_TLS_INSECURE", ""); s != "" {
				b, err := strconv.ParseBool(s)
				if err != nil {
					bad("SX_LDAP_TLS_INSECURE", err)
				}
				c.LDAP.TLSInsecure = b
			}
		}
		if c.OIDC.Issuer != "" {
			if u, err := url.Parse(c.OIDC.Issuer); err != nil || u.Scheme != "https" || u.Host == "" {
				bad("SX_OIDC_ISSUER", fmt.Errorf("%q must be https://host/...", c.OIDC.Issuer))
			}
			for _, kv := range [][2]string{{"SX_OIDC_CLIENT_ID", c.OIDC.ClientID}, {"SX_OIDC_CLIENT_SECRET", c.OIDC.ClientSecret}} {
				if kv[1] == "" {
					errs = append(errs, fmt.Errorf("%s is required when SX_OIDC_ISSUER is set", kv[0]))
				}
			}
			if c.OIDC.CAFile != "" {
				if _, err := CertPool(c.OIDC.CAFile); err != nil {
					bad("SX_OIDC_CA", err)
				}
			}
		}
		switch c.SMTP.TLS {
		case "starttls", "tls":
		case "none":
			if !LocalSMTPHost(c.SMTP.Host) {
				errs = append(errs, fmt.Errorf("SX_SMTP_TLS: none is only allowed for localhost, 127.0.0.1 or mailpit, not %q", c.SMTP.Host))
			}
		default:
			errs = append(errs, fmt.Errorf("SX_SMTP_TLS: %q must be starttls, tls or none", c.SMTP.TLS))
		}
	}
	switch c.Storage {
	case "local":
	case "s3":
		if c.S3.Bucket == "" {
			errs = append(errs, errors.New("SX_S3_BUCKET is required when SX_STORAGE=s3"))
		}
	default:
		errs = append(errs, fmt.Errorf("SX_STORAGE: %q must be local or s3", c.Storage))
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return c, nil
}

// LocalSMTPHost reports whether h may be used with SX_SMTP_TLS=none (unencrypted, local testing only).
func LocalSMTPHost(h string) bool { return h == "localhost" || h == "127.0.0.1" || h == "mailpit" }

// CertPool loads PEM certificates (one or a bundle) or a single DER certificate
// from path (SX_SYSLOG_CA, SX_LDAP_CA).
func CertPool(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p := x509.NewCertPool()
	if p.AppendCertsFromPEM(b) {
		return p, nil
	}
	cert, err := x509.ParseCertificate(b)
	if err != nil {
		return nil, fmt.Errorf("%s: no PEM or DER certificate", path)
	}
	p.AddCert(cert)
	return p, nil
}

// withOpenID makes sure the space-separated scope list contains "openid".
func withOpenID(scopes string) string {
	for _, s := range strings.Fields(scopes) {
		if s == "openid" {
			return scopes
		}
	}
	return strings.TrimSpace("openid " + scopes)
}
