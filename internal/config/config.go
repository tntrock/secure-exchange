// Package config loads settings from SX_-prefixed environment variables.
package config

import (
	"errors"
	"fmt"
	"net/mail"
	"net/netip"
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
	ShareMaxDays      int
}

// Load reads configuration via getenv (e.g. os.Getenv). All problems are
// reported together.
func Load(getenv func(string) string) (*Config, error) {
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
		SMTP: SMTPConfig{
			Host:     req("SX_SMTP_HOST"),
			Port:     587,
			Username: get("SX_SMTP_USERNAME", ""),
			Password: get("SX_SMTP_PASSWORD", ""),
			From:     req("SX_SMTP_FROM"),
			TLS:      get("SX_SMTP_TLS", "starttls"),
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
	if s := get("SX_S3_USE_SSL", ""); s != "" {
		b, err := strconv.ParseBool(s)
		if err != nil {
			bad("SX_S3_USE_SSL", err)
		}
		c.S3.UseSSL = b
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
	switch c.SMTP.TLS {
	case "starttls", "tls", "none":
	default:
		errs = append(errs, fmt.Errorf("SX_SMTP_TLS: %q must be starttls, tls or none", c.SMTP.TLS))
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
