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

type PreviewConfig struct {
	MaxBytes, MaxVideoBytes        int64
	MaxPages, MaxVideoSeconds, DPI int
}

type MarkConfig struct {
	MaxBytes  int64
	MaxPixels int
	Policy    string // "warn" or "block"
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
	Preview           PreviewConfig
	Mark              MarkConfig
	WorkerTmp         string
	FontFile          string // drawtext font for video watermarks
}

// Load reads configuration via getenv (e.g. os.Getenv). All problems are
// reported together.
func Load(getenv func(string) string) (*Config, error) { return load(getenv, false) }

// LoadWorker is Load for the preview worker: it checks only what the worker uses
// (database, master keys, storage, preview limits, SX_WORKER_TMP), not the web
// server or SMTP settings.
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
		BaseURL:           web("SX_BASE_URL"),
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
		WorkerTmp:         get("SX_WORKER_TMP", "/work"),
		FontFile:          get("SX_FONT_FILE", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
		// input + rendered output must fit the 4 GiB /work tmpfs (see .env.example)
		Preview: PreviewConfig{MaxBytes: 1 << 30, MaxPages: 500, MaxVideoBytes: 3 << 29, MaxVideoSeconds: 7200, DPI: 110},
		Mark:    MarkConfig{MaxBytes: 256 << 20, MaxPixels: 50_000_000, Policy: "warn"},
		SMTP: SMTPConfig{
			Host:     web("SX_SMTP_HOST"),
			Port:     587,
			Username: get("SX_SMTP_USERNAME", ""),
			Password: get("SX_SMTP_PASSWORD", ""),
			From:     web("SX_SMTP_FROM"),
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
