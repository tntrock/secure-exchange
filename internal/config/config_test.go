package config

import (
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func required() map[string]string {
	return map[string]string{
		"SX_BASE_URL":      "https://x.example",
		"SX_DATABASE_URL":  "postgres://u@h/db",
		"SX_MASTER_KEYS":   "1:abc",
		"SX_ACTIVE_KEY_ID": "1",
		"SX_SMTP_HOST":     "smtp.example",
		"SX_SMTP_FROM":     "SX <noreply@x.example>",
	}
}

func TestLoadDefaults(t *testing.T) {
	c, err := Load(env(required()))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8080" || c.Storage != "local" || c.StorageDir != "/data/blobs" ||
		c.StagingDir != "/data/staging" || c.MaxFileSize != 500<<30 ||
		c.SessionTTL != 12*time.Hour || c.ActiveKeyID != 1 ||
		c.BaseURL != "https://x.example" || len(c.TrustedProxies) != 0 {
		t.Fatalf("unexpected config: %+v", c)
	}
}

func TestLoadMissingRequired(t *testing.T) {
	m := required()
	delete(m, "SX_DATABASE_URL")
	_, err := Load(env(m))
	if err == nil || !strings.Contains(err.Error(), "SX_DATABASE_URL") {
		t.Fatalf("got %v", err)
	}
}

func TestLoadTrustedProxies(t *testing.T) {
	m := required()
	m["SX_TRUSTED_PROXIES"] = "10.0.0.0/8, 192.168.1.1/32"
	c, err := Load(env(m))
	if err != nil || len(c.TrustedProxies) != 2 || c.TrustedProxies[1].String() != "192.168.1.1/32" {
		t.Fatalf("got %+v, %v", c, err)
	}
	m["SX_TRUSTED_PROXIES"] = "bad"
	if _, err := Load(env(m)); err == nil {
		t.Fatal("want error for bad CIDR")
	}
}

func TestLoadS3RequiresBucket(t *testing.T) {
	m := required()
	m["SX_STORAGE"] = "s3"
	_, err := Load(env(m))
	if err == nil || !strings.Contains(err.Error(), "SX_S3_BUCKET") {
		t.Fatalf("got %v", err)
	}
}

func TestLoadActiveKeyIDMustBePositive(t *testing.T) {
	for _, v := range []string{"0", "-1", "2147483648"} {
		m := required()
		m["SX_ACTIVE_KEY_ID"] = v
		_, err := Load(env(m))
		if err == nil || !strings.Contains(err.Error(), "SX_ACTIVE_KEY_ID") {
			t.Fatalf("%s: got %v", v, err)
		}
	}
}

func TestLoadSMTPDefaults(t *testing.T) {
	c, err := Load(env(required()))
	if err != nil {
		t.Fatal(err)
	}
	if c.SMTP.Host != "smtp.example" || c.SMTP.Port != 587 || c.SMTP.TLS != "starttls" || c.ShareMaxDays != 30 {
		t.Fatalf("unexpected: %+v", c)
	}
}

func TestLoadSMTPRequired(t *testing.T) {
	for _, k := range []string{"SX_SMTP_HOST", "SX_SMTP_FROM"} {
		m := required()
		delete(m, k)
		if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), k) {
			t.Fatalf("%s: got %v", k, err)
		}
	}
}

func TestLoadSMTPFromInvalid(t *testing.T) {
	m := required()
	m["SX_SMTP_FROM"] = "not an address"
	if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), "SX_SMTP_FROM") {
		t.Fatalf("got %v", err)
	}
}

func TestLoadShareMaxDaysRange(t *testing.T) {
	for _, v := range []string{"0", "366", "x"} {
		m := required()
		m["SX_SHARE_MAX_DAYS"] = v
		if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), "SX_SHARE_MAX_DAYS") {
			t.Fatalf("%s: got %v", v, err)
		}
	}
	m := required()
	m["SX_SHARE_MAX_DAYS"] = "365"
	if c, err := Load(env(m)); err != nil || c.ShareMaxDays != 365 {
		t.Fatalf("got %+v, %v", c, err)
	}
}

func TestLoadSMTPTLSValues(t *testing.T) {
	m := required()
	m["SX_SMTP_HOST"] = "localhost"
	for _, v := range []string{"tls", "none", "starttls"} {
		m["SX_SMTP_TLS"] = v
		if c, err := Load(env(m)); err != nil || c.SMTP.TLS != v {
			t.Fatalf("%s: got %+v, %v", v, c, err)
		}
	}
	m["SX_SMTP_TLS"] = "bogus"
	if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), "SX_SMTP_TLS") {
		t.Fatalf("got %v", err)
	}
	m["SX_SMTP_TLS"] = "tls"
	m["SX_SMTP_PORT"] = "70000"
	if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), "SX_SMTP_PORT") {
		t.Fatalf("got %v", err)
	}
}

func TestLoadSMTPTLSNoneLocalOnly(t *testing.T) {
	m := required()
	m["SX_SMTP_TLS"] = "none"
	for _, h := range []string{"localhost", "127.0.0.1", "mailpit"} {
		m["SX_SMTP_HOST"] = h
		if _, err := Load(env(m)); err != nil {
			t.Fatalf("%s: %v", h, err)
		}
	}
	m["SX_SMTP_HOST"] = "smtp.example"
	if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), "SX_SMTP_TLS") {
		t.Fatalf("got %v", err)
	}
}
