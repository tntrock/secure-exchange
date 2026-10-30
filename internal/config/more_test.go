package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoadOverrides(t *testing.T) {
	m := required()
	for k, v := range map[string]string{
		"SX_STORAGE": "s3", "SX_S3_BUCKET": "b", "SX_S3_USE_SSL": "true",
		"SX_MAX_FILE_SIZE": "1024", "SX_SESSION_TTL": "90m", "SX_SMTP_PORT": "2525",
		"SX_PREVIEW_MAX_BYTES": "77", "SX_RENDER_DPI": "150",
	} {
		m[k] = v
	}
	c, err := Load(env(m))
	if err != nil {
		t.Fatal(err)
	}
	if !c.S3.UseSSL || c.S3.Bucket != "b" || c.MaxFileSize != 1024 || c.SessionTTL != 90*time.Minute ||
		c.SMTP.Port != 2525 || c.Preview.MaxBytes != 77 || c.Preview.DPI != 150 {
		t.Fatalf("unexpected: %+v", c)
	}
}

func TestLoadRejectsBadValues(t *testing.T) {
	for k, v := range map[string]string{
		"SX_S3_USE_SSL":        "maybe",
		"SX_PREVIEW_MAX_BYTES": "-1",
		"SX_RENDER_DPI":        "0",
		"SX_MAX_FILE_SIZE":     "lots",
		"SX_SESSION_TTL":       "-5m",
		"SX_SMTP_PORT":         "70000",
		"SX_STORAGE":           "ftp",
		"SX_SMTP_TLS":          "ssl3",
	} {
		m := required()
		m[k] = v
		if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), k) {
			t.Errorf("%s=%s: got %v", k, v, err)
		}
	}
}

func TestLoadSMTPNoneOnlyLocal(t *testing.T) {
	m := required()
	m["SX_SMTP_TLS"] = "none"
	if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), "only allowed") {
		t.Fatalf("remote host: %v", err)
	}
	m["SX_SMTP_HOST"] = "mailpit"
	if c, err := Load(env(m)); err != nil || c.SMTP.TLS != "none" {
		t.Fatalf("mailpit: %v", err)
	}
}

// The worker needs neither web nor SMTP settings, and ignores web-only values.
func TestLoadWorkerIgnoresWebSettings(t *testing.T) {
	m := map[string]string{
		"SX_DATABASE_URL": "postgres://u@h/db", "SX_MASTER_KEYS": "1:abc", "SX_ACTIVE_KEY_ID": "1",
		"SX_WORKER_TMP": "/tmp/w", "SX_SESSION_TTL": "garbage",
	}
	c, err := LoadWorker(env(m))
	if err != nil || c.WorkerTmp != "/tmp/w" {
		t.Fatalf("got %+v %v", c, err)
	}
	if _, err := Load(env(m)); err == nil {
		t.Fatal("web Load accepted a config without web settings")
	}
}
