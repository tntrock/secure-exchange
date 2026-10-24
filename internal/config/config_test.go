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
	for _, v := range []string{"0", "-1"} {
		m := required()
		m["SX_ACTIVE_KEY_ID"] = v
		_, err := Load(env(m))
		if err == nil || !strings.Contains(err.Error(), "SX_ACTIVE_KEY_ID") {
			t.Fatalf("%s: got %v", v, err)
		}
	}
}
