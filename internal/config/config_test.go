package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
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

func TestLoadPreviewDefaults(t *testing.T) {
	c, err := Load(env(required()))
	if err != nil {
		t.Fatal(err)
	}
	want := PreviewConfig{MaxBytes: 1 << 30, MaxPages: 500, MaxVideoBytes: 3 << 29, MaxVideoSeconds: 7200, DPI: 110}
	if c.Preview != want || c.WorkerTmp != "/work" || c.FontFile != "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf" {
		t.Fatalf("preview = %+v tmp=%q font=%q", c.Preview, c.WorkerTmp, c.FontFile)
	}
}

func TestLoadPreviewInvalid(t *testing.T) {
	for _, kv := range [][2]string{{"SX_PREVIEW_MAX_PAGES", "0"}, {"SX_RENDER_DPI", "abc"}, {"SX_PREVIEW_MAX_BYTES", "-1"}, {"SX_PREVIEW_MAX_VIDEO_BYTES", "0"}, {"SX_PREVIEW_MAX_VIDEO_SECONDS", "x"}} {
		m := required()
		m[kv[0]] = kv[1]
		if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), kv[0]) {
			t.Fatalf("%s=%s: err = %v", kv[0], kv[1], err)
		}
	}
}

func TestLoadWorker(t *testing.T) {
	m := map[string]string{
		"SX_BASE_URL":      "https://x.example",
		"SX_DATABASE_URL":  "postgres://u@h/db",
		"SX_MASTER_KEYS":   "1:abc",
		"SX_ACTIVE_KEY_ID": "1",
		// web-only settings are neither required nor validated
		"SX_SMTP_TLS":       "bogus",
		"SX_SESSION_TTL":    "x",
		"SX_SHARE_MAX_DAYS": "0",
	}
	c, err := LoadWorker(env(m))
	if err != nil {
		t.Fatal(err)
	}
	if c.WorkerTmp != "/work" || c.Preview.MaxPages != 500 || c.Storage != "local" {
		t.Fatalf("%+v", c)
	}
	if c.Scan != (ScanConfig{ClamdAddr: "clamav:3310", MaxBytes: 1 << 30}) || c.BaseURL != "https://x.example" {
		t.Fatalf("scan defaults: %+v", c.Scan)
	}
	m2 := map[string]string{"SX_DATABASE_URL": "postgres://u@h/db", "SX_MASTER_KEYS": "1:abc", "SX_ACTIVE_KEY_ID": "1"}
	if _, err := LoadWorker(env(m2)); err == nil || !strings.Contains(err.Error(), "SX_BASE_URL") {
		t.Fatalf("worker without SX_BASE_URL: %v", err)
	}
	m["SX_RENDER_DPI"] = "0"
	m["SX_STORAGE"] = "s3"
	delete(m, "SX_MASTER_KEYS")
	_, err = LoadWorker(env(m))
	for _, k := range []string{"SX_RENDER_DPI", "SX_S3_BUCKET", "SX_MASTER_KEYS"} {
		if err == nil || !strings.Contains(err.Error(), k) {
			t.Fatalf("%s: err = %v", k, err)
		}
	}
	if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), "SX_SMTP_HOST") {
		t.Fatalf("Load must still require SMTP: %v", err)
	}
}

func TestLoadMarkDefaults(t *testing.T) {
	c, err := Load(env(required()))
	if err != nil {
		t.Fatal(err)
	}
	if c.Mark != (MarkConfig{MaxBytes: 256 << 20, MaxPixels: 50_000_000, Policy: "warn"}) {
		t.Fatalf("unexpected mark config: %+v", c.Mark)
	}
}

func TestLoadMarkInvalid(t *testing.T) {
	for k, v := range map[string]string{"SX_MARK_MAX_BYTES": "0", "SX_MARK_MAX_PIXELS": "-1", "SX_UNMARKABLE_POLICY": "deny"} {
		m := required()
		m[k] = v
		if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), k) {
			t.Fatalf("%s=%s: err = %v", k, v, err)
		}
	}
	m := required()
	m["SX_UNMARKABLE_POLICY"] = "block"
	if c, err := Load(env(m)); err != nil || c.Mark.Policy != "block" {
		t.Fatalf("block: %v %+v", err, c)
	}
}

func TestLoadScan(t *testing.T) {
	m := required()
	m["SX_CLAMD_ADDR"] = "127.0.0.1:3311"
	m["SX_SCAN_MAX_BYTES"] = "4194304000"
	c, err := Load(env(m))
	if err != nil || c.Scan != (ScanConfig{ClamdAddr: "127.0.0.1:3311", MaxBytes: 4000 << 20}) {
		t.Fatalf("got %+v, %v", c.Scan, err)
	}
	for _, v := range []string{"4194304001", "0", "-1", "x"} {
		m["SX_SCAN_MAX_BYTES"] = v
		if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), "SX_SCAN_MAX_BYTES") {
			t.Fatalf("SX_SCAN_MAX_BYTES=%s: err = %v", v, err)
		}
	}
}

func TestVendorCreation(t *testing.T) {
	c, err := Load(env(required()))
	if err != nil || c.VendorCreation != "approval" {
		t.Fatal(c, err)
	}
	for _, v := range []string{"staff", "approval", "admin"} {
		m := required()
		m["SX_VENDOR_CREATION"] = v
		if c, err := Load(env(m)); err != nil || c.VendorCreation != v {
			t.Fatal(v, err)
		}
	}
	m := required()
	m["SX_VENDOR_CREATION"] = "bogus"
	if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), "SX_VENDOR_CREATION") {
		t.Fatal(err)
	}
}

func writeCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadSyslog(t *testing.T) {
	m := required()
	c, err := Load(env(m))
	if err != nil || c.Syslog != (SyslogConfig{Transport: "tls"}) {
		t.Fatalf("default: %+v %v", c.Syslog, err)
	}
	m["SX_SYSLOG_ADDR"] = "siem:6514"
	m["SX_SYSLOG_CA"] = writeCA(t)
	if c, err := Load(env(m)); err != nil || c.Syslog.Addr != "siem:6514" || c.Syslog.CAFile != m["SX_SYSLOG_CA"] {
		t.Fatalf("tls+ca: %+v %v", c, err)
	}
	m["SX_SYSLOG_TRANSPORT"] = "udp"
	if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), "SX_SYSLOG_CA") {
		t.Fatalf("CA with udp: %v", err)
	}
	delete(m, "SX_SYSLOG_CA")
	if c, err := Load(env(m)); err != nil || c.Syslog.Transport != "udp" {
		t.Fatalf("udp: %+v %v", c, err)
	}
	m["SX_SYSLOG_TRANSPORT"] = "bogus"
	if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), "SX_SYSLOG_TRANSPORT") {
		t.Fatalf("bad transport: %v", err)
	}
	m["SX_SYSLOG_TRANSPORT"] = "tls"
	m["SX_SYSLOG_CA"] = filepath.Join(t.TempDir(), "missing.pem")
	if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), "SX_SYSLOG_CA") {
		t.Fatalf("missing CA: %v", err)
	}
	bad := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(bad, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	m["SX_SYSLOG_CA"] = bad
	if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), "SX_SYSLOG_CA") {
		t.Fatalf("bad CA: %v", err)
	}
}

func ldapEnv() map[string]string {
	m := required()
	m["SX_LDAP_URL"] = "ldaps://dc.corp:636"
	m["SX_LDAP_BIND_DN"] = "CN=svc,DC=corp"
	m["SX_LDAP_BIND_PASSWORD"] = "pw"
	m["SX_LDAP_BASE_DN"] = "DC=corp"
	return m
}

func TestLoadLDAP(t *testing.T) {
	m := required()
	m["SX_LDAP_USER_FILTER"] = "no placeholder" // ignored: empty URL means disabled
	m["SX_LDAP_TLS_INSECURE"] = "maybe"
	if c, err := Load(env(m)); err != nil || c.LDAP.URL != "" {
		t.Fatalf("disabled: %+v %v", c, err)
	}

	m = ldapEnv()
	c, err := Load(env(m))
	if err != nil {
		t.Fatal(err)
	}
	want := LDAPConfig{URL: "ldaps://dc.corp:636", BindDN: "CN=svc,DC=corp", BindPassword: "pw", BaseDN: "DC=corp",
		UserFilter: "(&(objectClass=user)(|(sAMAccountName={username})(userPrincipalName={username})))",
		IDAttr:     "objectGUID", EmailAttr: "mail", NameAttr: "displayName"}
	if c.LDAP != want {
		t.Fatalf("defaults: %+v", c.LDAP)
	}

	m["SX_LDAP_URL"] = "ldap://dc.corp"
	m["SX_LDAP_CA"] = writeCA(t)
	m["SX_LDAP_TLS_INSECURE"] = "true"
	m["SX_LDAP_USER_FILTER"] = "(uid={username})"
	m["SX_LDAP_ID_ATTR"] = "entryUUID"
	m["SX_LDAP_EMAIL_ATTR"] = "email"
	m["SX_LDAP_NAME_ATTR"] = "cn"
	m["SX_LDAP_ADMIN_GROUP"] = "CN=Admins,DC=corp"
	if c, err = Load(env(m)); err != nil {
		t.Fatal(err)
	}
	want = LDAPConfig{URL: "ldap://dc.corp", CAFile: m["SX_LDAP_CA"], BindDN: "CN=svc,DC=corp", BindPassword: "pw", BaseDN: "DC=corp",
		UserFilter: "(uid={username})", IDAttr: "entryUUID", EmailAttr: "email", NameAttr: "cn", AdminGroup: "CN=Admins,DC=corp", TLSInsecure: true}
	if c.LDAP != want {
		t.Fatalf("custom: %+v", c.LDAP)
	}

	for _, tc := range []struct{ k, v, want string }{
		{"SX_LDAP_URL", "http://dc.corp", "SX_LDAP_URL"},
		{"SX_LDAP_URL", "ldaps://", "SX_LDAP_URL"},
		{"SX_LDAP_URL", "ldap://%zz", "SX_LDAP_URL"},
		{"SX_LDAP_BIND_DN", "", "SX_LDAP_BIND_DN"},
		{"SX_LDAP_BIND_PASSWORD", "", "SX_LDAP_BIND_PASSWORD"},
		{"SX_LDAP_BASE_DN", "", "SX_LDAP_BASE_DN"},
		{"SX_LDAP_USER_FILTER", "(uid=x)", "SX_LDAP_USER_FILTER"},
		{"SX_LDAP_TLS_INSECURE", "maybe", "SX_LDAP_TLS_INSECURE"},
		{"SX_LDAP_CA", filepath.Join(t.TempDir(), "missing.pem"), "SX_LDAP_CA"},
	} {
		m := ldapEnv()
		m[tc.k] = tc.v
		if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s=%q: %v", tc.k, tc.v, err)
		}
	}
	m = ldapEnv()
	m["SX_LDAP_BIND_PASSWORD"] = "  p w  "
	if c, err := Load(env(m)); err != nil || c.LDAP.BindPassword != "  p w  " {
		t.Fatalf("password trimmed: %+v %v", c, err)
	}
	// the worker does not validate LDAP settings
	m = ldapEnv()
	m["SX_LDAP_URL"] = "http://x"
	if _, err := LoadWorker(env(m)); err != nil {
		t.Fatal(err)
	}
}

func certFile(t *testing.T, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCertPoolPEMBundleAndDER(t *testing.T) {
	mk := func(cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			IsCA: parent == nil, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{cn}}
		signer, signKey := tmpl, key
		if parent != nil {
			signer, signKey = parent, parentKey
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signKey)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c, key
	}
	ca1, _ := mk("ca1", nil, nil)
	ca2, key2 := mk("ca2", nil, nil)
	leaf, _ := mk("leaf.test", ca2, key2)
	pemOf := func(c *x509.Certificate) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}

	p, err := CertPool(certFile(t, "bundle.pem", append(pemOf(ca1), pemOf(ca2)...)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: p, DNSName: "leaf.test"}); err != nil {
		t.Fatalf("bundle: %v", err)
	}
	p, err = CertPool(certFile(t, "ca.cer", ca2.Raw))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: p, DNSName: "leaf.test"}); err != nil {
		t.Fatalf("der: %v", err)
	}
	if _, err := CertPool(certFile(t, "junk", []byte("garbage"))); err == nil {
		t.Fatal("garbage accepted")
	}
}
