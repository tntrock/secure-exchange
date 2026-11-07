package ldapauth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/tntrock/secure-exchange/internal/config"
)

const (
	userDN  = "CN=A,DC=x"
	groupDN = "CN=Admins,DC=x"
)

var netErr = ldap.NewError(ldap.ErrorNetwork, errors.New("connection reset"))

type fakeConn struct {
	entries   []*ldap.Entry // returned by subtree searches
	pw        map[string]string
	userBind  error // overrides the result of a bind as userDN
	searchErr error
	chain     bool // the in-chain search finds the entry
	chainErr  error
	log       []string
	closed    bool
}

func (f *fakeConn) Bind(u, p string) error {
	f.log = append(f.log, "bind:"+u)
	if u == userDN && f.userBind != nil {
		return f.userBind
	}
	if want, ok := f.pw[u]; ok && want == p {
		return nil
	}
	return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials"))
}

func (f *fakeConn) Search(r *ldap.SearchRequest) (*ldap.SearchResult, error) {
	f.log = append(f.log, "search:"+r.Filter)
	if r.Scope == ldap.ScopeBaseObject {
		if f.chainErr != nil {
			return nil, f.chainErr
		}
		if f.chain {
			return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry(r.BaseDN, nil)}}, nil
		}
		return &ldap.SearchResult{}, nil
	}
	if f.searchErr != nil {
		return nil, f.searchErr
	}
	return &ldap.SearchResult{Entries: f.entries}, nil
}

func (f *fakeConn) Close() error { f.closed = true; return nil }

func testCfg() config.LDAPConfig {
	return config.LDAPConfig{URL: "ldaps://dc.x:636", BindDN: "CN=svc,DC=x", BindPassword: "svcpw", BaseDN: "DC=x",
		UserFilter: "(&(objectClass=user)(|(sAMAccountName={username})(userPrincipalName={username})))",
		IDAttr:     "objectGUID", EmailAttr: "mail", NameAttr: "displayName", AdminGroup: groupDN}
}

func entryA(extra map[string][]string) *ldap.Entry {
	attrs := map[string][]string{"objectGUID": {string([]byte{0x01, 0xab})}, "mail": {"a@x.test"}, "displayName": {"A"}}
	for k, v := range extra {
		attrs[k] = v
	}
	return ldap.NewEntry(userDN, attrs)
}

// fake returns a Directory whose dial hands out f, and a dial counter.
func fake(f *fakeConn) (*Directory, *int) {
	if f.pw == nil {
		f.pw = map[string]string{"CN=svc,DC=x": "svcpw", userDN: "pw"}
	}
	n := 0
	return &Directory{cfg: testCfg(), dial: func(context.Context) (conn, error) { n++; return f, nil }}, &n
}

func TestAuthenticateOK(t *testing.T) {
	f := &fakeConn{entries: []*ldap.Entry{entryA(nil)}}
	d, _ := fake(f)
	id, err := d.Authenticate(context.Background(), "a", "pw")
	if err != nil || id != (Identity{"01ab", "a@x.test", "A", false}) {
		t.Fatalf("%+v %v", id, err)
	}
	if !strings.HasPrefix(f.log[0], "bind:CN=svc,DC=x") || !strings.HasPrefix(f.log[1], "search:(&(objectClass=user)(|(sAMAccountName=a)") {
		t.Fatalf("order %q", f.log)
	}
	if f.log[len(f.log)-1] != "bind:"+userDN || !f.closed {
		t.Fatalf("user bind %q closed=%v", f.log, f.closed)
	}
}

func TestAuthenticateEmptyPasswordNoNetwork(t *testing.T) {
	d, n := fake(&fakeConn{})
	if _, err := d.Authenticate(context.Background(), "a", ""); !errors.Is(err, ErrInvalidCredentials) || *n != 0 {
		t.Fatalf("%v dials=%d", err, *n)
	}
}

func TestAuthenticateEscapesUsername(t *testing.T) {
	f := &fakeConn{}
	d, _ := fake(f)
	if _, err := d.Authenticate(context.Background(), "*)(sAMAccountName=*", "pw"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal(err)
	}
	if !strings.Contains(f.log[1], `\2a\29\28sAMAccountName=\2a`) {
		t.Fatalf("filter %q", f.log[1])
	}
}

func TestAuthenticateWrongPassword(t *testing.T) {
	d, _ := fake(&fakeConn{entries: []*ldap.Entry{entryA(nil)}})
	if _, err := d.Authenticate(context.Background(), "a", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal(err)
	}
	// any other user-bind failure is an outage, not a wrong password
	d, _ = fake(&fakeConn{entries: []*ldap.Entry{entryA(nil)}, userBind: netErr})
	if _, err := d.Authenticate(context.Background(), "a", "pw"); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}

func TestAuthenticateAmbiguous(t *testing.T) {
	d, _ := fake(&fakeConn{entries: []*ldap.Entry{entryA(nil), entryA(nil)}})
	if _, err := d.Authenticate(context.Background(), "a", "pw"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal(err)
	}
}

func TestAuthenticateDisabled(t *testing.T) {
	d, _ := fake(&fakeConn{entries: []*ldap.Entry{entryA(map[string][]string{"userAccountControl": {"514"}})}})
	if _, err := d.Authenticate(context.Background(), "a", "pw"); !errors.Is(err, ErrDisabled) {
		t.Fatal(err)
	}
	d, _ = fake(&fakeConn{entries: []*ldap.Entry{entryA(map[string][]string{"userAccountControl": {"512"}})}})
	if _, err := d.Authenticate(context.Background(), "a", "pw"); err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticateNoEmail(t *testing.T) {
	d, _ := fake(&fakeConn{entries: []*ldap.Entry{entryA(map[string][]string{"mail": nil})}})
	if _, err := d.Authenticate(context.Background(), "a", "pw"); !errors.Is(err, ErrNoEmail) {
		t.Fatal(err)
	}
	d, _ = fake(&fakeConn{entries: []*ldap.Entry{entryA(map[string][]string{"mail": {""}, "userPrincipalName": {"a@corp"}})}})
	if id, err := d.Authenticate(context.Background(), "a", "pw"); err != nil || id.Email != "a@corp" {
		t.Fatalf("%+v %v", id, err)
	}
}

func TestAuthenticateNoIDAttr(t *testing.T) {
	d, _ := fake(&fakeConn{entries: []*ldap.Entry{entryA(map[string][]string{"objectGUID": nil})}})
	if _, err := d.Authenticate(context.Background(), "a", "pw"); !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "objectGUID") {
		t.Fatal(err)
	}
}

func TestAdminDirectMemberOf(t *testing.T) {
	f := &fakeConn{entries: []*ldap.Entry{entryA(map[string][]string{"memberOf": {"CN=Other,DC=x", "cn=admins,dc=X"}})}}
	d, _ := fake(f)
	if id, err := d.Authenticate(context.Background(), "a", "pw"); err != nil || !id.Admin {
		t.Fatalf("%+v %v", id, err)
	}
	for _, l := range f.log {
		if strings.Contains(l, "1.2.840.113556.1.4.1941") {
			t.Fatalf("in-chain search not needed: %q", f.log)
		}
	}
}

func TestAdminNestedInChain(t *testing.T) {
	f := &fakeConn{entries: []*ldap.Entry{entryA(map[string][]string{"memberOf": {"CN=Other,DC=x"}})}, chain: true}
	d, _ := fake(f)
	if id, err := d.Authenticate(context.Background(), "a", "pw"); err != nil || !id.Admin {
		t.Fatalf("%+v %v", id, err)
	}
	found := false
	for _, l := range f.log {
		found = found || l == "search:(memberOf:1.2.840.113556.1.4.1941:=CN=Admins,DC=x)"
	}
	if !found {
		t.Fatalf("log %q", f.log)
	}
	// no admin group configured: nobody is admin and nothing is searched
	f = &fakeConn{entries: []*ldap.Entry{entryA(nil)}, chain: true}
	d, _ = fake(f)
	d.cfg.AdminGroup = ""
	if id, err := d.Authenticate(context.Background(), "a", "pw"); err != nil || id.Admin || len(f.log) != 3 {
		t.Fatalf("%+v %v %q", id, err, f.log)
	}
}

func TestAdminInChainUnsupported(t *testing.T) {
	d, _ := fake(&fakeConn{entries: []*ldap.Entry{entryA(nil)}, chainErr: ldap.NewError(ldap.LDAPResultInappropriateMatching, errors.New("no rule"))})
	if id, err := d.Authenticate(context.Background(), "a", "pw"); err != nil || id.Admin {
		t.Fatalf("%+v %v", id, err)
	}
	// a connection error during the in-chain search fails the login
	d, _ = fake(&fakeConn{entries: []*ldap.Entry{entryA(nil)}, chainErr: netErr})
	if _, err := d.Authenticate(context.Background(), "a", "pw"); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}

func TestUnavailable(t *testing.T) {
	cause := errors.New("dial tcp: refused")
	d := &Directory{cfg: testCfg(), dial: func(context.Context) (conn, error) { return nil, cause }}
	if _, err := d.Authenticate(context.Background(), "a", "pw"); !errors.Is(err, ErrUnavailable) || !errors.Is(err, cause) {
		t.Fatal(err)
	}
	d, _ = fake(&fakeConn{searchErr: netErr})
	if _, err := d.Authenticate(context.Background(), "a", "pw"); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	// a rejected service bind is a misconfiguration and looks like an outage
	d, _ = fake(&fakeConn{pw: map[string]string{}})
	if _, err := d.Authenticate(context.Background(), "a", "pw"); !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrInvalidCredentials) {
		t.Fatal(err)
	}
}

func TestLookup(t *testing.T) {
	f := &fakeConn{entries: []*ldap.Entry{entryA(nil)}}
	d, _ := fake(f)
	id, err := d.Lookup(context.Background(), "01ab")
	if err != nil || id != (Identity{"01ab", "a@x.test", "A", false}) {
		t.Fatalf("%+v %v", id, err)
	}
	if f.log[1] != `search:(objectGUID=\01\ab)` {
		t.Fatalf("log %q", f.log)
	}
	for _, f := range []*fakeConn{{}, {entries: []*ldap.Entry{entryA(map[string][]string{"userAccountControl": {"66050"}})}}} {
		d, _ := fake(f)
		if _, err := d.Lookup(context.Background(), "01ab"); !errors.Is(err, ErrGone) {
			t.Fatal(err)
		}
	}
	d, n := fake(&fakeConn{})
	if _, err := d.Lookup(context.Background(), "not hex"); !errors.Is(err, ErrGone) || *n != 0 {
		t.Fatal(err)
	}
	d, _ = fake(&fakeConn{searchErr: netErr})
	if _, err := d.Lookup(context.Background(), "01ab"); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	d, _ = fake(&fakeConn{entries: []*ldap.Entry{entryA(nil)}, chainErr: netErr})
	if _, err := d.Lookup(context.Background(), "01ab"); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}

func TestNewErrors(t *testing.T) {
	cfg := testCfg()
	cfg.URL = "ldap://%zz"
	if _, err := New(cfg); err == nil {
		t.Fatal("bad URL accepted")
	}
	cfg = testCfg()
	cfg.CAFile = filepath.Join(t.TempDir(), "missing.pem")
	if _, err := New(cfg); err == nil {
		t.Fatal("missing CA accepted")
	}
}

func TestTLSConfigInsecure(t *testing.T) {
	cfg := testCfg()
	tc, err := tlsConfig(cfg, "dc.x")
	if err != nil || tc.InsecureSkipVerify || tc.RootCAs != nil || tc.ServerName != "dc.x" || tc.MinVersion != tls.VersionTLS12 {
		t.Fatalf("%+v %v", tc, err)
	}
	_, pemBytes := selfSigned(t)
	cfg.CAFile = writeFile(t, pemBytes)
	cfg.TLSInsecure = true
	if tc, err = tlsConfig(cfg, "dc.x"); err != nil || !tc.InsecureSkipVerify || tc.RootCAs == nil {
		t.Fatalf("%+v %v", tc, err)
	}
}

func shortTimeout(t *testing.T) {
	old := timeout
	timeout = 500 * time.Millisecond
	t.Cleanup(func() { timeout = old })
}

func TestDialRefusesPlaintext(t *testing.T) {
	shortTimeout(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		b, _ := io.ReadAll(c) // until the client gives up and closes
		got <- b
	}()
	cfg := testCfg()
	cfg.URL = "ldap://" + l.Addr().String()
	d, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := d.Authenticate(context.Background(), "a", "pw"); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("took %v", time.Since(start))
	}
	b := <-got
	if !bytes.Contains(b, []byte("1.3.6.1.4.1.1466.20037")) || bytes.Contains(b, []byte("CN=svc")) || bytes.Contains(b, []byte("svcpw")) {
		t.Fatalf("sent %q", b)
	}
}

func selfSigned(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func writeFile(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTLSSelfSignedWithCA(t *testing.T) {
	shortTimeout(t)
	cert, pemBytes := selfSigned(t)
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() { // handshake, then answer nothing
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.(*tls.Conn).Handshake()
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	cfg := testCfg()
	cfg.URL = "ldaps://" + l.Addr().String()

	d, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Authenticate(context.Background(), "a", "pw")
	var cve *tls.CertificateVerificationError
	if !errors.Is(err, ErrUnavailable) || !errors.As(err, &cve) {
		t.Fatalf("no CA: %v", err)
	}

	for name, mod := range map[string]func(*config.LDAPConfig){
		"ca":       func(c *config.LDAPConfig) { c.CAFile = writeFile(t, pemBytes) },
		"insecure": func(c *config.LDAPConfig) { c.TLSInsecure = true },
	} {
		c := cfg
		mod(&c)
		d, err := New(c)
		if err != nil {
			t.Fatal(err)
		}
		cn, err := d.dial(context.Background())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		_ = cn.Close()
	}
}
