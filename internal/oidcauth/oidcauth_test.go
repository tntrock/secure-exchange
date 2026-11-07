package oidcauth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tntrock/secure-exchange/internal/config"
)

const redirect = "https://sx.test/api/auth/oidc/callback"

// idp is a fake OpenID provider (discovery, JWKS, token endpoint).
type idp struct {
	srv  *httptest.Server
	key  *rsa.PrivateKey
	caPE string

	mu            sync.Mutex
	claims        map[string]any // merged over the defaults; a nil value deletes the claim
	signKey       *rsa.PrivateKey
	tokenStatus   int
	tokenBody     string
	noIDToken     bool
	discoveryFail bool
	form          url.Values
	discoveries   int
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func newIDP(t *testing.T) *idp {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	i := &idp{key: key, signKey: key, claims: map[string]any{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		i.mu.Lock()
		i.discoveries++
		fail := i.discoveryFail
		i.mu.Unlock()
		if fail {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": i.srv.URL, "authorization_endpoint": i.srv.URL + "/authorize", "token_endpoint": i.srv.URL + "/token",
			"jwks_uri": i.srv.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "k1",
			"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		i.mu.Lock()
		defer i.mu.Unlock()
		i.form = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		if i.tokenStatus != 0 {
			w.WriteHeader(i.tokenStatus)
			_, _ = w.Write([]byte(i.tokenBody))
			return
		}
		resp := map[string]any{"access_token": "x", "token_type": "Bearer"}
		if !i.noIDToken {
			resp["id_token"] = i.sign()
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	i.srv = httptest.NewTLSServer(mux)
	t.Cleanup(i.srv.Close)
	i.caPE = filepath.Join(t.TempDir(), "ca.pem")
	pemb := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: i.srv.Certificate().Raw})
	if err := os.WriteFile(i.caPE, pemb, 0o600); err != nil {
		t.Fatal(err)
	}
	return i
}

// sign builds an RS256 ID token; the caller holds i.mu.
func (i *idp) sign() string {
	cl := map[string]any{"iss": i.srv.URL, "sub": "u1", "aud": "cid", "exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(), "nonce": "N", "email": "a@x.test", "name": "A"}
	for k, v := range i.claims {
		if v == nil {
			delete(cl, k)
		} else {
			cl[k] = v
		}
	}
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	p, _ := json.Marshal(cl)
	in := b64(h) + "." + b64(p)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, i.signKey, crypto.SHA256, sum[:])
	if err != nil {
		panic(err)
	}
	return in + "." + b64(sig)
}

func (i *idp) set(f func(*idp)) { i.mu.Lock(); f(i); i.mu.Unlock() }

func (i *idp) provider(t *testing.T, mod ...func(*config.OIDCConfig)) *Provider {
	t.Helper()
	cfg := config.OIDCConfig{Issuer: i.srv.URL, ClientID: "cid", ClientSecret: "sec", Scopes: "openid profile email",
		AdminClaim: "groups", AdminValue: "adm", CAFile: i.caPE}
	for _, m := range mod {
		m(&cfg)
	}
	p, err := New(cfg, redirect)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

var bg = context.Background()

func TestNewNoNetwork(t *testing.T) {
	p, err := New(config.OIDCConfig{Issuer: "https://127.0.0.1:1", ClientID: "c", ClientSecret: "s"}, redirect)
	if err != nil || p == nil {
		t.Fatalf("%v", err)
	}
	if _, err := New(config.OIDCConfig{Issuer: "https://x", CAFile: filepath.Join(t.TempDir(), "missing")}, redirect); err == nil {
		t.Fatal("bad CA accepted")
	}
}

func TestStartURL(t *testing.T) {
	i := newIDP(t)
	p := i.provider(t)
	raw, f, err := p.Start(bg)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	q := u.Query()
	sum := sha256.Sum256([]byte(f.Verifier))
	want := map[string]string{"response_type": "code", "client_id": "cid", "redirect_uri": redirect, "state": f.State,
		"nonce": f.Nonce, "code_challenge_method": "S256", "code_challenge": b64(sum[:])}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	if u.Host != i.srv.Listener.Addr().String() || u.Path != "/authorize" {
		t.Errorf("url %s", raw)
	}
	if q.Get("scope") != "openid profile email" {
		t.Errorf("scope %q", q.Get("scope"))
	}
	_, f2, _ := p.Start(bg)
	if f.State == f2.State || f.Nonce == f2.Nonce || f.Verifier == f2.Verifier || f.State == "" {
		t.Fatalf("flows not fresh: %+v %+v", f, f2)
	}
}

var flow = Flow{State: "S", Nonce: "N", Verifier: "V-erifier-0123456789012345678901234567890123456"}

func TestExchangeOK(t *testing.T) {
	i := newIDP(t)
	i.set(func(i *idp) { i.claims["groups"] = []string{"g1", "adm"} })
	got, err := i.provider(t).Exchange(bg, "the-code", flow)
	if err != nil {
		t.Fatal(err)
	}
	want := Identity{ExternalID: i.srv.URL + " u1", Email: "a@x.test", Name: "A", Admin: true}
	if got != want {
		t.Fatalf("got %+v", got)
	}
	if i.form.Get("code_verifier") != flow.Verifier || i.form.Get("code") != "the-code" || i.form.Get("redirect_uri") != redirect {
		t.Fatalf("token request %v", i.form)
	}
}

func TestExchangeRejects(t *testing.T) {
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	for name, mod := range map[string]func(*idp){
		"aud":       func(i *idp) { i.claims["aud"] = "someone-else" },
		"iss":       func(i *idp) { i.claims["iss"] = "https://evil.test" },
		"signature": func(i *idp) { i.signKey = other },
		"expired":   func(i *idp) { i.claims["exp"] = time.Now().Add(-time.Hour).Unix() },
		"nonce":     func(i *idp) { i.claims["nonce"] = "replayed" },
		"grant":     func(i *idp) { i.tokenStatus, i.tokenBody = 400, `{"error":"invalid_grant"}` },
		"no token":  func(i *idp) { i.noIDToken = true },
		"no sub":    func(i *idp) { i.claims["sub"] = nil },
	} {
		t.Run(name, func(t *testing.T) {
			i := newIDP(t)
			i.set(mod)
			if _, err := i.provider(t).Exchange(bg, "c", flow); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestExchangeUnavailable(t *testing.T) {
	for name, mod := range map[string]func(*idp){
		"500":            func(i *idp) { i.tokenStatus, i.tokenBody = 500, `oops` },
		"invalid_client": func(i *idp) { i.tokenStatus, i.tokenBody = 401, `{"error":"invalid_client"}` },
	} {
		t.Run(name, func(t *testing.T) {
			i := newIDP(t)
			i.set(mod)
			if _, err := i.provider(t).Exchange(bg, "c", flow); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	t.Run("closed", func(t *testing.T) {
		i := newIDP(t)
		p := i.provider(t)
		if _, _, err := p.Start(bg); err != nil { // cache discovery
			t.Fatal(err)
		}
		i.srv.Close()
		if _, err := p.Exchange(bg, "c", flow); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("undiscoverable", func(t *testing.T) {
		i := newIDP(t)
		i.set(func(i *idp) { i.discoveryFail = true })
		if _, err := i.provider(t).Exchange(bg, "c", flow); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestIdentityClaims(t *testing.T) {
	noAdmin := func(c *config.OIDCConfig) { c.AdminValue = "" }
	base := Identity{Email: "a@x.test", Name: "A"}
	with := func(f func(*Identity)) Identity { id := base; f(&id); return id }
	for _, tc := range []struct {
		name   string
		claims map[string]any
		cfg    func(*config.OIDCConfig)
		want   Identity
		err    error
	}{
		{name: "preferred_username", claims: map[string]any{"email": nil, "preferred_username": "p@x.test"}, want: with(func(i *Identity) { i.Email = "p@x.test" })},
		{name: "upn", claims: map[string]any{"email": nil, "upn": "u@x.test"}, want: with(func(i *Identity) { i.Email = "u@x.test" })},
		{name: "no email", claims: map[string]any{"email": nil}, err: ErrNoEmail},
		{name: "malformed email", claims: map[string]any{"email": "not-an-email@"}, err: ErrNoEmail},
		{name: "upn after non-email preferred_username", claims: map[string]any{"email": nil, "preferred_username": "alice", "upn": "a@x.test"}, want: with(func(i *Identity) { i.Email = "a@x.test" })},
		{name: "non-email preferred_username only", claims: map[string]any{"email": nil, "preferred_username": "alice"}, err: ErrNoEmail},
		{name: "name falls back to email", claims: map[string]any{"name": nil}, want: with(func(i *Identity) { i.Name = i.Email })},
		{name: "string claim", claims: map[string]any{"groups": "adm"}, want: with(func(i *Identity) { i.Admin = true })},
		{name: "string claim differs", claims: map[string]any{"groups": "other"}, want: base},
		{name: "array without value", claims: map[string]any{"groups": []string{"g1", "ADM"}}, want: base},
		{name: "array with non-strings", claims: map[string]any{"groups": []any{1, "adm"}}, want: with(func(i *Identity) { i.Admin = true })},
		{name: "empty admin value", claims: map[string]any{"groups": ""}, cfg: noAdmin, want: base},
		{name: "empty admin value vs empty element", claims: map[string]any{"groups": []string{""}}, cfg: noAdmin, want: base},
		{name: "custom claim", claims: map[string]any{"roles": []string{"adm"}}, cfg: func(c *config.OIDCConfig) { c.AdminClaim = "roles" }, want: with(func(i *Identity) { i.Admin = true })},
		{name: "overage", claims: map[string]any{"_claim_names": map[string]string{"groups": "src1"}, "_claim_sources": map[string]any{"src1": map[string]string{"endpoint": "https://graph.test/x"}}}, want: with(func(i *Identity) { i.GroupsOverage = true })},
		{name: "claim names for another claim", claims: map[string]any{"_claim_names": map[string]string{"x": "src1"}, "_claim_sources": map[string]any{"src1": map[string]string{"endpoint": "https://graph.test/x"}}}, want: base},
	} {
		t.Run(tc.name, func(t *testing.T) {
			i := newIDP(t)
			i.set(func(i *idp) { i.claims = tc.claims })
			var mod []func(*config.OIDCConfig)
			if tc.cfg != nil {
				mod = append(mod, tc.cfg)
			}
			got, err := i.provider(t, mod...).Exchange(bg, "c", flow)
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Fatalf("err = %v", err)
				}
				return
			}
			tc.want.ExternalID = i.srv.URL + " u1"
			if err != nil || got != tc.want {
				t.Fatalf("got %+v, %v; want %+v", got, err, tc.want)
			}
		})
	}
}

func TestDiscoveryRetried(t *testing.T) {
	i := newIDP(t)
	i.set(func(i *idp) { i.discoveryFail = true })
	p := i.provider(t)
	if _, _, err := p.Start(bg); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
	i.set(func(i *idp) { i.discoveryFail = false })
	for range 2 {
		if _, _, err := p.Start(bg); err != nil {
			t.Fatal(err)
		}
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.discoveries != 2 {
		t.Fatalf("discovery ran %d times, want 2 (one failure, one cached success)", i.discoveries)
	}
}

func TestInvalidClientLoggedAsError(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	i := newIDP(t)
	i.set(func(i *idp) { i.tokenStatus, i.tokenBody = 401, `{"error":"invalid_client"}` })
	if _, err := i.provider(t).Exchange(bg, "c", flow); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if out := buf.String(); !strings.Contains(out, "level=ERROR") || !strings.Contains(out, "SX_OIDC_CLIENT_SECRET") {
		t.Fatalf("log = %q", out)
	}
}
