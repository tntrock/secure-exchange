// Package oidcauth is an OpenID Connect relying party: Authorization Code flow
// with PKCE, state and nonce. It is provider-agnostic (Entra, Keycloak, ...).
// New does no network I/O; discovery runs on the first login and is retried
// until it succeeds, so an IdP outage never blocks startup.
package oidcauth

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/tntrock/secure-exchange/internal/config"
	"github.com/tntrock/secure-exchange/internal/mail"
)

var (
	// ErrUnavailable: discovery/JWKS/token endpoint unreachable or failing, or
	// the IdP rejected our client credentials (a configuration problem).
	ErrUnavailable = errors.New("oidc: identity provider unavailable")
	// ErrInvalid: bad code, or an ID token that fails verification.
	ErrInvalid = errors.New("oidc: invalid login response")
	ErrNoEmail = errors.New("oidc: account has no email")
)

// Flow is the per-login secret state, kept in a cookie between Start and Exchange.
type Flow struct{ State, Nonce, Verifier string }

type Identity struct {
	ExternalID, Email, Name string // ExternalID is "<iss> <sub>"
	Admin                   bool
	// GroupsOverage: the IdP omitted the admin claim and sent a pointer
	// (_claim_names) instead, so admin status could not be decided.
	GroupsOverage bool
}

type Provider struct {
	cfg    config.OIDCConfig
	redir  string
	client *http.Client

	mu   sync.Mutex
	prov *oidc.Provider
}

// New validates nothing over the network; cfg is already checked by config.Load.
func New(cfg config.OIDCConfig, redirectURL string) (*Provider, error) {
	c := &http.Client{Timeout: 10 * time.Second}
	if cfg.CAFile != "" {
		pool, err := config.CertPool(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		c.Transport = &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	}
	return &Provider{cfg: cfg, redir: redirectURL, client: c}, nil
}

func (p *Provider) discover(ctx context.Context) (*oidc.Provider, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.prov != nil {
		return p.prov, nil
	}
	prov, err := oidc.NewProvider(oidc.ClientContext(ctx, p.client), p.cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	p.prov = prov
	return prov, nil
}

func (p *Provider) oauth(prov *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{ClientID: p.cfg.ClientID, ClientSecret: p.cfg.ClientSecret, Endpoint: prov.Endpoint(),
		RedirectURL: p.redir, Scopes: strings.Fields(p.cfg.Scopes)}
}

func random() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // never fails (Go 1.24+)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Start returns the IdP authorization URL and the Flow to keep until Exchange.
func (p *Provider) Start(ctx context.Context) (string, Flow, error) {
	prov, err := p.discover(ctx)
	if err != nil {
		return "", Flow{}, err
	}
	f := Flow{State: random(), Nonce: random(), Verifier: oauth2.GenerateVerifier()}
	return p.oauth(prov).AuthCodeURL(f.State, oauth2.S256ChallengeOption(f.Verifier), oidc.Nonce(f.Nonce)), f, nil
}

// Exchange redeems the code and verifies the ID token (signature, iss, aud,
// exp, nonce) before mapping its claims.
func (p *Provider) Exchange(ctx context.Context, code string, f Flow) (Identity, error) {
	prov, err := p.discover(ctx)
	if err != nil {
		return Identity{}, err
	}
	ctx = oidc.ClientContext(ctx, p.client)
	tok, err := p.oauth(prov).Exchange(ctx, code, oauth2.VerifierOption(f.Verifier))
	if err != nil {
		var re *oauth2.RetrieveError
		if errors.As(err, &re) && re.ErrorCode == "invalid_client" {
			slog.Error("oidc: IdP rejected the client; check SX_OIDC_CLIENT_SECRET and its expiry", "err", err)
		}
		if !errors.As(err, &re) || re.ErrorCode == "invalid_client" || re.Response.StatusCode >= 500 {
			return Identity{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
		}
		return Identity{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return Identity{}, fmt.Errorf("%w: no id_token", ErrInvalid)
	}
	// A JWKS fetch failure here also lands in ErrInvalid; the user retries.
	idt, err := prov.Verifier(&oidc.Config{ClientID: p.cfg.ClientID}).Verify(ctx, raw)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if idt.Nonce != f.Nonce {
		return Identity{}, fmt.Errorf("%w: nonce mismatch", ErrInvalid)
	}
	var cl map[string]any
	if err := idt.Claims(&cl); err != nil {
		return Identity{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if idt.Subject == "" {
		return Identity{}, fmt.Errorf("%w: no sub", ErrInvalid)
	}
	id := Identity{ExternalID: idt.Issuer + " " + idt.Subject}
	for _, k := range []string{"email", "preferred_username", "upn"} {
		s, _ := cl[k].(string)
		if v, ok := mail.ValidAddress(s); ok {
			id.Email = v
			break
		}
	}
	if id.Email == "" {
		return Identity{}, ErrNoEmail
	}
	if id.Name, _ = cl["name"].(string); id.Name == "" {
		id.Name = id.Email
	}
	if want := p.cfg.AdminValue; want != "" {
		switch v := cl[p.cfg.AdminClaim].(type) {
		case string:
			id.Admin = v == want
		case []any:
			for _, e := range v {
				if s, _ := e.(string); s == want {
					id.Admin = true
				}
			}
		}
	}
	if names, _ := cl["_claim_names"].(map[string]any); names != nil {
		_, id.GroupsOverage = names[p.cfg.AdminClaim]
	}
	return id, nil
}
