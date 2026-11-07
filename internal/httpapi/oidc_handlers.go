package httpapi

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/oidcauth"
)

// OIDCProvider is the OpenID Connect login; *oidcauth.Provider satisfies it.
type OIDCProvider interface {
	Start(ctx context.Context) (string, oidcauth.Flow, error)
	Exchange(ctx context.Context, code string, f oidcauth.Flow) (oidcauth.Identity, error)
}

const (
	oidcCookie     = "sx_oidc"
	oidcCookiePath = "/api/auth/oidc"
	oidcFlowTTL    = 600
)

// setFlowCookie stores the flow for the callback. It must be Lax: the IdP reaches the callback by a
// cross-site top-level GET, which a Strict cookie would not accompany.
func setFlowCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: value, Path: oidcCookiePath, MaxAge: maxAge,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

// flowFromCookie parses state.nonce.verifier; any missing or empty part is rejected.
func flowFromCookie(r *http.Request) (oidcauth.Flow, bool) {
	c, err := r.Cookie(oidcCookie)
	if err != nil {
		return oidcauth.Flow{}, false
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return oidcauth.Flow{}, false
	}
	return oidcauth.Flow{State: parts[0], Nonce: parts[1], Verifier: parts[2]}, true
}

func (s *server) oidcStart(w http.ResponseWriter, r *http.Request) {
	if s.OIDC == nil {
		writeJSON(w, http.StatusNotFound, errBody("not_found"))
		return
	}
	loc, f, err := s.OIDC.Start(r.Context())
	if err != nil {
		slog.Warn("oidc start", "err", err)
		s.record(r, audit.Event{Action: audit.ActLoginFail, Result: "fail", Detail: map[string]any{"source": "oidc", "stage": "oidc_unavailable"}})
		http.Redirect(w, r, "/login?oidc_error=unavailable", http.StatusFound)
		return
	}
	setFlowCookie(w, f.State+"."+f.Nonce+"."+f.Verifier, oidcFlowTTL)
	http.Redirect(w, r, loc, http.StatusFound)
}

func (s *server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	if s.OIDC == nil {
		writeJSON(w, http.StatusNotFound, errBody("not_found"))
		return
	}
	flow, haveFlow := flowFromCookie(r)
	setFlowCookie(w, "", -1) // single use, whatever happens next
	detail := map[string]any{"source": "oidc"}
	fail := func(actor, stage, code string) {
		detail["stage"] = stage
		s.record(r, audit.Event{Action: audit.ActLoginFail, ActorID: actor, Result: "fail", Detail: detail})
		http.Redirect(w, r, "/login?oidc_error="+code, http.StatusFound)
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		detail["idp_error"] = Truncate(e, 64)
		fail("", "oidc_denied", "denied")
		return
	}
	if !haveFlow || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(flow.State)) != 1 {
		fail("", "oidc_state", "invalid")
		return
	}
	id, err := s.OIDC.Exchange(r.Context(), q.Get("code"), flow)
	switch {
	case errors.Is(err, oidcauth.ErrInvalid):
		fail("", "oidc_token", "invalid")
		return
	case errors.Is(err, oidcauth.ErrNoEmail):
		fail("", "oidc_no_email", "invalid")
		return
	case err != nil: // unavailable, or anything unexpected: fail closed
		slog.Warn("oidc callback", "err", err)
		fail("", "oidc_unavailable", "unavailable")
		return
	}
	detail["email"] = Truncate(id.Email, maxEmailLen)
	if id.GroupsOverage {
		detail["groups_overage"] = true
	}
	u, prevRole, err := s.Users.UpsertExternal(r.Context(), "oidc", id.ExternalID, id.Email, id.Name, id.Admin)
	if errors.Is(err, auth.ErrEmailTaken) {
		detail["external_id"] = id.ExternalID // lets an admin re-key the old row (see the admin manual)
		fail("", "email_conflict", "email_conflict")
		return
	}
	if err != nil {
		slog.Error("oidc upsert", "err", err)
		fail("", "db", "unavailable")
		return
	}
	if !u.Active(time.Now()) { // disabled here by an admin, whatever the IdP says
		fail(u.ID.String(), "disabled", "invalid")
		return
	}
	if err := s.finishExternalLogin(r, w, u, prevRole, detail); err != nil {
		slog.Error("oidc session", "err", err)
		fail(u.ID.String(), "db", "unavailable")
		return
	}
	http.Redirect(w, r, "/files", http.StatusFound)
}

// finishExternalLogin opens the session for an LDAP or OIDC user and audits the login.
func (s *server) finishExternalLogin(r *http.Request, w http.ResponseWriter, u *auth.User, prevRole string, detail map[string]any) error {
	token, err := s.Sessions.Create(r.Context(), u.ID, true, s.ip(r), UserAgent(r), s.SessionTTL)
	if err != nil {
		return err
	}
	s.setSessionCookie(w, token, int(s.SessionTTL.Seconds()))
	s.touchLogin(r, u.ID)
	if prevRole != "" && prevRole != u.Role {
		detail["role_from"], detail["role_to"] = prevRole, u.Role
	}
	s.record(r, audit.Event{Action: audit.ActLoginOK, ActorID: u.ID.String(), Result: "ok", Detail: detail})
	return nil
}
