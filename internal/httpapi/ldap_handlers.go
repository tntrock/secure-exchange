package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/ldapauth"
)

// Directory is the AD/LDAP login directory; *ldapauth.Directory satisfies it.
type Directory interface {
	Authenticate(ctx context.Context, username, password string) (ldapauth.Identity, error)
	Lookup(ctx context.Context, externalID string) (ldapauth.Identity, error)
}

func (s *server) authMethods(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ldap": s.LDAP != nil, "oidc": s.OIDC != nil, "oidc_label": s.OIDCLabel})
}

func (s *server) ldapLogin(w http.ResponseWriter, r *http.Request) {
	if s.LDAP == nil {
		writeJSON(w, http.StatusNotFound, errBody("not_found"))
		return
	}
	var in struct{ Username, Password string }
	if !readJSON(w, r, &in) {
		return
	}
	username := strings.TrimSpace(in.Username)
	if !s.accountLimit.allow("ldap:" + strings.ToLower(username)) {
		tooMany(w)
		return
	}
	detail := map[string]any{"source": "ldap", "username": Truncate(username, maxEmailLen)}
	fail := func(actor, stage string, status int, code string) {
		detail["stage"] = stage
		s.record(r, audit.Event{Action: audit.ActLoginFail, ActorID: actor, Result: "fail", Detail: detail})
		writeJSON(w, status, errBody(code))
	}
	id, err := s.LDAP.Authenticate(r.Context(), username, in.Password)
	switch {
	case errors.Is(err, ldapauth.ErrInvalidCredentials):
		fail("", "password", http.StatusUnauthorized, "invalid_credentials")
		return
	case errors.Is(err, ldapauth.ErrDisabled):
		fail("", "ldap_disabled", http.StatusUnauthorized, "invalid_credentials")
		return
	case errors.Is(err, ldapauth.ErrNoEmail):
		fail("", "ldap_no_email", http.StatusUnauthorized, "invalid_credentials")
		return
	case err != nil: // unavailable, or anything unexpected: fail closed
		if errors.Is(err, ldapauth.ErrCertificate) {
			detail["reason"] = "certificate"
		}
		slog.Warn("ldap login", "err", err)
		fail("", "ldap_unavailable", http.StatusServiceUnavailable, "directory_unavailable")
		return
	}
	u, prevRole, err := s.Users.UpsertExternal(r.Context(), "ldap", id.ExternalID, id.Email, id.Name, id.Admin)
	if errors.Is(err, auth.ErrEmailTaken) {
		detail["external_id"] = id.ExternalID // lets an admin re-key the old row (see the admin manual)
		fail("", "email_conflict", http.StatusConflict, "email_conflict")
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return
	}
	if !u.Active(time.Now()) { // disabled here by an admin, whatever AD says
		fail(u.ID.String(), "disabled", http.StatusUnauthorized, "invalid_credentials")
		return
	}
	if err := s.finishExternalLogin(r, w, u, prevRole, detail); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"mfa_required": false, "totp_setup_required": false})
}

// recheck re-reads an LDAP user from the directory once every LDAPRecheck per session and returns the
// refreshed user. Any failure ends the session (fail closed) and returns nil.
func (s *server) recheck(r *http.Request, token string, u *auth.User) *auth.User {
	// a failed claim re-checks anyway rather than skip it
	if claimed, err := s.Sessions.ClaimCheck(r.Context(), token, s.LDAPRecheck); err == nil && !claimed {
		return u
	}
	if s.LDAP == nil { // LDAP turned off since the login
		s.endSession(r, token, u, "ldap_unavailable", false)
		return nil
	}
	id, err := s.LDAP.Lookup(r.Context(), u.ExternalID)
	if errors.Is(err, ldapauth.ErrGone) {
		s.endSession(r, token, u, "ldap_gone", true)
		return nil
	}
	if err != nil {
		slog.Warn("ldap recheck", "err", err)
		s.endSession(r, token, u, "ldap_unavailable", false)
		return nil
	}
	// a lookup may lack attributes the login had; keep what is stored
	if id.Email == "" {
		id.Email = u.Email
	}
	if id.Name == "" {
		id.Name = u.DisplayName
	}
	nu, prevRole, err := s.Users.UpsertExternal(r.Context(), "ldap", u.ExternalID, id.Email, id.Name, id.Admin)
	if err != nil {
		slog.Error("ldap recheck update", "err", err)
		s.endSession(r, token, u, "ldap_error", false)
		return nil
	}
	if prevRole != "" && prevRole != nu.Role {
		s.record(r, audit.Event{ActorType: "system", Action: audit.ActUserRole, TargetType: "user", TargetID: nu.ID.String(), Result: "ok",
			Detail: map[string]any{"source": "ldap", "role_from": prevRole, "role_to": nu.Role, "stage": "recheck"}})
	}
	return nu
}

// endSession revokes this session (or all of the user's) and audits why.
func (s *server) endSession(r *http.Request, token string, u *auth.User, reason string, all bool) {
	var err error
	if all {
		err = s.Sessions.RevokeAllForUser(r.Context(), u.ID)
	} else {
		err = s.Sessions.Revoke(r.Context(), token)
	}
	if err != nil {
		slog.Error("end session", "err", err)
	}
	s.record(r, audit.Event{Action: audit.ActSessionEnd, ActorID: u.ID.String(), Result: "ok", Detail: map[string]any{"reason": reason}})
}
