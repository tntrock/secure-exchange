package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/auth"
)

// record appends an audit event with the request's client IP and UA filled in.
func (s *server) record(r *http.Request, e audit.Event) {
	e.IP, e.UserAgent = s.ip(r), UserAgent(r)
	if e.ActorType == "" {
		e.ActorType = "user"
	}
	// the event happened even if the client has since hung up
	if err := s.Audit.Append(context.WithoutCancel(r.Context()), e); err != nil {
		slog.Error("audit append", "action", e.Action, "err", err)
	}
}

func (s *server) setSessionCookie(w http.ResponseWriter, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: token, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	var in struct{ Email, Password string }
	if !readJSON(w, r, &in) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(in.Email))
	if !s.accountLimit.allow("email:" + email) {
		tooMany(w)
		return
	}
	u, err := s.Users.ByEmail(r.Context(), email)
	if err != nil && !errors.Is(err, auth.ErrNotFound) {
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return
	}
	hash := s.dummyHash // run argon2 even for unknown users so timing does not reveal them
	if u != nil && u.PasswordHash != "" {
		hash = u.PasswordHash
	}
	pwOK := auth.VerifyPassword(hash, in.Password)
	if u == nil || u.PasswordHash == "" || !pwOK || u.Disabled {
		ev := audit.Event{Action: audit.ActLoginFail, Result: "fail", Detail: map[string]any{"email": Truncate(email, maxEmailLen), "stage": "password"}}
		if u != nil {
			ev.ActorID = u.ID.String()
		}
		s.record(r, ev)
		writeJSON(w, http.StatusUnauthorized, errBody("invalid_credentials"))
		return
	}
	if !u.Active(time.Now()) { // pending, rejected, expired, or a vendor still without TOTP
		s.record(r, audit.Event{Action: audit.ActLoginFail, ActorID: u.ID.String(), Result: "fail",
			Detail: map[string]any{"email": Truncate(email, maxEmailLen), "stage": "inactive"}})
		writeJSON(w, http.StatusUnauthorized, errBody("invalid_credentials"))
		return
	}
	rl, err := s.Rules.Get(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return
	}
	if u.Role == "vendor" && !rl.IPAllowed(s.addr(r)) {
		s.record(r, audit.Event{Action: audit.ActLoginFail, ActorID: u.ID.String(), Result: "fail",
			Detail: map[string]any{"email": Truncate(email, maxEmailLen), "stage": "ip_denied", "reason": "ip_denied"}})
		writeJSON(w, http.StatusUnauthorized, errBody("invalid_credentials")) // same as a bad password: no oracle
		return
	}
	// site rules force local staff and admins to enrol TOTP before the session is usable
	setup := !u.TOTPEnabled && u.Role != "vendor" && u.AuthSource == "local" && rl.ForceTOTP
	full := !u.TOTPEnabled && !setup
	ttl := s.SessionTTL
	if !full {
		ttl = auth.PendingMFATTL
	}
	token, err := s.Sessions.Create(r.Context(), u.ID, full, s.ip(r), UserAgent(r), ttl)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return
	}
	s.setSessionCookie(w, token, int(ttl.Seconds()))
	if full { // fully logged in; otherwise the OK event is written after the code / enrolment step
		s.touchLogin(r, u.ID)
		s.record(r, audit.Event{Action: audit.ActLoginOK, ActorID: u.ID.String(), Result: "ok"})
	}
	writeJSON(w, http.StatusOK, map[string]bool{"mfa_required": u.TOTPEnabled, "totp_setup_required": setup})
}

func (s *server) totp(w http.ResponseWriter, r *http.Request) {
	token, se, ok := s.session(r)
	if !ok || se.MFAPassed {
		writeJSON(w, http.StatusUnauthorized, errBody("unauthorized"))
		return
	}
	var in struct{ Code string }
	if !readJSON(w, r, &in) {
		return
	}
	if !s.accountLimit.allow("user:" + se.UserID.String()) {
		tooMany(w)
		return
	}
	u, err := s.Users.ByID(r.Context(), se.UserID)
	if err != nil || !u.Active(time.Now()) || !u.TOTPEnabled || !s.Users.CheckTOTP(r.Context(), u.ID, in.Code) {
		s.record(r, audit.Event{Action: audit.ActLoginFail, ActorID: se.UserID.String(), Result: "fail", Detail: map[string]any{"stage": "totp"}})
		writeJSON(w, http.StatusUnauthorized, errBody("invalid_code"))
		return
	}
	if err := s.Sessions.MarkMFA(r.Context(), token, s.SessionTTL); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return
	}
	s.setSessionCookie(w, token, int(s.SessionTTL.Seconds())) // the half-session cookie was short-lived
	s.touchLogin(r, u.ID)
	s.record(r, audit.Event{Action: audit.ActLoginOK, ActorID: u.ID.String(), Result: "ok", Detail: map[string]any{"stage": "totp"}})
	writeJSON(w, http.StatusOK, map[string]bool{"mfa_required": false})
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	if token, se, ok := s.session(r); ok {
		if err := s.Sessions.Revoke(r.Context(), token); err != nil {
			writeJSON(w, http.StatusInternalServerError, errBody("internal"))
			return
		}
		s.record(r, audit.Event{Action: audit.ActLogout, ActorID: se.UserID.String(), Result: "ok"})
	}
	s.setSessionCookie(w, "", -1)
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) me(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	out := map[string]any{"id": u.ID, "email": u.Email, "display_name": u.DisplayName,
		"role": u.Role, "auth_source": u.AuthSource, "totp_enabled": u.TOTPEnabled, "expires_at": u.ExpiresAt}
	if u.Role == "admin" {
		out["version"] = s.Version
	}
	if u.OrgID != nil {
		var org string
		if err := s.Pool.QueryRow(r.Context(), `SELECT name FROM vendor_orgs WHERE id=$1`, u.OrgID).Scan(&org); err != nil {
			writeJSON(w, http.StatusInternalServerError, errBody("internal"))
			return
		}
		out["org"] = org
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) totpSetup(w http.ResponseWriter, r *http.Request) {
	url, err := s.Users.BeginTOTP(r.Context(), auth.UserFrom(r.Context()).ID)
	if errors.Is(err, auth.ErrTOTPAlreadyEnabled) {
		writeJSON(w, http.StatusConflict, errBody("totp_already_enabled"))
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"otpauth_url": url})
}

func (s *server) totpEnable(w http.ResponseWriter, r *http.Request) {
	var in struct{ Code string }
	if !readJSON(w, r, &in) {
		return
	}
	u := auth.UserFrom(r.Context())
	if u.TOTPEnabled {
		writeJSON(w, http.StatusConflict, errBody("totp_already_enabled"))
		return
	}
	beforeEnableTOTP()
	err := s.Users.EnableTOTP(r.Context(), u.ID, in.Code)
	if errors.Is(err, auth.ErrTOTPAlreadyEnabled) {
		writeJSON(w, http.StatusConflict, errBody("totp_already_enabled"))
		return
	}
	if errors.Is(err, auth.ErrBadCode) {
		writeJSON(w, http.StatusBadRequest, errBody("invalid_code"))
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return
	}
	s.record(r, audit.Event{Action: audit.ActTOTPEnable, ActorID: u.ID.String(), Result: "ok"})
	w.WriteHeader(http.StatusNoContent)
}

const (
	maxUALen    = 512
	maxEmailLen = 254 // RFC 5321 path limit
)

// Truncate drops invalid UTF-8 from s and cuts it to at most n bytes without splitting a sequence.
// Client-controlled strings go through it before reaching the append-only audit log or sessions.
func Truncate(s string, n int) string {
	s = strings.ToValidUTF8(s, "")
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// UserAgent is the request User-Agent capped for storage.
func UserAgent(r *http.Request) string { return Truncate(r.UserAgent(), maxUALen) }

// touchLogin stamps last_login_at; a failure is logged, never fatal to the login.
func (s *server) touchLogin(r *http.Request, id uuid.UUID) {
	if err := s.Users.TouchLogin(r.Context(), id); err != nil {
		slog.Error("touch login", "err", err)
	}
}

// localOnly refuses externally managed (LDAP) accounts, which have no TOTP of their own here.
func localOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if auth.UserFrom(r.Context()).AuthSource != "local" {
			writeJSON(w, http.StatusConflict, errBody("external_account")) // as 7.2 reports account.ErrExternal
			return
		}
		next(w, r)
	}
}
