package httpapi

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/auth"
)

// record appends an audit event with the request's client IP and UA filled in.
func (s *server) record(r *http.Request, e audit.Event) {
	e.IP, e.UserAgent = s.ip(r), UserAgent(r)
	if e.ActorType == "" {
		e.ActorType = "user"
	}
	if err := s.Audit.Append(r.Context(), e); err != nil {
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
	token, err := s.Sessions.Create(r.Context(), u.ID, !u.TOTPEnabled, s.ip(r), UserAgent(r), s.SessionTTL)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return
	}
	s.setSessionCookie(w, token, int(s.SessionTTL.Seconds()))
	if !u.TOTPEnabled { // fully logged in; with TOTP the OK event is written after the code step
		s.record(r, audit.Event{Action: audit.ActLoginOK, ActorID: u.ID.String(), Result: "ok"})
	}
	writeJSON(w, http.StatusOK, map[string]bool{"mfa_required": u.TOTPEnabled})
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
	if err != nil || u.Disabled || !u.TOTPEnabled || !s.Users.CheckTOTP(r.Context(), u.ID, in.Code) {
		s.record(r, audit.Event{Action: audit.ActLoginFail, ActorID: se.UserID.String(), Result: "fail", Detail: map[string]any{"stage": "totp"}})
		writeJSON(w, http.StatusUnauthorized, errBody("invalid_code"))
		return
	}
	if err := s.Sessions.MarkMFA(r.Context(), token); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return
	}
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
	writeJSON(w, http.StatusOK, map[string]any{"id": u.ID, "email": u.Email, "display_name": u.DisplayName,
		"role": u.Role, "totp_enabled": u.TOTPEnabled})
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
	err := s.Users.EnableTOTP(r.Context(), u.ID, in.Code)
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

// Truncate cuts s to at most n bytes without splitting a UTF-8 sequence.
// Client-controlled strings go through it before reaching the append-only audit log or sessions.
func Truncate(s string, n int) string {
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
