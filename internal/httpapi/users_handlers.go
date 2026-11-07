package httpapi

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/tntrock/secure-exchange/internal/account"
	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/auth"
)

func accountErr(w http.ResponseWriter, err error) {
	var ve *account.ValidationError
	status, code := http.StatusInternalServerError, "internal"
	switch {
	case errors.As(err, &ve):
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "validation", "field": ve.Field, "code": ve.Code})
		return
	case errors.Is(err, account.ErrNotFound):
		status, code = http.StatusNotFound, "not_found"
	case errors.Is(err, account.ErrEmailTaken):
		status, code = http.StatusConflict, "email_taken"
	case errors.Is(err, account.ErrState):
		status, code = http.StatusConflict, "wrong_state"
	case errors.Is(err, account.ErrLastAdmin):
		status, code = http.StatusConflict, "last_admin"
	case errors.Is(err, account.ErrExternal):
		status, code = http.StatusConflict, "external_account"
	case errors.Is(err, account.ErrInviteGone):
		status, code = http.StatusGone, "gone"
	case errors.Is(err, account.ErrBadCode):
		status, code = http.StatusUnauthorized, "invalid_code"
	case errors.Is(err, account.ErrTOTPRequired):
		status, code = http.StatusBadRequest, "totp_required"
	default:
		slog.Error("account", "err", err)
	}
	writeJSON(w, status, errBody(code))
}

func accountBody(a *account.Account) map[string]any {
	return map[string]any{"id": a.ID, "email": a.Email, "display_name": a.DisplayName, "role": a.Role, "auth_source": a.AuthSource,
		"status": a.Status, "totp_enabled": a.TOTPEnabled, "last_login_at": ts(a.LastLoginAt), "created_at": ts(a.CreatedAt)}
}

func (s *server) listUsers(w http.ResponseWriter, r *http.Request) {
	as, err := s.Accounts.List(r.Context())
	if err != nil {
		accountErr(w, err)
		return
	}
	out := make([]map[string]any, len(as))
	for i := range as {
		out[i] = accountBody(&as[i])
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
		Role        string `json:"role"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	u := auth.UserFrom(r.Context())
	a, err := s.Accounts.Create(r.Context(), u, account.CreateInput{Email: in.Email, DisplayName: in.DisplayName, Role: in.Role})
	if err != nil {
		accountErr(w, err)
		return
	}
	s.record(r, vendorEvent(u, audit.ActUserCreate, a.ID))
	writeJSON(w, http.StatusCreated, accountBody(a))
}

// userAction serves a /api/admin/users/{id} change: do runs, then the action is audited and 204 sent.
func (s *server) userAction(action string, do func(*http.Request, *auth.User, uuid.UUID) (map[string]any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathUUID(w, r, "id")
		if !ok {
			return
		}
		u := auth.UserFrom(r.Context())
		detail, err := do(r, u, id)
		if err != nil {
			accountErr(w, err)
			return
		}
		ev := vendorEvent(u, action, id)
		ev.Detail = detail
		s.record(r, ev)
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *server) setUserDisabled(disabled bool) func(*http.Request, *auth.User, uuid.UUID) (map[string]any, error) {
	return func(r *http.Request, _ *auth.User, id uuid.UUID) (map[string]any, error) {
		return nil, s.Accounts.SetDisabled(r.Context(), id, disabled)
	}
}

func (s *server) setUserRole(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Role string `json:"role"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	s.userAction(audit.ActUserRole, func(r *http.Request, _ *auth.User, id uuid.UUID) (map[string]any, error) {
		cur, err := s.Users.ByID(r.Context(), id)
		if errors.Is(err, auth.ErrNotFound) {
			return nil, account.ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		return map[string]any{"from": cur.Role, "to": in.Role}, s.Accounts.SetRole(r.Context(), id, in.Role)
	})(w, r)
}

func (s *server) resetUserTOTP(r *http.Request, u *auth.User, id uuid.UUID) (map[string]any, error) {
	return nil, s.Accounts.ResetTOTP(r.Context(), u, id)
}

func (s *server) reinviteUser(r *http.Request, u *auth.User, id uuid.UUID) (map[string]any, error) {
	return nil, s.Accounts.Reinvite(r.Context(), u, id)
}

func (s *server) activateInfo(w http.ResponseWriter, r *http.Request) {
	email, required, url, err := s.Accounts.InviteInfo(r.Context(), r.PathValue("token"))
	if err != nil {
		accountErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"email": email, "totp_required": required, "otpauth_url": url})
}

func (s *server) activateStaff(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	id, err := s.Accounts.Activate(r.Context(), r.PathValue("token"), in.Password, in.Code)
	if err != nil && !errors.Is(err, account.ErrBadCode) {
		accountErr(w, err)
		return
	}
	result := "ok"
	if err != nil {
		result = "fail"
	}
	s.record(r, audit.Event{ActorID: id.String(), Action: audit.ActUserActivate, TargetType: "user", TargetID: id.String(), Result: result})
	if err != nil {
		accountErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// enrolUser returns the half-logged-in user who must still enrol TOTP, or writes 401.
func (s *server) enrolUser(w http.ResponseWriter, r *http.Request) (token string, u *auth.User, ok bool) {
	token, se, ok := s.session(r)
	if ok && !se.MFAPassed {
		var err error
		u, err = s.Users.ByID(r.Context(), se.UserID)
		ok = err == nil && u.Active(time.Now()) && !u.TOTPEnabled && u.Role != "vendor" && u.AuthSource == "local"
	} else {
		ok = false
	}
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errBody("unauthorized"))
		return "", nil, false
	}
	if !s.accountLimit.allow("user:" + u.ID.String()) {
		tooMany(w)
		return "", nil, false
	}
	return token, u, true
}

func (s *server) totpSetupPending(w http.ResponseWriter, r *http.Request) {
	_, u, ok := s.enrolUser(w, r)
	if !ok {
		return
	}
	url, err := s.Users.PendingTOTP(r.Context(), u.ID)
	if err == nil && url == "" {
		url, err = s.Users.BeginTOTP(r.Context(), u.ID)
	}
	if err != nil {
		slog.Error("totp setup", "err", err)
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"otpauth_url": url})
}

func (s *server) totpEnroll(w http.ResponseWriter, r *http.Request) {
	var in struct{ Code string }
	if !readJSON(w, r, &in) {
		return
	}
	token, u, ok := s.enrolUser(w, r)
	if !ok {
		return
	}
	beforeEnableTOTP()
	err := s.Users.EnableTOTP(r.Context(), u.ID, in.Code)
	if errors.Is(err, auth.ErrTOTPAlreadyEnabled) { // lost a race with another enrolment
		writeJSON(w, http.StatusUnauthorized, errBody("unauthorized"))
		return
	}
	if errors.Is(err, auth.ErrBadCode) {
		s.record(r, audit.Event{Action: audit.ActLoginFail, ActorID: u.ID.String(), Result: "fail", Detail: map[string]any{"stage": "totp_enrol"}})
		writeJSON(w, http.StatusUnauthorized, errBody("invalid_code"))
		return
	}
	if err == nil {
		err = s.Sessions.MarkMFA(r.Context(), token, s.SessionTTL)
	}
	if err != nil {
		slog.Error("totp enrol", "err", err)
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return
	}
	s.touchLogin(r, u.ID)
	s.record(r, audit.Event{Action: audit.ActTOTPEnable, ActorID: u.ID.String(), Result: "ok"})
	s.record(r, audit.Event{Action: audit.ActLoginOK, ActorID: u.ID.String(), Result: "ok", Detail: map[string]any{"stage": "totp_enrol"}})
	writeJSON(w, http.StatusOK, map[string]bool{"mfa_required": false})
}

// beforeEnableTOTP lets tests run a concurrent enrolment just before the enabling update.
var beforeEnableTOTP = func() {}
