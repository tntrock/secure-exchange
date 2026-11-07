package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/vendor"
)

func vendorErr(w http.ResponseWriter, err error) {
	var ve *vendor.ValidationError
	switch {
	case errors.As(err, &ve):
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "validation", "field": ve.Field, "code": ve.Code})
	case errors.Is(err, vendor.ErrNotFound):
		writeJSON(w, http.StatusNotFound, errBody("not_found"))
	case errors.Is(err, vendor.ErrForbidden):
		writeJSON(w, http.StatusForbidden, errBody("forbidden"))
	case errors.Is(err, vendor.ErrEmailTaken):
		writeJSON(w, http.StatusConflict, errBody("email_taken"))
	case errors.Is(err, vendor.ErrBadStatus):
		writeJSON(w, http.StatusConflict, errBody("bad_status"))
	case errors.Is(err, vendor.ErrState):
		writeJSON(w, http.StatusConflict, errBody("wrong_state"))
	case errors.Is(err, vendor.ErrInviteGone):
		writeJSON(w, http.StatusGone, errBody("gone"))
	case errors.Is(err, vendor.ErrBadCode):
		writeJSON(w, http.StatusUnauthorized, errBody("invalid_code"))
	default:
		slog.Error("vendor", "err", err)
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
	}
}

func vendorEvent(u *auth.User, action string, id uuid.UUID) audit.Event {
	return audit.Event{ActorID: u.ID.String(), Action: action, TargetType: "user", TargetID: id.String(), Result: "ok"}
}

func vendorBody(v *vendor.Vendor, caller *auth.User) map[string]any {
	return map[string]any{"id": v.ID, "email": v.Email, "display_name": v.DisplayName, "org": v.Org, "status": v.Status,
		"expires_at": ts(&v.ExpiresAt), "created_by_name": v.CreatedByName, "created_at": ts(&v.CreatedAt),
		"can_manage": caller.Role == "admin" || (v.CreatedByID != nil && *v.CreatedByID == caller.ID)}
}

func (s *server) listVendors(w http.ResponseWriter, r *http.Request) {
	vs, err := s.Vendors.List(r.Context(), r.URL.Query().Get("active") == "1")
	if err != nil {
		vendorErr(w, err)
		return
	}
	u := auth.UserFrom(r.Context())
	out := make([]map[string]any, len(vs))
	for i := range vs {
		out[i] = vendorBody(&vs[i], u)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) createVendor(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email       string    `json:"email"`
		DisplayName string    `json:"display_name"`
		Org         string    `json:"org"`
		ExpiresAt   time.Time `json:"expires_at"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	u := auth.UserFrom(r.Context())
	v, err := s.Vendors.Create(r.Context(), u, vendor.CreateInput{Email: in.Email, DisplayName: in.DisplayName, Org: in.Org, ExpiresAt: in.ExpiresAt})
	if err != nil {
		vendorErr(w, err)
		return
	}
	ev := vendorEvent(u, audit.ActVendorCreate, v.ID)
	if v.Reopened {
		ev.Detail = map[string]any{"reopened": true}
	}
	s.record(r, ev)
	writeJSON(w, http.StatusCreated, vendorBody(v, u))
}

// vendorAction serves a /api/vendors/{id} change: do runs as the caller, then the action is audited and 204 sent.
func (s *server) vendorAction(action string, do func(context.Context, *auth.User, uuid.UUID) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathUUID(w, r, "id")
		if !ok {
			return
		}
		u := auth.UserFrom(r.Context())
		if err := do(r.Context(), u, id); err != nil {
			vendorErr(w, err)
			return
		}
		s.record(r, vendorEvent(u, action, id))
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *server) setDisabled(disabled bool) func(context.Context, *auth.User, uuid.UUID) error {
	return func(ctx context.Context, u *auth.User, id uuid.UUID) error {
		return s.Vendors.SetDisabled(ctx, u, id, disabled)
	}
}

func (s *server) setVendorExpiry(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ExpiresAt time.Time `json:"expires_at"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	s.vendorAction(audit.ActVendorExpiry, func(ctx context.Context, u *auth.User, id uuid.UUID) error {
		return s.Vendors.SetExpiry(ctx, u, id, in.ExpiresAt)
	})(w, r)
}

func (s *server) inviteInfo(w http.ResponseWriter, r *http.Request) {
	email, url, err := s.Vendors.InviteInfo(r.Context(), r.PathValue("token"))
	if err != nil {
		vendorErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"email": email, "otpauth_url": url})
}

func (s *server) activateVendor(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	id, err := s.Vendors.Activate(r.Context(), r.PathValue("token"), in.Password, in.Code)
	result := "ok"
	if errors.Is(err, vendor.ErrBadCode) {
		result = "fail"
	} else if err != nil {
		vendorErr(w, err)
		return
	}
	s.record(r, audit.Event{ActorType: "vendor", ActorID: id.String(), Action: audit.ActVendorActivate, TargetType: "user", TargetID: id.String(), Result: result})
	if err != nil {
		vendorErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
