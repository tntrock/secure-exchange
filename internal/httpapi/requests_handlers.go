package httpapi

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/intake"
)

const intakeCookieName = "sx_intake"

func intakeErr(w http.ResponseWriter, err error) {
	var ve *intake.ValidationError
	switch {
	case errors.As(err, &ve):
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "invalid", "field": ve.Field, "code": ve.Code})
	case errors.Is(err, intake.ErrNotFound):
		writeJSON(w, http.StatusNotFound, errBody("not_found"))
	case errors.Is(err, intake.ErrGone):
		writeJSON(w, http.StatusGone, errBody("gone"))
	case errors.Is(err, intake.ErrBadCode):
		writeJSON(w, http.StatusUnauthorized, errBody("invalid_code"))
	case errors.Is(err, intake.ErrUnauthorized):
		writeJSON(w, http.StatusUnauthorized, errBody("unauthorized"))
	case errors.Is(err, intake.ErrExtNotAllowed):
		writeJSON(w, http.StatusForbidden, errBody("ext_not_allowed"))
	case errors.Is(err, intake.ErrTooManyFiles):
		writeJSON(w, http.StatusForbidden, errBody("too_many_files"))
	case errors.Is(err, intake.ErrQuotaExceeded):
		writeJSON(w, http.StatusForbidden, errBody("quota_exceeded"))
	default:
		slog.Error("upload request", "err", err)
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
	}
}

func (s *server) requestEvent(u *auth.User, action string, id uuid.UUID) audit.Event {
	return audit.Event{ActorID: u.ID.String(), Action: action, TargetType: "request", TargetID: id.String(), Result: "ok"}
}

func requestBase(q *intake.Request) map[string]any {
	return map[string]any{"id": q.ID, "created_at": ts(&q.CreatedAt), "expires_at": ts(&q.ExpiresAt), "revoked": q.RevokedAt != nil,
		"expired": !q.ExpiresAt.After(time.Now()), "file_count": q.FileCount, "total_bytes": q.TotalBytes,
		"max_files": q.MaxFiles, "max_total_bytes": q.MaxTotalBytes, "uploader_count": q.UploaderCount}
}

func (s *server) requestDetail(r *http.Request, q *intake.Request) (map[string]any, error) {
	m := requestBase(q)
	m["url"], m["message"], m["allowed_exts"] = q.URL, q.Message, q.AllowedExts
	ups := make([]map[string]any, len(q.Uploaders))
	for i, u := range q.Uploaders {
		ups[i] = map[string]any{"id": u.ID, "email": u.Email, "first_opened_at": ts(u.FirstOpenedAt), "last_access_at": ts(u.LastAccessAt)}
	}
	m["uploaders"] = ups
	rows, err := s.Pool.Query(r.Context(), `SELECT f.id, f.name, f.size, u.email, f.created_at, f.scan_status, f.scan_result, f.deleted_at IS NOT NULL
		FROM files f JOIN request_uploaders u ON u.id = f.uploader_id
		WHERE f.request_id = $1
		ORDER BY f.created_at DESC`, q.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	files := []map[string]any{}
	for rows.Next() {
		var id uuid.UUID
		var name, email, status string
		var result *string
		var size int64
		var created time.Time
		var deleted bool
		if err := rows.Scan(&id, &name, &size, &email, &created, &status, &result, &deleted); err != nil {
			return nil, err
		}
		files = append(files, map[string]any{"id": id, "name": name, "size": size, "uploader_email": email, "created_at": ts(&created),
			"scan_status": status, "scan_result": result, "deleted": deleted})
	}
	m["files"] = files
	return m, rows.Err()
}

func (s *server) createRequest(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Emails        []string  `json:"emails"`
		ExpiresAt     time.Time `json:"expires_at"`
		MaxFiles      int       `json:"max_files"`
		MaxTotalBytes int64     `json:"max_total_bytes"`
		AllowedExts   []string  `json:"allowed_exts"`
		Message       string    `json:"message"`
	}
	if !readJSONMax(w, r, &in, 64<<10) {
		return
	}
	u := auth.UserFrom(r.Context())
	q, err := s.Requests.Create(r.Context(), u, intake.CreateInput{Emails: in.Emails, ExpiresAt: in.ExpiresAt, MaxFiles: in.MaxFiles,
		MaxTotalBytes: in.MaxTotalBytes, AllowedExts: in.AllowedExts, Message: in.Message})
	if err != nil {
		intakeErr(w, err)
		return
	}
	s.record(r, s.requestEvent(u, audit.ActRequestCreate, q.ID))
	m, err := s.requestDetail(r, q)
	if err != nil {
		intakeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, m)
}

func (s *server) listRequests(w http.ResponseWriter, r *http.Request) {
	qs, err := s.Requests.List(r.Context(), auth.UserFrom(r.Context()).ID)
	if err != nil {
		intakeErr(w, err)
		return
	}
	out := make([]map[string]any, len(qs))
	for i := range qs {
		out[i] = requestBase(&qs[i])
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) getRequest(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	q, err := s.Requests.Get(r.Context(), auth.UserFrom(r.Context()).ID, id) // the owner check
	if err != nil {
		intakeErr(w, err)
		return
	}
	m, err := s.requestDetail(r, q)
	if err != nil {
		intakeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *server) revokeRequest(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	u := auth.UserFrom(r.Context())
	if err := s.Requests.Revoke(r.Context(), u.ID, id); err != nil {
		intakeErr(w, err)
		return
	}
	s.record(r, s.requestEvent(u, audit.ActRequestRevoke, id))
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) uploaderLanding(w http.ResponseWriter, r *http.Request) {
	q, err := s.Requests.Landing(r.Context(), r.PathValue("token"), s.addr(r))
	if err != nil {
		intakeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"owner_name": q.OwnerName, "message": q.Message, "expires_at": ts(&q.ExpiresAt),
		"max_files": q.MaxFiles, "max_total_bytes": q.MaxTotalBytes, "allowed_exts": q.AllowedExts})
}

func (s *server) uploaderCode(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email string `json:"email"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	token, email := r.PathValue("token"), recipientEmail(in.Email)
	if !s.codeLimit.allow(tokenKey(token) + email) {
		tooMany(w)
		return
	}
	q, err := s.Requests.Landing(r.Context(), token, s.addr(r))
	if err != nil {
		intakeErr(w, err)
		return
	}
	sent, err := s.Requests.RequestCode(r.Context(), token, email, s.addr(r))
	if err != nil {
		intakeErr(w, err)
		return
	}
	result := "ok"
	if !sent {
		result = "ignored"
	}
	s.record(r, audit.Event{ActorType: "uploader", ActorID: email, Action: audit.ActRequestOTPRequest, TargetType: "request", TargetID: q.ID.String(), Result: result})
	writeJSON(w, http.StatusOK, map[string]bool{"sent": true})
}

func (s *server) uploaderVerify(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	token, email := r.PathValue("token"), recipientEmail(in.Email)
	q, err := s.Requests.Landing(r.Context(), token, s.addr(r))
	if err != nil {
		intakeErr(w, err)
		return
	}
	session, a, err := s.Requests.VerifyCode(r.Context(), token, email, in.Code, s.addr(r), UserAgent(r))
	ev := audit.Event{ActorType: "uploader", ActorID: email, Action: audit.ActRequestOTPVerify, TargetType: "request", TargetID: q.ID.String(), Result: "ok"}
	if errors.Is(err, intake.ErrBadCode) {
		ev.Result, ev.Detail = "fail", map[string]any{"reason": "invalid_code"}
	}
	if err == nil || ev.Result == "fail" {
		s.record(r, ev)
	}
	if err != nil {
		intakeErr(w, err)
		return
	}
	body, err := s.uploaderFiles(r, a)
	if err != nil {
		intakeErr(w, err)
		return
	}
	// the session never outlives the request, so the cookie's MaxAge follows the same bound
	maxAge := int(time.Until(a.Request.ExpiresAt).Seconds())
	if d := int((24 * time.Hour).Seconds()); maxAge > d {
		maxAge = d
	}
	http.SetCookie(w, &http.Cookie{Name: intakeCookieName, Value: session, Path: "/", MaxAge: max(maxAge, 1),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, body)
}

// uploaderFiles lists the caller's own live uploads and what is left of the request's limits.
func (s *server) uploaderFiles(r *http.Request, a *intake.Access) (map[string]any, error) {
	rows, err := s.Pool.Query(r.Context(), `SELECT id, name, size, created_at FROM files
		WHERE request_id = $1 AND uploader_id = $2 AND deleted_at IS NULL ORDER BY created_at DESC`, a.Request.ID, a.Uploader.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	files := []map[string]any{}
	for rows.Next() {
		var id uuid.UUID
		var name string
		var size int64
		var created time.Time
		if err := rows.Scan(&id, &name, &size, &created); err != nil {
			return nil, err
		}
		files = append(files, map[string]any{"id": id, "name": name, "size": size, "created_at": ts(&created)})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	n, b, err := intake.Usage(r.Context(), s.Pool, a.Request.ID)
	if err != nil {
		return nil, err
	}
	return map[string]any{"files": files, "files_left": max(a.Request.MaxFiles-n, 0), "bytes_left": max(a.Request.MaxTotalBytes-b, 0)}, nil
}

func (s *server) listUploaderFiles(w http.ResponseWriter, r *http.Request) {
	body, err := s.uploaderFiles(r, intake.AccessFrom(r.Context()))
	if err != nil {
		intakeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *server) uploaderLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(intakeCookieName); err == nil && c.Value != "" {
		if err := s.Requests.Logout(r.Context(), c.Value); err != nil {
			intakeErr(w, err)
			return
		}
	}
	http.SetCookie(w, &http.Cookie{Name: intakeCookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

// requireUploader needs a live uploader session for the request named by {token}.
func (s *server) requireUploader(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(intakeCookieName)
		if err != nil || c.Value == "" {
			writeJSON(w, http.StatusUnauthorized, errBody("unauthorized"))
			return
		}
		a, err := s.Requests.Authorize(r.Context(), c.Value, s.addr(r))
		if err != nil {
			intakeErr(w, err)
			return
		}
		var same bool
		if err := s.Pool.QueryRow(r.Context(), `SELECT token_hash = $2 FROM upload_requests WHERE id = $1`, a.Request.ID, []byte(tokenKey(r.PathValue("token")))).
			Scan(&same); err != nil {
			intakeErr(w, err)
			return
		}
		if !same {
			writeJSON(w, http.StatusUnauthorized, errBody("unauthorized"))
			return
		}
		next(w, r.WithContext(intake.WithAccess(r.Context(), a)))
	})
}
