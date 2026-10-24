package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/mail"
	"github.com/tntrock/secure-exchange/internal/share"
)

const shareCookieName = "sx_share"

type accessKey struct{}

func accessFrom(ctx context.Context) *share.Access { return ctx.Value(accessKey{}).(*share.Access) }

// addr is the client IP for share access checks; an unparsable one matches no allow list.
func (s *server) addr(r *http.Request) netip.Addr {
	a, _ := netip.ParseAddr(s.ip(r))
	return a
}

// recipientEmail normalises email the way share.Service does, capped for audit and limiter keys (P8).
func recipientEmail(email string) string {
	if e, ok := mail.ValidAddress(email); ok {
		return e
	}
	return Truncate(strings.ToLower(strings.TrimSpace(email)), 254)
}

func recipientErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, share.ErrNotFound):
		writeJSON(w, http.StatusNotFound, errBody("not_found"))
	case errors.Is(err, share.ErrGone):
		writeJSON(w, http.StatusGone, errBody("gone"))
	case errors.Is(err, share.ErrIPDenied):
		writeJSON(w, http.StatusForbidden, errBody("ip_denied"))
	case errors.Is(err, share.ErrBadCode):
		writeJSON(w, http.StatusUnauthorized, errBody("invalid_code"))
	case errors.Is(err, share.ErrViewLimit):
		writeJSON(w, http.StatusForbidden, errBody("view_limit"))
	case errors.Is(err, share.ErrUnauthorized):
		writeJSON(w, http.StatusUnauthorized, errBody("unauthorized"))
	default:
		slog.Error("recipient request", "err", err)
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
	}
}

// bufferedWriter holds a response back so padded can release it later.
type bufferedWriter struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
}

func (b *bufferedWriter) WriteHeader(code int) {
	if b.status == 0 {
		b.status = code
	}
}

func (b *bufferedWriter) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	return b.buf.Write(p)
}

// padded sends every response, 429s and errors included, no sooner than CodeDelay after the
// request started, so listed and unlisted addresses take the same time (P10).
func (s *server) padded(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		bw := &bufferedWriter{ResponseWriter: w}
		next.ServeHTTP(bw, r)
		if left := s.CodeDelay - time.Since(start); left > 0 {
			time.Sleep(left)
		} else if s.CodeDelay > 0 {
			slog.Warn("recipient code request exceeded timing pad", "route", r.Pattern, "elapsed", time.Since(start))
		}
		if bw.status == 0 {
			bw.status = http.StatusOK
		}
		w.WriteHeader(bw.status)
		w.Write(bw.buf.Bytes())
	})
}

func (s *server) recipientLanding(w http.ResponseWriter, r *http.Request) {
	sh, err := s.Shares.Landing(r.Context(), r.PathValue("token"), s.addr(r))
	if err != nil {
		recipientErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"owner_name": sh.OwnerName, "message": sh.Message, "expires_at": ts(&sh.ExpiresAt)})
}

func tokenKey(token string) string {
	h := sha256.Sum256([]byte(token))
	return string(h[:])
}

func (s *server) requestCode(w http.ResponseWriter, r *http.Request) {
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
	sh, err := s.Shares.Landing(r.Context(), token, s.addr(r))
	if err != nil {
		recipientErr(w, err)
		return
	}
	sent, err := s.Shares.RequestCode(r.Context(), token, email, s.addr(r))
	if err != nil {
		recipientErr(w, err)
		return
	}
	result := "ok"
	if !sent {
		result = "ignored"
	}
	s.record(r, audit.Event{ActorType: "recipient", ActorID: email, Action: audit.ActShareOTPRequest, TargetType: "share", TargetID: sh.ID.String(), Result: result})
	writeJSON(w, http.StatusOK, map[string]bool{"sent": true})
}

func (s *server) verifyCode(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	token, email := r.PathValue("token"), recipientEmail(in.Email)
	sh, err := s.Shares.Landing(r.Context(), token, s.addr(r))
	if err != nil {
		recipientErr(w, err)
		return
	}
	session, a, err := s.Shares.VerifyCode(r.Context(), token, email, in.Code, s.addr(r), UserAgent(r))
	ev := audit.Event{ActorType: "recipient", ActorID: email, Action: audit.ActShareOTPVerify, TargetType: "share", TargetID: sh.ID.String(), Result: "ok"}
	switch {
	case err == nil:
		s.record(r, ev)
	case errors.Is(err, share.ErrBadCode), errors.Is(err, share.ErrViewLimit):
		reason := "invalid_code"
		if errors.Is(err, share.ErrViewLimit) {
			reason = "view_limit"
		}
		ev.Result, ev.Detail = "fail", map[string]any{"reason": reason}
		s.record(r, ev)
		fallthrough
	default:
		recipientErr(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: shareCookieName, Value: session, Path: "/", MaxAge: 3600,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, http.StatusOK, recipientFiles(a))
}

// requireRecipient needs a live recipient session for the share named by {token}.
func (s *server) requireRecipient(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(shareCookieName)
		if err != nil || c.Value == "" {
			writeJSON(w, http.StatusUnauthorized, errBody("unauthorized"))
			return
		}
		a, err := s.Shares.Authorize(r.Context(), c.Value, s.addr(r))
		if err != nil {
			recipientErr(w, err)
			return
		}
		var same bool
		if err := s.Pool.QueryRow(r.Context(), `SELECT token_hash = $2 FROM shares WHERE id = $1`, a.Share.ID, []byte(tokenKey(r.PathValue("token")))).
			Scan(&same); err != nil {
			recipientErr(w, err) // 500 + log; the error text carries no token
			return
		}
		if !same {
			writeJSON(w, http.StatusUnauthorized, errBody("unauthorized"))
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), accessKey{}, a)))
	})
}

func recipientFiles(a *share.Access) map[string]any {
	sh := a.Share
	files := make([]map[string]any, len(sh.Files))
	for i, f := range sh.Files {
		files[i] = map[string]any{"id": f.ID, "name": f.Name, "size": f.Size, "available": !f.Deleted}
	}
	return map[string]any{"message": sh.Message, "expires_at": ts(&sh.ExpiresAt), "allow_download": sh.AllowDownload,
		"watermark": sh.Watermark, "files": files}
}

func (s *server) listRecipientFiles(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, recipientFiles(accessFrom(r.Context())))
}

func (s *server) recipientDownload(w http.ResponseWriter, r *http.Request) {
	a := accessFrom(r.Context())
	fid, ok := pathUUID(w, r, "fid")
	if !ok {
		return
	}
	f := fileRow{id: fid}
	err := s.Pool.QueryRow(r.Context(), `SELECT f.name, f.size, f.sha256, f.wrapped_dek, f.key_id, f.storage_key
		FROM share_files sf JOIN files f ON f.id = sf.file_id
		WHERE sf.share_id = $1 AND sf.file_id = $2 AND f.deleted_at IS NULL`, a.Share.ID, fid).
		Scan(&f.name, &f.size, &f.sum, &f.wrappedDEK, &f.keyID, &f.key)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, errBody("not_found"))
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return
	}
	if !a.Share.AllowDownload {
		writeJSON(w, http.StatusForbidden, errBody("view_only"))
		return
	}
	st := s.serveFile(w, r, &f, audit.Event{ActorType: "recipient", ActorID: a.Recipient.ID.String(), Detail: map[string]any{"share_id": a.Share.ID.String()}})
	if r.Method == http.MethodGet && (st == http.StatusOK || st == http.StatusPartialContent) {
		if err := s.Shares.RecordDownload(context.WithoutCancel(r.Context()), a, fid); err != nil {
			slog.Error("record share download", "share", a.Share.ID, "file", fid, "err", err)
		}
	}
}

func (s *server) recipientLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(shareCookieName); err == nil && c.Value != "" {
		if err := s.Shares.Logout(r.Context(), c.Value); err != nil {
			writeJSON(w, http.StatusInternalServerError, errBody("internal"))
			return
		}
	}
	http.SetCookie(w, &http.Cookie{Name: shareCookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}
