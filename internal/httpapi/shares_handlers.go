package httpapi

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/mark"
	"github.com/tntrock/secure-exchange/internal/preview"
	"github.com/tntrock/secure-exchange/internal/share"
)

func ts(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format(time.RFC3339)
	return &s
}

// shareErr maps service errors to HTTP; it reports whether err was handled.
func shareErr(w http.ResponseWriter, err error) {
	var ve *share.ValidationError
	switch {
	case errors.As(err, &ve):
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "validation", "field": ve.Field, "code": ve.Code})
	case errors.Is(err, share.ErrNotFound):
		writeJSON(w, http.StatusNotFound, errBody("not_found"))
	case errors.Is(err, share.ErrRevoked):
		writeJSON(w, http.StatusConflict, errBody("revoked"))
	case errors.Is(err, share.ErrExpired):
		writeJSON(w, http.StatusConflict, errBody("expired"))
	default:
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
	}
}

func (s *server) shareEvent(u *auth.User, action string, id uuid.UUID, detail map[string]any) audit.Event {
	return audit.Event{ActorID: u.ID.String(), Action: action, TargetType: "share", TargetID: id.String(), Result: "ok", Detail: detail}
}

type recipientJSON struct {
	ID            uuid.UUID `json:"id"`
	Email         string    `json:"email"`
	Revoked       bool      `json:"revoked"`
	FirstOpenedAt *string   `json:"first_opened_at"`
	LastAccessAt  *string   `json:"last_access_at"`
}

func shareBase(sh *share.Share) map[string]any {
	now := time.Now()
	return map[string]any{"id": sh.ID, "created_at": ts(&sh.CreatedAt), "expires_at": ts(&sh.ExpiresAt), "revoked": sh.RevokedAt != nil,
		"expired": !sh.ExpiresAt.After(now), "max_views": sh.MaxViews, "view_count": sh.ViewCount}
}

func shareDetail(sh *share.Share) map[string]any {
	m := shareBase(sh)
	m["message"], m["allow_download"], m["watermark"] = sh.Message, sh.AllowDownload, sh.Watermark
	ips := make([]string, len(sh.IPAllow))
	for i, p := range sh.IPAllow {
		ips[i] = p.String()
	}
	m["ip_allow"] = ips
	files := make([]map[string]any, len(sh.Files))
	for i, f := range sh.Files {
		files[i] = map[string]any{"id": f.ID, "name": f.Name, "size": f.Size, "deleted": f.Deleted}
	}
	m["files"] = files
	rs := make([]recipientJSON, len(sh.Recipients))
	for i, r := range sh.Recipients {
		rs[i] = recipientJSON{r.ID, r.Email, r.RevokedAt != nil, ts(r.FirstOpenedAt), ts(r.LastAccessAt)}
	}
	m["recipients"] = rs
	return m
}

func (s *server) createShare(w http.ResponseWriter, r *http.Request) {
	var in struct {
		FileIDs       []uuid.UUID `json:"file_ids"`
		Emails        []string    `json:"emails"`
		AllowDownload bool        `json:"allow_download"`
		Watermark     bool        `json:"watermark"`
		ExpiresAt     time.Time   `json:"expires_at"`
		MaxViews      *int        `json:"max_views"`
		IPAllow       []string    `json:"ip_allow"`
		Message       string      `json:"message"`
	}
	if !readJSONMax(w, r, &in, 64<<10) {
		return
	}
	u := auth.UserFrom(r.Context())
	if s.Mark.Policy == "block" && in.AllowDownload && in.Watermark {
		bad, err := s.unmarkable(r.Context(), u.ID, in.FileIDs)
		if err != nil {
			slog.Error("unmarkable check", "err", err)
			writeJSON(w, http.StatusInternalServerError, errBody("internal"))
			return
		}
		if len(bad) > 0 {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "unmarkable", "file_ids": bad})
			return
		}
	}
	sh, err := s.Shares.Create(r.Context(), u, share.CreateInput{FileIDs: in.FileIDs, Emails: in.Emails, AllowDownload: in.AllowDownload,
		Watermark: in.Watermark, ExpiresAt: in.ExpiresAt, MaxViews: in.MaxViews, IPAllow: in.IPAllow, Message: in.Message})
	if err != nil {
		shareErr(w, err)
		return
	}
	s.record(r, s.shareEvent(u, audit.ActShareCreate, sh.ID, map[string]any{"recipient_count": len(sh.Recipients), "file_count": len(sh.Files)}))
	writeJSON(w, http.StatusCreated, shareDetail(sh))
}

func (s *server) listShares(w http.ResponseWriter, r *http.Request) {
	shs, err := s.Shares.List(r.Context(), auth.UserFrom(r.Context()).ID)
	if err != nil {
		shareErr(w, err)
		return
	}
	out := make([]map[string]any, len(shs))
	for i := range shs {
		m := shareBase(&shs[i])
		m["file_count"], m["recipient_count"] = shs[i].FileCount, shs[i].RecipientCount
		out[i] = m
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) getShare(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	sh, err := s.Shares.Get(r.Context(), auth.UserFrom(r.Context()).ID, id)
	if err != nil {
		shareErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, shareDetail(sh))
}

func (s *server) revokeShare(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	u := auth.UserFrom(r.Context())
	if err := s.Shares.Revoke(r.Context(), u.ID, id); err != nil {
		shareErr(w, err)
		return
	}
	s.record(r, s.shareEvent(u, audit.ActShareRevoke, id, nil))
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) addRecipients(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var in struct {
		Emails []string `json:"emails"`
	}
	if !readJSONMax(w, r, &in, 64<<10) {
		return
	}
	u := auth.UserFrom(r.Context())
	added, err := s.Shares.AddRecipients(r.Context(), u, id, in.Emails)
	if err != nil {
		shareErr(w, err)
		return
	}
	out := make([]recipientJSON, len(added))
	for i, a := range added {
		out[i] = recipientJSON{ID: a.ID, Email: a.Email}
		s.record(r, s.shareEvent(u, audit.ActShareRecipientAdd, id, map[string]any{"recipient_id": a.ID}))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) revokeRecipient(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	rid, ok := pathUUID(w, r, "rid")
	if !ok {
		return
	}
	u := auth.UserFrom(r.Context())
	if err := s.Shares.RevokeRecipient(r.Context(), u.ID, id, rid); err != nil {
		shareErr(w, err)
		return
	}
	s.record(r, s.shareEvent(u, audit.ActShareRecipientRevoke, id, map[string]any{"recipient_id": rid}))
	w.WriteHeader(http.StatusNoContent)
}

// pathUUID parses a path value; a malformed id is a 404.
func pathUUID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue(name))
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("not_found"))
	}
	return id, err == nil
}

// unmarkable returns the caller's live files among ids whose watermarked download would fall back
// (mark.Plan.Degraded). Pixels are not read here, so an image over Mark.MaxPixels is only refused at
// download. Ids that are not the caller's are left for Shares.Create to reject.
// ponytail: SX_UNMARKABLE_POLICY moves to the admin UI in phase 7.
func (s *server) unmarkable(ctx context.Context, owner uuid.UUID, ids []uuid.UUID) ([]uuid.UUID, error) {
	rows, err := s.Pool.Query(ctx, `SELECT f.id, f.name, f.size, f.sha256, f.wrapped_dek, f.key_id, f.storage_key, p.kind, p.status
		FROM files f LEFT JOIN file_previews p ON p.file_id = f.id
		WHERE f.id = ANY($1) AND f.owner_id = $2 AND f.deleted_at IS NULL`, ids, owner)
	if err != nil {
		return nil, err
	}
	type file struct {
		fileRow
		p *preview.Preview
	}
	var files []file
	for rows.Next() {
		var f file
		var kind, status *string
		if err := rows.Scan(&f.id, &f.name, &f.size, &f.sum, &f.wrappedDEK, &f.keyID, &f.key, &kind, &status); err != nil {
			rows.Close()
			return nil, err
		}
		if kind != nil {
			f.p = &preview.Preview{Kind: preview.Kind(*kind), Status: preview.Status(*status)}
		}
		files = append(files, f)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	bad := []uuid.UUID{}
	for _, f := range files {
		head, err := s.head(ctx, &f.fileRow)
		if err != nil {
			return nil, err
		}
		if mark.Decide(f.name, head, f.size, 0, f.p, true, s.Mark).Degraded {
			bad = append(bad, f.id)
		}
	}
	return bad, nil
}

// head reads the first preview.HeadLen plaintext bytes of f.
func (s *server) head(ctx context.Context, f *fileRow) ([]byte, error) {
	rs, err := s.openPlain(ctx, f)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	return readHead(rs, f.size)
}

func readHead(r io.Reader, size int64) ([]byte, error) {
	head := make([]byte, min(preview.HeadLen, size))
	_, err := io.ReadFull(r, head)
	return head, err
}
