package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/mark"
	"github.com/tntrock/secure-exchange/internal/preview"
)

func (s *server) listFiles(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	rows, err := s.Pool.Query(r.Context(), `SELECT f.id, f.name, f.content_type, f.size, f.sha256, f.created_at,
			COALESCE(p.status, 'unsupported'), COALESCE(p.kind, 'none'),
			f.scan_status, f.scan_result, f.request_id
		FROM files f LEFT JOIN file_previews p ON p.file_id = f.id
		WHERE f.owner_id = $1 AND f.deleted_at IS NULL ORDER BY f.created_at DESC`, u.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return
	}
	defer rows.Close()
	type item struct {
		ID            uuid.UUID  `json:"id"`
		Name          string     `json:"name"`
		ContentType   string     `json:"content_type"`
		Size          int64      `json:"size"`
		SHA256        string     `json:"sha256"`
		CreatedAt     string     `json:"created_at"`
		PreviewStatus string     `json:"preview_status"`
		PreviewKind   string     `json:"preview_kind"`
		ScanStatus    string     `json:"scan_status"`
		ScanResult    string     `json:"scan_result"`
		RequestID     *uuid.UUID `json:"request_id"`
		Mark          fileMark   `json:"mark"`
	}
	out := []item{}
	for rows.Next() {
		var it item
		var sum []byte
		var at time.Time
		if err := rows.Scan(&it.ID, &it.Name, &it.ContentType, &it.Size, &sum, &at, &it.PreviewStatus, &it.PreviewKind, &it.ScanStatus, &it.ScanResult, &it.RequestID); err != nil {
			writeJSON(w, http.StatusInternalServerError, errBody("internal"))
			return
		}
		it.SHA256, it.CreatedAt = fmt.Sprintf("%x", sum), at.UTC().Format(time.RFC3339)
		p := &preview.Preview{Kind: preview.Kind(it.PreviewKind), Status: preview.Status(it.PreviewStatus)}
		wm, plain := s.listPlan(it.Name, it.Size, p, true), s.listPlan(it.Name, it.Size, p, false)
		it.Mark = fileMark{wm.Method, plain.Method, wm.Degraded}
		out = append(out, it)
	}
	if rows.Err() != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type fileRow struct {
	id         uuid.UUID
	name, key  string
	size       int64
	sum        []byte
	wrappedDEK []byte
	keyID      int
	scan       string
}

// ownFile loads a live file owned by the caller; otherwise it writes 404 and returns false.
func (s *server) ownFile(w http.ResponseWriter, r *http.Request) (*fileRow, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("not_found"))
		return nil, false
	}
	f := fileRow{id: id}
	err = s.Pool.QueryRow(r.Context(), `SELECT name, size, sha256, wrapped_dek, key_id, storage_key, scan_status FROM files
		WHERE id = $1 AND owner_id = $2 AND deleted_at IS NULL`, id, auth.UserFrom(r.Context()).ID).
		Scan(&f.name, &f.size, &f.sum, &f.wrappedDEK, &f.keyID, &f.key, &f.scan)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, errBody("not_found"))
		return nil, false
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return nil, false
	}
	return &f, true
}

func (s *server) downloadFile(w http.ResponseWriter, r *http.Request) {
	f, ok := s.ownCleanFile(w, r)
	if !ok {
		return
	}
	rs, err := s.openPlain(r.Context(), f)
	if err != nil {
		slog.Error("open file", "file", f.id, "err", err)
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return
	}
	defer rs.Close()
	s.serveFile(w, r, f, rs, audit.Event{ActorID: auth.UserFrom(r.Context()).ID.String()})
}

func (s *server) deleteFile(w http.ResponseWriter, r *http.Request) {
	f, ok := s.ownFile(w, r)
	if !ok {
		return
	}
	u := auth.UserFrom(r.Context())
	tag, err := s.Pool.Exec(r.Context(), `UPDATE files SET deleted_at = now() WHERE id = $1 AND owner_id = $2 AND deleted_at IS NULL`, f.id, u.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return
	}
	if tag.RowsAffected() == 0 {
		writeJSON(w, http.StatusNotFound, errBody("not_found"))
		return
	}
	if err := s.Store.Delete(context.WithoutCancel(r.Context()), f.key); err != nil { // the row is already marked deleted
		slog.Error("blob delete", "file", f.id, "err", err)
	}
	if err := preview.DeleteItems(context.WithoutCancel(r.Context()), s.Pool, s.Store, f.id); err != nil {
		slog.Error("preview items delete", "file", f.id, "err", err)
	}
	s.record(r, audit.Event{ActorID: u.ID.String(), Action: audit.ActDelete, TargetType: "file", TargetID: f.id.String(), Result: "ok"})
	w.WriteHeader(http.StatusNoContent)
}

// contentDisposition builds `attachment` with an ASCII fallback and an RFC 5987 filename*.
func contentDisposition(name string) string {
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '/' || r == '\\' {
			return -1
		}
		return r
	}, name)
	fallback := strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			return '_'
		}
		return r
	}, name)
	var enc strings.Builder
	for _, b := range []byte(name) {
		if b < 0x80 && (b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.IndexByte("!#$&+-.^_`|~", b) >= 0) {
			enc.WriteByte(b)
		} else {
			fmt.Fprintf(&enc, "%%%02X", b)
		}
	}
	return `attachment; filename="` + fallback + `"; filename*=UTF-8''` + enc.String()
}

// statusWriter records the status code ServeContent chose and the body bytes written.
type statusWriter struct {
	http.ResponseWriter
	status int
	n      int64
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.n += int64(n)
	return n, err
}

type fileMark struct {
	Watermark mark.Method `json:"watermark"`
	Plain     mark.Method `json:"plain"`
	Degraded  bool        `json:"degraded"`
}

// listPlan is mark.Decide for file lists, which decrypt nothing: the preview kind stands in for the
// first bytes (Classify gives a .pdf kind pages only with the %PDF- magic) and pixels are unknown (0),
// so an image is degraded only by MaxBytes.
// ponytail: images are told jpeg/png by extension, so a gif named .png lists as markable; the
// download re-decides from the real bytes. Store a sniffed type on files if that ever matters.
func (s *server) listPlan(name string, size int64, p *preview.Preview, watermark bool) mark.Plan {
	var head []byte
	switch {
	case p.Kind == preview.KindPages:
		head = []byte("%PDF-")
	case p.Kind == preview.KindImage && strings.EqualFold(filepath.Ext(name), ".png"):
		head = []byte("\x89PNG\r\n\x1a\n")
	case p.Kind == preview.KindImage && (strings.EqualFold(filepath.Ext(name), ".jpg") || strings.EqualFold(filepath.Ext(name), ".jpeg")):
		head = []byte("\xff\xd8\xff")
	}
	return mark.Decide(name, head, size, 0, p, watermark, s.Mark)
}

// ownCleanFile is ownFile for reads: files not yet scanned, or quarantined, are refused.
func (s *server) ownCleanFile(w http.ResponseWriter, r *http.Request) (*fileRow, bool) {
	f, ok := s.ownFile(w, r)
	if !ok {
		return nil, false
	}
	switch f.scan {
	case "pending":
		writeJSON(w, http.StatusConflict, errBody("scan_pending"))
	case "infected":
		writeJSON(w, http.StatusForbidden, errBody("quarantined"))
	case "error":
		writeJSON(w, http.StatusForbidden, errBody("scan_failed"))
	default:
		return f, true
	}
	return nil, false
}
