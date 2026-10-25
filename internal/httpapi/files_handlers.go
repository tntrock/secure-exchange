package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/preview"
)

func (s *server) listFiles(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	rows, err := s.Pool.Query(r.Context(), `SELECT id, name, content_type, size, sha256, created_at
		FROM files WHERE owner_id = $1 AND deleted_at IS NULL ORDER BY created_at DESC`, u.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return
	}
	defer rows.Close()
	type item struct {
		ID          uuid.UUID `json:"id"`
		Name        string    `json:"name"`
		ContentType string    `json:"content_type"`
		Size        int64     `json:"size"`
		SHA256      string    `json:"sha256"`
		CreatedAt   string    `json:"created_at"`
	}
	out := []item{}
	for rows.Next() {
		var it item
		var sum []byte
		var at time.Time
		if err := rows.Scan(&it.ID, &it.Name, &it.ContentType, &it.Size, &sum, &at); err != nil {
			writeJSON(w, http.StatusInternalServerError, errBody("internal"))
			return
		}
		it.SHA256, it.CreatedAt = fmt.Sprintf("%x", sum), at.UTC().Format(time.RFC3339)
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
}

// ownFile loads a live file owned by the caller; otherwise it writes 404 and returns false.
func (s *server) ownFile(w http.ResponseWriter, r *http.Request) (*fileRow, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("not_found"))
		return nil, false
	}
	f := fileRow{id: id}
	err = s.Pool.QueryRow(r.Context(), `SELECT name, size, sha256, wrapped_dek, key_id, storage_key FROM files
		WHERE id = $1 AND owner_id = $2 AND deleted_at IS NULL`, id, auth.UserFrom(r.Context()).ID).
		Scan(&f.name, &f.size, &f.sum, &f.wrappedDEK, &f.keyID, &f.key)
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
	f, ok := s.ownFile(w, r)
	if !ok {
		return
	}
	s.serveFile(w, r, f, audit.Event{ActorID: auth.UserFrom(r.Context()).ID.String()})
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

// statusWriter records the status code ServeContent chose.
type statusWriter struct {
	http.ResponseWriter
	status int
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
	return w.ResponseWriter.Write(b)
}
