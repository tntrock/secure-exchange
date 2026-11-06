package httpapi

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/vendor"
)

// listVendorRecipients is the staff the signed-in vendor may upload to (never the full staff list).
func (s *server) listVendorRecipients(w http.ResponseWriter, r *http.Request) {
	targets, err := vendor.UploadTargets(r.Context(), s.Pool, auth.UserFrom(r.Context()).ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return
	}
	out := make([]map[string]any, len(targets))
	for i, t := range targets {
		out[i] = map[string]any{"id": t.ID, "name": t.Name, "email": t.Email}
	}
	writeJSON(w, http.StatusOK, out)
}

// listVendorUploads is the signed-in vendor's finished uploads that still exist, newest first.
func (s *server) listVendorUploads(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Pool.Query(r.Context(), `SELECT f.id, f.name, f.size, coalesce(nullif(o.display_name,''), o.email), f.created_at
		FROM files f JOIN users o ON o.id = f.owner_id
		WHERE f.vendor_id = $1 AND f.deleted_at IS NULL ORDER BY f.created_at DESC, f.id`, auth.UserFrom(r.Context()).ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id uuid.UUID
		var name, owner string
		var size int64
		var at time.Time
		if err := rows.Scan(&id, &name, &size, &owner, &at); err != nil {
			writeJSON(w, http.StatusInternalServerError, errBody("internal"))
			return
		}
		out = append(out, map[string]any{"id": id, "name": name, "size": size, "recipient_name": owner, "created_at": ts(&at)})
	}
	if rows.Err() != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return
	}
	writeJSON(w, http.StatusOK, out)
}
