package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/auth"
)

func (s *server) getNotifyPrefs(w http.ResponseWriter, r *http.Request) {
	p, err := s.Users.NotifyPrefs(r.Context(), auth.UserFrom(r.Context()).ID)
	if err != nil {
		slog.Error("notify prefs", "err", err)
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *server) setNotifyPrefs(w http.ResponseWriter, r *http.Request) {
	var raw struct { // pointers: a missing field must be told from false
		FirstOpen *bool `json:"first_open"`
		Download  *bool `json:"download"`
		Upload    *bool `json:"upload"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&raw); err != nil || raw.FirstOpen == nil || raw.Download == nil || raw.Upload == nil {
		writeJSON(w, http.StatusBadRequest, errBody("bad_request"))
		return
	}
	u := auth.UserFrom(r.Context())
	p := auth.NotifyPrefs{FirstOpen: *raw.FirstOpen, Download: *raw.Download, Upload: *raw.Upload}
	if err := s.Users.SetNotifyPrefs(r.Context(), u.ID, p); err != nil {
		slog.Error("notify prefs", "err", err)
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return
	}
	s.record(r, audit.Event{ActorID: u.ID.String(), Action: audit.ActNotifyPrefs, TargetType: "user", TargetID: u.ID.String(), Result: "ok",
		Detail: map[string]any{"first_open": p.FirstOpen, "download": p.Download, "upload": p.Upload}})
	w.WriteHeader(http.StatusNoContent)
}
