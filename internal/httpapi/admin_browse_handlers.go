package httpapi

import (
	"net/http"
	"strconv"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/auth"
)

// adminPage reads the ?q= and ?offset= of an admin list.
func adminPage(r *http.Request) (string, int) {
	off, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	return r.URL.Query().Get("q"), max(off, 0)
}

func (s *server) adminListShares(w http.ResponseWriter, r *http.Request) {
	q, off := adminPage(r)
	shs, err := s.Shares.AdminList(r.Context(), q, off)
	if err != nil {
		shareErr(w, err)
		return
	}
	out := make([]map[string]any, len(shs))
	for i := range shs {
		out[i] = shareListItem(&shs[i])
		out[i]["owner_email"] = shs[i].OwnerEmail
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) adminGetShare(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	sh, err := s.Shares.AdminGet(r.Context(), id)
	if err != nil {
		shareErr(w, err)
		return
	}
	m := shareDetail(sh)
	m["owner_email"] = sh.OwnerEmail
	writeJSON(w, http.StatusOK, m)
}

func (s *server) adminRevokeShare(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	sh, err := s.Shares.AdminGet(r.Context(), id) // for the owner in the audit entry, and the 404
	if err == nil {
		err = s.Shares.AdminRevoke(r.Context(), id)
	}
	if err != nil {
		shareErr(w, err)
		return
	}
	s.record(r, s.shareEvent(auth.UserFrom(r.Context()), audit.ActShareRevoke, id, map[string]any{"owner_id": sh.OwnerID, "admin": true}))
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) adminListRequests(w http.ResponseWriter, r *http.Request) {
	q, off := adminPage(r)
	qs, err := s.Requests.AdminList(r.Context(), q, off)
	if err != nil {
		intakeErr(w, err)
		return
	}
	out := make([]map[string]any, len(qs))
	for i := range qs {
		out[i] = requestBase(&qs[i])
		out[i]["owner_email"] = qs[i].OwnerEmail
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) adminGetRequest(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	q, err := s.Requests.AdminGet(r.Context(), id)
	if err != nil {
		intakeErr(w, err)
		return
	}
	m, err := s.requestDetail(r, q)
	if err != nil {
		intakeErr(w, err)
		return
	}
	m["owner_email"] = q.OwnerEmail
	writeJSON(w, http.StatusOK, m)
}

func (s *server) adminRevokeRequest(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	q, err := s.Requests.AdminGet(r.Context(), id)
	if err == nil {
		err = s.Requests.AdminRevoke(r.Context(), id)
	}
	if err != nil {
		intakeErr(w, err)
		return
	}
	e := s.requestEvent(auth.UserFrom(r.Context()), audit.ActRequestRevoke, id)
	e.Detail = map[string]any{"owner_id": q.OwnerID, "admin": true}
	s.record(r, e)
	w.WriteHeader(http.StatusNoContent)
}
