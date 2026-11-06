package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/rules"
)

func (s *server) getRules(w http.ResponseWriter, r *http.Request) {
	rl, err := s.Rules.Get(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return
	}
	writeJSON(w, http.StatusOK, rl)
}

func (s *server) putRules(w http.ResponseWriter, r *http.Request) {
	var in rules.Rules
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("bad_request"))
		return
	}
	u := auth.UserFrom(r.Context())
	ctx := r.Context()
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return
	}
	defer tx.Rollback(ctx)
	fail := func(err error) {
		var ve *rules.ValidationError
		if errors.As(err, &ve) {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "validation", "field": ve.Field, "code": ve.Code})
			return
		}
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
	}
	before, err := s.Rules.Update(ctx, tx, in)
	if err != nil {
		fail(err)
		return
	}
	after, err := s.Rules.GetTx(ctx, tx)
	if err != nil {
		fail(err)
		return
	}
	n, err := s.Shares.NotifyRulesTightened(ctx, tx, before, after)
	if err != nil {
		fail(err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		fail(err)
		return
	}
	s.record(r, audit.Event{ActorID: u.ID.String(), Action: audit.ActRulesUpdate, TargetType: "rules", TargetID: "site", Result: "ok",
		Detail: map[string]any{"before": before, "after": after}})
	writeJSON(w, http.StatusOK, map[string]any{"rules": after, "affected_shares": n})
}
