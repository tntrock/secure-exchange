package httpapi

import (
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/syslogfwd"
)

type auditRow struct {
	ID         int64          `json:"id"`
	At         time.Time      `json:"at"`
	ActorType  string         `json:"actor_type"`
	ActorID    string         `json:"actor_id"`
	ActorLabel string         `json:"actor_label"`
	IP         string         `json:"ip"`
	UserAgent  string         `json:"user_agent"`
	Action     string         `json:"action"`
	TargetType string         `json:"target_type"`
	TargetID   string         `json:"target_id"`
	Result     string         `json:"result"`
	Detail     map[string]any `json:"detail"`
}

func toAuditRows(es []audit.Entry) []auditRow {
	out := make([]auditRow, 0, len(es))
	for _, en := range es {
		e := en.Event
		out = append(out, auditRow{en.ID, en.At, e.ActorType, e.ActorID, en.ActorLabel, e.IP, e.UserAgent,
			e.Action, e.TargetType, e.TargetID, e.Result, e.Detail})
	}
	return out
}

// auditFilter parses the shared list/export query; ok=false means a 400 was written.
func auditFilter(w http.ResponseWriter, r *http.Request) (f audit.Filter, ok bool) {
	q := r.URL.Query()
	f = audit.Filter{Actor: q.Get("actor"), ActionPrefix: q.Get("action"), Target: q.Get("target")}
	for _, p := range []struct {
		key string
		dst *time.Time
	}{{"since", &f.Since}, {"until", &f.Until}} {
		if v := q.Get(p.key); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, errBody("bad_time"))
				return f, false
			}
			*p.dst = t
		}
	}
	f.BeforeID, _ = strconv.ParseInt(q.Get("before"), 10, 64)
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	return f, true
}

func (s *server) auditList(w http.ResponseWriter, r *http.Request) {
	f, ok := auditFilter(w, r)
	if !ok {
		return
	}
	es, next, err := s.Audit.List(r.Context(), f)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": toAuditRows(es), "next_before": next})
}

// csvCell neutralises spreadsheet formulas.
func csvCell(s string) string {
	if s != "" && strings.IndexByte("=+-@\t\r", s[0]) >= 0 {
		return "'" + s
	}
	return s
}

func (s *server) auditExport(w http.ResponseWriter, r *http.Request) {
	f, ok := auditFilter(w, r)
	if !ok {
		return
	}
	filter := map[string]any{}
	for k, v := range r.URL.Query() {
		filter[k] = v[0]
	}
	s.record(r, audit.Event{ActorID: auth.UserFrom(r.Context()).ID.String(), Action: audit.ActAuditExport,
		Result: "ok", Detail: map[string]any{"filter": filter}})
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="audit-`+time.Now().UTC().Format("20060102-150405")+`.csv"`)
	// headers are sent: on a write error just stop; a truncated file is the signal
	if _, err := w.Write([]byte("\xEF\xBB\xBF")); err != nil {
		return
	}
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"id", "at", "actor_type", "actor_id", "actor_label", "ip", "user_agent", "action",
		"target_type", "target_id", "result", "detail", "prev_hash", "hash"})
	n := 0
	err := s.Audit.Each(r.Context(), f, func(en audit.Entry) error {
		e := en.Event
		d, _ := json.Marshal(e.Detail)
		if err := cw.Write([]string{strconv.FormatInt(en.ID, 10), en.At.UTC().Format(time.RFC3339Nano), csvCell(e.ActorType),
			csvCell(e.ActorID), csvCell(en.ActorLabel), csvCell(e.IP), csvCell(e.UserAgent), csvCell(e.Action),
			csvCell(e.TargetType), csvCell(e.TargetID), csvCell(e.Result), csvCell(string(d)),
			hex.EncodeToString(en.PrevHash), hex.EncodeToString(en.Hash)}); err != nil {
			return err
		}
		if n++; n%500 == 0 {
			cw.Flush()
			return cw.Error()
		}
		return nil
	})
	cw.Flush()
	if err == nil {
		err = cw.Error()
	}
	if err != nil {
		slog.Error("audit export", "err", err)
		panic(http.ErrAbortHandler) // a truncated body must not end like a complete one
	}
}

func (s *server) auditVerify(w http.ResponseWriter, r *http.Request) {
	checked, bad, err := s.Audit.Verify(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return
	}
	res := "ok"
	if bad != 0 {
		res = "broken"
	}
	s.record(r, audit.Event{ActorID: auth.UserFrom(r.Context()).ID.String(), Action: audit.ActAuditVerify,
		Result: res, Detail: map[string]any{"checked": checked, "bad_id": bad}})
	writeJSON(w, http.StatusOK, map[string]int64{"checked": checked, "bad_id": bad})
}

func (s *server) auditForwarding(w http.ResponseWriter, r *http.Request) {
	st, err := syslogfwd.GetStatus(r.Context(), s.Pool, s.SyslogEnabled, time.Now())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// shareAudit lists a share's newest 200 events; admin skips the owner check.
func (s *server) shareAudit(admin bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathUUID(w, r, "id")
		if !ok {
			return
		}
		var err error
		if admin {
			_, err = s.Shares.AdminGet(r.Context(), id)
		} else {
			_, err = s.Shares.Get(r.Context(), auth.UserFrom(r.Context()).ID, id)
		}
		if err != nil {
			shareErr(w, err)
			return
		}
		es, _, err := s.Audit.List(r.Context(), audit.Filter{Target: id.String(), Limit: 200})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, errBody("internal"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"entries": toAuditRows(es)})
	}
}
