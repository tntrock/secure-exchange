package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"mime"
	"net/http"
	"slices"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/mark"
)

// viaRank orders hits: a direct code lookup, then what was read out of the file, then the hash match.
var viaRank = map[string]int{"code": 0, "metadata": 1, "text_layer": 2, "invisible": 3, "sha256": 4}

type traceResult struct {
	Hits     []mark.Hit `json:"hits"`
	Analyzed bool       `json:"analyzed"`
	SHA256   string     `json:"sha256,omitempty"`
}

// trace finds who a leaked copy was handed to: by trace code, by SHA-256, or by uploaded file.
// Codes read from a file are only lookup keys, so a code absent from the database yields no hit.
func (s *server) trace(w http.ResponseWriter, r *http.Request) {
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	var (
		res  traceResult
		by   string
		hits []mark.Hit
		err  error
	)
	switch mt {
	case "application/json":
		var in struct{ Code, SHA256 string }
		if !readJSON(w, r, &in) {
			return
		}
		switch {
		case (in.Code == "") == (in.SHA256 == ""):
			writeJSON(w, http.StatusBadRequest, errBody("bad_request"))
			return
		case in.Code != "":
			code, ok := mark.NormalizeCode(in.Code)
			if !ok {
				writeJSON(w, http.StatusBadRequest, errBody("bad_code"))
				return
			}
			by = "code"
			hits, err = s.byCode(r, code, "code")
		default:
			sum, derr := hex.DecodeString(in.SHA256)
			if derr != nil || len(sum) != sha256.Size {
				writeJSON(w, http.StatusBadRequest, errBody("bad_sha256"))
				return
			}
			by, res.SHA256 = "sha256", hex.EncodeToString(sum)
			hits, err = s.bySHA(r, sum)
		}
	case "multipart/form-data":
		by = "file"
		head, sum, ok := s.readUpload(w, r)
		if !ok {
			return
		}
		res.SHA256 = hex.EncodeToString(sum)
		if res.Analyzed = int64(len(head)) <= s.Mark.MaxBytes; res.Analyzed {
			for _, f := range mark.InspectMax(head, int(min(s.Mark.MaxPixels, 1<<31-1))) { //nolint:contextcheck // PDFCodes sets its own timeout
				var h []mark.Hit
				if h, err = s.byCode(r, f.Code, f.Via); err != nil {
					break
				}
				hits = append(hits, h...)
			}
		}
		if err == nil {
			var h []mark.Hit
			if h, err = s.bySHA(r, sum); err == nil {
				hits = append(hits, h...)
			}
		}
	default:
		writeJSON(w, http.StatusBadRequest, errBody("bad_request"))
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return
	}
	res.Hits = dedupHits(hits)
	s.record(r, audit.Event{ActorID: auth.UserFrom(r.Context()).ID.String(), Action: audit.ActTraceLookup,
		TargetType: "trace", Result: "ok", Detail: map[string]any{"by": by, "hits": len(res.Hits)}})
	writeJSON(w, http.StatusOK, res)
}

func (s *server) byCode(r *http.Request, code, via string) ([]mark.Hit, error) {
	hits, err := mark.ByCode(r.Context(), s.Pool, code)
	for i := range hits {
		hits[i].Via = via
	}
	return hits, err
}

func (s *server) bySHA(r *http.Request, sum []byte) ([]mark.Hit, error) {
	hits, err := mark.BySHA(r.Context(), s.Pool, sum)
	for i := range hits {
		hits[i].Via = "sha256"
	}
	return hits, err
}

// dedupHits orders by viaRank and drops a row already reported by an earlier, stronger match
// (a marked copy matches both by embedded code and by hash). It never returns nil.
func dedupHits(in []mark.Hit) []mark.Hit {
	slices.SortStableFunc(in, func(a, b mark.Hit) int { return viaRank[a.Via] - viaRank[b.Via] })
	out := make([]mark.Hit, 0, len(in))
	seen := map[[3]string]bool{}
	for _, h := range in {
		k := [3]string{h.Source, h.Code, h.FileID.String()}
		if !seen[k] {
			seen[k] = true
			out = append(out, h)
		}
	}
	return out
}

// readUpload streams the "file" part: SHA-256 over all of it, only the first Mark.MaxBytes+1
// bytes kept in memory. Nothing touches disk. On failure it has written 400.
func (s *server) readUpload(w http.ResponseWriter, r *http.Request) (head, sum []byte, ok bool) {
	mr, err := r.MultipartReader()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("bad_request"))
		return nil, nil, false
	}
	for {
		p, err := mr.NextPart()
		if err != nil { // io.EOF: no file part; anything else: broken body
			writeJSON(w, http.StatusBadRequest, errBody("bad_request"))
			return nil, nil, false
		}
		if p.FormName() != "file" {
			continue
		}
		h := sha256.New()
		head, err = io.ReadAll(io.LimitReader(p, s.Mark.MaxBytes+1))
		if err == nil {
			h.Write(head)
			_, err = io.Copy(h, p)
		}
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errBody("bad_request"))
			return nil, nil, false
		}
		return head, h.Sum(nil), true
	}
}
