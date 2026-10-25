package httpapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image/png"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/preview"
	"github.com/tntrock/secure-exchange/internal/share"
)

// previewHandler serves one view of fileID; a is nil for the owner (no watermark, no trace).
type previewHandler func(w http.ResponseWriter, r *http.Request, fileID uuid.UUID, a *share.Access)

func (s *server) previewRoutes(mux *http.ServeMux) {
	own := func(h previewHandler) http.Handler {
		return s.requireUser(func(w http.ResponseWriter, r *http.Request) {
			if f, ok := s.ownFile(w, r); ok {
				viewHeaders(w)
				h(w, r, f.id, nil)
			}
		})
	}
	recip := func(h previewHandler) http.Handler {
		return s.requireRecipient(func(w http.ResponseWriter, r *http.Request) {
			a := accessFrom(r.Context())
			if fid, ok := s.sharedFile(w, r, a); ok {
				viewHeaders(w)
				h(w, r, fid, a)
			}
		})
	}
	for prefix, wrap := range map[string]func(previewHandler) http.Handler{"/api/files/{id}": own, "/api/s/{token}/files/{fid}": recip} {
		mux.Handle("GET "+prefix+"/preview", wrap(s.previewStatus))
		mux.Handle("GET "+prefix+"/preview/pages/{n}", wrap(s.previewPage))
		mux.Handle("GET "+prefix+"/preview/video.m3u8", wrap(s.previewPlaylist))
		mux.Handle("GET "+prefix+"/preview/segments/{seg}", wrap(s.previewSegment))
	}
}

func viewHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Content-Disposition", "inline")
}

// sharedFile resolves {fid} to a live file of the recipient's share; otherwise it writes 404.
// allow_download does not matter: view-only shares may still be viewed.
func (s *server) sharedFile(w http.ResponseWriter, r *http.Request, a *share.Access) (uuid.UUID, bool) {
	fid, err := uuid.Parse(r.PathValue("fid"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, errBody("not_found"))
		return uuid.Nil, false
	}
	var one int
	err = s.Pool.QueryRow(r.Context(), `SELECT 1 FROM share_files sf JOIN files f ON f.id = sf.file_id
		WHERE sf.share_id = $1 AND sf.file_id = $2 AND f.deleted_at IS NULL`, a.Share.ID, fid).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, errBody("not_found"))
		return uuid.Nil, false
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return uuid.Nil, false
	}
	return fid, true
}

func (s *server) previewStatus(w http.ResponseWriter, r *http.Request, fid uuid.UUID, _ *share.Access) {
	p, err := preview.GetStatus(r.Context(), s.Pool, fid)
	if errors.Is(err, preview.ErrNoPreview) {
		writeJSON(w, http.StatusOK, map[string]string{"kind": string(preview.KindNone), "status": string(preview.StatusUnsupported)})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"kind": p.Kind, "status": p.Status, "page_count": p.PageCount,
		"width": p.Width, "height": p.Height, "duration_ms": p.DurationMs})
}

// ready loads a ready preview of one of kinds; otherwise it writes 404 or 409 and returns false.
func (s *server) ready(w http.ResponseWriter, r *http.Request, fid uuid.UUID, kinds ...preview.Kind) (*preview.Preview, bool) {
	p, err := preview.GetStatus(r.Context(), s.Pool, fid)
	switch {
	case errors.Is(err, preview.ErrNoPreview):
		writeJSON(w, http.StatusNotFound, errBody("not_found"))
		return nil, false
	case err != nil:
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return nil, false
	case p.Status != preview.StatusReady:
		writeJSON(w, http.StatusConflict, map[string]any{"error": "preview_not_ready", "status": p.Status})
		return nil, false
	}
	for _, k := range kinds {
		if p.Kind == k {
			return p, true
		}
	}
	writeJSON(w, http.StatusNotFound, errBody("not_found"))
	return nil, false
}

// index parses a non-negative item number; otherwise it writes 404.
func index(w http.ResponseWriter, s string) (int, bool) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		writeJSON(w, http.StatusNotFound, errBody("not_found"))
		return 0, false
	}
	return n, true
}

// mark returns the recipient's watermark for fid (ok=false: don't draw one). It records the
// (session, file) trace on first use, and the file.view audit entry when the trace is new;
// unwatermarked views are traced too (from item 0 only) so file.view has one dedupe.
func (s *server) mark(r *http.Request, a *share.Access, fid uuid.UUID, n int) (preview.Mark, bool, error) {
	if a == nil || !a.Share.Watermark && n != 0 {
		return preview.Mark{}, false, nil
	}
	ip := s.ip(r)
	code, created, err := preview.Trace(r.Context(), s.Pool, fid, a.Share.ID, a.Recipient.ID, a.SessionHash, ip)
	if err != nil {
		return preview.Mark{}, false, err
	}
	if created {
		d := map[string]any{"share_id": a.Share.ID.String()}
		if a.Share.Watermark {
			d["trace_code"] = code
		}
		s.record(r, audit.Event{ActorType: "recipient", ActorID: a.Recipient.ID.String(), Action: audit.ActFileView,
			TargetType: "file", TargetID: fid.String(), Result: "ok", Detail: d})
	}
	return preview.Mark{Email: a.Recipient.Email, IP: ip, At: time.Now().UTC(), Code: code}, a.Share.Watermark, nil
}

func (s *server) previewPage(w http.ResponseWriter, r *http.Request, fid uuid.UUID, a *share.Access) {
	p, ok := s.ready(w, r, fid, preview.KindPages, preview.KindImage)
	if !ok {
		return
	}
	n, ok := index(w, r.PathValue("n"))
	if !ok {
		return
	}
	kind := "page"
	if p.Kind == preview.KindImage {
		kind = "image"
	}
	if kind == "image" && n != 0 || kind == "page" && n >= p.PageCount {
		writeJSON(w, http.StatusNotFound, errBody("not_found"))
		return
	}
	rs, _, err := preview.OpenItem(r.Context(), s.Pool, s.Store, s.Keys, fid, kind, n)
	if errors.Is(err, preview.ErrNoItem) {
		writeJSON(w, http.StatusNotFound, errBody("not_found"))
		return
	}
	if err != nil {
		s.viewErr(w, r, fid, err)
		return
	}
	defer rs.Close()
	img, err := png.Decode(rs)
	if err != nil {
		s.viewErr(w, r, fid, err)
		return
	}
	m, draw, err := s.mark(r, a, fid, n)
	if err != nil {
		s.viewErr(w, r, fid, err)
		return
	}
	if draw {
		if img, err = preview.Apply(img, m); err != nil {
			s.viewErr(w, r, fid, err)
			return
		}
	}
	var buf bytes.Buffer
	if err := preview.EncodeJPEG(&buf, img); err != nil {
		s.viewErr(w, r, fid, err)
		return
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.Write(buf.Bytes())
}

func (s *server) previewPlaylist(w http.ResponseWriter, r *http.Request, fid uuid.UUID, _ *share.Access) {
	if _, ok := s.ready(w, r, fid, preview.KindVideo); !ok {
		return
	}
	items, err := preview.ListItems(r.Context(), s.Pool, fid, "segment")
	if err != nil {
		s.viewErr(w, r, fid, err)
		return
	}
	if len(items) == 0 {
		writeJSON(w, http.StatusNotFound, errBody("not_found"))
		return
	}
	var maxMs int64
	var body strings.Builder
	for _, it := range items {
		maxMs = max(maxMs, it.DurationMs)
		fmt.Fprintf(&body, "#EXTINF:%.3f,\nsegments/%d.ts\n", float64(it.DurationMs)/1000, it.Idx)
	}
	w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
	fmt.Fprintf(w, "#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:%d\n#EXT-X-MEDIA-SEQUENCE:0\n#EXT-X-PLAYLIST-TYPE:VOD\n%s#EXT-X-ENDLIST\n",
		int(math.Ceil(float64(maxMs)/1000)), body.String())
}

func (s *server) previewSegment(w http.ResponseWriter, r *http.Request, fid uuid.UUID, a *share.Access) {
	if _, ok := s.ready(w, r, fid, preview.KindVideo); !ok {
		return
	}
	seg, ok := strings.CutSuffix(r.PathValue("seg"), ".ts")
	if !ok {
		writeJSON(w, http.StatusNotFound, errBody("not_found"))
		return
	}
	n, ok := index(w, seg)
	if !ok {
		return
	}
	rs, _, err := preview.OpenItem(r.Context(), s.Pool, s.Store, s.Keys, fid, "segment", n)
	if errors.Is(err, preview.ErrNoItem) {
		writeJSON(w, http.StatusNotFound, errBody("not_found"))
		return
	}
	if err != nil {
		s.viewErr(w, r, fid, err)
		return
	}
	defer rs.Close()
	m, draw, err := s.mark(r, a, fid, n)
	if err != nil {
		s.viewErr(w, r, fid, err)
		return
	}
	w.Header().Set("Content-Type", "video/mp2t")
	if !draw {
		http.ServeContent(w, r, "", time.Time{}, rs)
		return
	}
	// buffered so a failed burn is a clean 500, not a truncated segment
	var buf bytes.Buffer
	if err := s.burnSegment(r.Context(), &buf, rs, m); err != nil {
		w.Header().Del("Content-Type")
		s.viewErr(w, r, fid, err)
		return
	}
	w.Write(buf.Bytes())
}

func (s *server) viewErr(w http.ResponseWriter, r *http.Request, fid uuid.UUID, err error) {
	if !errors.Is(err, context.Canceled) {
		slog.Error("preview view", "route", r.Pattern, "file", fid, "err", err)
	}
	writeJSON(w, http.StatusInternalServerError, errBody("internal"))
}
