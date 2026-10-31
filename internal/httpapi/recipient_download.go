package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/mark"
	"github.com/tntrock/secure-exchange/internal/preview"
	"github.com/tntrock/secure-exchange/internal/share"
)

func (s *server) recipientDownload(w http.ResponseWriter, r *http.Request) {
	a := accessFrom(r.Context())
	fid, ok := pathUUID(w, r, "fid")
	if !ok {
		return
	}
	f := fileRow{id: fid}
	err := s.Pool.QueryRow(r.Context(), `SELECT f.name, f.size, f.sha256, f.wrapped_dek, f.key_id, f.storage_key
		FROM share_files sf JOIN files f ON f.id = sf.file_id
		WHERE sf.share_id = $1 AND sf.file_id = $2 AND f.deleted_at IS NULL`, a.Share.ID, fid).
		Scan(&f.name, &f.size, &f.sum, &f.wrappedDEK, &f.keyID, &f.key)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, errBody("not_found"))
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return
	}
	if !a.Share.AllowDownload {
		writeJSON(w, http.StatusForbidden, errBody("view_only"))
		return
	}
	rs, err := s.openPlain(r.Context(), &f)
	if err != nil {
		slog.Error("open file", "file", fid, "err", err)
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return
	}
	defer rs.Close()
	plan, p, err := s.planDownload(r.Context(), &f, rs, a.Share.Watermark)
	if err != nil {
		slog.Error("plan download", "file", fid, "err", err)
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return
	}
	block := s.Mark.Policy == "block"
	switch {
	case plan.Pending:
		writeJSON(w, http.StatusConflict, errBody("mark_pending"))
		return
	case plan.Degraded && block:
		writeJSON(w, http.StatusForbidden, errBody("unmarkable"))
		return
	}
	ev := audit.Event{ActorType: "recipient", ActorID: a.Recipient.ID.String(), Detail: map[string]any{"share_id": a.Share.ID.String()}}
	st := 0
	if plan.Method != mark.None {
		if r.Method == http.MethodHead {
			markedHeaders(w, plan.OutName)
			w.WriteHeader(http.StatusOK)
			return
		}
		if st = s.serveMarked(w, r, &f, rs, a, plan, p, ev); st == 0 {
			if a.Share.Watermark && block { // the fallback below is unmarked
				writeJSON(w, http.StatusForbidden, errBody("unmarkable"))
				return
			}
		}
	}
	if st == 0 {
		if st = s.serveUnmarked(w, r, &f, rs, a, ev); st == 0 {
			return
		}
	}
	if r.Method == http.MethodGet && (st == http.StatusOK || st == http.StatusPartialContent) {
		if err := s.Shares.RecordDownload(context.WithoutCancel(r.Context()), a, fid); err != nil {
			slog.Error("record share download", "share", a.Share.ID, "file", fid, "err", err)
		}
	}
}

// planDownload reads what mark.Decide needs: the head, the preview status and, for an image, its
// size from the header alone (the full file is read only by a GET that marks it).
func (s *server) planDownload(ctx context.Context, f *fileRow, rs io.ReadSeeker, watermark bool) (mark.Plan, *preview.Preview, error) {
	head, err := readHead(rs, f.size)
	if err != nil {
		return mark.Plan{}, nil, err
	}
	p, err := preview.GetStatus(ctx, s.Pool, f.id)
	if errors.Is(err, preview.ErrNoPreview) {
		p, err = nil, nil
	}
	if err != nil {
		return mark.Plan{}, nil, err
	}
	pixels := 0
	if mark.ImageMIME(head) != "" && f.size <= s.Mark.MaxBytes {
		if _, err := rs.Seek(0, io.SeekStart); err != nil {
			return mark.Plan{}, nil, err
		}
		pixels = math.MaxInt // undecodable: unmarkable
		if c, _, err := image.DecodeConfig(rs); err == nil {
			pixels = c.Width * c.Height // checked against MaxPixels before any full decode
		}
	}
	return mark.Decide(f.name, head, f.size, pixels, p, watermark, s.Mark), p, nil
}

// markedResponse is the response of a marked download. Its headers go out with the first byte, so
// a marker that fails before then leaves the response untouched for the fallback; err keeps the
// first write error, so a dead client is not mistaken for a file that cannot be marked.
type markedResponse struct {
	w    http.ResponseWriter
	name string
	n    int64
	err  error
}

func (m *markedResponse) Write(p []byte) (int, error) {
	if len(p) == 0 { // an empty write would commit the headers with nothing sent
		return 0, nil
	}
	if m.n == 0 && m.err == nil {
		markedHeaders(m.w, m.name)
	}
	n, err := m.w.Write(p)
	m.n += int64(n)
	if err != nil && m.err == nil {
		m.err = err
	}
	return n, err
}

func markedHeaders(w http.ResponseWriter, name string) {
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", contentDisposition(name))
	h.Set("Cache-Control", "private, no-store")
	h.Set("Accept-Ranges", "none")
}

// serveMarked sends a freshly traced copy and returns 200. If marking fails before any byte is
// sent it returns 0 (the caller falls back to unmarked); after that it aborts the response.
func (s *server) serveMarked(w http.ResponseWriter, r *http.Request, f *fileRow, rs io.ReadSeeker, a *share.Access,
	plan mark.Plan, p *preview.Preview, ev audit.Event) int {
	ctx := r.Context()
	code, err := mark.Start(ctx, s.Pool, mark.Download{FileID: f.id, ShareID: a.Share.ID, RecipientID: a.Recipient.ID,
		Method: plan.Method, IP: s.ip(r), UserAgent: UserAgent(r)})
	if err != nil {
		slog.Error("start download trace", "file", f.id, "err", err)
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return http.StatusInternalServerError
	}
	m := preview.Mark{Email: a.Recipient.Email, IP: s.ip(r), At: time.Now().UTC(), Code: code}
	sum := sha256.New()
	mr := &markedResponse{w: w, name: plan.OutName}
	out := io.MultiWriter(mr, sum)
	if err := s.writeMarked(ctx, out, w, f, rs, plan.Method, p, m); err != nil {
		if mr.n == 0 && ctx.Err() != nil { // the client left before anything was sent (e.g. waiting for a slot)
			if _, err := s.Pool.Exec(context.WithoutCancel(ctx), `DELETE FROM download_traces WHERE code = $1`, code); err != nil {
				slog.Error("drop unused download trace", "code", code, "err", err)
			}
			panic(http.ErrAbortHandler)
		}
		if mr.n == 0 && mr.err == nil { // the marker failed, not the client
			slog.Warn("mark failed, sending unmarked", "file", f.id, "method", plan.Method, "err", err)
			// the code was never delivered: drop its row so the unmarked fallback is the only record
			if _, err := s.Pool.Exec(context.WithoutCancel(ctx), `DELETE FROM download_traces WHERE code = $1`, code); err != nil {
				slog.Error("drop unused download trace", "code", code, "err", err)
			}
			return 0
		}
		if !errors.Is(err, context.Canceled) {
			slog.Error("marked download aborted", "file", f.id, "method", plan.Method, "code", code, "sent", mr.n, "err", err)
		}
		panic(http.ErrAbortHandler) // a truncated body must not end like a complete one
	}
	if err := mark.Complete(context.WithoutCancel(ctx), s.Pool, code, sum.Sum(nil), mr.n); err != nil {
		slog.Error("complete download trace", "code", code, "err", err)
	}
	ev.Detail["trace_code"], ev.Detail["mark"], ev.Detail["status"] = code, plan.Method, http.StatusOK
	ev.Action, ev.TargetType, ev.TargetID, ev.Result = audit.ActDownload, "file", f.id.String(), "ok"
	s.record(r, ev)
	return http.StatusOK
}

// markSlots bounds the in-memory marked builds (pdf_meta, image_*) running at once.
var markSlots = make(chan struct{}, 2)

// writeMarked writes f marked with m to cw (the response). pdf_pages and the zip methods stream; the others are
// built in memory first so they can carry a Content-Length.
func (s *server) writeMarked(ctx context.Context, cw io.Writer, w http.ResponseWriter, f *fileRow, rs io.ReadSeeker,
	method mark.Method, p *preview.Preview, m preview.Mark) error {
	var buf bytes.Buffer
	var data []byte
	if method == mark.PDFMeta || method == mark.ImageVisible || method == mark.ImageInvisible {
		// ponytail: whole file in memory, bounded by Mark.MaxBytes. An image also holds several decoded
		// copies (decode, orient's and Apply's RGBA, EmbedInvisible's RGBA plus a float32 luma buffer:
		// up to ~20 B/px, so ~1 GB at the default 50 MP). markSlots lets only two such builds run at
		// once; make it configurable, or lower SX_MARK_MAX_PIXELS, if that is too few or too many.
		select {
		case markSlots <- struct{}{}:
			defer func() { <-markSlots }()
		case <-ctx.Done():
			return ctx.Err()
		}
		if _, err := rs.Seek(0, io.SeekStart); err != nil {
			return err
		}
		var err error
		if data, err = io.ReadAll(rs); err != nil {
			return err
		}
	}
	switch method {
	case mark.PDFPages:
		return mark.WritePagesPDF(cw, p.PageCount, func(i int) (image.Image, error) {
			rc, _, err := preview.OpenItem(ctx, s.Pool, s.Store, s.Keys, f.id, "page", i)
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			img, err := png.Decode(rc)
			if err != nil {
				return nil, err
			}
			out, err := preview.Apply(img, m)
			if err != nil {
				return nil, err
			}
			return out, nil
		}, m.Code)
	case mark.OOXMLMeta, mark.ODFMeta:
		if _, err := rs.Seek(0, io.SeekStart); err != nil {
			return err
		}
		return mark.AddZipMeta(mark.ReaderAt(rs), f.size, cw, m.Code, method == mark.ODFMeta)
	case mark.PDFMeta:
		if err := mark.AddPDFMeta(bytes.NewReader(data), &buf, m.Code); err != nil { //nolint:contextcheck // bounded by its own pdfcpu timeout
			return err
		}
	default: // image_visible, image_invisible
		img, err := mark.DecodeImage(data)
		if err != nil {
			return err
		}
		if method == mark.ImageVisible {
			if img, err = preview.Apply(img, m); err != nil {
				return err
			}
		}
		out := mark.EmbedInvisible(img, m.Code)
		if mark.ImageMIME(data) == "image/png" {
			err = png.Encode(&buf, out)
		} else {
			err = jpeg.Encode(&buf, out, &jpeg.Options{Quality: 92})
		}
		if err != nil {
			return err
		}
	}
	w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
	_, err := cw.Write(buf.Bytes())
	return err
}

// serveUnmarked serves the original with Range support under the (recipient, file) none trace
// and returns the status served (0 if nothing was).
func (s *server) serveUnmarked(w http.ResponseWriter, r *http.Request, f *fileRow, rs io.ReadSeeker, a *share.Access, ev audit.Event) int {
	code := ""
	if r.Method == http.MethodGet { // HEAD leaves no trace
		var err error
		code, err = mark.Start(r.Context(), s.Pool, mark.Download{FileID: f.id, ShareID: a.Share.ID, RecipientID: a.Recipient.ID,
			Method: mark.None, IP: s.ip(r), UserAgent: UserAgent(r)})
		if err != nil {
			slog.Error("start download trace", "file", f.id, "err", err)
			writeJSON(w, http.StatusInternalServerError, errBody("internal"))
			return 0
		}
		ev.Detail["trace_code"], ev.Detail["mark"] = code, mark.None
	}
	st, n := s.serveFile(w, r, f, rs, ev)
	if code != "" && st == http.StatusOK && n == f.size {
		if err := mark.Complete(context.WithoutCancel(r.Context()), s.Pool, code, f.sum, f.size); err != nil {
			slog.Error("complete download trace", "code", code, "err", err)
		}
	}
	return st
}
