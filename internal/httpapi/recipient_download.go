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
	plan, p, data, err := s.planDownload(r.Context(), &f, rs, a.Share.Watermark)
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
		if st = s.serveMarked(w, r, &f, rs, a, plan, p, data, ev); st == 0 {
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

// planDownload reads what mark.Decide needs. data is the whole file when the plan buffers it
// (pdf_meta, image_*), which Decide only allows up to Mark.MaxBytes.
func (s *server) planDownload(ctx context.Context, f *fileRow, rs io.ReadSeeker, watermark bool) (mark.Plan, *preview.Preview, []byte, error) {
	head, err := readHead(rs, f.size)
	if err != nil {
		return mark.Plan{}, nil, nil, err
	}
	p, err := preview.GetStatus(ctx, s.Pool, f.id)
	if errors.Is(err, preview.ErrNoPreview) {
		p, err = nil, nil
	}
	if err != nil {
		return mark.Plan{}, nil, nil, err
	}
	readAll := func() ([]byte, error) {
		if _, err := rs.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		return io.ReadAll(rs)
	}
	var data []byte
	pixels := 0
	if mark.ImageMIME(head) != "" && f.size <= s.Mark.MaxBytes {
		if data, err = readAll(); err != nil {
			return mark.Plan{}, nil, nil, err
		}
		pixels = math.MaxInt // undecodable: unmarkable
		if c, _, err := image.DecodeConfig(bytes.NewReader(data)); err == nil {
			pixels = c.Width * c.Height // checked against MaxPixels before any full decode
		}
	}
	plan := mark.Decide(f.name, head, f.size, pixels, p, watermark, s.Mark)
	if plan.Method == mark.PDFMeta {
		data, err = readAll()
	}
	return plan, p, data, err
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
	plan mark.Plan, p *preview.Preview, data []byte, ev audit.Event) int {
	ctx := r.Context()
	code, err := mark.Start(ctx, s.Pool, mark.Download{FileID: f.id, ShareID: a.Share.ID, RecipientID: a.Recipient.ID,
		Method: plan.Method, IP: s.ip(r), UserAgent: UserAgent(r)})
	if err != nil {
		slog.Error("start download trace", "file", f.id, "err", err)
		writeJSON(w, http.StatusInternalServerError, errBody("internal"))
		return http.StatusInternalServerError
	}
	m := preview.Mark{Email: a.Recipient.Email, IP: s.ip(r), At: time.Now().UTC(), Code: code}
	markedHeaders(w, plan.OutName)
	sum := sha256.New()
	cw := &mark.CountWriter{W: io.MultiWriter(w, sum)}
	if err := s.writeMarked(ctx, cw, w, f, rs, plan.Method, p, data, m); err != nil {
		if cw.N == 0 {
			slog.Warn("mark failed, sending unmarked", "file", f.id, "method", plan.Method, "err", err)
			// the code was never delivered: drop its row so the unmarked fallback is the only record
			if _, err := s.Pool.Exec(context.WithoutCancel(ctx), `DELETE FROM download_traces WHERE code = $1`, code); err != nil {
				slog.Error("drop unused download trace", "code", code, "err", err)
			}
			return 0
		}
		if !errors.Is(err, context.Canceled) {
			slog.Error("marked download aborted", "file", f.id, "method", plan.Method, "code", code, "sent", cw.N, "err", err)
		}
		panic(http.ErrAbortHandler) // a truncated body must not end like a complete one
	}
	if err := mark.Complete(context.WithoutCancel(ctx), s.Pool, code, sum.Sum(nil), cw.N); err != nil {
		slog.Error("complete download trace", "code", code, "err", err)
	}
	ev.Detail["trace_code"], ev.Detail["mark"], ev.Detail["status"] = code, plan.Method, http.StatusOK
	ev.Action, ev.TargetType, ev.TargetID, ev.Result = audit.ActDownload, "file", f.id.String(), "ok"
	s.record(r, ev)
	return http.StatusOK
}

// writeMarked writes f marked with m to cw. pdf_pages and the zip methods stream; the others are
// built in memory first so they can carry a Content-Length.
func (s *server) writeMarked(ctx context.Context, cw *mark.CountWriter, w http.ResponseWriter, f *fileRow, rs io.ReadSeeker,
	method mark.Method, p *preview.Preview, data []byte, m preview.Mark) error {
	var buf bytes.Buffer
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
		img, _, err := image.Decode(bytes.NewReader(data))
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
