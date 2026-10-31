package httpapi

import (
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"time"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
)

// openPlain opens a seekable plaintext view of f.
func (s *server) openPlain(ctx context.Context, f *fileRow) (io.ReadSeekCloser, error) {
	dek, err := s.Keys.UnwrapDEK(f.wrappedDEK, f.keyID)
	if err != nil {
		return nil, err
	}
	return sxcrypto.OpenPlain(ctx, func(ctx context.Context, off, n int64) (io.ReadCloser, error) {
		return s.Store.OpenRange(ctx, f.key, off, n)
	}, dek, f.id, f.size), nil // R7: size from the DB
}

// serveFile streams rs (f's plaintext) with Range/ETag support and returns the status served and
// the body bytes written. ev carries ActorType/ActorID and extra Detail for the file.download audit
// entry; it is written only for 200/206 GETs, by what was actually served (R15).
func (s *server) serveFile(w http.ResponseWriter, r *http.Request, f *fileRow, rs io.ReadSeeker, ev audit.Event) (int, int64) {
	h := w.Header()
	h.Set("ETag", `"`+hex.EncodeToString(f.sum)+`"`)
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", contentDisposition(f.name))
	h.Set("Cache-Control", "private, no-store")
	sw := &statusWriter{ResponseWriter: w}
	http.ServeContent(sw, r, "", time.Time{}, rs)
	if r.Method == http.MethodGet && (sw.status == http.StatusOK || sw.status == http.StatusPartialContent) {
		d := map[string]any{}
		for k, v := range ev.Detail {
			d[k] = v
		}
		d["status"], d["range"] = sw.status, h.Get("Content-Range") // what was served wins over caller detail (R15)
		ev.Action, ev.TargetType, ev.TargetID, ev.Result, ev.Detail = audit.ActDownload, "file", f.id.String(), "ok", d
		s.record(r, ev)
	}
	return sw.status, sw.n
}
