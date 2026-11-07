package httpapi

import (
	"io"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Handlers may write audit rows after the body is sent (download audits record what was served),
// so a test reading the audit log right after a response could race the handler. syncRT tags each
// request and makes the response body's Close wait until the server-side handler has returned.
const syncHeader = "X-Test-Sync"

type syncRT struct {
	base http.RoundTripper
	done *sync.Map // id -> chan struct{}, closed when the handler returns
	n    atomic.Int64
}

func (s *syncRT) RoundTrip(r *http.Request) (*http.Response, error) {
	id := strconv.FormatInt(s.n.Add(1), 10)
	ch := make(chan struct{})
	s.done.Store(id, ch)
	r = r.Clone(r.Context())
	r.Header.Set(syncHeader, id)
	resp, err := s.base.RoundTrip(r)
	if err != nil {
		s.done.Delete(id)
		return nil, err
	}
	resp.Body = &syncBody{ReadCloser: resp.Body, done: ch}
	return resp, nil
}

type syncBody struct {
	io.ReadCloser
	done chan struct{}
}

func (b *syncBody) Close() error {
	err := b.ReadCloser.Close()
	select {
	case <-b.done:
	case <-time.After(10 * time.Second): // a handler still blocked on purpose must not hang the test
	}
	return err
}

func syncHandler(h http.Handler, done *sync.Map) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if ch, ok := done.LoadAndDelete(r.Header.Get(syncHeader)); ok {
				close(ch.(chan struct{}))
			}
		}()
		h.ServeHTTP(w, r)
	})
}
