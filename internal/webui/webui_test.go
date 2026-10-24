package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestSPAFallbackAndAssets(t *testing.T) {
	h := newHandler(fstest.MapFS{
		"index.html":    {Data: []byte("<!doctype html><title>x</title>")},
		"assets/app.js": {Data: []byte("console.log(1)")},
	})
	for _, c := range []struct{ path, ctype, body string }{
		{"/files", "text/html", "<title>x</title>"},
		{"/", "text/html", "<title>x</title>"},
		{"/assets/app.js", "text/javascript", "console.log"},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", c.path, nil))
		if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), c.ctype) || !strings.Contains(rec.Body.String(), c.body) {
			t.Errorf("%s: code=%d ctype=%q body=%q", c.path, rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
		}
	}
}

func TestEmbeddedHandlerCompiles(t *testing.T) {
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/files", nil))
	if rec.Code != 200 && rec.Code != http.StatusNotFound { // 404 when the frontend is not built
		t.Fatalf("code=%d", rec.Code)
	}
}
