package webui

import (
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestRejectsAndUnbuilt(t *testing.T) {
	built := newHandler(fstest.MapFS{"index.html": {Data: []byte("x")}})
	rec := httptest.NewRecorder()
	built.ServeHTTP(rec, httptest.NewRequest("POST", "/", nil))
	if rec.Code != 405 {
		t.Fatalf("POST: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	built.ServeHTTP(rec, httptest.NewRequest("HEAD", "/", nil))
	if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("HEAD: %d %v", rec.Code, rec.Header())
	}
	rec = httptest.NewRecorder()
	newHandler(fstest.MapFS{}).ServeHTTP(rec, httptest.NewRequest("GET", "/files", nil))
	if rec.Code != 404 || !strings.Contains(rec.Body.String(), "not built") {
		t.Fatalf("unbuilt: %d %q", rec.Code, rec.Body.String())
	}
}
