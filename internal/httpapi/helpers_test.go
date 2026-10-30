package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/tntrock/secure-exchange/internal/share"
)

func TestClientIPOddRemoteAddr(t *testing.T) {
	for remote, want := range map[string]string{
		"203.0.113.9": "203.0.113.9", // no port
		"@unix":       "@unix",       // not an address: passed through
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		if got := ClientIP(r, nil); got != want {
			t.Errorf("%q: got %q", remote, got)
		}
	}
}

func TestLimiterDropsRefilledBuckets(t *testing.T) {
	l := newLimiter(rate.Every(time.Hour), 2)
	for i := range 10001 {
		l.allow(fmt.Sprint("full", i)) // one token left each: not dropped
	}
	l.m["fresh"] = rate.NewLimiter(l.r, l.burst) // a full bucket: equal to a fresh one
	if !l.allow("new") {
		t.Fatal("new key limited")
	}
	if _, ok := l.m["fresh"]; ok || len(l.m) != 10002 {
		t.Fatalf("fresh kept=%v, %d buckets", ok, len(l.m))
	}
	// a dropped bucket must not reset a used one
	if !l.allow("full0") || l.allow("full0") {
		t.Fatal("full0 budget wrong")
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	h := rateLimit(func(*http.Request) string { return "k" }, rate.Every(time.Hour), 1)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	for _, want := range []int{http.StatusTeapot, http.StatusTooManyRequests} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "/", nil))
		if w.Code != want {
			t.Fatalf("got %d want %d: %s", w.Code, want, w.Body)
		}
	}
}

func TestTruncateRuneBoundary(t *testing.T) {
	for _, c := range []struct {
		s    string
		n    int
		want string
	}{{"abc", 5, "abc"}, {"abcdef", 3, "abc"}, {"a測試", 2, "a"}, {"a測試", 4, "a測"}, {"測", 1, ""}} {
		if got := Truncate(c.s, c.n); got != c.want {
			t.Errorf("Truncate(%q, %d) = %q, want %q", c.s, c.n, got, c.want)
		}
	}
}

func TestRecipientEmailNormalised(t *testing.T) {
	if got := recipientEmail(" R@Y.com "); got != "r@y.com" {
		t.Fatal(got)
	}
	// invalid addresses are still normalised and capped for limiter keys and audit
	if got := recipientEmail("  NOT AN EMAIL" + strings.Repeat("x", 300)); got != Truncate("not an email"+strings.Repeat("x", 300), 254) || len(got) != 254 {
		t.Fatal(got)
	}
}

func TestErrorMappingDefaultsToInternal(t *testing.T) {
	w := httptest.NewRecorder()
	recipientErr(w, errors.New("db down"))
	if w.Code != 500 || strings.TrimSpace(w.Body.String()) != `{"error":"internal"}` {
		t.Fatal(w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	recipientErr(w, fmt.Errorf("wrapped: %w", share.ErrIPDenied))
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
	w = httptest.NewRecorder()
	shareErr(w, errors.New("db down"))
	if w.Code != 500 || strings.TrimSpace(w.Body.String()) != `{"error":"internal"}` {
		t.Fatal(w.Code, w.Body)
	}
}

func TestPaddedEmptyAndWriteOnlyResponses(t *testing.T) {
	s := &server{}
	for name, h := range map[string]http.HandlerFunc{
		"empty":      func(http.ResponseWriter, *http.Request) {},
		"write only": func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("hi")) },
	} {
		w := httptest.NewRecorder()
		s.padded(h).ServeHTTP(w, httptest.NewRequest("POST", "/", nil))
		if w.Code != 200 || (name == "write only") != (w.Body.String() == "hi") {
			t.Fatalf("%s: %d %q", name, w.Code, w.Body)
		}
	}
}
