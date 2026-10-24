package httpapi

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"

	"golang.org/x/time/rate"

	"github.com/tntrock/secure-exchange/internal/auth"
)

const cookieName = "sx_session"

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' blob: data:; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Strict-Transport-Security", "max-age=31536000")
		next.ServeHTTP(w, r)
	})
}

// ClientIP returns the peer address, or — only when the peer is a trusted proxy —
// the rightmost X-Forwarded-For entry that is not itself a trusted proxy.
func ClientIP(r *http.Request, trusted []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	peer = peer.Unmap()
	isTrusted := func(a netip.Addr) bool {
		for _, p := range trusted {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	if !isTrusted(peer) {
		return peer.String()
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break // garbage below a trusted hop: don't trust anything further left
		}
		if a = a.Unmap(); !isTrusted(a) {
			return a.String()
		}
	}
	return peer.String()
}

// limiter is a keyed token-bucket set.
// ponytail: 單機記憶體限流，多實例部署時改存 PostgreSQL
type limiter struct {
	mu    sync.Mutex
	m     map[string]*rate.Limiter
	r     rate.Limit
	burst int
}

func newLimiter(r rate.Limit, burst int) *limiter {
	return &limiter{m: map[string]*rate.Limiter{}, r: r, burst: burst}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.m) > 10000 { // drop buckets that have fully refilled; they equal fresh ones
		for k, v := range l.m {
			if v.Tokens() >= float64(l.burst) {
				delete(l.m, k)
			}
		}
	}
	lim, ok := l.m[key]
	if !ok {
		lim = rate.NewLimiter(l.r, l.burst)
		l.m[key] = lim
	}
	return lim.Allow()
}

func tooMany(w http.ResponseWriter) {
	writeJSON(w, http.StatusTooManyRequests, errBody("rate_limited"))
}

// rateLimit rejects with 429 once key(r) has used up its budget.
func rateLimit(key func(*http.Request) string, r rate.Limit, burst int) func(http.Handler) http.Handler {
	l := newLimiter(r, burst)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if !l.allow(key(req)) {
				tooMany(w)
				return
			}
			next.ServeHTTP(w, req)
		})
	}
}

// session returns the cookie token and its live session, or ok=false.
func (s *server) session(r *http.Request) (string, *auth.Session, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" {
		return "", nil, false
	}
	se, err := s.Sessions.Lookup(r.Context(), c.Value)
	if err != nil {
		return "", nil, false
	}
	return c.Value, se, true
}

// requireUser needs a fully authenticated (MFA passed) session of an enabled user.
func (s *server) requireUser(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, se, ok := s.session(r)
		if !ok || !se.MFAPassed {
			writeJSON(w, http.StatusUnauthorized, errBody("unauthorized"))
			return
		}
		u, err := s.Users.ByID(r.Context(), se.UserID)
		if err != nil || u.Disabled {
			writeJSON(w, http.StatusUnauthorized, errBody("unauthorized"))
			return
		}
		next(w, r.WithContext(auth.WithUser(r.Context(), u)))
	})
}
