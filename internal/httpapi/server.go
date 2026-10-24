// Package httpapi is the JSON HTTP API.
package httpapi

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/time/rate"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/blob"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
)

type Deps struct {
	Users          *auth.Users
	Sessions       *auth.Sessions
	Audit          *audit.Log
	TrustedProxies []netip.Prefix
	SessionTTL     time.Duration
	Uploads        http.Handler // tus endpoint (internal/upload), mounted under /api/uploads/
	Pool           *pgxpool.Pool
	Keys           *sxcrypto.Keyring
	Store          blob.Store
}

type server struct {
	Deps
	dummyHash    string   // verified against when the email is unknown, to equalise timing
	accountLimit *limiter // per email (login) / per user (totp)
}

func NewServer(deps Deps) http.Handler {
	dummy, err := auth.HashPassword(rand.Text())
	if err != nil {
		panic(err) // only fails if rand fails
	}
	s := &server{Deps: deps, dummyHash: dummy, accountLimit: newLimiter(rate.Every(12*time.Second), 5)}
	return securityHeaders(http.NewCrossOriginProtection().Handler(s.routes()))
}

func (s *server) routes() *http.ServeMux {
	perIP := rateLimit(s.ip, rate.Every(6*time.Second), 10)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })

	mux.Handle("POST /api/auth/login", perIP(http.HandlerFunc(s.login)))
	mux.Handle("POST /api/auth/totp", perIP(http.HandlerFunc(s.totp)))
	mux.HandleFunc("POST /api/auth/logout", s.logout)

	mux.Handle("GET /api/me", s.requireUser(s.me))
	mux.Handle("GET /api/files", s.requireUser(s.listFiles))
	mux.Handle("GET /api/files/{id}/content", s.requireUser(s.downloadFile))
	mux.Handle("DELETE /api/files/{id}", s.requireUser(s.deleteFile))
	mux.Handle("POST /api/me/totp/setup", s.requireUser(s.totpSetup))
	mux.Handle("POST /api/me/totp/enable", s.requireUser(s.totpEnable))
	if s.Uploads != nil {
		mux.Handle("/api/uploads/", s.requireUser(s.Uploads.ServeHTTP))
	}
	return mux
}

func (s *server) ip(r *http.Request) string { return ClientIP(r, s.TrustedProxies) }

func errBody(code string) map[string]string { return map[string]string{"error": code} }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// readJSON decodes a small JSON body into v; on failure it writes 400 and returns false.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("bad_request"))
		return false
	}
	return true
}
