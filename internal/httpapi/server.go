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
	"github.com/tntrock/secure-exchange/internal/config"
	"github.com/tntrock/secure-exchange/internal/share"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
	"github.com/tntrock/secure-exchange/internal/webui"
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
	Shares         *share.Service
	FontFile       string // TTF for burned-in video watermarks (SX_FONT_FILE)
	Mark           config.MarkConfig
	CodeDelay      time.Duration // recipient /code and /verify answer no sooner than this after the request starts (P10)
}

type server struct {
	Deps
	dummyHash    string   // verified against when the email is unknown, to equalise timing
	accountLimit *limiter // per email (login) / per user (totp)
	codeLimit    *limiter // recipient code requests per (share token, email)
}

func NewServer(deps Deps) http.Handler {
	dummy, err := auth.HashPassword(rand.Text())
	if err != nil {
		panic(err) // only fails if rand fails
	}
	s := &server{Deps: deps, dummyHash: dummy, accountLimit: newLimiter(rate.Every(12*time.Second), 5),
		codeLimit: newLimiter(rate.Every(200*time.Second), 3)}
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
	mux.Handle("POST /api/shares", s.requireUser(s.createShare))
	mux.Handle("GET /api/shares", s.requireUser(s.listShares))
	mux.Handle("GET /api/shares/{id}", s.requireUser(s.getShare))
	mux.Handle("POST /api/shares/{id}/revoke", s.requireUser(s.revokeShare))
	mux.Handle("POST /api/shares/{id}/recipients", s.requireUser(s.addRecipients))
	mux.Handle("POST /api/shares/{id}/recipients/{rid}/revoke", s.requireUser(s.revokeRecipient))
	// external recipients: no staff login
	recipIP := func(h http.HandlerFunc) http.Handler {
		return s.padded(rateLimit(s.ip, rate.Every(6*time.Second), 10)(h))
	}
	mux.HandleFunc("GET /api/s/{token}", s.recipientLanding)
	mux.Handle("POST /api/s/{token}/code", recipIP(s.requestCode))
	mux.Handle("POST /api/s/{token}/verify", recipIP(s.verifyCode))
	mux.Handle("GET /api/s/{token}/files", s.requireRecipient(s.listRecipientFiles))
	mux.Handle("GET /api/s/{token}/files/{fid}/content", s.requireRecipient(s.recipientDownload))
	mux.HandleFunc("POST /api/s/{token}/logout", s.recipientLogout)
	s.previewRoutes(mux)
	mux.Handle("POST /api/me/totp/setup", s.requireUser(s.totpSetup))
	mux.Handle("POST /api/me/totp/enable", s.requireUser(s.totpEnable))
	mux.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusNotFound, errBody("not_found")) })
	mux.Handle("/", webui.Handler())
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
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool { return readJSONMax(w, r, v, 4<<10) }

func readJSONMax(w http.ResponseWriter, r *http.Request, v any, max int64) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, max)).Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("bad_request"))
		return false
	}
	return true
}
