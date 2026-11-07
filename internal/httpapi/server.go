// Package httpapi is the JSON HTTP API.
package httpapi

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/time/rate"

	"github.com/tntrock/secure-exchange/internal/account"
	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/blob"
	"github.com/tntrock/secure-exchange/internal/config"
	"github.com/tntrock/secure-exchange/internal/intake"
	"github.com/tntrock/secure-exchange/internal/rules"
	"github.com/tntrock/secure-exchange/internal/share"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
	"github.com/tntrock/secure-exchange/internal/vendor"
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
	Requests       *intake.Service
	Vendors        *vendor.Service
	Accounts       *account.Service
	Rules          *rules.Service
	FontFile       string // TTF for burned-in video watermarks (SX_FONT_FILE)
	Mark           config.MarkConfig
	CodeDelay      time.Duration // recipient /code and /verify answer no sooner than this after the request starts (P10)
	SyslogEnabled  bool          // a syslog forwarder is running (reported by /api/admin/audit/forwarding)
	LDAP           Directory     // nil when LDAP login is off
	LDAPRecheck    time.Duration // how often an LDAP session is re-read from the directory (default 15m)
	OIDC           OIDCProvider  // nil when OIDC login is off
	OIDCLabel      string        // login button text (SX_OIDC_BUTTON_TEXT), may be empty
}

type server struct {
	Deps
	dummyHash    string   // verified against when the email is unknown, to equalise timing
	accountLimit *limiter // per email (login) / per user (totp)
	codeLimit    *limiter // recipient code requests per (share token, email)
	adminViews   struct {
		sync.Mutex
		at map[string]time.Time // (session hash, file) -> end of its audit window
	}
}

func NewServer(deps Deps) http.Handler {
	dummy, err := auth.HashPassword(rand.Text())
	if err != nil {
		panic(err) // only fails if rand fails
	}
	s := &server{Deps: deps, dummyHash: dummy, accountLimit: newLimiter(rate.Every(12*time.Second), 5),
		codeLimit: newLimiter(rate.Every(200*time.Second), 3)}
	s.adminViews.at = map[string]time.Time{}
	if s.LDAPRecheck == 0 {
		s.LDAPRecheck = 15 * time.Minute
	}
	return securityHeaders(http.NewCrossOriginProtection().Handler(s.external(s.routes())))
}

func (s *server) routes() *http.ServeMux {
	perIP := rateLimit(s.rateKey, rate.Every(6*time.Second), 10)
	// browser-navigated SSO routes get their own budget and a redirect the login page can explain, not a JSON 429
	sso := rateLimitFn(s.rateKey, rate.Every(6*time.Second), 10, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login?oidc_error=rate_limited", http.StatusFound)
	})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })

	mux.Handle("POST /api/auth/login", perIP(http.HandlerFunc(s.login)))
	mux.Handle("POST /api/auth/totp", perIP(http.HandlerFunc(s.totp)))
	mux.Handle("POST /api/auth/ldap", perIP(http.HandlerFunc(s.ldapLogin)))
	mux.Handle("GET /api/auth/oidc/start", sso(http.HandlerFunc(s.oidcStart)))
	mux.Handle("GET /api/auth/oidc/callback", sso(http.HandlerFunc(s.oidcCallback)))
	mux.HandleFunc("GET /api/auth/methods", s.authMethods)
	mux.HandleFunc("POST /api/auth/logout", s.logout)
	mux.Handle("POST /api/auth/totp/setup", http.HandlerFunc(s.totpSetupPending))
	mux.Handle("POST /api/auth/totp/enroll", http.HandlerFunc(s.totpEnroll))
	// local staff and admin accounts: admins manage them; the activation pages need no login (and no external-IP gate)
	mux.Handle("GET /api/admin/users", s.requireAdmin(s.listUsers))
	mux.Handle("POST /api/admin/users", s.requireAdmin(s.createUser))
	mux.Handle("PATCH /api/admin/users/{id}", s.requireAdmin(s.setUserRole))
	mux.Handle("POST /api/admin/users/{id}/disable", s.requireAdmin(s.userAction(audit.ActUserDisable, s.setUserDisabled(true))))
	mux.Handle("POST /api/admin/users/{id}/enable", s.requireAdmin(s.userAction(audit.ActUserEnable, s.setUserDisabled(false))))
	mux.Handle("POST /api/admin/users/{id}/reset-totp", s.requireAdmin(s.userAction(audit.ActUserTOTPReset, s.resetUserTOTP)))
	mux.Handle("POST /api/admin/users/{id}/reinvite", s.requireAdmin(s.userAction(audit.ActUserReinvite, s.reinviteUser)))
	mux.Handle("GET /api/activate/{token}", perIP(http.HandlerFunc(s.activateInfo)))
	mux.Handle("POST /api/activate/{token}", perIP(http.HandlerFunc(s.activateStaff)))

	mux.Handle("GET /api/me", s.requireAccount(s.me))
	mux.Handle("GET /api/me/notifications", s.requireUser(s.getNotifyPrefs))
	mux.Handle("PUT /api/me/notifications", s.requireUser(s.setNotifyPrefs))
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
		return s.padded(rateLimit(s.rateKey, rate.Every(6*time.Second), 10)(h))
	}
	mux.HandleFunc("GET /api/s/{token}", s.recipientLanding)
	mux.Handle("POST /api/s/{token}/code", recipIP(s.requestCode))
	mux.Handle("POST /api/s/{token}/verify", recipIP(s.verifyCode))
	mux.Handle("GET /api/s/{token}/files", s.requireRecipient(s.listRecipientFiles))
	mux.Handle("GET /api/s/{token}/files/{fid}/content", s.requireRecipient(s.recipientDownload))
	mux.HandleFunc("POST /api/s/{token}/logout", s.recipientLogout)
	// upload requests: staff, then external uploaders (no staff login)
	mux.Handle("POST /api/requests", s.requireUser(s.createRequest))
	mux.Handle("GET /api/requests", s.requireUser(s.listRequests))
	mux.Handle("GET /api/requests/{id}", s.requireUser(s.getRequest))
	mux.Handle("POST /api/requests/{id}/revoke", s.requireUser(s.revokeRequest))
	mux.HandleFunc("GET /api/r/{token}", s.uploaderLanding)
	mux.Handle("POST /api/r/{token}/code", recipIP(s.uploaderCode))
	mux.Handle("POST /api/r/{token}/verify", recipIP(s.uploaderVerify))
	mux.Handle("GET /api/r/{token}/files", s.requireUploader(s.listUploaderFiles))
	mux.HandleFunc("POST /api/r/{token}/logout", s.uploaderLogout)
	mux.Handle("GET /api/admin/audit", s.requireAdmin(s.auditList))
	mux.Handle("GET /api/admin/audit/export", s.requireAdmin(s.auditExport))
	mux.Handle("POST /api/admin/audit/verify", s.requireAdmin(s.auditVerify))
	mux.Handle("GET /api/admin/audit/forwarding", s.requireAdmin(s.auditForwarding))
	mux.Handle("GET /api/shares/{id}/audit", s.requireUser(s.shareAudit(false)))
	mux.Handle("GET /api/admin/shares/{id}/audit", s.requireAdmin(s.shareAudit(true)))
	mux.Handle("GET /api/admin/shares", s.requireAdmin(s.adminListShares))
	mux.Handle("GET /api/admin/shares/{id}", s.requireAdmin(s.adminGetShare))
	mux.Handle("POST /api/admin/shares/{id}/revoke", s.requireAdmin(s.adminRevokeShare))
	mux.Handle("GET /api/admin/requests", s.requireAdmin(s.adminListRequests))
	mux.Handle("GET /api/admin/requests/{id}", s.requireAdmin(s.adminGetRequest))
	mux.Handle("POST /api/admin/requests/{id}/revoke", s.requireAdmin(s.adminRevokeRequest))
	s.previewRoutes(mux)
	// vendor accounts: staff manage them; the invitation pages need no login
	mux.Handle("GET /api/vendors", s.requireUser(s.listVendors))
	mux.Handle("POST /api/vendors", s.requireUser(s.createVendor))
	mux.Handle("PATCH /api/vendors/{id}", s.requireUser(s.setVendorExpiry))
	mux.Handle("POST /api/vendors/{id}/approve", s.requireAdmin(s.vendorAction(audit.ActVendorApprove, s.Vendors.Approve)))
	mux.Handle("POST /api/vendors/{id}/reject", s.requireAdmin(s.vendorAction(audit.ActVendorReject, s.Vendors.Reject)))
	mux.Handle("POST /api/vendors/{id}/disable", s.requireUser(s.vendorAction(audit.ActVendorDisable, s.setDisabled(true))))
	mux.Handle("POST /api/vendors/{id}/enable", s.requireUser(s.vendorAction(audit.ActVendorEnable, s.setDisabled(false))))
	mux.Handle("POST /api/vendors/{id}/reinvite", s.requireUser(s.vendorAction(audit.ActVendorReinvite, s.Vendors.Reinvite)))
	mux.Handle("GET /api/vendor/shares", s.requireVendor(s.listVendorShares))
	mux.Handle("GET /api/vendor/shares/{id}", s.requireVendorShare(s.listRecipientFiles))
	mux.Handle("GET /api/vendor/shares/{id}/files/{fid}/content", s.requireVendorShare(s.recipientDownload))
	mux.Handle("GET /api/vendor/recipients", s.requireVendor(s.listVendorRecipients))
	mux.Handle("GET /api/vendor/uploads", s.requireVendor(s.listVendorUploads))
	mux.Handle("GET /api/invite/{token}", recipIP(s.inviteInfo))
	mux.Handle("POST /api/invite/{token}", recipIP(s.activateVendor))
	mux.Handle("POST /api/admin/trace", perIP(s.requireAdmin(s.trace)))
	mux.Handle("GET /api/rules", s.requireUser(s.getRules))
	mux.Handle("PUT /api/admin/rules", s.requireAdmin(s.putRules))
	mux.Handle("POST /api/me/totp/setup", s.requireAccount(localOnly(s.totpSetup)))
	mux.Handle("POST /api/me/totp/enable", s.requireAccount(localOnly(s.totpEnable)))
	mux.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusNotFound, errBody("not_found")) })
	mux.Handle("/", webui.Handler())
	if s.Uploads != nil {
		mux.Handle("/api/uploads/", s.requireUser(s.Uploads.ServeHTTP))
		// only creating an upload is limited; HEAD/PATCH/DELETE/OPTIONS on an existing one are bounded by the
		// uploader session and the per-upload lock, and a multi-file upload sends many of them
		perIPUpload := rateLimit(s.rateKey, rate.Every(time.Second), 120)
		postLimited := func(h http.Handler) http.Handler {
			limited := perIPUpload(h)
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					limited.ServeHTTP(w, r)
					return
				}
				h.ServeHTTP(w, r)
			})
		}
		mux.Handle("/api/r/{token}/uploads/", postLimited(s.requireUploader(s.Uploads.ServeHTTP)))
		mux.Handle("/api/vendor/uploads/", postLimited(s.requireVendor(s.Uploads.ServeHTTP)))
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

// rateKey is the rate-limit bucket for a client: the IPv4 address, or the IPv6 /64 so one
// subscriber cannot dodge limits by rotating addresses. Audit and logs keep the full address.
func (s *server) rateKey(r *http.Request) string {
	ip := s.ip(r)
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is6() {
		return ip
	}
	return netip.PrefixFrom(a, 64).Masked().String()
}
