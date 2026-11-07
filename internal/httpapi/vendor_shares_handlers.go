package httpapi

import (
	"context"
	"net/http"

	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/share"
)

// listVendorShares is the signed-in vendor's "shared with me" list.
func (s *server) listVendorShares(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	rl, err := s.Rules.Get(r.Context())
	if err != nil {
		recipientErr(w, err)
		return
	}
	if !rl.DomainAllowed(u.Email) {
		recipientErr(w, share.ErrDomainBlocked)
		return
	}
	shs, err := s.Shares.VendorShares(r.Context(), u.ID)
	if err != nil {
		recipientErr(w, err)
		return
	}
	forbid := rl.ForbidDownload
	out := make([]map[string]any, len(shs))
	for i, sh := range shs {
		out[i] = map[string]any{"id": sh.ID, "owner_name": sh.OwnerName, "message": sh.Message, "expires_at": ts(&sh.ExpiresAt),
			"file_count": sh.FileCount, "allow_download": sh.AllowDownload && !forbid, "watermark": sh.Watermark || rl.ForceWatermark, "download_forbidden": forbid}
	}
	writeJSON(w, http.StatusOK, out)
}

// requireVendorShare needs a signed-in vendor who is a live recipient of share {id}; it stores the
// access under accessKey{} so the recipient handlers serve vendors unchanged.
func (s *server) requireVendorShare(next http.HandlerFunc) http.Handler {
	return s.requireVendor(func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathUUID(w, r, "id")
		if !ok {
			return
		}
		c, _ := r.Cookie(cookieName) // requireVendor admitted it
		a, err := s.Shares.VendorAccess(r.Context(), auth.UserFrom(r.Context()).ID, id, auth.TokenHash(c.Value), s.addr(r))
		if err != nil {
			recipientErr(w, err)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), accessKey{}, a)))
	})
}
