package httpapi_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/blob"
	"github.com/tntrock/secure-exchange/internal/config"
	"github.com/tntrock/secure-exchange/internal/db/testdb"
	"github.com/tntrock/secure-exchange/internal/httpapi"
	"github.com/tntrock/secure-exchange/internal/intake"
	"github.com/tntrock/secure-exchange/internal/mail"
	"github.com/tntrock/secure-exchange/internal/mail/mailtest"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
	"github.com/tntrock/secure-exchange/internal/upload"
)

// TestIntakePatchAfterRevoke: once the owner revokes the request, an uploader's
// next PATCH gets 410 and the upload does not advance.
func TestIntakePatchAfterRevoke(t *testing.T) {
	pool := testdb.New(t)
	k := make([]byte, 32)
	rand.Read(k)
	keys, err := sxcrypto.ParseKeyring("1:"+base64.StdEncoding.EncodeToString(k), 1)
	if err != nil {
		t.Fatal(err)
	}
	store, err := blob.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	users, log := auth.NewUsers(pool, keys), audit.New(pool)
	owner, err := users.Create(context.Background(), "a@x.com", "A", "staff", "password-12345")
	if err != nil {
		t.Fatal(err)
	}
	svc := intake.NewService(pool, mail.NewOutbox(pool, keys, &mail.Recorder{}), keys, "https://x.example", 30)
	ts := httptest.NewTLSServer(httpapi.NewServer(httpapi.Deps{
		Users: users, Sessions: auth.NewSessions(pool), Audit: log, SessionTTL: time.Hour,
		Pool: pool, Keys: keys, Store: store, Requests: svc,
		Uploads: upload.NewHandler(pool, keys, store, log, t.TempDir(), 1<<30, nil, config.PreviewConfig{MaxBytes: 1 << 30, MaxVideoBytes: 1 << 30}),
	}))
	defer ts.Close()
	c := ts.Client()
	c.Jar, _ = cookiejar.New(nil)

	req, err := svc.Create(context.Background(), owner, intake.CreateInput{Emails: []string{"u@x.com"}, ExpiresAt: time.Now().Add(48 * time.Hour), MaxFiles: 3, MaxTotalBytes: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	link := regexp.MustCompile(`https://x\.example/r/([A-Za-z0-9_-]+)`)
	var tok string
	for _, m := range mailtest.Messages(t, pool, keys) {
		if m.To == "u@x.com" {
			if g := link.FindStringSubmatch(m.Body); g != nil {
				tok = g[1]
			}
		}
	}
	if tok == "" {
		t.Fatal("no invitation link")
	}
	do := func(method, path string, body any, hdr ...string) (*http.Response, []byte) {
		t.Helper()
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		r, _ := http.NewRequest(method, ts.URL+path, rd)
		r.Header.Set("Origin", ts.URL)
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Set(hdr[i], hdr[i+1])
		}
		resp, err := c.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}
	// uploader signs in with the emailed code
	if resp, b := do("POST", "/api/r/"+tok+"/code", map[string]string{"email": "u@x.com"}); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode, string(b))
	}
	var code string
	for _, m := range mailtest.Messages(t, pool, keys) {
		if g := regexp.MustCompile(`驗證碼是：(\d{6})`).FindStringSubmatch(m.Body); g != nil && m.To == "u@x.com" {
			code = g[1]
		}
	}
	if resp, b := do("POST", "/api/r/"+tok+"/verify", map[string]string{"email": "u@x.com", "code": code}); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode, string(b))
	}

	data := make([]byte, 2*sxcrypto.ChunkSize)
	meta := "filename " + base64.StdEncoding.EncodeToString([]byte("a.bin"))
	resp, _ := do("POST", "/api/r/"+tok+"/uploads/", nil, "Tus-Resumable", "1.0.0", "Upload-Length", "2097152", "Upload-Metadata", meta)
	loc := resp.Header.Get("Location")
	if resp.StatusCode != 201 || !strings.HasPrefix(loc, "/api/r/"+tok+"/uploads/") {
		t.Fatalf("create: %d %q", resp.StatusCode, loc)
	}
	patch := func(off string, b []byte) *http.Response {
		t.Helper()
		r, _ := http.NewRequest("PATCH", ts.URL+loc, bytes.NewReader(b))
		r.Header.Set("Origin", ts.URL)
		r.Header.Set("Tus-Resumable", "1.0.0")
		r.Header.Set("Content-Type", "application/offset+octet-stream")
		r.Header.Set("Upload-Offset", off)
		resp, err := c.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	if r := patch("0", data[:sxcrypto.ChunkSize]); r.StatusCode != 204 {
		t.Fatalf("chunk 1: %d", r.StatusCode)
	}
	if err := svc.Revoke(context.Background(), owner.ID, req.ID); err != nil {
		t.Fatal(err)
	}
	if r := patch("1048576", data[sxcrypto.ChunkSize:]); r.StatusCode != 410 {
		t.Fatalf("after revoke: %d", r.StatusCode)
	}
	var off int64
	if err := pool.QueryRow(context.Background(), `SELECT "offset" FROM uploads WHERE request_id = $1`, req.ID).Scan(&off); err != nil || off != sxcrypto.ChunkSize {
		t.Fatalf("offset %d err %v", off, err)
	}
}

// Only creating uploads is rate limited; the HEAD/PATCH traffic of a fast multi-file upload is not.
func TestIntakeRateLimitOnlyCreates(t *testing.T) {
	pool := testdb.New(t)
	k := make([]byte, 32)
	rand.Read(k)
	keys, err := sxcrypto.ParseKeyring("1:"+base64.StdEncoding.EncodeToString(k), 1)
	if err != nil {
		t.Fatal(err)
	}
	store, err := blob.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	users, log := auth.NewUsers(pool, keys), audit.New(pool)
	svc := intake.NewService(pool, mail.NewOutbox(pool, keys, &mail.Recorder{}), keys, "https://x.example", 30)
	ts := httptest.NewTLSServer(httpapi.NewServer(httpapi.Deps{
		Users: users, Sessions: auth.NewSessions(pool), Audit: log, SessionTTL: time.Hour,
		Pool: pool, Keys: keys, Store: store, Requests: svc,
		Uploads: upload.NewHandler(pool, keys, store, log, t.TempDir(), 1<<30, nil, config.PreviewConfig{MaxBytes: 1 << 30, MaxVideoBytes: 1 << 30}),
	}))
	defer ts.Close()
	send := func(method string) int {
		r, _ := http.NewRequest(method, ts.URL+"/api/r/tok/uploads/x", nil)
		r.Header.Set("Origin", ts.URL)
		resp, err := ts.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for i := 0; i < 130; i++ {
		for _, m := range []string{"HEAD", "PATCH", "DELETE"} {
			if send(m) == http.StatusTooManyRequests {
				t.Fatalf("%s %d was rate limited", m, i)
			}
		}
	}
	var limited bool
	for i := 0; i < 130 && !limited; i++ {
		limited = send("POST") == http.StatusTooManyRequests
	}
	if !limited {
		t.Fatal("POST was never rate limited")
	}
}
