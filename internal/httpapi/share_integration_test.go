package httpapi_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/blob"
	"github.com/tntrock/secure-exchange/internal/db/testdb"
	"github.com/tntrock/secure-exchange/internal/httpapi"
	"github.com/tntrock/secure-exchange/internal/mail"
	"github.com/tntrock/secure-exchange/internal/mail/mailtest"
	"github.com/tntrock/secure-exchange/internal/share"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
	"github.com/tntrock/secure-exchange/internal/upload"
)

// TestShareEndToEnd runs the one-time share flow over real HTTP with the real
// tus handler, share service and mail outbox: upload, share to two people,
// OTP verify and download, view limit, revoke, audit chain.
func TestShareEndToEnd(t *testing.T) {
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
	if _, err := users.Create(context.Background(), "a@x.com", "A", "staff", "password-12345"); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewTLSServer(httpapi.NewServer(httpapi.Deps{
		Users: users, Sessions: auth.NewSessions(pool), Audit: log, SessionTTL: time.Hour,
		Pool: pool, Keys: keys, Store: store,
		Shares:  share.NewService(pool, mail.NewOutbox(pool, keys, &mail.Recorder{}), keys, "https://x.example", 30),
		Uploads: upload.NewHandler(pool, keys, store, log, t.TempDir(), 1<<30, nil),
	}))
	defer ts.Close()

	// one cookie jar per actor: owner, recipient 1, recipient 2
	newClient := func() *http.Client {
		c := ts.Client()
		cc := *c
		cc.Jar, _ = cookiejar.New(nil)
		return &cc
	}
	owner, r1, r2 := newClient(), newClient(), newClient()
	do := func(c *http.Client, method, path string, body []byte, hdr ...string) (*http.Response, []byte) {
		t.Helper()
		req, _ := http.NewRequest(method, ts.URL+path, bytes.NewReader(body))
		req.Header.Set("Origin", ts.URL)
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}
	jdo := func(c *http.Client, method, path string, v any) (*http.Response, []byte) {
		b, _ := json.Marshal(v)
		return do(c, method, path, b, "Content-Type", "application/json")
	}

	if resp, b := jdo(owner, "POST", "/api/auth/login", map[string]string{"email": "a@x.com", "password": "password-12345"}); resp.StatusCode != 200 {
		t.Fatalf("login: %d %s", resp.StatusCode, b)
	}
	data := make([]byte, 300_000)
	rand.Read(data)
	resp, _ := do(owner, "POST", "/api/uploads/", nil, "Tus-Resumable", "1.0.0", "Upload-Length", strconv.Itoa(len(data)),
		"Upload-Metadata", "filename "+base64.StdEncoding.EncodeToString([]byte("share.bin")))
	if resp.StatusCode != 201 {
		t.Fatalf("create upload: %d", resp.StatusCode)
	}
	resp, _ = do(owner, "PATCH", resp.Header.Get("Location"), data, "Tus-Resumable", "1.0.0",
		"Content-Type", "application/offset+octet-stream", "Upload-Offset", "0")
	fid := resp.Header.Get("X-SX-File-ID")
	if resp.StatusCode != 204 || fid == "" {
		t.Fatalf("patch: %d %v", resp.StatusCode, resp.Header)
	}

	resp, b := jdo(owner, "POST", "/api/shares", map[string]any{
		"file_ids": []string{fid}, "emails": []string{"r1@y.com", "r2@y.com"}, "allow_download": true, "max_views": 2,
		"expires_at": time.Now().Add(48 * time.Hour).Format(time.RFC3339), "message": "hello",
	})
	var sh struct{ ID string }
	json.Unmarshal(b, &sh)
	if resp.StatusCode != 201 || sh.ID == "" {
		t.Fatalf("create share: %d %s", resp.StatusCode, b)
	}

	lastMail := func(to string) string {
		msgs := mailtest.Messages(t, pool, keys)
		for i := len(msgs) - 1; i >= 0; i-- {
			if msgs[i].To == to {
				return msgs[i].Body
			}
		}
		t.Fatalf("no mail to %s", to)
		return ""
	}
	link := regexp.MustCompile(`https://x\.example/s/([A-Za-z0-9_-]+)`).FindStringSubmatch(lastMail("r1@y.com"))
	if link == nil {
		t.Fatal("no link in invitation")
	}
	tok := link[1]
	otpRE := regexp.MustCompile(`驗證碼是：(\d{6})`)
	var codes []string // every code seen, for the at-rest scan below
	verify := func(c *http.Client, email string) (*http.Response, []byte) {
		t.Helper()
		if resp, b := jdo(c, "POST", "/api/s/"+tok+"/code", map[string]string{"email": email}); resp.StatusCode != 200 || string(b) != `{"sent":true}`+"\n" {
			t.Fatalf("code: %d %s", resp.StatusCode, b)
		}
		m := otpRE.FindStringSubmatch(lastMail(email))
		if m == nil {
			t.Fatal("no code in mail")
		}
		codes = append(codes, m[1])
		return jdo(c, "POST", "/api/s/"+tok+"/verify", map[string]string{"email": email, "code": m[1]})
	}
	sum := sha256.Sum256(data)
	content := "/api/s/" + tok + "/files/" + fid + "/content"

	if resp, b := verify(r1, "r1@y.com"); resp.StatusCode != 200 {
		t.Fatalf("verify r1: %d %s", resp.StatusCode, b)
	}
	if resp, b := do(r1, "GET", content, nil); resp.StatusCode != 200 || sha256.Sum256(b) != sum {
		t.Fatalf("r1 download: %d len=%d", resp.StatusCode, len(b))
	}
	if resp, b := verify(r2, "r2@y.com"); resp.StatusCode != 200 {
		t.Fatalf("verify r2: %d %s", resp.StatusCode, b)
	}
	// both views used: a third verification is refused
	if resp, b := verify(newClient(), "r1@y.com"); resp.StatusCode != 403 || string(b) != `{"error":"view_limit"}`+"\n" {
		t.Fatalf("third verify: %d %s", resp.StatusCode, b)
	}

	if resp, _ := do(owner, "POST", "/api/shares/"+sh.ID+"/revoke", nil); resp.StatusCode != 204 {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}
	// ruling P9: revoke drops recipient sessions, so the old session is simply unauthorized
	if resp, _ := do(r2, "GET", "/api/s/"+tok+"/files", nil); resp.StatusCode != 401 {
		t.Fatalf("files after revoke: %d", resp.StatusCode)
	}

	ctx := context.Background()
	for _, want := range []struct {
		action, actorType string
		n                 int
	}{{audit.ActShareCreate, "user", 1}, {audit.ActShareOTPVerify, "recipient", 3}, {audit.ActDownload, "recipient", 1}, {audit.ActShareRevoke, "user", 1}} {
		ents, err := log.List(ctx, audit.Filter{Action: want.action})
		if err != nil || len(ents) != want.n || ents[0].Event.ActorType != want.actorType {
			t.Fatalf("audit %s: %v %+v", want.action, err, ents)
		}
	}
	if bad, err := log.Verify(ctx); err != nil || bad != 0 {
		t.Fatalf("audit chain: bad=%d err=%v", bad, err)
	}

	// secrets at rest: no code or link token in any text/bytea column of the share and mail tables
	for _, table := range []string{"mail_outbox", "share_otps", "share_sessions", "shares"} {
		rows, err := pool.Query(ctx, `SELECT column_name, data_type FROM information_schema.columns
			WHERE table_schema = current_schema() AND table_name = $1 AND data_type IN ('text', 'bytea')`, table)
		if err != nil {
			t.Fatal(err)
		}
		var exprs []string
		for rows.Next() {
			var col, typ string
			if err := rows.Scan(&col, &typ); err != nil {
				t.Fatal(err)
			}
			if typ == "bytea" {
				col = "encode(" + col + ", 'escape')"
			}
			exprs = append(exprs, "coalesce("+col+", '')")
		}
		if rows.Err() != nil || len(exprs) == 0 {
			t.Fatalf("%s columns: %v", table, rows.Err())
		}
		var dump string
		if err := pool.QueryRow(ctx, `SELECT coalesce(string_agg(concat_ws(' ', `+strings.Join(exprs, ", ")+`), ' '), '') FROM `+table).Scan(&dump); err != nil {
			t.Fatal(err)
		}
		for _, secret := range append([]string{tok}, codes...) {
			if strings.Contains(dump, secret) {
				t.Errorf("%s stores %q in plaintext", table, secret)
			}
		}
	}
}
