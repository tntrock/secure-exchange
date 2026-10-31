package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/intake"
	"github.com/tntrock/secure-exchange/internal/mail/mailtest"
)

var requestLinkRE = regexp.MustCompile(`https://x\.example/r/([A-Za-z0-9_-]+)`)

// newRequest has the logged-in owner open a request for emails; it returns the request id and link token.
func (e *env) newRequest(t *testing.T, emails ...string) (string, string) {
	t.Helper()
	resp, b := e.do(t, "POST", "/api/requests", map[string]any{"emails": emails, "expires_at": time.Now().Add(48 * time.Hour).Format(time.RFC3339),
		"max_files": 3, "max_total_bytes": 1 << 20, "allowed_exts": []string{".PDF", "txt"}, "message": "hi"})
	if resp.StatusCode != 201 {
		t.Fatal(resp.StatusCode, string(b))
	}
	var m map[string]any
	json.Unmarshal(b, &m)
	link := requestLinkRE.FindStringSubmatch(e.lastMail(t, emails[0]).Body)
	if link == nil {
		t.Fatal("no link in invitation")
	}
	return m["id"].(string), link[1]
}

func (e *env) uploaderVerify(t *testing.T, token, email string) *http.Response {
	t.Helper()
	if resp, b := e.do(t, "POST", "/api/r/"+token+"/code", map[string]string{"email": email}); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode, string(b))
	}
	m := otpRE.FindStringSubmatch(e.lastMail(t, email).Body)
	if m == nil {
		t.Fatal("no code mail")
	}
	resp, b := e.do(t, "POST", "/api/r/"+token+"/verify", map[string]string{"email": email, "code": m[1]})
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode, string(b))
	}
	return resp
}

func TestRequestCreateListGetRevoke(t *testing.T) {
	e := newEnv(t)
	e.user(t, "a@x.com")
	e.login(t, "a@x.com", pw)
	id, tok := e.newRequest(t, "u1@y.com", "u2@y.com")

	resp, b := e.do(t, "GET", "/api/requests", nil)
	var list []map[string]any
	json.Unmarshal(b, &list)
	if resp.StatusCode != 200 || len(list) != 1 || list[0]["id"] != id || list[0]["uploader_count"] != float64(2) || list[0]["max_files"] != float64(3) {
		t.Fatal(resp.StatusCode, string(b))
	}
	resp, b = e.do(t, "GET", "/api/requests/"+id, nil)
	var d struct {
		URL         string           `json:"url"`
		AllowedExts []string         `json:"allowed_exts"`
		Uploaders   []map[string]any `json:"uploaders"`
		Files       []any            `json:"files"`
	}
	json.Unmarshal(b, &d)
	if resp.StatusCode != 200 || !strings.Contains(d.URL, "/r/"+tok) || len(d.Uploaders) != 2 || d.Files == nil || len(d.AllowedExts) != 2 || d.AllowedExts[0] != "pdf" {
		t.Fatal(resp.StatusCode, string(b))
	}
	if resp, b := e.do(t, "POST", "/api/requests/"+id+"/revoke", nil); resp.StatusCode != 204 {
		t.Fatal(resp.StatusCode, string(b))
	}
	if resp, _ := e.do(t, "GET", "/api/r/"+tok, nil); resp.StatusCode != 410 {
		t.Fatal(resp.StatusCode)
	}
	e.auditOne(t, audit.ActRequestCreate)
	e.auditOne(t, audit.ActRequestRevoke)
}

func TestRequestCreateInvalid(t *testing.T) {
	e := newEnv(t)
	e.user(t, "a@x.com")
	e.login(t, "a@x.com", pw)
	resp, b := e.do(t, "POST", "/api/requests", map[string]any{"emails": []string{"u@y.com"}, "expires_at": time.Now().Add(48 * time.Hour).Format(time.RFC3339),
		"max_files": 0, "max_total_bytes": 1 << 20})
	var m map[string]string
	json.Unmarshal(b, &m)
	if resp.StatusCode != 422 || m["field"] != "max_files" || m["error"] != "validation" {
		t.Fatal(resp.StatusCode, string(b))
	}
}

func TestRequestOtherOwner404(t *testing.T) {
	e := newEnv(t)
	e.user(t, "a@x.com")
	e.user(t, "b@x.com")
	e.login(t, "a@x.com", pw)
	id, _ := e.newRequest(t, "u@y.com")
	e.do(t, "POST", "/api/auth/logout", nil)
	e.login(t, "b@x.com", pw)
	if resp, _ := e.do(t, "GET", "/api/requests/"+id, nil); resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := e.do(t, "POST", "/api/requests/"+id+"/revoke", nil); resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}
}

func TestUploaderLandingAndCode(t *testing.T) {
	e := newEnv(t)
	e.user(t, "a@x.com")
	e.login(t, "a@x.com", pw)
	_, tok := e.newRequest(t, "u@y.com")

	resp, b := e.do(t, "GET", "/api/r/"+tok, nil)
	var land map[string]any
	json.Unmarshal(b, &land)
	exts, _ := land["allowed_exts"].([]any)
	if resp.StatusCode != 200 || len(land) != 6 || land["owner_name"] != "D" || len(exts) != 2 || land["max_files"] != float64(3) {
		t.Fatal(resp.StatusCode, string(b))
	}
	if resp, b := e.do(t, "POST", "/api/r/"+tok+"/code", map[string]string{"email": "eve@y.com"}); resp.StatusCode != 200 || string(b) != `{"sent":true}`+"\n" {
		t.Fatal(resp.StatusCode, string(b))
	}
	if ev := e.auditOne(t, audit.ActRequestOTPRequest); ev.Result != "ignored" || ev.ActorType != "uploader" || ev.ActorID != "eve@y.com" {
		t.Fatalf("%+v", ev)
	}
	before := len(mailtest.Messages(t, e.pool, e.keys))
	if resp, b := e.do(t, "POST", "/api/r/"+tok+"/code", map[string]string{"email": "u@y.com"}); resp.StatusCode != 200 || string(b) != `{"sent":true}`+"\n" {
		t.Fatal(resp.StatusCode, string(b))
	}
	if n := len(mailtest.Messages(t, e.pool, e.keys)); n != before+1 {
		t.Fatal("outbox", before, n)
	}
}

func TestUploaderVerifySetsCookie(t *testing.T) {
	e := newEnv(t)
	e.user(t, "a@x.com")
	e.login(t, "a@x.com", pw)
	_, tok := e.newRequest(t, "u@y.com")
	if resp, _ := e.do(t, "GET", "/api/r/"+tok+"/files", nil); resp.StatusCode != 401 {
		t.Fatal("files before verify", resp.StatusCode)
	}
	if resp, b := e.do(t, "POST", "/api/r/"+tok+"/verify", map[string]string{"email": "u@y.com", "code": "123456"}); resp.StatusCode != 401 || string(b) != `{"error":"invalid_code"}`+"\n" {
		t.Fatal(resp.StatusCode, string(b))
	}
	resp := e.uploaderVerify(t, tok, "u@y.com")
	sc := resp.Header.Get("Set-Cookie")
	for _, want := range []string{"sx_intake=", "HttpOnly", "Secure", "SameSite=Strict", "Path=/api/r/" + tok, "Max-Age="} {
		if !strings.Contains(sc, want) {
			t.Fatalf("cookie %q missing %q", sc, want)
		}
	}
	resp, b := e.do(t, "GET", "/api/r/"+tok+"/files", nil)
	var fl struct {
		Files     []any `json:"files"`
		FilesLeft int   `json:"files_left"`
		BytesLeft int64 `json:"bytes_left"`
	}
	json.Unmarshal(b, &fl)
	if resp.StatusCode != 200 || fl.FilesLeft != 3 || fl.BytesLeft != 1<<20 || fl.Files == nil || len(fl.Files) != 0 {
		t.Fatal(resp.StatusCode, string(b))
	}
	ents, err := e.audit.List(context.Background(), audit.Filter{Action: audit.ActRequestOTPVerify, Limit: 5})
	if err != nil || len(ents) != 2 || ents[0].Event.Result != "ok" || ents[1].Event.Result != "fail" || ents[0].Event.ActorType != "uploader" {
		t.Fatalf("%v %+v", err, ents)
	}
	if resp, _ := e.do(t, "POST", "/api/r/"+tok+"/logout", nil); resp.StatusCode != 204 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := e.do(t, "GET", "/api/r/"+tok+"/files", nil); resp.StatusCode != 401 {
		t.Fatal("files after logout", resp.StatusCode)
	}
}

func TestUploaderCookieWrongToken(t *testing.T) {
	e := newEnv(t)
	e.user(t, "a@x.com")
	e.login(t, "a@x.com", pw)
	_, tokA := e.newRequest(t, "u@y.com")
	_, tokB := e.newRequest(t, "u@y.com")
	e.uploaderVerify(t, tokA, "u@y.com")
	if resp, _ := e.do(t, "GET", "/api/r/"+tokA+"/files", nil); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := e.do(t, "GET", "/api/r/"+tokB+"/files", nil); resp.StatusCode != 401 {
		t.Fatal(resp.StatusCode)
	}
}

func TestUploaderVerifyRateLimited(t *testing.T) {
	e := newEnv(t, func(d *Deps) { d.CodeDelay = 0 })
	e.user(t, "a@x.com")
	e.login(t, "a@x.com", pw)
	_, tok := e.newRequest(t, "u@y.com")
	for i := 1; i <= 11; i++ {
		resp, _ := e.do(t, "POST", "/api/r/"+tok+"/verify", map[string]string{"email": "u@y.com", "code": "123456"})
		want := 401
		if i == 11 {
			want = 429
		}
		if resp.StatusCode != want {
			t.Fatal(i, resp.StatusCode)
		}
	}
}

func cookieNamed(t *testing.T, resp *http.Response, name string) *http.Cookie {
	t.Helper()
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no %s cookie in %v", name, resp.Header["Set-Cookie"])
	return nil
}

func TestUploaderCookieMaxAgeAndLogout(t *testing.T) {
	e := newEnv(t)
	e.user(t, "a@x.com")
	e.login(t, "a@x.com", pw)
	id, tok := e.newRequest(t, "u@y.com") // expires in 48h: the session cap is 24h
	c := cookieNamed(t, e.uploaderVerify(t, tok, "u@y.com"), intakeCookieName)
	if c.MaxAge != 24*3600 || c.Path != "/api/r/"+tok || c.Value == "" {
		t.Fatalf("long request: %+v", c)
	}
	resp, _ := e.do(t, "POST", "/api/r/"+tok+"/logout", nil)
	if c := cookieNamed(t, resp, intakeCookieName); resp.StatusCode != 204 || c.MaxAge != -1 || c.Path != "/api/r/"+tok || c.Value != "" {
		t.Fatalf("logout cookie: %d %+v", resp.StatusCode, c)
	}
	// logging out without a session still clears the cookie
	if resp, _ := e.do(t, "POST", "/api/r/"+tok+"/logout", nil); resp.StatusCode != 204 {
		t.Fatal(resp.StatusCode)
	}

	// a request ending within the day bounds the cookie to the time left
	if _, err := e.pool.Exec(context.Background(), `UPDATE upload_requests SET expires_at = now() + interval '2 hours' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	c = cookieNamed(t, e.uploaderVerify(t, tok, "u@y.com"), intakeCookieName)
	if c.MaxAge < 2*3600-60 || c.MaxAge > 2*3600 {
		t.Fatalf("short request MaxAge = %d", c.MaxAge)
	}
}

func TestUploaderVerifyFailAuditsReason(t *testing.T) {
	e := newEnv(t)
	e.user(t, "a@x.com")
	e.login(t, "a@x.com", pw)
	_, tok := e.newRequest(t, "u@y.com")
	e.do(t, "POST", "/api/r/"+tok+"/verify", map[string]string{"email": "u@y.com", "code": "123456"})
	ev := e.auditOne(t, audit.ActRequestOTPVerify)
	if ev.Result != "fail" || ev.Detail["reason"] != "invalid_code" || ev.ActorID != "u@y.com" {
		t.Fatalf("%+v", ev)
	}
}

func TestUploaderCodeRateLimited(t *testing.T) {
	e := newEnv(t)
	e.user(t, "a@x.com")
	e.login(t, "a@x.com", pw)
	_, tok := e.newRequest(t, "u@y.com")
	for i, email := range []string{"u@y.com", " U@Y.com", "u@y.com", "u@y.com"} {
		resp, _ := e.do(t, "POST", "/api/r/"+tok+"/code", map[string]string{"email": email})
		if want := map[bool]int{true: 429, false: 200}[i == 3]; resp.StatusCode != want {
			t.Fatal(i, resp.StatusCode)
		}
	}
	if resp, _ := e.do(t, "POST", "/api/r/"+tok+"/code", map[string]string{"email": "other@y.com"}); resp.StatusCode != 200 {
		t.Fatal("other email shares the bucket", resp.StatusCode)
	}
}

func TestUploaderUnknownAndRevokedToken(t *testing.T) {
	e := newEnv(t)
	e.user(t, "a@x.com")
	e.login(t, "a@x.com", pw)
	id, tok := e.newRequest(t, "u@y.com")
	call := func(token string) (int, int, int) {
		a, _ := e.do(t, "GET", "/api/r/"+token, nil)
		b, _ := e.do(t, "POST", "/api/r/"+token+"/code", map[string]string{"email": "u@y.com"})
		c, _ := e.do(t, "POST", "/api/r/"+token+"/verify", map[string]string{"email": "u@y.com", "code": "123456"})
		return a.StatusCode, b.StatusCode, c.StatusCode
	}
	if a, b, c := call("nosuchtoken"); a != 404 || b != 404 || c != 404 {
		t.Fatal("unknown token:", a, b, c)
	}
	if resp, _ := e.do(t, "POST", "/api/requests/"+id+"/revoke", nil); resp.StatusCode != 204 {
		t.Fatal(resp.StatusCode)
	}
	if a, b, c := call(tok); a != 410 || b != 410 || c != 410 {
		t.Fatal("revoked token:", a, b, c)
	}
}

func TestRequestMalformedID(t *testing.T) {
	e := newEnv(t)
	e.user(t, "a@x.com")
	e.login(t, "a@x.com", pw)
	if resp, _ := e.do(t, "GET", "/api/requests/not-a-uuid", nil); resp.StatusCode != 404 {
		t.Fatal("get", resp.StatusCode)
	}
	if resp, _ := e.do(t, "POST", "/api/requests/not-a-uuid/revoke", nil); resp.StatusCode != 404 {
		t.Fatal("revoke", resp.StatusCode)
	}
}

func TestIntakeErrMapping(t *testing.T) {
	for _, c := range []struct {
		err  error
		code int
		body string
	}{
		{intake.ErrExtNotAllowed, 403, "ext_not_allowed"}, {intake.ErrTooManyFiles, 403, "too_many_files"},
		{intake.ErrQuotaExceeded, 403, "quota_exceeded"}, {intake.ErrUnauthorized, 401, "unauthorized"},
		{fmt.Errorf("wrapped: %w", intake.ErrBadCode), 401, "invalid_code"}, {errors.New("db down"), 500, "internal"},
	} {
		w := httptest.NewRecorder()
		intakeErr(w, c.err)
		if w.Code != c.code || strings.TrimSpace(w.Body.String()) != `{"error":"`+c.body+`"}` {
			t.Errorf("%v: %d %s", c.err, w.Code, w.Body)
		}
	}
}

// addReceived records a file received through the request from the uploader with email.
func (e *env) addReceived(t *testing.T, reqID, email, name string, size int64, scan string, deleted bool) string {
	t.Helper()
	id := uuid.New()
	if _, err := e.pool.Exec(context.Background(), `INSERT INTO files (id,owner_id,name,content_type,size,sha256,wrapped_dek,key_id,storage_key,request_id,uploader_id,scan_status,scan_result,deleted_at)
		SELECT $1::uuid, r.owner_id, $3, 'x', $4, '\x00', '\x00', 1, $1::text, r.id, q.id, $5, CASE WHEN $5 = 'infected' THEN 'Eicar' ELSE '' END, CASE WHEN $6 THEN now() END
		FROM upload_requests r JOIN request_uploaders q ON q.request_id = r.id WHERE r.id = $2 AND q.email = $7`,
		id, reqID, name, size, scan, deleted, email); err != nil {
		t.Fatal(err)
	}
	return id.String()
}

func TestRequestDetailListsReceivedFiles(t *testing.T) {
	e := newEnv(t)
	e.user(t, "a@x.com")
	e.login(t, "a@x.com", pw)
	id, tok := e.newRequest(t, "u@y.com", "v@y.com")
	clean := e.addReceived(t, id, "u@y.com", "ok.txt", 5, "clean", false)
	bad := e.addReceived(t, id, "v@y.com", "bad.txt", 7, "infected", false)
	gone := e.addReceived(t, id, "u@y.com", "gone.txt", 3, "clean", true)

	_, b := e.do(t, "GET", "/api/requests/"+id, nil)
	var d struct {
		FileCount  int   `json:"file_count"`
		TotalBytes int64 `json:"total_bytes"`
		Files      []struct {
			ID            string  `json:"id"`
			Name          string  `json:"name"`
			UploaderEmail string  `json:"uploader_email"`
			ScanStatus    string  `json:"scan_status"`
			ScanResult    *string `json:"scan_result"`
			Size          int64   `json:"size"`
			Deleted       bool    `json:"deleted"`
		} `json:"files"`
	}
	if err := json.Unmarshal(b, &d); err != nil || d.FileCount != 3 || d.TotalBytes != 15 || len(d.Files) != 3 {
		t.Fatal(err, string(b))
	}
	got := map[string]int{}
	for i, f := range d.Files {
		got[f.ID] = i
	}
	if f := d.Files[got[bad]]; f.UploaderEmail != "v@y.com" || f.ScanStatus != "infected" || f.ScanResult == nil || *f.ScanResult != "Eicar" || f.Deleted || f.Size != 7 {
		t.Fatalf("infected: %+v", f)
	}
	if f := d.Files[got[clean]]; f.ScanResult == nil || *f.ScanResult != "" || f.UploaderEmail != "u@y.com" {
		t.Fatalf("clean: %+v", f)
	}
	if !d.Files[got[gone]].Deleted {
		t.Fatal("deleted flag missing")
	}

	// the uploader sees only their own live files and what is left of the limits
	e.uploaderVerify(t, tok, "u@y.com")
	_, b = e.do(t, "GET", "/api/r/"+tok+"/files", nil)
	var fl struct {
		Files []struct {
			ID, Name string
			Size     int64
		}
		FilesLeft int   `json:"files_left"`
		BytesLeft int64 `json:"bytes_left"`
	}
	if err := json.Unmarshal(b, &fl); err != nil || len(fl.Files) != 1 || fl.Files[0].ID != clean || fl.Files[0].Name != "ok.txt" || fl.Files[0].Size != 5 {
		t.Fatal(err, string(b))
	}
	if fl.FilesLeft != 0 || fl.BytesLeft != 1<<20-15 { // max_files 3, all three counted, deleted included
		t.Fatalf("left: %d files, %d bytes", fl.FilesLeft, fl.BytesLeft)
	}
}

func TestRequestEndpointsRejectBadJSON(t *testing.T) {
	e := newEnv(t)
	e.user(t, "a@x.com")
	e.login(t, "a@x.com", pw)
	_, tok := e.newRequest(t, "u@y.com")
	for _, p := range []string{"/api/requests", "/api/r/" + tok + "/code", "/api/r/" + tok + "/verify"} {
		resp, err := e.c.Post(e.ts.URL+p, "application/json", strings.NewReader("{nope"))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 400 || string(b) != `{"error":"bad_request"}`+"\n" {
			t.Errorf("%s: %d %s", p, resp.StatusCode, b)
		}
	}
	var n int
	if err := e.pool.QueryRow(context.Background(), `SELECT count(*) FROM upload_requests`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("%d requests (%v), a bad body created one", n, err)
	}
}

// An unusable database is a 500, never mistaken for a bad session.
func TestUploaderSessionDatabaseFailure(t *testing.T) {
	e := newEnv(t)
	e.user(t, "a@x.com")
	e.login(t, "a@x.com", pw)
	_, tok := e.newRequest(t, "u@y.com")
	e.uploaderVerify(t, tok, "u@y.com")
	e.pool.Close()
	if resp, _ := e.do(t, "GET", "/api/r/"+tok+"/files", nil); resp.StatusCode != 500 {
		t.Fatal("files:", resp.StatusCode)
	}
	if resp, _ := e.do(t, "POST", "/api/r/"+tok+"/logout", nil); resp.StatusCode != 500 {
		t.Fatal("logout:", resp.StatusCode)
	}
	if resp, _ := e.do(t, "GET", "/api/r/"+tok, nil); resp.StatusCode != 500 {
		t.Fatal("landing:", resp.StatusCode)
	}
}
