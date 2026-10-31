package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/tntrock/secure-exchange/internal/audit"
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
