package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/mail"
	"github.com/tntrock/secure-exchange/internal/mail/mailtest"
)

var (
	shareLinkRE = regexp.MustCompile(`https://x\.example/s/([A-Za-z0-9_-]+)`)
	otpRE       = regexp.MustCompile(`驗證碼是：(\d{6})`)
)

// lastMail returns the newest queued message to addr.
func (e *env) lastMail(t *testing.T, to string) mail.Message {
	t.Helper()
	msgs := mailtest.Messages(t, e.pool, e.keys)
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].To == to {
			return msgs[i]
		}
	}
	t.Fatalf("no mail to %s", to)
	return mail.Message{}
}

// recipShare has the logged-in owner share files without IP limits; it returns the share id and link token.
func (e *env) recipShare(t *testing.T, allowDownload bool, files []uuid.UUID, emails ...string) (string, string) {
	t.Helper()
	resp, b := e.do(t, "POST", "/api/shares", map[string]any{"file_ids": files, "emails": emails, "allow_download": allowDownload,
		"expires_at": time.Now().Add(48 * time.Hour).Format(time.RFC3339), "message": "hi"})
	if resp.StatusCode != 201 {
		t.Fatal(resp.StatusCode, string(b))
	}
	var m map[string]any
	json.Unmarshal(b, &m)
	link := shareLinkRE.FindStringSubmatch(e.lastMail(t, emails[0]).Body)
	if link == nil {
		t.Fatal("no link in invitation")
	}
	return m["id"].(string), link[1]
}

// recipVerify requests a code for email, verifies it and returns the verify response.
func (e *env) recipVerify(t *testing.T, token, email string) *http.Response {
	t.Helper()
	if resp, b := e.do(t, "POST", "/api/s/"+token+"/code", map[string]string{"email": email}); resp.StatusCode != 200 || string(b) != `{"sent":true}`+"\n" {
		t.Fatal(resp.StatusCode, string(b))
	}
	m := otpRE.FindStringSubmatch(e.lastMail(t, email).Body)
	if m == nil {
		t.Fatal("no code mail")
	}
	resp, b := e.do(t, "POST", "/api/s/"+token+"/verify", map[string]string{"email": email, "code": m[1]})
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode, string(b))
	}
	return resp
}

func (e *env) auditOne(t *testing.T, action string) audit.Event {
	t.Helper()
	ents, err := e.audit.List(context.Background(), audit.Filter{Action: action, Limit: 5})
	if err != nil || len(ents) != 1 {
		t.Fatalf("%s: %v %+v", action, err, ents)
	}
	return ents[0].Event
}

func TestRecipientHappyPath(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "a@x.com")
	plain := []byte("secret contents")
	f := e.putFile(t, a.ID, "doc.txt", plain)
	e.login(t, "a@x.com", pw)
	id, tok := e.recipShare(t, true, []uuid.UUID{f}, "r@y.com")

	resp, b := e.get(t, "/api/s/"+tok)
	var land map[string]any
	json.Unmarshal(b, &land)
	if resp.StatusCode != 200 || len(land) != 3 || land["owner_name"] != "D" || land["message"] != "hi" || land["expires_at"] == nil {
		t.Fatal(resp.StatusCode, string(b))
	}
	if resp, _ := e.get(t, "/api/s/nope"); resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := e.get(t, "/api/s/"+tok+"/files"); resp.StatusCode != 401 {
		t.Fatal("files before verify", resp.StatusCode)
	}
	if resp, b := e.do(t, "POST", "/api/s/"+tok+"/verify", map[string]string{"email": "r@y.com", "code": "123456"}); resp.StatusCode != 401 || string(b) != `{"error":"invalid_code"}`+"\n" {
		t.Fatal(resp.StatusCode, string(b))
	}

	e.recipVerify(t, tok, "r@y.com")
	resp, b = e.get(t, "/api/s/"+tok+"/files")
	var fl struct {
		Message       string `json:"message"`
		AllowDownload bool   `json:"allow_download"`
		Files         []struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			Size      int64  `json:"size"`
			Available bool   `json:"available"`
		} `json:"files"`
	}
	json.Unmarshal(b, &fl)
	if resp.StatusCode != 200 || fl.Message != "hi" || !fl.AllowDownload || len(fl.Files) != 1 || fl.Files[0].ID != f.String() ||
		fl.Files[0].Name != "doc.txt" || fl.Files[0].Size != int64(len(plain)) || !fl.Files[0].Available {
		t.Fatal(resp.StatusCode, string(b))
	}
	resp, b = e.get(t, "/api/s/"+tok+"/files/"+f.String()+"/content")
	if resp.StatusCode != 200 || sha256.Sum256(b) != sha256.Sum256(plain) {
		t.Fatal(resp.StatusCode, string(b))
	}

	var owner []mail.Message
	for _, m := range mailtest.Messages(t, e.pool, e.keys) {
		if m.To == "a@x.com" {
			owner = append(owner, m)
		}
	}
	if len(owner) != 2 || !strings.Contains(owner[0].Body, "r@y.com") || !strings.Contains(owner[1].Body, "doc.txt") {
		t.Fatalf("owner notifications: %+v", owner)
	}

	var rid string
	e.pool.QueryRow(context.Background(), `SELECT id::text FROM share_recipients WHERE share_id = $1`, id).Scan(&rid)
	if ev := e.auditOne(t, audit.ActDownload); ev.ActorType != "recipient" || ev.ActorID != rid || ev.Detail["share_id"] != id ||
		ev.Detail["status"] != float64(200) || ev.TargetID != f.String() {
		t.Fatalf("%+v", ev)
	}
	if ev := e.auditOne(t, audit.ActShareOTPRequest); ev.ActorType != "recipient" || ev.ActorID != "r@y.com" || ev.Result != "ok" || ev.TargetID != id {
		t.Fatalf("%+v", ev)
	}
	ents, _ := e.audit.List(context.Background(), audit.Filter{Action: audit.ActShareOTPVerify, Limit: 5})
	if len(ents) != 2 || ents[0].Event.Result != "ok" || ents[1].Event.Result != "fail" || ents[0].Event.ActorID != "r@y.com" || ents[0].Event.TargetID != id {
		t.Fatalf("%+v", ents)
	}

	if resp, _ := e.do(t, "POST", "/api/s/"+tok+"/logout", nil); resp.StatusCode != 204 {
		t.Fatal(resp.StatusCode)
	}
	var n int
	e.pool.QueryRow(context.Background(), `SELECT count(*) FROM share_sessions`).Scan(&n)
	if resp, _ := e.get(t, "/api/s/"+tok+"/files"); resp.StatusCode != 401 || n != 0 {
		t.Fatal("session survived logout", resp.StatusCode, n)
	}
}

func TestRecipientUnknownEmailUniform(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "a@x.com")
	f := e.putFile(t, a.ID, "doc", []byte("x"))
	e.login(t, "a@x.com", pw)
	_, tok := e.recipShare(t, true, []uuid.UUID{f}, "r@y.com")
	r1, b1 := e.do(t, "POST", "/api/s/"+tok+"/code", map[string]string{"email": "r@y.com"})
	r2, b2 := e.do(t, "POST", "/api/s/"+tok+"/code", map[string]string{"email": "eve@y.com"})
	if r1.StatusCode != 200 || r1.StatusCode != r2.StatusCode || string(b1) != string(b2) || string(b1) != `{"sent":true}`+"\n" {
		t.Fatal(r1.StatusCode, string(b1), r2.StatusCode, string(b2))
	}
	ents, _ := e.audit.List(context.Background(), audit.Filter{Action: audit.ActShareOTPRequest, Limit: 5})
	if len(ents) != 2 || ents[0].Event.Result != "ignored" || ents[0].Event.ActorID != "eve@y.com" || ents[1].Event.Result != "ok" {
		t.Fatalf("%+v", ents)
	}
}

func TestRecipientViewOnlyNoDownload(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "a@x.com")
	f := e.putFile(t, a.ID, "doc", []byte("x"))
	e.login(t, "a@x.com", pw)
	_, tok := e.recipShare(t, false, []uuid.UUID{f}, "r@y.com")
	e.recipVerify(t, tok, "r@y.com")
	resp, b := e.get(t, "/api/s/"+tok+"/files/"+f.String()+"/content")
	if resp.StatusCode != 403 || string(b) != `{"error":"view_only"}`+"\n" {
		t.Fatal(resp.StatusCode, string(b))
	}
	if resp, _ := e.get(t, "/api/s/"+tok+"/files/"+uuidZero+"/content"); resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}
}

func TestDeletedFileUnavailable(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "a@x.com")
	f1 := e.putFile(t, a.ID, "one", []byte("1"))
	f2 := e.putFile(t, a.ID, "two", []byte("2"))
	other := e.putFile(t, a.ID, "not shared", []byte("3"))
	e.login(t, "a@x.com", pw)
	_, tok := e.recipShare(t, true, []uuid.UUID{f1, f2}, "r@y.com")
	e.recipVerify(t, tok, "r@y.com")
	if resp, _ := e.do(t, "DELETE", "/api/files/"+f1.String(), nil); resp.StatusCode != 204 {
		t.Fatal(resp.StatusCode)
	}
	_, b := e.get(t, "/api/s/"+tok+"/files")
	var fl struct {
		Files []map[string]any `json:"files"`
	}
	json.Unmarshal(b, &fl)
	avail := map[string]any{}
	for _, f := range fl.Files {
		avail[f["id"].(string)] = f["available"]
	}
	if len(avail) != 2 || avail[f1.String()] != false || avail[f2.String()] != true {
		t.Fatal(string(b))
	}
	for _, c := range []struct {
		id   uuid.UUID
		want int
	}{{f1, 404}, {other, 404}, {f2, 200}} {
		if resp, _ := e.get(t, "/api/s/"+tok+"/files/"+c.id.String()+"/content"); resp.StatusCode != c.want {
			t.Fatal(c.id, resp.StatusCode)
		}
	}
}

func TestRecipientCannotUseOtherShare(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "a@x.com")
	f := e.putFile(t, a.ID, "doc", []byte("x"))
	e.login(t, "a@x.com", pw)
	_, tokA := e.recipShare(t, true, []uuid.UUID{f}, "r@y.com")
	_, tokB := e.recipShare(t, true, []uuid.UUID{f}, "r@y.com")
	e.recipVerify(t, tokA, "r@y.com")
	for _, p := range []string{"/files", "/files/" + f.String() + "/content"} {
		if resp, b := e.get(t, "/api/s/"+tokB+p); resp.StatusCode != 401 || string(b) != `{"error":"unauthorized"}`+"\n" {
			t.Fatal(p, resp.StatusCode, string(b))
		}
	}
	if resp, _ := e.get(t, "/api/s/"+tokA+"/files"); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
}

func TestRecipientRevokedMidSession(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "a@x.com")
	f := e.putFile(t, a.ID, "doc", []byte("x"))
	e.login(t, "a@x.com", pw)
	id, tok := e.recipShare(t, true, []uuid.UUID{f}, "r@y.com")
	e.recipVerify(t, tok, "r@y.com")
	if resp, _ := e.do(t, "POST", "/api/shares/"+id+"/revoke", nil); resp.StatusCode != 204 {
		t.Fatal(resp.StatusCode)
	}
	// ruling P9: revoke deletes recipient sessions, so the session itself is gone
	if resp, b := e.get(t, "/api/s/"+tok+"/files"); resp.StatusCode != 401 {
		t.Fatal(resp.StatusCode, string(b))
	}
	if resp, b := e.get(t, "/api/s/"+tok); resp.StatusCode != 410 || string(b) != `{"error":"gone"}`+"\n" {
		t.Fatal(resp.StatusCode, string(b))
	}
	if resp, _ := e.do(t, "POST", "/api/s/"+tok+"/code", map[string]string{"email": "r@y.com"}); resp.StatusCode != 410 {
		t.Fatal(resp.StatusCode)
	}
}

func TestRecipientIPDenied(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "a@x.com")
	f := e.putFile(t, a.ID, "doc", []byte("x"))
	e.login(t, "a@x.com", pw)
	e.mkShare(t, []string{f.String()}, "r@y.com") // allows only 10.0.0.0/8
	tok := shareLinkRE.FindStringSubmatch(e.lastMail(t, "r@y.com").Body)[1]
	if resp, b := e.get(t, "/api/s/"+tok); resp.StatusCode != 403 || string(b) != `{"error":"ip_denied"}`+"\n" {
		t.Fatal(resp.StatusCode, string(b))
	}
}

func TestRecipientCodeRateLimit(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "a@x.com")
	f := e.putFile(t, a.ID, "doc", []byte("x"))
	e.login(t, "a@x.com", pw)
	_, tok := e.recipShare(t, true, []uuid.UUID{f}, "r@y.com")
	for i, email := range []string{"r@y.com", " R@Y.com", "r@y.com", "r@y.com"} {
		resp, _ := e.do(t, "POST", "/api/s/"+tok+"/code", map[string]string{"email": email})
		if want := map[bool]int{true: 429, false: 200}[i == 3]; resp.StatusCode != want {
			t.Fatal(i, resp.StatusCode)
		}
	}
	if resp, _ := e.do(t, "POST", "/api/s/"+tok+"/code", map[string]string{"email": "q@y.com"}); resp.StatusCode != 200 {
		t.Fatal("other email shares the bucket", resp.StatusCode)
	}
}

func TestRecipientCookieAttributes(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "a@x.com")
	f := e.putFile(t, a.ID, "doc", []byte("x"))
	e.login(t, "a@x.com", pw)
	_, tok := e.recipShare(t, true, []uuid.UUID{f}, "r@y.com")
	sc := e.recipVerify(t, tok, "r@y.com").Header.Get("Set-Cookie")
	for _, want := range []string{"sx_share=", "Path=/", "Max-Age=3600", "HttpOnly", "Secure", "SameSite=Strict"} {
		if !strings.Contains(sc, want) {
			t.Fatalf("cookie %q missing %q", sc, want)
		}
	}
	resp, _ := e.do(t, "POST", "/api/s/"+tok+"/logout", nil)
	if sc := resp.Header.Get("Set-Cookie"); !strings.HasPrefix(sc, "sx_share=;") || !strings.Contains(sc, "Max-Age=0") {
		t.Fatalf("logout cookie %q", sc)
	}
}

func TestRecipientPadOverrunLogsNoToken(t *testing.T) {
	buf := &lockedBuf{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	e := newEnv(t, func(d *Deps) { d.CodeDelay = time.Nanosecond })
	a := e.user(t, "a@x.com")
	f := e.putFile(t, a.ID, "doc", []byte("x"))
	e.login(t, "a@x.com", pw)
	_, tok := e.recipShare(t, true, []uuid.UUID{f}, "r@y.com")
	e.do(t, "POST", "/api/s/"+tok+"/code", map[string]string{"email": "r@y.com"})
	out := buf.String()
	if !strings.Contains(out, "exceeded timing pad") || !strings.Contains(out, "/api/s/{token}/code") || strings.Contains(out, tok) {
		t.Fatal(out)
	}
}

func TestRecipientCodeTimingPadded(t *testing.T) {
	const pad = 300 * time.Millisecond
	e := newEnv(t, func(d *Deps) { d.CodeDelay = pad })
	a := e.user(t, "a@x.com")
	f := e.putFile(t, a.ID, "doc", []byte("x"))
	e.login(t, "a@x.com", pw)
	_, tok := e.recipShare(t, true, []uuid.UUID{f}, "r@y.com")
	var bodies []string
	for _, c := range []struct{ path, email string }{{"/code", "r@y.com"}, {"/code", "eve@y.com"}, {"/verify", "eve@y.com"}} {
		start := time.Now()
		_, b := e.do(t, "POST", "/api/s/"+tok+c.path, map[string]string{"email": c.email, "code": "123456"})
		if d := time.Since(start); d < pad {
			t.Fatal(c, d)
		}
		bodies = append(bodies, string(b))
	}
	if bodies[0] != bodies[1] || bodies[2] != `{"error":"invalid_code"}`+"\n" {
		t.Fatal(bodies)
	}
}

// lockedBuf is a log sink shared between the server goroutines and the test.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
