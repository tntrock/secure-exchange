package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"image"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/config"
	"github.com/tntrock/secure-exchange/internal/mark"
)

type traceResp struct {
	Hits     []mark.Hit
	Analyzed *bool
	SHA256   string
}

func (e *env) adminLogin(t *testing.T) {
	t.Helper()
	if _, err := e.users.Create(context.Background(), "adm@x.com", "Adm", "admin", pw); err != nil {
		t.Fatal(err)
	}
	e.login(t, "adm@x.com", pw)
}

func (e *env) tracePost(t *testing.T, ct string, body []byte) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest("POST", e.ts.URL+"/api/admin/trace", bytes.NewReader(body))
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	resp, err := e.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func (e *env) traceJSON(t *testing.T, body string) (*http.Response, []byte) {
	return e.tracePost(t, "application/json", []byte(body))
}

func (e *env) traceUpload(t *testing.T, data []byte) traceResp {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("note", "x")
	fw, _ := mw.CreateFormFile("file", "leak.bin")
	fw.Write(data)
	mw.Close()
	resp, b := e.tracePost(t, mw.FormDataContentType(), buf.Bytes())
	return decodeTrace(t, resp, b)
}

func decodeTrace(t *testing.T, resp *http.Response, b []byte) traceResp {
	t.Helper()
	var tr traceResp
	if resp.StatusCode != 200 || json.Unmarshal(b, &tr) != nil || strings.Contains(string(b), `"hits":null`) {
		t.Fatal(resp.StatusCode, string(b))
	}
	return tr
}

func TestTraceByCode(t *testing.T) {
	e, f, _ := markShare(t, "a.pdf", []byte("%PDF-1.4\n"), false)
	var rid, shareID uuid.UUID
	if err := e.pool.QueryRow(context.Background(), `SELECT id, share_id FROM share_recipients LIMIT 1`).Scan(&rid, &shareID); err != nil {
		t.Fatal(err)
	}
	code, err := mark.Start(context.Background(), e.pool, mark.Download{FileID: f, ShareID: shareID, RecipientID: rid, Method: mark.PDFMeta, IP: "9.9.9.9"})
	if err != nil {
		t.Fatal(err)
	}
	e.adminLogin(t)
	resp, b := e.traceJSON(t, `{"code":"sx-`+strings.ToLower(code)+`"}`)
	tr := decodeTrace(t, resp, b)
	if len(tr.Hits) != 1 || tr.Hits[0].Via != "code" || tr.Hits[0].Source != "download" || tr.Hits[0].RecipientEmail != "r@y.com" ||
		tr.Hits[0].IP != "9.9.9.9" || tr.Hits[0].OwnerEmail != "a@x.com" || tr.Hits[0].Code != code || tr.Hits[0].FileID != f || tr.Hits[0].At.IsZero() {
		t.Fatal(string(b))
	}
	if tr.Analyzed == nil || *tr.Analyzed || tr.SHA256 != "" {
		t.Fatal(string(b))
	}
	d := e.auditOne(t, audit.ActTraceLookup)
	if d.Detail["by"] != "code" || d.Detail["hits"] != float64(1) || d.Result != "ok" {
		t.Fatal(d)
	}
	// unknown code: no hit
	resp, b = e.traceJSON(t, `{"code":"ZZZZZZZZZZ"}`)
	if tr := decodeTrace(t, resp, b); len(tr.Hits) != 0 || !strings.Contains(string(b), `"hits":[]`) {
		t.Fatal(string(b))
	}
}

func TestTraceBySHA(t *testing.T) {
	e, f, tok := markShare(t, "a.txt", []byte("plain original"), false)
	if resp, _ := e.get(t, contentURL(tok, f)); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	e.adminLogin(t)
	sum := sha256.Sum256([]byte("plain original"))
	resp, b := e.traceJSON(t, `{"sha256":"`+strings.ToUpper(hex.EncodeToString(sum[:]))+`"}`)
	tr := decodeTrace(t, resp, b)
	if len(tr.Hits) != 2 || tr.Hits[0].Source != "download" || tr.Hits[0].Via != "sha256" || tr.Hits[1].Source != "file" || tr.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal(string(b))
	}
	if d := e.auditOne(t, audit.ActTraceLookup); d.Detail["by"] != "sha256" || d.Detail["hits"] != float64(2) {
		t.Fatal(d)
	}
}

func TestTraceByUpload(t *testing.T) {
	img, _ := testPage()
	var src bytes.Buffer
	if err := mark.WritePagesPDF(&src, 1, func(int) (image.Image, error) { return img, nil }, "ABCDEFGH12"); err != nil {
		t.Fatal(err)
	}
	e, f, tok := markShare(t, "a.pdf", src.Bytes(), false)
	_, marked := e.get(t, contentURL(tok, f))
	d := e.delivered(t, f, marked, mark.PDFMeta)
	e.adminLogin(t)
	tr := e.traceUpload(t, marked)
	if len(tr.Hits) != 1 || tr.Hits[0].Via != "metadata" || tr.Hits[0].Source != "download" || tr.Hits[0].Code != d.code ||
		tr.Hits[0].RecipientEmail != "r@y.com" || tr.Analyzed == nil || !*tr.Analyzed {
		t.Fatalf("%+v", tr)
	}
	if sum := sha256.Sum256(marked); tr.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal(tr.SHA256)
	}
	if a := e.auditOne(t, audit.ActTraceLookup); a.Detail["by"] != "file" || a.Detail["hits"] != float64(1) {
		t.Fatal(a)
	}

	// the original: its embedded ABCDEFGH12 is not in the DB, so only the file row matches (by hash)
	tr = e.traceUpload(t, src.Bytes())
	if len(tr.Hits) != 1 || tr.Hits[0].Source != "file" || tr.Hits[0].Via != "sha256" {
		t.Fatalf("%+v", tr)
	}
}

func TestTraceGarbageUpload(t *testing.T) {
	e := newEnv(t)
	e.adminLogin(t)
	junk := make([]byte, 1024)
	rand.Read(junk)
	tr := e.traceUpload(t, junk)
	if len(tr.Hits) != 0 || tr.Analyzed == nil || !*tr.Analyzed {
		t.Fatalf("%+v", tr)
	}
	for _, d := range [][]byte{[]byte("%PDF-1.4 broken"), []byte("PK\x03\x04broken"), []byte("\xff\xd8\xffbroken"), nil} {
		if tr := e.traceUpload(t, d); len(tr.Hits) != 0 {
			t.Fatal(tr)
		}
	}
}

func TestTraceOversizeUpload(t *testing.T) {
	e := newEnv(t, func(d *Deps) { d.Mark = config.MarkConfig{MaxBytes: 1 << 10, MaxPixels: 50_000_000, Policy: "warn"} })
	e.adminLogin(t)
	big := make([]byte, 4<<10)
	rand.Read(big)
	sum := sha256.Sum256(big)
	tr := e.traceUpload(t, big)
	if tr.Analyzed == nil || *tr.Analyzed || tr.SHA256 != hex.EncodeToString(sum[:]) || len(tr.Hits) != 0 {
		t.Fatalf("%+v", tr)
	}
	// exactly MaxBytes is still analysed
	if tr := e.traceUpload(t, big[:1<<10]); tr.Analyzed == nil || !*tr.Analyzed {
		t.Fatalf("%+v", tr)
	}
}

func TestTraceAdminOnly(t *testing.T) {
	e, _, tok := markShare(t, "a.txt", []byte("x"), false)
	e.c.Jar, _ = cookiejar.New(nil)
	e.recipVerify(t, tok, "r@y.com") // a recipient session only
	if resp, _ := e.traceJSON(t, `{"code":"ABCDEFGH12"}`); resp.StatusCode != 401 {
		t.Fatal("recipient", resp.StatusCode)
	}
	e.login(t, "a@x.com", pw) // staff
	if resp, b := e.traceJSON(t, `{"code":"ABCDEFGH12"}`); resp.StatusCode != 403 || string(b) != `{"error":"forbidden"}`+"\n" {
		t.Fatal("staff", resp.StatusCode, string(b))
	}
	e2 := newEnv(t)
	if resp, _ := e2.traceJSON(t, `{"code":"ABCDEFGH12"}`); resp.StatusCode != 401 {
		t.Fatal("anon", resp.StatusCode)
	}
}

func TestTraceBadInput(t *testing.T) {
	e := newEnv(t)
	e.adminLogin(t)
	for _, c := range []struct{ body, want string }{
		{`{"code":"nope"}`, "bad_code"},
		{`{"sha256":"abc"}`, "bad_sha256"},
		{`{"sha256":"` + strings.Repeat("g", 64) + `"}`, "bad_sha256"},
		{`{}`, "bad_request"},
		{`{"code":"ABCDEFGH12","sha256":"` + strings.Repeat("a", 64) + `"}`, "bad_request"},
		{`not json`, "bad_request"},
	} {
		if resp, b := e.traceJSON(t, c.body); resp.StatusCode != 400 || !strings.Contains(string(b), `"`+c.want+`"`) {
			t.Errorf("%s: %d %s", c.body, resp.StatusCode, b)
		}
	}
	if resp, b := e.tracePost(t, "text/plain", []byte("x")); resp.StatusCode != 400 {
		t.Error("text/plain", resp.StatusCode, b)
	}
	if resp, b := e.tracePost(t, "", nil); resp.StatusCode != 400 {
		t.Error("no content type", resp.StatusCode, b)
	}
}

func TestTraceBadMultipart(t *testing.T) {
	e := newEnv(t)
	e.adminLogin(t)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("other", "x")
	mw.Close()
	if resp, b := e.tracePost(t, mw.FormDataContentType(), buf.Bytes()); resp.StatusCode != 400 {
		t.Error("no file part", resp.StatusCode, b)
	}
	trunc := "--" + mw.Boundary() + "\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nabc"
	if resp, b := e.tracePost(t, mw.FormDataContentType(), []byte(trunc)); resp.StatusCode != 400 {
		t.Error("truncated", resp.StatusCode, b)
	}
}

func TestTraceDBError(t *testing.T) {
	e := newEnv(t)
	e.adminLogin(t)
	if _, err := e.pool.Exec(context.Background(), `DROP TABLE download_traces CASCADE`); err != nil {
		t.Fatal(err)
	}
	if resp, b := e.traceJSON(t, `{"code":"ABCDEFGH12"}`); resp.StatusCode != 500 {
		t.Fatal(resp.StatusCode, string(b))
	}
	if resp, _ := e.traceJSON(t, `{"sha256":"`+strings.Repeat("a", 64)+`"}`); resp.StatusCode != 500 {
		t.Fatal(resp.StatusCode)
	}
	// a file carrying a code fails at the code lookup, a plain one at the hash lookup
	pdf := []byte("%PDF-1.4\n/sx_trace (SX-ABCDEFGH12)\n")
	for _, d := range [][]byte{pdf, []byte("plain")} {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		fw, _ := mw.CreateFormFile("file", "x")
		fw.Write(d)
		mw.Close()
		if resp, b := e.tracePost(t, mw.FormDataContentType(), buf.Bytes()); resp.StatusCode != 500 {
			t.Fatal(resp.StatusCode, string(b))
		}
	}
}
