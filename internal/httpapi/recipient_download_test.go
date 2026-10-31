package httpapi

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"image"
	"image/jpeg"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/mark"
	"github.com/tntrock/secure-exchange/internal/preview"
)

// markShare uploads name as a@x.com, shares it (download allowed) with r@y.com and verifies r@y.com.
func markShare(t *testing.T, name string, plain []byte, wm bool, mods ...func(*Deps)) (*env, uuid.UUID, string) {
	t.Helper()
	e := newEnv(t, mods...)
	a := e.user(t, "a@x.com")
	f := e.putFile(t, a.ID, name, plain)
	e.login(t, "a@x.com", pw)
	_, tok := e.recipShareWM(t, true, wm, []uuid.UUID{f}, "r@y.com")
	e.recipVerify(t, tok, "r@y.com")
	return e, f, tok
}

func contentURL(tok string, f uuid.UUID) string {
	return "/api/s/" + tok + "/files/" + f.String() + "/content"
}

type dlTrace struct {
	code, method string
	sum          []byte
	size         *int64
}

func (e *env) dlTraces(t *testing.T, fid uuid.UUID) []dlTrace {
	t.Helper()
	rows, err := e.pool.Query(context.Background(), `SELECT code, method, sha256, size FROM download_traces WHERE file_id = $1 ORDER BY created_at, code`, fid)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []dlTrace
	for rows.Next() {
		var d dlTrace
		if err := rows.Scan(&d.code, &d.method, &d.sum, &d.size); err != nil {
			t.Fatal(err)
		}
		out = append(out, d)
	}
	return out
}

// delivered checks the newest trace is method, completed with body's hash and size, and audited.
// The client can hold the whole body before the handler has completed the row, so it waits a little.
func (e *env) delivered(t *testing.T, fid uuid.UUID, body []byte, method mark.Method) dlTrace {
	t.Helper()
	sum := sha256.Sum256(body)
	var (
		d    dlTrace
		ents []audit.Entry
		err  error
	)
	for range 100 {
		rows := e.dlTraces(t, fid)
		d = rows[len(rows)-1]
		ents, err = e.audit.List(context.Background(), audit.Filter{Action: audit.ActDownload, Limit: 1})
		if d.method == string(method) && bytes.Equal(d.sum, sum[:]) && d.size != nil && *d.size == int64(len(body)) &&
			err == nil && len(ents) == 1 && ents[0].Event.Detail["trace_code"] == d.code && ents[0].Event.Detail["mark"] == string(method) &&
			ents[0].Event.Detail["status"] == float64(200) && ents[0].Event.ActorType == "recipient" {
			return d
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("trace %+v, audit %v %+v; want %s with the body hash", d, err, ents, method)
	return d
}

func mkZip(t *testing.T, entries ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 0; i < len(entries); i += 2 {
		w, err := zw.Create(entries[i])
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(entries[i+1]))
	}
	zw.Close()
	return buf.Bytes()
}

func TestRecipientDownloadMarkedPDFPages(t *testing.T) {
	e, f, tok := markShare(t, "a.pdf", []byte("%PDF-1.4\n% original\n"), true)
	e.seedPreview(t, f, preview.KindPages, preview.StatusReady, 2)
	resp, b := e.get(t, contentURL(tok, f))
	if resp.StatusCode != 200 || resp.Header.Get("Accept-Ranges") == "bytes" || resp.Header.Get("Cache-Control") != "private, no-store" ||
		!strings.Contains(resp.Header.Get("Content-Disposition"), "a.pdf") || bytes.Contains(b, []byte("% original")) {
		t.Fatal(resp.StatusCode, resp.Header)
	}
	d := e.delivered(t, f, b, mark.PDFPages)
	if meta, text := mark.PDFCodes(b); len(meta) != 1 || meta[0] != d.code || len(text) != 1 || text[0] != d.code {
		t.Fatal(meta, text, d.code)
	}
	if n := bytes.Count(b, []byte("/Type /Page ")); n != 2 {
		t.Fatalf("%d pages", n)
	}
	resp, b2 := e.get(t, contentURL(tok, f))
	if rows := e.dlTraces(t, f); resp.StatusCode != 200 || len(rows) != 2 || rows[0].code == rows[1].code {
		t.Fatal(resp.StatusCode, rows)
	}
	if d2 := e.delivered(t, f, b2, mark.PDFPages); d2.code == d.code {
		t.Fatal("same code twice")
	}
}

func TestRecipientDownloadOfficeAsPages(t *testing.T) {
	e, f, tok := markShare(t, "Report.docx", mkZip(t, "docProps/core.xml", "<cp:coreProperties></cp:coreProperties>"), true)
	e.seedPreview(t, f, preview.KindPages, preview.StatusReady, 1)
	resp, b := e.get(t, contentURL(tok, f))
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Disposition"), `filename="Report.pdf"`) || !bytes.HasPrefix(b, []byte("%PDF-")) {
		t.Fatal(resp.StatusCode, resp.Header)
	}
	e.delivered(t, f, b, mark.PDFPages)
}

func TestRecipientDownloadPDFMeta(t *testing.T) {
	var src bytes.Buffer
	img, _ := testPage()
	if err := mark.WritePagesPDF(&src, 1, func(int) (image.Image, error) { return img, nil }, "ABCDEFGH12"); err != nil {
		t.Fatal(err)
	}
	e, f, tok := markShare(t, "a.pdf", src.Bytes(), false)
	resp, b := e.get(t, contentURL(tok, f))
	if resp.StatusCode != 200 || resp.Header.Get("Accept-Ranges") != "none" || resp.ContentLength != int64(len(b)) {
		t.Fatal(resp.StatusCode, resp.Header)
	}
	d := e.delivered(t, f, b, mark.PDFMeta)
	if meta, _ := mark.PDFCodes(b); !contains(meta, d.code) {
		t.Fatal(meta, d.code)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestRecipientDownloadImage(t *testing.T) {
	img, pngBytes := testPage()
	var jpg bytes.Buffer
	jpeg.Encode(&jpg, img, &jpeg.Options{Quality: 95})
	for _, c := range []struct {
		name   string
		plain  []byte
		wm     bool
		method mark.Method
	}{{"a.png", pngBytes, true, mark.ImageVisible}, {"a.jpg", jpg.Bytes(), false, mark.ImageInvisible}} {
		t.Run(c.name, func(t *testing.T) {
			e, f, tok := markShare(t, c.name, c.plain, c.wm)
			resp, b := e.get(t, contentURL(tok, f))
			if resp.StatusCode != 200 || resp.ContentLength != int64(len(b)) {
				t.Fatal(resp.StatusCode, resp.Header)
			}
			d := e.delivered(t, f, b, c.method)
			got, format, err := image.Decode(bytes.NewReader(b))
			if err != nil || format != strings.TrimPrefix(mark.ImageMIME(c.plain), "image/") || got.Bounds() != img.Bounds() {
				t.Fatal(err, format)
			}
			if code, ok := mark.ExtractInvisible(got); !ok || code != d.code {
				t.Fatal(code, ok, d.code)
			}
		})
	}
}

func TestRecipientDownloadOOXML(t *testing.T) {
	e, f, tok := markShare(t, "a.docx", mkZip(t, "docProps/core.xml", "<cp:coreProperties></cp:coreProperties>", "word/document.xml", "<doc/>"), false)
	resp, b := e.get(t, contentURL(tok, f))
	if resp.StatusCode != 200 || resp.Header.Get("Accept-Ranges") != "none" {
		t.Fatal(resp.StatusCode, resp.Header)
	}
	d := e.delivered(t, f, b, mark.OOXMLMeta)
	if c := mark.ZipCodes(b); len(c) != 1 || c[0] != d.code {
		t.Fatal(c, d.code)
	}
}

func TestRecipientDownloadUnmarkedRange(t *testing.T) {
	plain := make([]byte, 100)
	rand.Read(plain)
	e, f, tok := markShare(t, "a.zip", plain, false)
	resp, b := e.get(t, contentURL(tok, f), "Range", "bytes=0-9")
	if resp.StatusCode != 206 || !bytes.Equal(b, plain[:10]) || resp.Header.Get("Accept-Ranges") != "bytes" {
		t.Fatal(resp.StatusCode, resp.Header)
	}
	rows := e.dlTraces(t, f)
	if len(rows) != 1 || rows[0].method != "none" || rows[0].sum != nil {
		t.Fatal(rows)
	}
	resp, b = e.get(t, contentURL(tok, f))
	if resp.StatusCode != 200 || !bytes.Equal(b, plain) {
		t.Fatal(resp.StatusCode)
	}
	if d := e.delivered(t, f, plain, mark.None); d.code != rows[0].code || len(e.dlTraces(t, f)) != 1 {
		t.Fatal(d, rows)
	}
}

func TestPendingPreviewNeverServesOriginal(t *testing.T) {
	plain := mkZip(t, "docProps/core.xml", "<cp:coreProperties></cp:coreProperties>", "word/document.xml", "SECRET-ORIGINAL")
	e, f, tok := markShare(t, "a.docx", plain, true)
	e.seedPreview(t, f, preview.KindPages, preview.StatusPending, 0)
	for _, m := range []string{"GET", "HEAD"} {
		req, _ := http.NewRequest(m, e.ts.URL+contentURL(tok, f), nil)
		resp, err := e.c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		buf.ReadFrom(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 409 || bytes.Contains(buf.Bytes(), []byte("SECRET")) || m == "GET" && buf.String() != `{"error":"mark_pending"}`+"\n" {
			t.Fatal(m, resp.StatusCode, buf.String())
		}
	}
	if rows := e.dlTraces(t, f); len(rows) != 0 {
		t.Fatal(rows)
	}
}

// failAfter accepts n bytes, then fails like a gone client.
type failAfter struct {
	h http.Header
	n int
}

func (w *failAfter) Header() http.Header { return w.h }
func (w *failAfter) WriteHeader(int)     {}
func (w *failAfter) Write(p []byte) (int, error) {
	k := min(len(p), w.n)
	w.n -= k
	if k < len(p) {
		return k, errors.New("client gone")
	}
	return k, nil
}

// direct calls recipientDownload in-process as the verified recipient, bypassing the HTTP stack.
func (e *env) direct(t *testing.T, tok string, f uuid.UUID, w http.ResponseWriter) (panicked any) {
	t.Helper()
	u, _ := url.Parse(e.ts.URL)
	var session string
	for _, c := range e.c.Jar.Cookies(u) {
		if c.Name == shareCookieName {
			session = c.Value
		}
	}
	a, err := e.deps.Shares.Authorize(context.Background(), session, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", contentURL(tok, f), nil)
	req.SetPathValue("fid", f.String())
	req = req.WithContext(context.WithValue(req.Context(), accessKey{}, a))
	defer func() { panicked = recover() }()
	(&server{Deps: e.deps}).recipientDownload(w, req)
	return nil
}

func TestMarkedDownloadAbortKeepsRow(t *testing.T) {
	e, f, tok := markShare(t, "a.pdf", []byte("%PDF-1.4\n"), true)
	e.seedPreview(t, f, preview.KindPages, preview.StatusReady, 2)
	if p := e.direct(t, tok, f, &failAfter{h: http.Header{}, n: 300}); p != any(http.ErrAbortHandler) {
		t.Fatalf("want abort, got %v", p)
	}
	rows := e.dlTraces(t, f)
	if len(rows) != 1 || rows[0].sum != nil || rows[0].size != nil || rows[0].method != "pdf_pages" {
		t.Fatal(rows)
	}
	hits, err := mark.ByCode(context.Background(), e.pool, rows[0].code)
	if err != nil || len(hits) != 1 || hits[0].RecipientEmail != "r@y.com" {
		t.Fatal(err, hits)
	}
	if resp, b := e.get(t, contentURL(tok, f)); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	} else if d := e.delivered(t, f, b, mark.PDFPages); d.code == rows[0].code || len(e.dlTraces(t, f)) != 2 {
		t.Fatal("retry reused the aborted row")
	}
}

func TestMarkFailureFallsBack(t *testing.T) {
	_, pngBytes := testPage()
	broken := pngBytes[:200] // header and size intact, pixel data cut: DecodeConfig ok, Decode fails
	t.Run("warn", func(t *testing.T) {
		e, f, tok := markShare(t, "a.png", broken, true)
		resp, b := e.get(t, contentURL(tok, f))
		if resp.StatusCode != 200 || !bytes.Equal(b, broken) || resp.Header.Get("Accept-Ranges") != "bytes" {
			t.Fatal(resp.StatusCode, resp.Header)
		}
		if rows := e.dlTraces(t, f); len(rows) != 1 {
			t.Fatal("stray marked row", rows)
		}
		e.delivered(t, f, b, mark.None)
	})
	t.Run("block", func(t *testing.T) {
		e, f, tok := markShare(t, "a.png", broken, true, func(d *Deps) { d.Mark.Policy = "block" })
		if resp, b := e.get(t, contentURL(tok, f)); resp.StatusCode != 403 || string(b) != `{"error":"unmarkable"}`+"\n" {
			t.Fatal(resp.StatusCode, string(b))
		}
		if rows := e.dlTraces(t, f); len(rows) != 0 {
			t.Fatal(rows)
		}
	})
	t.Run("corrupt pdf", func(t *testing.T) {
		plain := []byte("%PDF-1.4\nnot really a pdf\n")
		e, f, tok := markShare(t, "a.pdf", plain, false)
		if resp, b := e.get(t, contentURL(tok, f)); resp.StatusCode != 200 || !bytes.Equal(b, plain) {
			t.Fatal(resp.StatusCode, string(b))
		}
		e.delivered(t, f, plain, mark.None)
	})
	t.Run("docx without core.xml", func(t *testing.T) {
		plain := mkZip(t, "word/document.xml", "<doc/>")
		e, f, tok := markShare(t, "a.docx", plain, false)
		if resp, b := e.get(t, contentURL(tok, f)); resp.StatusCode != 200 || !bytes.Equal(b, plain) {
			t.Fatal(resp.StatusCode)
		}
		e.delivered(t, f, plain, mark.None)
	})
}

func TestUnmarkablePolicyBlock(t *testing.T) {
	for _, policy := range []string{"block", "warn"} {
		t.Run(policy, func(t *testing.T) {
			e := newEnv(t, func(d *Deps) { d.Mark.Policy = policy })
			a := e.user(t, "a@x.com")
			z := e.putFile(t, a.ID, "a.zip", []byte("PK\x03\x04 not much"))
			_, pngBytes := testPage()
			p := e.putFile(t, a.ID, "b.png", pngBytes)
			e.login(t, "a@x.com", pw)
			in := map[string]any{"file_ids": []uuid.UUID{z, p}, "emails": []string{"r@y.com"}, "allow_download": true, "watermark": true,
				"expires_at": time.Now().Add(48 * time.Hour).Format(time.RFC3339)}
			resp, b := e.do(t, "POST", "/api/shares", in)
			var out struct {
				Error   string   `json:"error"`
				FileIDs []string `json:"file_ids"`
			}
			json.Unmarshal(b, &out)
			if policy == "block" && (resp.StatusCode != 422 || out.Error != "unmarkable" || len(out.FileIDs) != 1 || out.FileIDs[0] != z.String()) ||
				policy == "warn" && resp.StatusCode != 201 {
				t.Fatal(resp.StatusCode, string(b))
			}
			// view-only and unwatermarked shares are never blocked
			for _, mod := range []map[string]any{{"allow_download": false}, {"watermark": false}} {
				body := map[string]any{}
				for k, v := range in {
					body[k] = v
				}
				for k, v := range mod {
					body[k] = v
				}
				if mod["allow_download"] == false {
					e.seedPreview(t, z, preview.KindPages, preview.StatusReady, 0) // view-only needs ready previews
					e.seedPreview(t, p, preview.KindImage, preview.StatusReady, 0)
				}
				if resp, b := e.do(t, "POST", "/api/shares", body); resp.StatusCode != 201 {
					t.Fatal(mod, resp.StatusCode, string(b))
				}
			}
			// a share made before the policy changed: download is blocked per file
			id, tok := e.recipShareWM(t, true, false, []uuid.UUID{z, p}, "s@y.com")
			e.pool.Exec(context.Background(), `UPDATE shares SET watermark = true WHERE id = $1`, id)
			e.recipVerify(t, tok, "s@y.com")
			resp, b = e.get(t, contentURL(tok, z))
			if policy == "block" && (resp.StatusCode != 403 || string(b) != `{"error":"unmarkable"}`+"\n") || policy == "warn" && resp.StatusCode != 200 {
				t.Fatal(resp.StatusCode, string(b))
			}
			if resp, _ := e.get(t, contentURL(tok, p)); resp.StatusCode != 200 {
				t.Fatal("markable file blocked", resp.StatusCode)
			}
		})
	}
}

func TestHeadCreatesNoTrace(t *testing.T) {
	e, f, tok := markShare(t, "a.pdf", []byte("%PDF-1.4\n"), true)
	e.seedPreview(t, f, preview.KindPages, preview.StatusReady, 1)
	a := e.user(t, "b@x.com")
	z := e.putFile(t, a.ID, "z.zip", []byte("zip bytes"))
	e.pool.Exec(context.Background(), `INSERT INTO share_files (share_id, file_id) SELECT share_id, $1 FROM share_files WHERE file_id = $2`, z, f)
	for _, fid := range []uuid.UUID{f, z} {
		req, _ := http.NewRequest("HEAD", e.ts.URL+contentURL(tok, fid), nil)
		resp, err := e.c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 || resp.Header.Get("Content-Disposition") == "" || resp.Header.Get("Content-Type") != "application/octet-stream" {
			t.Fatal(resp.StatusCode, resp.Header)
		}
		if rows := e.dlTraces(t, fid); len(rows) != 0 {
			t.Fatal(rows)
		}
	}
}

func TestListFilesMark(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "a@x.com")
	_, pngBytes := testPage()
	files := map[string]uuid.UUID{
		"a.pdf":  e.putFile(t, a.ID, "a.pdf", []byte("%PDF-1.4\n")),
		"b.docx": e.putFile(t, a.ID, "b.docx", []byte("PK")),
		"c.zip":  e.putFile(t, a.ID, "c.zip", []byte("PK")),
		"d.png":  e.putFile(t, a.ID, "d.png", pngBytes),
		"e.JPEG": e.putFile(t, a.ID, "e.JPEG", pngBytes),
	}
	e.seedPreview(t, files["a.pdf"], preview.KindPages, preview.StatusReady, 0)
	e.seedPreview(t, files["b.docx"], preview.KindPages, preview.StatusFailed, 0)
	e.seedPreview(t, files["d.png"], preview.KindImage, preview.StatusReady, 0)
	e.seedPreview(t, files["e.JPEG"], preview.KindImage, preview.StatusReady, 0)
	e.login(t, "a@x.com", pw)
	resp, b := e.get(t, "/api/files")
	var items []struct {
		Name string `json:"name"`
		Mark struct {
			Watermark string `json:"watermark"`
			Plain     string `json:"plain"`
			Degraded  bool   `json:"degraded"`
		} `json:"mark"`
	}
	if err := json.Unmarshal(b, &items); err != nil || resp.StatusCode != 200 || len(items) != 5 {
		t.Fatal(err, resp.StatusCode, string(b))
	}
	want := map[string]string{"a.pdf": "pdf_pages pdf_meta false", "b.docx": "ooxml_meta ooxml_meta true",
		"c.zip": "none none true", "d.png": "image_visible image_invisible false", "e.JPEG": "image_visible image_invisible false"}
	for _, it := range items {
		got := it.Mark.Watermark + " " + it.Mark.Plain + " " + map[bool]string{true: "true", false: "false"}[it.Mark.Degraded]
		if got != want[it.Name] {
			t.Errorf("%s: %s want %s", it.Name, got, want[it.Name])
		}
	}
}

func TestRecipientFilesMarkPending(t *testing.T) {
	for _, c := range []struct {
		wm     bool
		status preview.Status
		want   bool
	}{{true, preview.StatusPending, true}, {true, preview.StatusReady, false}, {false, preview.StatusPending, false}} {
		e, f, tok := markShare(t, "a.docx", []byte("PK"), c.wm)
		e.seedPreview(t, f, preview.KindPages, c.status, 0)
		_, b := e.get(t, "/api/s/"+tok+"/files")
		var fl struct {
			Files []struct {
				MarkPending bool `json:"mark_pending"`
			} `json:"files"`
		}
		if err := json.Unmarshal(b, &fl); err != nil || len(fl.Files) != 1 || fl.Files[0].MarkPending != c.want {
			t.Fatal(c, string(b))
		}
	}
}

func TestMarkedDownloadErrors(t *testing.T) {
	t.Run("unreadable file", func(t *testing.T) {
		e, f, tok := markShare(t, "a.zip", []byte("zip"), false, func(d *Deps) { d.Mark.Policy = "block" })
		e.pool.Exec(context.Background(), `UPDATE files SET key_id = 99 WHERE id = $1`, f)
		if resp, _ := e.get(t, contentURL(tok, f)); resp.StatusCode != 500 {
			t.Fatal(resp.StatusCode)
		}
		resp, b := e.do(t, "POST", "/api/shares", map[string]any{"file_ids": []uuid.UUID{f}, "emails": []string{"r@y.com"},
			"allow_download": true, "watermark": true, "expires_at": time.Now().Add(48 * time.Hour).Format(time.RFC3339)})
		if resp.StatusCode != 500 {
			t.Fatal(resp.StatusCode, string(b))
		}
	})
	t.Run("page missing mid-stream", func(t *testing.T) {
		e, f, tok := markShare(t, "a.pdf", []byte("%PDF-1.4\n"), true)
		e.seedPreview(t, f, preview.KindPages, preview.StatusReady, 1)
		e.pool.Exec(context.Background(), `UPDATE file_previews SET page_count = 2 WHERE file_id = $1`, f)
		if p := e.direct(t, tok, f, httptest.NewRecorder()); p != any(http.ErrAbortHandler) {
			t.Fatalf("want abort, got %v", p)
		}
		if rows := e.dlTraces(t, f); len(rows) != 1 || rows[0].sum != nil {
			t.Fatal(rows)
		}
	})
}
