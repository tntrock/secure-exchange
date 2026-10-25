package httpapi

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/preview"
)

// testPage is a smooth light gradient (like a document page), so JPEG round trips stay close to it.
func testPage() (image.Image, []byte) {
	img := image.NewRGBA(image.Rect(0, 0, 400, 300))
	for y := 0; y < 300; y++ {
		for x := 0; x < 400; x++ {
			img.Set(x, y, color.RGBA{uint8(200 + x*55/400), uint8(200 + y*55/300), 240, 255})
		}
	}
	var buf bytes.Buffer
	png.Encode(&buf, img)
	return img, buf.Bytes()
}

// seedPreview records a preview row for fid and stores pages copies of a test page.
func (e *env) seedPreview(t *testing.T, fid uuid.UUID, kind preview.Kind, status preview.Status, pages int) image.Image {
	t.Helper()
	ctx := context.Background()
	img, pngBytes := testPage()
	if _, err := e.pool.Exec(ctx, `INSERT INTO file_previews (file_id, kind, status, page_count, width, height) VALUES ($1,$2,$3,$4,400,300)`,
		fid, kind, status, pages); err != nil {
		t.Fatal(err)
	}
	itemKind := "page"
	if kind == preview.KindImage {
		itemKind = "image"
	}
	for i := 0; i < pages; i++ {
		if _, err := preview.PutItem(ctx, e.pool, e.store, e.keys, fid, itemKind, i, bytes.NewReader(pngBytes), int64(len(pngBytes)), preview.Item{Width: 400, Height: 300}); err != nil {
			t.Fatal(err)
		}
	}
	return img
}

// meanDiff decodes a JPEG and returns its mean absolute RGB difference from want, and the
// share of pixels with some channel off by more than 24 (JPEG noise on the gradient stays below).
func meanDiff(t *testing.T, jpg []byte, want image.Image) (float64, float64) {
	t.Helper()
	got, err := jpeg.Decode(bytes.NewReader(jpg))
	if err != nil {
		t.Fatal(err)
	}
	if got.Bounds() != want.Bounds() {
		t.Fatalf("bounds %v want %v", got.Bounds(), want.Bounds())
	}
	var sum, n, marked float64
	b := want.Bounds()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r1, g1, b1, _ := got.At(x, y).RGBA()
			r2, g2, b2, _ := want.At(x, y).RGBA()
			hit := false
			for _, d := range []int{int(r1>>8) - int(r2>>8), int(g1>>8) - int(g2>>8), int(b1>>8) - int(b2>>8)} {
				sum += float64(max(d, -d))
				n++
				hit = hit || max(d, -d) > 24
			}
			if hit {
				marked++
			}
		}
	}
	return sum / n, marked / (n / 3)
}

func viewHeadersOK(t *testing.T, resp *http.Response, ctype string) {
	t.Helper()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != ctype || resp.Header.Get("Cache-Control") != "private, no-store" ||
		resp.Header.Get("Content-Disposition") != "inline" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal(resp.StatusCode, resp.Header)
	}
}

func (e *env) traces(t *testing.T, fid uuid.UUID) int {
	t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(), `SELECT count(*) FROM view_traces WHERE file_id = $1`, fid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestOwnerPreviewNoWatermark(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "a@x.com")
	f := e.putFile(t, a.ID, "doc.pdf", []byte("x"))
	want := e.seedPreview(t, f, preview.KindPages, preview.StatusReady, 2)
	e.login(t, "a@x.com", pw)

	resp, b := e.get(t, "/api/files/"+f.String()+"/preview")
	if resp.StatusCode != 200 || strings.TrimSpace(string(b)) != `{"duration_ms":0,"height":300,"kind":"pages","page_count":2,"status":"ready","width":400}` {
		t.Fatal(resp.StatusCode, string(b))
	}
	resp, b = e.get(t, "/api/files/"+f.String()+"/preview/pages/1")
	viewHeadersOK(t, resp, "image/jpeg")
	if d, m := meanDiff(t, b, want); d >= 3 || m > 0.001 {
		t.Fatalf("owner page differs from base: mean %.2f, marked %.4f", d, m)
	}
	if e.traces(t, f) != 0 {
		t.Fatal("owner view left a trace")
	}

	g := e.putFile(t, a.ID, "none.bin", []byte("x"))
	if resp, b := e.get(t, "/api/files/"+g.String()+"/preview"); resp.StatusCode != 200 || strings.TrimSpace(string(b)) != `{"kind":"none","status":"unsupported"}` {
		t.Fatal(resp.StatusCode, string(b))
	}
}

func TestOwnerPreviewOtherUser404(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "a@x.com")
	e.user(t, "b@x.com")
	f := e.putFile(t, a.ID, "doc.pdf", []byte("x"))
	e.seedPreview(t, f, preview.KindPages, preview.StatusReady, 1)
	e.login(t, "b@x.com", pw)
	for _, p := range []string{"/preview", "/preview/pages/0", "/preview/video.m3u8", "/preview/segments/0.ts"} {
		if resp, _ := e.get(t, "/api/files/"+f.String()+p); resp.StatusCode != 404 {
			t.Fatal(p, resp.StatusCode)
		}
	}
}

func TestRecipientWatermarkToggle(t *testing.T) {
	for _, wm := range []bool{true, false} {
		e := newEnv(t)
		a := e.user(t, "a@x.com")
		f := e.putFile(t, a.ID, "doc.pdf", []byte("x"))
		want := e.seedPreview(t, f, preview.KindPages, preview.StatusReady, 2)
		e.login(t, "a@x.com", pw)
		sid, tok := e.recipShareWM(t, true, wm, []uuid.UUID{f}, "r@y.com")
		e.recipVerify(t, tok, "r@y.com")

		base := "/api/s/" + tok + "/files/" + f.String() + "/preview"
		resp, b := e.get(t, base)
		if resp.StatusCode != 200 || !strings.Contains(string(b), `"page_count":2`) {
			t.Fatal(resp.StatusCode, string(b))
		}
		resp, b = e.get(t, base+"/pages/0")
		viewHeadersOK(t, resp, "image/jpeg")
		// the brief asked for mean diff > 3; at the ruled alpha (Q11) a mark moves the mean only ~2,
		// so the watermark is detected by the share of clearly changed pixels instead
		d, m := meanDiff(t, b, want)
		if wm && m < 0.01 || !wm && (d >= 3 || m > 0.001) {
			t.Fatalf("watermark=%v: mean diff %.2f, marked %.4f", wm, d, m)
		}
		if resp, _ := e.get(t, base+"/pages/1"); resp.StatusCode != 200 {
			t.Fatal(resp.StatusCode)
		}
		if n := e.traces(t, f); n != 1 {
			t.Fatalf("watermark=%v: %d traces", wm, n)
		}
		ev := e.auditOne(t, audit.ActFileView)
		var code string
		e.pool.QueryRow(context.Background(), `SELECT code FROM view_traces WHERE file_id = $1`, f).Scan(&code)
		if ev.ActorType != "recipient" || ev.TargetID != f.String() || ev.Detail["share_id"] != sid {
			t.Fatalf("%+v", ev)
		}
		if tc, ok := ev.Detail["trace_code"]; wm && tc != code || !wm && ok {
			t.Fatalf("watermark=%v detail %+v (code %s)", wm, ev.Detail, code)
		}
	}
}

func TestRecipientViewOnlyCanView(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "a@x.com")
	f := e.putFile(t, a.ID, "doc.pdf", []byte("x"))
	e.seedPreview(t, f, preview.KindPages, preview.StatusReady, 1)
	e.login(t, "a@x.com", pw)
	_, tok := e.recipShare(t, false, []uuid.UUID{f}, "r@y.com")
	e.recipVerify(t, tok, "r@y.com")
	if resp, _ := e.get(t, "/api/s/"+tok+"/files/"+f.String()+"/preview/pages/0"); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := e.get(t, "/api/s/"+tok+"/files/"+f.String()+"/content"); resp.StatusCode != 403 {
		t.Fatal(resp.StatusCode)
	}
}

func TestRecipientPageBounds(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "a@x.com")
	f := e.putFile(t, a.ID, "doc.pdf", []byte("x"))
	other := e.putFile(t, a.ID, "other.pdf", []byte("x"))
	img := e.putFile(t, a.ID, "pic.png", []byte("x"))
	e.seedPreview(t, f, preview.KindPages, preview.StatusReady, 2)
	e.seedPreview(t, other, preview.KindPages, preview.StatusReady, 1)
	e.seedPreview(t, img, preview.KindImage, preview.StatusReady, 1)
	e.login(t, "a@x.com", pw)
	_, tok := e.recipShare(t, true, []uuid.UUID{f, img}, "r@y.com")
	e.recipVerify(t, tok, "r@y.com")
	base := "/api/s/" + tok + "/files/"
	for p, want := range map[string]int{
		f.String() + "/preview/pages/2": 404, f.String() + "/preview/pages/-1": 404, f.String() + "/preview/pages/x": 404,
		other.String() + "/preview/pages/0": 404, other.String() + "/preview": 404,
		img.String() + "/preview/pages/0": 200, img.String() + "/preview/pages/1": 404,
		f.String() + "/preview/video.m3u8": 404, f.String() + "/preview/segments/0.ts": 404,
	} {
		if resp, b := e.get(t, base+p); resp.StatusCode != want {
			t.Fatal(p, resp.StatusCode, string(b))
		}
	}
	anon := &http.Client{Transport: e.c.Transport}
	resp, err := anon.Get(e.ts.URL + base + f.String() + "/preview/pages/0")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatal(resp.StatusCode)
	}
}

func TestPreviewNotReady(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "a@x.com")
	f := e.putFile(t, a.ID, "doc.pdf", []byte("x"))
	e.seedPreview(t, f, preview.KindPages, preview.StatusPending, 0)
	e.login(t, "a@x.com", pw)
	resp, b := e.get(t, "/api/files/"+f.String()+"/preview/pages/0")
	if resp.StatusCode != 409 || strings.TrimSpace(string(b)) != `{"error":"preview_not_ready","status":"pending"}` {
		t.Fatal(resp.StatusCode, string(b))
	}
}

// seedVideo records a ready video preview of fid with segments "segment-0".."segment-2" (6/6/2 s).
func (e *env) seedVideo(t *testing.T, f uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	if _, err := e.pool.Exec(ctx, `INSERT INTO file_previews (file_id, kind, status, duration_ms) VALUES ($1,'video','ready',14000)`, f); err != nil {
		t.Fatal(err)
	}
	for i, ms := range []int64{6000, 6000, 2000} {
		seg := []byte("segment-" + string(rune('0'+i)))
		if _, err := preview.PutItem(ctx, e.pool, e.store, e.keys, f, "segment", i, bytes.NewReader(seg), int64(len(seg)), preview.Item{DurationMs: ms}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPlaylist(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "a@x.com")
	f := e.putFile(t, a.ID, "v.mp4", []byte("x"))
	e.seedVideo(t, f)
	e.login(t, "a@x.com", pw)
	resp, b := e.get(t, "/api/files/"+f.String()+"/preview/video.m3u8")
	viewHeadersOK(t, resp, "application/vnd.apple.mpegurl")
	want := "#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:6\n#EXT-X-MEDIA-SEQUENCE:0\n#EXT-X-PLAYLIST-TYPE:VOD\n" +
		"#EXTINF:6.000,\nsegments/0.ts\n#EXTINF:6.000,\nsegments/1.ts\n#EXTINF:2.000,\nsegments/2.ts\n#EXT-X-ENDLIST\n"
	if string(b) != want {
		t.Fatalf("playlist:\n%s", b)
	}
	resp, b = e.get(t, "/api/files/"+f.String()+"/preview/segments/1.ts")
	viewHeadersOK(t, resp, "video/mp2t")
	if string(b) != "segment-1" {
		t.Fatal(string(b))
	}
	if resp, _ := e.get(t, "/api/files/"+f.String()+"/preview/segments/3.ts"); resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}

	// watermark=false: the recipient gets the stored segment as is, and one file.view
	_, tok := e.recipShare(t, false, []uuid.UUID{f}, "r@y.com")
	e.recipVerify(t, tok, "r@y.com")
	base := "/api/s/" + tok + "/files/" + f.String() + "/preview/"
	if resp, b := e.get(t, base+"video.m3u8"); resp.StatusCode != 200 || string(b) != want {
		t.Fatal(resp.StatusCode, string(b))
	}
	for _, n := range []string{"0", "0", "2"} {
		if resp, b := e.get(t, base+"segments/"+n+".ts"); resp.StatusCode != 200 || string(b) != "segment-"+n {
			t.Fatal(resp.StatusCode, string(b))
		}
	}
	if ev := e.auditOne(t, audit.ActFileView); ev.TargetID != f.String() {
		t.Fatalf("%+v", ev)
	}
}

func TestDrawtextEscape(t *testing.T) {
	if got := drawtextEscape(`a:b'c\d%e`); got != `'a\:b\'\''c\\\\d\\%e'` {
		t.Fatal(got)
	}
	if got := filterQuote(`/f:o'n.ttf`); got != `'/f\:o\'\''n.ttf'` {
		t.Fatal(got)
	}
}

// wmVideoShare seeds a video for a fresh owner and logs a recipient into a watermark=true share of it.
func wmVideoShare(t *testing.T, mods ...func(*Deps)) (*env, uuid.UUID, string) {
	t.Helper()
	e := newEnv(t, mods...)
	a := e.user(t, "a@x.com")
	f := e.putFile(t, a.ID, "v.mp4", []byte("x"))
	e.seedVideo(t, f)
	e.login(t, "a@x.com", pw)
	_, tok := e.recipShareWM(t, true, true, []uuid.UUID{f}, "r@y.com")
	e.recipVerify(t, tok, "r@y.com")
	return e, f, "/api/s/" + tok + "/files/" + f.String() + "/preview/"
}

func TestRecipientPreviewHeadNotAllowed(t *testing.T) {
	e, f, base := wmVideoShare(t)
	for _, p := range []string{"", "segments/0.ts", "video.m3u8"} {
		req, _ := http.NewRequest("HEAD", e.ts.URL+strings.TrimSuffix(base+p, "/"), nil)
		resp, err := e.c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 405 || resp.Header.Get("Allow") != "GET" {
			t.Fatal(p, resp.StatusCode, resp.Header)
		}
	}
	if n := e.traces(t, f); n != 0 {
		t.Fatalf("%d traces", n)
	}
	if ents, err := e.audit.List(context.Background(), audit.Filter{Action: audit.ActFileView, Limit: 5}); err != nil || len(ents) != 0 {
		t.Fatal(err, ents)
	}
}

// Without a usable font (or ffmpeg) a watermarked segment must fail closed, never fall back to the bare one.
func TestSegmentBurnFailsClosed(t *testing.T) {
	e, _, base := wmVideoShare(t, func(d *Deps) { d.FontFile = filepath.Join(t.TempDir(), "missing.ttf") })
	resp, b := e.get(t, base+"segments/0.ts")
	if resp.StatusCode != 500 || bytes.Contains(b, []byte("segment-0")) {
		t.Fatal(resp.StatusCode, string(b))
	}
}

func TestSegmentBurnBusy(t *testing.T) {
	e, _, base := wmVideoShare(t)
	for range cap(burnSlots) {
		burnSlots <- struct{}{}
	}
	defer func() {
		for range cap(burnSlots) {
			<-burnSlots
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	req := httptest.NewRequestWithContext(ctx, "GET", e.ts.URL+base+"segments/0.ts", nil)
	u, _ := url.Parse(e.ts.URL)
	for _, c := range e.c.Jar.Cookies(u) {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.ts.Config.Handler.ServeHTTP(rec, req)
	if rec.Code != 503 || rec.Header().Get("Retry-After") != "2" || strings.TrimSpace(rec.Body.String()) != `{"error":"busy"}` {
		t.Fatal(rec.Code, rec.Header(), rec.Body.String())
	}
}
