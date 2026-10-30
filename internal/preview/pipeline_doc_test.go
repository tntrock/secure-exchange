package preview

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tntrock/secure-exchange/internal/config"
)

func TestParsePages(t *testing.T) {
	out := "Title:          x\nPages:          12\nEncrypted:      no\n"
	if n, err := parsePages([]byte(out)); err != nil || n != 12 {
		t.Fatalf("%d %v", n, err)
	}
	for _, bad := range []string{"Title: x\n", "Pages: abc\n", "Pages: 0\n"} {
		if _, err := parsePages([]byte(bad)); err == nil {
			t.Fatalf("%q: want error", bad)
		}
	}
}

func TestPageFilesSorted(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"p-10.png", "p-2.png", "p-1.png", "in.pdf"} {
		os.WriteFile(filepath.Join(dir, n), nil, 0o600)
	}
	files, err := pageFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range files {
		names = append(names, filepath.Base(f))
	}
	if strings.Join(names, ",") != "p-1.png,p-2.png,p-10.png" {
		t.Fatal(names)
	}
}

func TestParsePagesLastMatch(t *testing.T) {
	// a Title with an embedded newline must not spoof the page count
	out := "Title:          x\nPages:          1\nProducer:       y\nPages:          700\n"
	if n, err := parsePages([]byte(out)); err != nil || n != 700 {
		t.Fatalf("%d %v", n, err)
	}
}

func TestRenderScale(t *testing.T) {
	page := func(n int, size string) string {
		return fmt.Sprintf("Page %4d size: %s pts\nPage %4d rot:  0\n", n, size, n)
	}
	letter := page(1, "612 x 792") + page(2, "612 x 792")
	for _, c := range []struct {
		name, out string
		pages     int
		want      string
	}{
		{"normal", letter, 2, "-r 110"},
		{"one huge page", letter + page(3, "5000 x 300.5"), 3, "-scale-to 2000"},
		{"exponent form", page(1, "3e+06 x 400"), 1, "-scale-to 2000"},
		{"exponent but small", page(1, "6.12e+02 x 792"), 1, "-r 110"},
		{"truncated listing", letter, 3, "-scale-to 2000"},
		{"spoofed extra line", page(1, "612 x 792") + letter, 2, "-scale-to 2000"},
		{"unparsable", page(1, "abc x 792"), 1, "-scale-to 2000"},
		{"non-finite", page(1, "inf x 792"), 1, "-scale-to 2000"},
		{"zero", page(1, "0 x 792"), 1, "-scale-to 2000"},
		{"no sizes", "nothing", 1, "-scale-to 2000"},
	} {
		if got := strings.Join(renderScale([]byte(c.out), 110, c.pages), " "); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestToolErrOmitsOutput(t *testing.T) {
	err := toolErr("soffice", errors.New("exit status 3"), []byte("secret document text"))
	if err.Error() != "soffice: exit status 3" {
		t.Fatal(err)
	}
	if err := toolErr("pdftoppm", ErrTimeout, nil); err.Error() != "pdftoppm: timeout" || !errors.Is(err, ErrTimeout) {
		t.Fatal(err)
	}
	if err := toolErr("ffmpeg", errors.New("exit status 1"), []byte("x: No space left on device")); !errors.Is(err, errTooLarge) {
		t.Fatal(err)
	}
}

func letterSizes(n int) string {
	var b strings.Builder
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, "Page %4d size: 612 x 792 pts\n", i)
	}
	return b.String()
}

func goodDoc() map[string]string {
	return map[string]string{"pdfs": "1", "pdfinfo": "Title: x\nPages: 2\n", "sizes": letterSizes(2), "pages": "100x50 2500x100"}
}

func TestDocPipelineFake(t *testing.T) {
	for _, name := range []string{"in.docx", "in.PDF"} {
		t.Run(name, func(t *testing.T) {
			fakeToolsOnPath(t, goodDoc())
			res, items, err := runPipeline(t, docPipeline, config.PreviewConfig{MaxPages: 5, DPI: 110}, name, []byte("doc"))
			if err != nil {
				t.Fatal(err)
			}
			if res.Kind != KindPages || res.PageCount != 2 || res.Width != 100 || res.Height != 50 || len(items) != 2 {
				t.Fatalf("%+v items %d", res, len(items))
			}
			// a page within maxPageSide is stored as rendered; a larger one is scaled down
			for i, want := range [][2]int{{100, 50}, {2000, 80}} {
				it := items[i]
				w, h := pngSize(t, it.data)
				if it.kind != "page" || it.idx != i || w != want[0] || h != want[1] || it.meta.Width != w || it.meta.Height != h {
					t.Fatalf("page %d: %s/%d %dx%d meta %+v", i, it.kind, it.idx, w, h, it.meta)
				}
			}
		})
	}
}

func TestDocPipelineFakeErrors(t *testing.T) {
	for _, c := range []struct {
		name     string
		set      map[string]string
		tooLarge bool
		want     string
	}{
		{"soffice fails", map[string]string{"fail.soffice": "secret"}, false, "soffice: exit status 3"},
		{"soffice no pdf", map[string]string{"pdfs": "0"}, false, "soffice: no PDF produced"},
		{"soffice two pdfs", map[string]string{"pdfs": "2"}, false, "soffice: no PDF produced"},
		{"pdfinfo fails", map[string]string{"fail.pdfinfo": "secret"}, false, "pdfinfo: exit status 3"},
		{"bad page count", map[string]string{"pdfinfo": "Pages: x\n"}, false, "pdfinfo: bad page count"},
		{"too many pages", map[string]string{"pdfinfo": "Pages: 6\n"}, true, "6 pages"},
		{"sizes fail", map[string]string{"fail.sizes": "secret"}, false, "pdfinfo: exit status 3"},
		{"pdftoppm fails", map[string]string{"fail.pdftoppm": "secret"}, false, "pdftoppm: exit status 3"},
		{"no pages rendered", map[string]string{"pages": ""}, false, "0 pages rendered, want 2"},
		{"extra page rendered", map[string]string{"pages": "10x10 10x10 10x10"}, false, "3 pages rendered, want 2"},
		{"page not an image", map[string]string{"pages": "10x10 junk"}, false, "page 2: decode"},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg := goodDoc()
			for k, v := range c.set {
				cfg[k] = v
			}
			fakeToolsOnPath(t, cfg)
			_, _, err := runPipeline(t, docPipeline, config.PreviewConfig{MaxPages: 5, DPI: 110}, "in.docx", []byte("doc"))
			if err == nil || errors.Is(err, errTooLarge) != c.tooLarge || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), "secret") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestDocPipelinePutError(t *testing.T) {
	fakeToolsOnPath(t, goodDoc())
	dir := t.TempDir()
	in := filepath.Join(dir, "in.pdf")
	os.WriteFile(in, []byte("doc"), 0o600)
	boom := errors.New("store down")
	put := func(string, int, io.Reader, int64, Item) error { return boom }
	_, err := docPipeline(&jobEnv{ctx: ctx, cfg: config.PreviewConfig{MaxPages: 5, DPI: 110}, dir: dir, in: in, put: put})
	if !errors.Is(err, boom) || !strings.HasPrefix(err.Error(), "page 1:") {
		t.Fatalf("err = %v", err)
	}
}

func TestPutPageMissingFile(t *testing.T) {
	if _, _, err := putPage(&jobEnv{}, 0, filepath.Join(t.TempDir(), "p-1.png")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v", err)
	}
}
