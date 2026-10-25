//go:build tools

// These tests need soffice, pdfinfo and pdftoppm; run them in the worker-test
// container: docker compose -f docker-compose.dev.yml --profile tools run --rm worker-test
package preview

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tntrock/secure-exchange/internal/config"
)

var toolCfg = config.PreviewConfig{MaxPages: 5, DPI: 50}

func lines(n int) []byte {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "測試文件 line %d\n", i)
	}
	return []byte(b.String())
}

func TestDocPipelineDocx(t *testing.T) {
	res, items, err := runPipeline(t, docPipeline, toolCfg, "in.txt", lines(80))
	if err != nil {
		t.Fatal(err)
	}
	if res.Kind != KindPages || res.PageCount < 1 || len(items) != res.PageCount || res.Width == 0 {
		t.Fatalf("%+v items %d", res, len(items))
	}
	for i, it := range items {
		if it.kind != "page" || it.idx != i {
			t.Fatalf("item %d: %s/%d", i, it.kind, it.idx)
		}
	}
	img, err := png.Decode(bytes.NewReader(items[0].data))
	if err != nil {
		t.Fatal(err)
	}
	if allWhite(img) {
		t.Fatal("first page is blank")
	}
}

func allWhite(img image.Image) bool {
	b := img.Bounds()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			if r, g, bl, _ := img.At(x, y).RGBA(); r < 0xf000 || g < 0xf000 || bl < 0xf000 {
				return false
			}
		}
	}
	return true
}

func TestPDFPageCap(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "long.txt")
	os.WriteFile(src, lines(600), 0o600)
	if out, err := Run(ctx, dir, sofficeTimeout, "soffice", "--headless", "--norestore", "--nolockcheck",
		"-env:UserInstallation=file://"+dir+"/profile", "--convert-to", "pdf", "--outdir", dir, src); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	pdf, err := os.ReadFile(filepath.Join(dir, "long.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	_, items, err := runPipeline(t, docPipeline, toolCfg, "in.pdf", pdf)
	if !errors.Is(err, errTooLarge) || len(items) != 0 {
		t.Fatalf("err = %v items %d", err, len(items))
	}
}

func TestSofficeTimeout(t *testing.T) {
	orig := sofficeTimeout
	sofficeTimeout = time.Millisecond
	defer func() { sofficeTimeout = orig }()
	_, _, err := runPipeline(t, docPipeline, toolCfg, "in.txt", lines(3))
	if !errors.Is(err, ErrTimeout) || errors.Is(err, errTooLarge) {
		t.Fatalf("err = %v", err)
	}
}

// onePagePDF is a minimal valid PDF with one blank page of w×h points.
func onePagePDF(w, h int, extra string) []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n")
	objs := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] %s >>", w, h, extra),
	}
	var offs []int
	for i, o := range objs {
		offs = append(offs, b.Len())
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for _, o := range offs {
		fmt.Fprintf(&b, "%010d 00000 n \n", o)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, xref)
	return b.Bytes()
}

func TestHugePageBounded(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.pdf")
	os.WriteFile(in, onePagePDF(5000, 5000, ""), 0o600)
	// at 110 DPI this page would be 7639 px square; pdftoppm itself must stay ≤ 2000
	cfg := config.PreviewConfig{MaxPages: 5, DPI: 110}
	var rendered image.Config // pdftoppm's own output, before any Go downscale
	e := &jobEnv{ctx: ctx, cfg: cfg, dir: dir, in: in, put: func(string, int, io.Reader, int64, Item) error {
		f, err := os.Open(filepath.Join(dir, "p-1.png"))
		if err != nil {
			return err
		}
		defer f.Close()
		rendered, err = png.DecodeConfig(f)
		return err
	}}
	if _, err := docPipeline(e); err != nil {
		t.Fatal(err)
	}
	if rendered.Width > 2000 || rendered.Height > 2000 || rendered.Width < 1900 {
		t.Fatalf("rendered %dx%d", rendered.Width, rendered.Height)
	}
}

// A sandboxed child must not read the worker's environment (master keys) via /proc.
func TestChildCannotReadParentEnviron(t *testing.T) {
	if err := NoDump(); err != nil {
		t.Fatal(err)
	}
	out, err := Run(ctx, t.TempDir(), 5*time.Second, "cat", fmt.Sprintf("/proc/%d/environ", os.Getpid()))
	if err == nil || !strings.Contains(string(out), "Permission denied") {
		t.Fatalf("err = %v out = %q", err, out)
	}
}

// A small CropBox on a huge MediaBox: pdfinfo reports the crop box, so pdftoppm must render that box.
func TestHugeMediaBoxSmallCropBox(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.pdf")
	os.WriteFile(in, onePagePDF(14000, 14000, "/CropBox [0 0 600 600]"), 0o600)
	var rendered image.Config
	e := &jobEnv{ctx: ctx, cfg: config.PreviewConfig{MaxPages: 5, DPI: 110}, dir: dir, in: in, put: func(_ string, _ int, r io.Reader, _ int64, _ Item) error {
		var err error
		rendered, err = png.DecodeConfig(r)
		return err
	}}
	if _, err := docPipeline(e); err != nil {
		t.Fatal(err)
	}
	if rendered.Width != 917 || rendered.Height != 917 {
		t.Fatalf("rendered %dx%d", rendered.Width, rendered.Height)
	}
}
