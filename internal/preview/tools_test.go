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
