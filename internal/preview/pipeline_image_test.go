package preview

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	"image/color"
	"image/gif"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/tntrock/secure-exchange/internal/config"
)

type putItem struct {
	kind string
	idx  int
	data []byte
	meta Item
}

// runPipeline runs p on data in a fresh dir and collects the items it puts.
func runPipeline(t *testing.T, p pipeline, cfg config.PreviewConfig, name string, data []byte) (Result, []putItem, error) {
	t.Helper()
	dir := t.TempDir()
	in := filepath.Join(dir, name)
	if err := os.WriteFile(in, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var items []putItem
	put := func(kind string, idx int, r io.Reader, size int64, meta Item) error {
		b, err := io.ReadAll(r)
		if err != nil || int64(len(b)) != size {
			t.Fatalf("put %s/%d: size %d != %d (%v)", kind, idx, len(b), size, err)
		}
		items = append(items, putItem{kind, idx, b, meta})
		return nil
	}
	res, err := p(&jobEnv{ctx: ctx, cfg: cfg, dir: dir, in: in, put: put})
	return res, items, err
}

func encodePNG(t *testing.T, img image.Image) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestImagePipeline(t *testing.T) {
	src := encodePNG(t, image.NewGray(image.Rect(0, 0, 5000, 3000)))
	res, items, err := runPipeline(t, imagePipeline, config.PreviewConfig{}, "in.png", src)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].kind != "image" || items[0].idx != 0 {
		t.Fatalf("items %+v", items)
	}
	img, err := png.Decode(bytes.NewReader(items[0].data))
	if err != nil {
		t.Fatal(err)
	}
	b := img.Bounds()
	if b.Dx() != 4096 || b.Dy() != 2458 {
		t.Fatalf("output %v", b)
	}
	if res.Kind != KindImage || res.Width != 4096 || res.Height != 2458 || items[0].meta.Width != 4096 || items[0].meta.Height != 2458 {
		t.Fatalf("result %+v meta %+v", res, items[0].meta)
	}
}

func TestImagePipelineSmallUnchanged(t *testing.T) {
	src := encodePNG(t, image.NewGray(image.Rect(0, 0, 30, 20)))
	res, _, err := runPipeline(t, imagePipeline, config.PreviewConfig{}, "in", src)
	if err != nil || res.Width != 30 || res.Height != 20 {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestImagePipelineGIFFirstFrame(t *testing.T) {
	pal := color.Palette{color.Black, color.White}
	frame := func(c uint8) *image.Paletted {
		p := image.NewPaletted(image.Rect(0, 0, 8, 6), pal)
		for i := range p.Pix {
			p.Pix[i] = c
		}
		return p
	}
	var buf bytes.Buffer
	if err := gif.EncodeAll(&buf, &gif.GIF{Image: []*image.Paletted{frame(1), frame(0)}, Delay: []int{0, 0}}); err != nil {
		t.Fatal(err)
	}
	res, items, err := runPipeline(t, imagePipeline, config.PreviewConfig{}, "in.gif", buf.Bytes())
	if err != nil || res.Width != 8 || res.Height != 6 {
		t.Fatalf("%+v %v", res, err)
	}
	img, _ := png.Decode(bytes.NewReader(items[0].data))
	if r, _, _, _ := img.At(0, 0).RGBA(); r != 0xffff {
		t.Fatal("not the first (white) frame")
	}
}

// bombPNG is a valid PNG header claiming w×h with no real pixel data.
func bombPNG(w, h uint32) []byte {
	var b bytes.Buffer
	b.WriteString("\x89PNG\r\n\x1a\n")
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:], w)
	binary.BigEndian.PutUint32(ihdr[4:], h)
	ihdr[8], ihdr[9] = 8, 6 // 8-bit RGBA
	binary.Write(&b, binary.BigEndian, uint32(len(ihdr)))
	chunk := append([]byte("IHDR"), ihdr...)
	b.Write(chunk)
	binary.Write(&b, binary.BigEndian, crc32.ChecksumIEEE(chunk))
	return b.Bytes()
}

func TestImageBomb(t *testing.T) {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, items, err := runPipeline(t, imagePipeline, config.PreviewConfig{}, "in.png", bombPNG(30000, 30000))
	runtime.ReadMemStats(&after)
	if !errors.Is(err, errTooLarge) || len(items) != 0 {
		t.Fatalf("err = %v items %d", err, len(items))
	}
	if d := after.TotalAlloc - before.TotalAlloc; d > 50<<20 {
		t.Fatalf("allocated %d bytes", d)
	}
}

func TestImageGarbage(t *testing.T) {
	_, _, err := runPipeline(t, imagePipeline, config.PreviewConfig{}, "in.png", []byte("\x89PNG not really an image at all"))
	if err == nil || errors.Is(err, errTooLarge) {
		t.Fatalf("err = %v", err)
	}
}

func TestImageTruncated(t *testing.T) {
	// a valid header passes the size check; the pixel data then fails to decode
	full := encodePNG(t, image.NewGray(image.Rect(0, 0, 64, 64)))
	_, items, err := runPipeline(t, imagePipeline, config.PreviewConfig{}, "in.png", full[:len(full)-20])
	if err == nil || errors.Is(err, errTooLarge) || len(items) != 0 {
		t.Fatalf("err = %v items %d", err, len(items))
	}
}

func TestImageInputMissing(t *testing.T) {
	_, err := imagePipeline(&jobEnv{ctx: ctx, in: filepath.Join(t.TempDir(), "in.png")})
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v", err)
	}
}
