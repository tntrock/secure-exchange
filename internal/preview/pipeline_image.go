package preview

import (
	"bytes"
	"fmt"
	"image"
	_ "image/gif" // registered decoders; GIF decodes its first frame
	_ "image/jpeg"
	"image/png"
	"io"
	"os"

	_ "golang.org/x/image/bmp"
	"golang.org/x/image/draw"
	_ "golang.org/x/image/tiff"
	_ "golang.org/x/image/webp"
)

const (
	maxImagePixels = 100_000_000 // decompression-bomb guard, checked from the header alone
	maxImageSide   = 4096
)

func imagePipeline(e *jobEnv) (Result, error) {
	f, err := os.Open(e.in)
	if err != nil {
		return Result{}, err
	}
	defer f.Close()
	img, err := decodeBounded(f)
	if err != nil {
		return Result{}, err
	}
	w, h, err := putPNG(e, "image", 0, fit(img, maxImageSide))
	return Result{Kind: KindImage, Width: w, Height: h}, err
}

// decodeBounded checks the declared size before decoding so a tiny file cannot claim a huge canvas.
func decodeBounded(r io.ReadSeeker) (image.Image, error) {
	cfg, format, err := image.DecodeConfig(r)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if cfg.Width <= 0 || cfg.Height <= 0 {
		return nil, fmt.Errorf("image: bad %s size %dx%d", format, cfg.Width, cfg.Height)
	}
	if int64(cfg.Width)*int64(cfg.Height) > maxImagePixels {
		return nil, fmt.Errorf("%w: %s %dx%d", errTooLarge, format, cfg.Width, cfg.Height)
	}
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	img, _, err := image.Decode(r)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return img, nil
}

// fit scales img down so its longest side is at most limit; smaller images are returned as is.
func fit(img image.Image, limit int) image.Image {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	long := max(w, h)
	if long <= limit {
		return img
	}
	scale := func(side int) int { return max(1, int((int64(side)*int64(limit)+int64(long)/2)/int64(long))) }
	dst := image.NewRGBA(image.Rect(0, 0, scale(w), scale(h)))
	draw.CatmullRom.Scale(dst, dst.Bounds(), img, b, draw.Src, nil)
	return dst
}

// putPNG encodes img and stores it as one item, returning its size.
func putPNG(e *jobEnv, kind string, idx int, img image.Image) (w, h int, err error) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return 0, 0, err
	}
	b := img.Bounds()
	w, h = b.Dx(), b.Dy()
	return w, h, e.put(kind, idx, &buf, int64(buf.Len()), Item{Width: w, Height: h})
}
