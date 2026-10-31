package mark

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"math"
	"math/rand/v2"
	"testing"

	"golang.org/x/image/draw"
)

const testCode = "7K3M9ZQ4TB"

// synthPhoto builds a deterministic gradient + sinusoid + noise "photo".
func synthPhoto(seed uint64, w, h int) *image.RGBA {
	r := rand.New(rand.NewPCG(seed, 1))
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			fx, fy := float64(x)/float64(w), float64(y)/float64(h)
			base := 60 + 120*fx + 40*fy + 25*math.Sin(fx*37+fy*11)
			n := func() float64 { return r.NormFloat64() * 6 }
			img.SetRGBA(x, y, color.RGBA{
				clamp8(base + n()), clamp8(base*0.9 + 10 + n()), clamp8(base*0.8 + 20 + n()), 255,
			})
		}
	}
	return img
}

func clamp8(v float64) uint8 { return uint8(math.Max(0, math.Min(255, math.Round(v)))) }

func jpegRT(t *testing.T, img image.Image, q int) image.Image {
	t.Helper()
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: q}); err != nil {
		t.Fatal(err)
	}
	out, err := jpeg.Decode(&buf)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func psnr(a, b *image.RGBA) float64 {
	var sum float64
	for i := range a.Pix {
		d := float64(a.Pix[i]) - float64(b.Pix[i])
		sum += d * d
	}
	return 10 * math.Log10(255*255/(sum/float64(len(a.Pix))))
}

func TestInvisibleRoundTrip(t *testing.T) {
	out := EmbedInvisible(synthPhoto(1, 1600, 1200), testCode)
	got, ok := ExtractInvisible(out)
	if !ok || got != testCode {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestInvisibleSurvivesJPEGAndScale(t *testing.T) {
	out := EmbedInvisible(synthPhoto(2, 1600, 1200), testCode)
	img := jpegRT(t, out, 70)
	small := image.NewRGBA(image.Rect(0, 0, 800, 600))
	draw.BiLinear.Scale(small, small.Bounds(), img, img.Bounds(), draw.Src, nil)
	got, ok := ExtractInvisible(jpegRT(t, small, 80))
	if !ok || got != testCode {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestInvisibleQuality(t *testing.T) {
	src := synthPhoto(3, 1600, 1200)
	p := psnr(src, EmbedInvisible(src, testCode))
	t.Logf("PSNR %.2f dB", p)
	if p < 38 {
		t.Fatalf("PSNR %.2f < 38", p)
	}
}

func TestInvisibleNoFalsePositive(t *testing.T) {
	for s := uint64(100); s < 120; s++ {
		if c, ok := ExtractInvisible(synthPhoto(s, 640, 480)); ok {
			t.Fatalf("seed %d: false positive %q", s, c)
		}
	}
	out := EmbedInvisible(synthPhoto(4, 1600, 1200), testCode)
	cropped := out.SubImage(image.Rect(480, 0, 1600, 1200))
	if c, ok := ExtractInvisible(cropped); ok {
		t.Fatalf("cropped: false positive %q", c)
	}
}

func TestInvisibleTooSmall(t *testing.T) {
	src := synthPhoto(5, 100, 100)
	out := EmbedInvisible(src, testCode)
	if !bytes.Equal(out.Pix, src.Pix) {
		t.Fatal("small image modified")
	}
	if _, ok := ExtractInvisible(out); ok {
		t.Fatal("small image extracted")
	}
}

func TestInvisibleKeepsPremultipliedAlpha(t *testing.T) {
	src := synthPhoto(4, 400, 300)
	semi := image.NewNRGBA(src.Rect)
	for i := 0; i < len(src.Pix); i += 4 {
		copy(semi.Pix[i:i+3], src.Pix[i:i+3])
		semi.Pix[i+3] = 128
	}
	out := EmbedInvisible(semi, testCode)
	for i := 0; i < len(out.Pix); i += 4 {
		if a := out.Pix[i+3]; out.Pix[i] > a || out.Pix[i+1] > a || out.Pix[i+2] > a {
			t.Fatalf("pixel %d: %v exceeds its alpha", i/4, out.Pix[i:i+4])
		}
	}
}
