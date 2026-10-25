package preview

import (
	"image"
	"image/color"
	"image/draw"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/image/font"
	"golang.org/x/image/font/opentype"
	"unicode/utf8"

	"github.com/google/uuid"
)

func whiteImg(w, h int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	draw.Draw(img, img.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)
	return img
}

var testMark = Mark{Email: "a@example.com", IP: "1.2.3.4", At: time.Date(2026, 10, 25, 9, 5, 0, 0, time.UTC), Code: "ABCDEFGHJK"}

func TestApplyChangesPixelsKeepsSize(t *testing.T) {
	src := whiteImg(800, 1000)
	out, err := Apply(src, testMark)
	if err != nil {
		t.Fatal(err)
	}
	if out.Bounds() != src.Bounds() {
		t.Fatalf("bounds %v", out.Bounds())
	}
	changed := 0
	for i := 0; i < len(out.Pix); i += 4 {
		p := out.Pix[i : i+4]
		if p[0] != 255 || p[1] != 255 || p[2] != 255 {
			changed++
			if p[0] < 100 {
				t.Fatalf("pixel too dark: %v", p)
			}
		}
	}
	if changed < 800*1000*2/100 {
		t.Fatalf("only %d pixels changed", changed)
	}
	if src.Pix[0] != 255 || src.Pix[len(src.Pix)-1] != 255 {
		t.Fatal("source mutated")
	}
}

func TestApplyCoversWholeImage(t *testing.T) {
	out, err := Apply(whiteImg(800, 1000), testMark)
	if err != nil {
		t.Fatal(err)
	}
	for gy := 0; gy < 4; gy++ {
		for gx := 0; gx < 4; gx++ {
			n := 0
			for y := gy * 250; y < (gy+1)*250; y++ {
				for x := gx * 200; x < (gx+1)*200; x++ {
					if out.RGBAAt(x, y).R != 255 {
						n++
					}
				}
			}
			if n == 0 {
				t.Fatalf("cell %d,%d untouched", gx, gy)
			}
		}
	}
}

func TestMarkText(t *testing.T) {
	if got, want := testMark.Text(), "a@example.com · 1.2.3.4 · 2026-10-25 09:05 UTC · ABCDEFGHJK"; got != want {
		t.Fatalf("got %q", got)
	}
	m := testMark
	m.Email = strings.Repeat("x", 300)
	if got := strings.SplitN(m.Text(), " · ", 2)[0]; len(got) != 254 {
		t.Fatalf("email len %d", len(got))
	}
}

func TestTraceCodeAlphabet(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		c := NewTraceCode()
		if len(c) != 10 || strings.Trim(c, traceAlphabet) != "" || seen[c] {
			t.Fatalf("bad code %q", c)
		}
		seen[c] = true
	}
}

func TestTraceStablePerSession(t *testing.T) {
	pool, owner := newPool(t)
	f := addFile(t, pool, owner, "a.png", 1, []byte{1}, 1, "")
	s1, s2 := []byte("session-one-hash"), []byte("session-two-hash")
	c1, created, err := Trace(ctx, pool, f, uuid.Nil, uuid.Nil, s1, strings.Repeat("9", 100))
	if err != nil || !created {
		t.Fatalf("first: %v %v", created, err)
	}
	c1b, created, err := Trace(ctx, pool, f, uuid.Nil, uuid.Nil, s1, "1.1.1.1")
	if err != nil || created || c1b != c1 {
		t.Fatalf("second: %q %v %v", c1b, created, err)
	}
	c2, created, err := Trace(ctx, pool, f, uuid.Nil, uuid.Nil, s2, "1.1.1.1")
	if err != nil || !created || c2 == c1 {
		t.Fatalf("other session: %q %v %v", c2, created, err)
	}
	var ip string
	pool.QueryRow(ctx, `SELECT ip FROM view_traces WHERE code=$1`, c1).Scan(&ip)
	if len(ip) != 64 {
		t.Fatalf("ip len %d", len(ip))
	}
}

func BenchmarkApply(b *testing.B) {
	src := whiteImg(1600, 2000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Apply(src, testMark); err != nil {
			b.Fatal(err)
		}
	}
}

func countLum(t *testing.T, img *image.RGBA, f func(r uint8) bool) int {
	n := 0
	for i := 0; i < len(img.Pix); i += 4 {
		if f(img.Pix[i]) {
			n++
		}
	}
	return n
}

func TestApplyVisibleOnWhiteAndBlack(t *testing.T) {
	out, err := Apply(whiteImg(800, 1000), testMark)
	if err != nil {
		t.Fatal(err)
	}
	if n := countLum(t, out, func(r uint8) bool { return r < 230 }); n < 3000 {
		t.Fatalf("only %d dark pixels on white", n)
	}
	black := image.NewRGBA(image.Rect(0, 0, 800, 1000))
	draw.Draw(black, black.Bounds(), image.NewUniform(color.Black), image.Point{}, draw.Src)
	out, err = Apply(black, testMark)
	if err != nil {
		t.Fatal(err)
	}
	if n := countLum(t, out, func(r uint8) bool { return r > 20 }); n < 3000 {
		t.Fatalf("only %d light pixels on black", n)
	}
}

func TestMarkTextCutsOnRuneBoundary(t *testing.T) {
	m := testMark
	m.Email = strings.Repeat("é", 200) // 400 bytes, 2 each
	e := strings.SplitN(m.Text(), " · ", 2)[0]
	if len(e) > 254 || !utf8.ValidString(e) {
		t.Fatalf("len %d valid %v", len(e), utf8.ValidString(e))
	}
}

func TestApplyShrinksTextToFitWidth(t *testing.T) {
	m := testMark
	m.Email = strings.Repeat("a", 60) + "@example.com"
	w := 600
	if _, err := Apply(whiteImg(w, 800), m); err != nil {
		t.Fatal(err)
	}
	// 254-char email: floor of 10px applies, must not blow up (text can exceed width at the floor).
	m.Email = strings.Repeat("a", 254)
	if _, err := Apply(whiteImg(w, 800), m); err != nil {
		t.Fatal(err)
	}
	// the chosen size for the 60-char case must make the rotated row fit
	m.Email = strings.Repeat("a", 60) + "@example.com"
	size := wmSize(w, m.Text())
	f, _ := opentype.NewFace(wmFont, &opentype.FaceOptions{Size: size, DPI: 72})
	if tw := float64(font.MeasureString(f, m.Text()).Ceil()) * 0.866; tw > float64(w) {
		t.Fatalf("size %v: rotated width %v > %d", size, tw, w)
	}
}

func TestTraceConcurrentSameSession(t *testing.T) {
	pool, owner := newPool(t)
	f := addFile(t, pool, owner, "a.png", 1, []byte{1}, 1, "")
	const n = 8
	var wg sync.WaitGroup
	start := make(chan struct{})
	codes := make([]string, n)
	made := make([]bool, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			c, cr, err := Trace(ctx, pool, f, uuid.Nil, uuid.Nil, []byte("same-session"), "1.1.1.1")
			if err != nil {
				t.Error(err)
			}
			codes[i], made[i] = c, cr
		}()
	}
	close(start)
	wg.Wait()
	created := 0
	for i := range codes {
		if codes[i] != codes[0] || codes[i] == "" {
			t.Fatalf("codes differ: %v", codes)
		}
		if made[i] {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("created=%d", created)
	}
}
