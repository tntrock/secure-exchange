package preview

import (
	"image"
	"image/color"
	"image/draw"
	"strings"
	"testing"
	"time"

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
	out := Apply(src, testMark)
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
	out := Apply(whiteImg(800, 1000), testMark)
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
		Apply(src, testMark)
	}
}
