package mark

import (
	"image"
	"image/draw"
	"math"
	"math/rand/v2"
	"slices"
	"strings"
)

const (
	traceAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	codeLen       = 10
	payloadBits   = 64
	gridN         = 24
	minSide       = 192
	// qimStep is the QIM step; tuned within the 12-24 range allowed by the plan.
	qimStep = 16.0
)

// bitOf[k] is the payload bit carried by grid cell k (fixed shuffle, 9 cells per bit).
var bitOf = func() [gridN * gridN]int {
	var p [gridN * gridN]int
	for i := range p {
		p[i] = i
	}
	r := rand.New(rand.NewPCG(0x5345, 0)) //nolint:gosec // deterministic public permutation, not a secret
	r.Shuffle(len(p), func(i, j int) { p[i], p[j] = p[j], p[i] })
	var b [gridN * gridN]int
	for k, v := range p {
		b[k] = v % payloadBits
	}
	return b
}()

// crc14 is a bitwise CRC-14 (poly 0x2805, init 0) over bits, MSB first.
func crc14(bits []byte) uint16 {
	var crc uint16
	for _, b := range bits {
		top := (crc>>13)&1 ^ uint16(b)
		crc = (crc << 1) & 0x3fff
		if top == 1 {
			crc ^= 0x2805
		}
	}
	return crc
}

func encodePayload(code string) ([]byte, bool) {
	if len(code) != codeLen {
		return nil, false
	}
	bits := make([]byte, 0, payloadBits)
	for _, ch := range code {
		v := strings.IndexRune(traceAlphabet, ch)
		if v < 0 {
			return nil, false
		}
		for i := 4; i >= 0; i-- {
			bits = append(bits, byte((v>>i)&1))
		}
	}
	c := crc14(bits)
	for i := 13; i >= 0; i-- {
		bits = append(bits, byte((c>>i)&1))
	}
	return bits, true
}

func decodePayload(bits []byte) (string, bool) {
	// all-zero has a valid CRC (init 0) and is what smooth images with ~0 coefficients decode to; reject (odds of a real code: 2^-50).
	if !slices.Contains(bits, 1) {
		return "", false
	}
	c := crc14(bits[:50])
	for i := 0; i < 14; i++ {
		if bits[50+i] != byte((c>>(13-i))&1) {
			return "", false
		}
	}
	var sb strings.Builder
	for i := 0; i < codeLen; i++ {
		v := 0
		for j := 0; j < 5; j++ {
			v = v<<1 | int(bits[i*5+j])
		}
		sb.WriteByte(traceAlphabet[v])
	}
	return sb.String(), true
}

func toRGBA(img image.Image) *image.RGBA {
	b := img.Bounds()
	out := image.NewRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
	draw.Draw(out, out.Bounds(), img, b.Min, draw.Src)
	return out
}

func luma(img *image.RGBA) []float32 { // float32 halves the buffer (4 B/px); coef sums in float64
	w, h := img.Rect.Dx(), img.Rect.Dy()
	y := make([]float32, w*h)
	for j := 0; j < h; j++ {
		row := img.Pix[j*img.Stride:]
		for i := 0; i < w; i++ {
			y[j*w+i] = 0.299*float32(row[i*4]) + 0.587*float32(row[i*4+1]) + 0.114*float32(row[i*4+2])
		}
	}
	return y
}

// cell holds the DCT (1,1) basis for one grid cell.
type cell struct {
	x0, y0, cw, ch int
	bx, by         []float64
	energy         float64 // sum of B^2
}

func newCell(k, w, h int) cell {
	cx, cy := k%gridN, k/gridN
	x0, x1 := cx*w/gridN, (cx+1)*w/gridN
	y0, y1 := cy*h/gridN, (cy+1)*h/gridN
	c := cell{x0: x0, y0: y0, cw: x1 - x0, ch: y1 - y0}
	c.bx = make([]float64, c.cw)
	c.by = make([]float64, c.ch)
	var sx, sy float64
	for i := range c.bx {
		c.bx[i] = math.Cos(math.Pi * float64(2*i+1) / float64(2*c.cw))
		sx += c.bx[i] * c.bx[i]
	}
	for j := range c.by {
		c.by[j] = math.Cos(math.Pi * float64(2*j+1) / float64(2*c.ch))
		sy += c.by[j] * c.by[j]
	}
	c.energy = sx * sy
	return c
}

func (c cell) coef(y []float32, w int) float64 {
	var s float64
	for j := 0; j < c.ch; j++ {
		row := y[(c.y0+j)*w+c.x0:]
		var r float64
		for i := 0; i < c.cw; i++ {
			r += float64(row[i]) * c.bx[i]
		}
		s += r * c.by[j]
	}
	return s / c.energy
}

// EmbedInvisible writes code into the image's luma DCT(1,1) coefficients via QIM.
// Images smaller than 192px on either side, or invalid codes, are returned as an unmodified copy.
func EmbedInvisible(img image.Image, code string) *image.RGBA {
	out := toRGBA(img)
	w, h := out.Rect.Dx(), out.Rect.Dy()
	bits, ok := encodePayload(code)
	if !ok || w < minSide || h < minSide {
		return out
	}
	y := luma(out)
	for k := 0; k < gridN*gridN; k++ {
		c := newCell(k, w, h)
		coef := c.coef(y, w)
		off := 0.0
		if bits[bitOf[k]] == 1 {
			off = qimStep / 2
		}
		target := qimStep*math.Round((coef-off)/qimStep) + off
		diff := target - coef
		for j := 0; j < c.ch; j++ {
			row := out.Pix[(c.y0+j)*out.Stride+c.x0*4:]
			for i := 0; i < c.cw; i++ {
				d := diff * c.bx[i] * c.by[j]
				a := row[i*4+3] // premultiplied: a colour channel never exceeds alpha
				for ch := 0; ch < 3; ch++ {
					row[i*4+ch] = min(clampU8(float64(row[i*4+ch])+d), a)
				}
			}
		}
	}
	return out
}

func clampU8(v float64) uint8 {
	return uint8(math.Max(0, math.Min(255, math.Round(v))))
}

// ExtractInvisible recovers the code by weighted majority vote per bit; ok is false if CRC fails.
func ExtractInvisible(img image.Image) (string, bool) {
	rgba := toRGBA(img)
	w, h := rgba.Rect.Dx(), rgba.Rect.Dy()
	if w < minSide || h < minSide {
		return "", false
	}
	y := luma(rgba)
	var votes [payloadBits]float64
	for k := 0; k < gridN*gridN; k++ {
		coef := newCell(k, w, h).coef(y, w)
		d0 := math.Abs(coef - qimStep*math.Round(coef/qimStep))
		d1 := math.Abs(coef - qimStep/2 - qimStep*math.Round((coef-qimStep/2)/qimStep))
		votes[bitOf[k]] += d1 - d0 // positive favors bit 0
	}
	bits := make([]byte, payloadBits)
	for i, v := range votes {
		if v < 0 {
			bits[i] = 1
		}
	}
	return decodePayload(bits)
}
