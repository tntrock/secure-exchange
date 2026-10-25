package preview

import (
	"context"
	"crypto/rand"
	"image"
	"image/color"
	stddraw "image/draw"
	"image/jpeg"
	"io"
	"math"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/image/draw"
	"golang.org/x/image/font"
	"golang.org/x/image/font/gofont/goregular"
	"golang.org/x/image/font/opentype"
	"golang.org/x/image/math/f64"
	"golang.org/x/image/math/fixed"
)

const (
	traceAlphabet  = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	watermarkAlpha = uint8(56) // ≈ 0.22 * 255
)

// Mark is the per-viewer watermark content.
type Mark struct {
	Email, IP string
	At        time.Time
	Code      string
}

func (m Mark) Text() string {
	e := m.Email
	if len(e) > 254 {
		n := 254
		for !utf8.RuneStart(e[n]) {
			n--
		}
		e = e[:n]
	}
	return m.Code + " · " + m.At.UTC().Format("2006-01-02 15:04") + " UTC · " + m.IP + " · " + e
}

var wmFont = func() *opentype.Font {
	f, err := opentype.Parse(goregular.TTF)
	if err != nil {
		panic(err)
	}
	return f
}()

// wmSize picks max(14,w/45) px, shrinking to a 10px floor until the 30°-rotated text row fits width w.
func wmSize(w int, text string) float64 {
	size := math.Max(14, float64(w/45))
	for ; size > 10; size-- {
		f, err := opentype.NewFace(wmFont, &opentype.FaceOptions{Size: size, DPI: 72})
		if err != nil {
			break
		}
		tw := float64(font.MeasureString(f, text).Ceil() + 4)
		f.Close()
		if tw*math.Cos(math.Pi/6)+(size*1.5+4)*math.Sin(math.Pi/6) <= float64(w) {
			break
		}
	}
	return size
}

// Apply returns a copy of img with the mark tiled over it at 30°.
// ponytail: tile is rebuilt per call (~ms); cache by (text,size) if it ever shows in profiles.
func Apply(img image.Image, m Mark) (*image.RGBA, error) {
	b := img.Bounds()
	out := image.NewRGBA(b)
	stddraw.Draw(out, b, img, b.Min, stddraw.Src)

	text := m.Text()
	sin, cos := math.Sin(math.Pi/6), math.Cos(math.Pi/6)
	size := wmSize(b.Dx(), text)
	face, err := opentype.NewFace(wmFont, &opentype.FaceOptions{Size: size, DPI: 72, Hinting: font.HintingNone})
	if err != nil {
		return nil, err
	}
	defer face.Close()
	tw := font.MeasureString(face, text).Ceil() + 4
	th := int(size*1.5) + 4

	// 1px white halo (8 neighbours), then dark glyphs on top, on a transparent tile.
	tile := image.NewRGBA(image.Rect(0, 0, tw, th))
	draw1 := func(c color.Color, dx, dy int) {
		d := font.Drawer{Dst: tile, Src: image.NewUniform(c), Face: face, Dot: fixed.P(2+dx, int(size*1.1)+dy)}
		d.DrawString(text)
	}
	for dy := -1; dy <= 1; dy++ {
		for dx := -1; dx <= 1; dx++ {
			if dx != 0 || dy != 0 {
				draw1(color.White, dx, dy)
			}
		}
	}
	draw1(color.RGBA{0x30, 0x30, 0x30, 0xff}, 0, 0)

	// Rotate 30° about the tile centre into a bounding box.
	rw := int(math.Ceil(float64(tw)*cos + float64(th)*sin))
	rh := int(math.Ceil(float64(tw)*sin + float64(th)*cos))
	cx, cy, rcx, rcy := float64(tw)/2, float64(th)/2, float64(rw)/2, float64(rh)/2
	// dst->src mapping for Transform is src->dst; we need dst = R*(src-c)+rc, with y down
	// and a visually upward slant (rotate by -30°).
	rot := image.NewRGBA(image.Rect(0, 0, rw, rh))
	draw.BiLinear.Transform(rot, f64.Aff3{
		cos, sin, rcx - cos*cx - sin*cy,
		-sin, cos, rcy + sin*cx - cos*cy,
	}, tile, tile.Bounds(), draw.Over, nil)

	// Dense: tiles nearly end to end, rows ~110px apart, so no 150px window is clean.
	stepX, stepY := int(float64(rw)*1.05), min(110, int(float64(rh)*0.4))
	for i := range rot.Pix { // premultiplied, so scaling all channels applies the global alpha
		rot.Pix[i] = uint8(int(rot.Pix[i]) * int(watermarkAlpha) / 255)
	}
	row := 0
	for y := b.Min.Y - rh; y < b.Max.Y; y += stepY {
		off := 0
		if row%2 == 1 {
			off = stepX / 2
		}
		for x := b.Min.X - off; x < b.Max.X; x += stepX {
			r := image.Rect(x, y, x+rw, y+rh)
			stddraw.Draw(out, r, rot, image.Point{}, stddraw.Over)
		}
		row++
	}
	return out, nil
}

func EncodeJPEG(w io.Writer, img image.Image) error {
	return jpeg.Encode(w, img, &jpeg.Options{Quality: 85})
}

func NewTraceCode() string {
	var b [10]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = traceAlphabet[b[i]&31]
	}
	return string(b[:])
}

func nullUUID(u uuid.UUID) any {
	if u == uuid.Nil {
		return nil
	}
	return u
}

// Trace returns the code for (session, file), creating it on first use.
func Trace(ctx context.Context, pool Querier, fileID, shareID, recipientID uuid.UUID, sessionHash []byte, ip string) (string, bool, error) {
	if len(ip) > 64 {
		ip = ip[:64]
	}
	var code string
	err := pool.QueryRow(ctx, `INSERT INTO view_traces (code, file_id, share_id, recipient_id, session_hash, ip)
		VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (session_hash, file_id) DO NOTHING RETURNING code`,
		NewTraceCode(), fileID, nullUUID(shareID), nullUUID(recipientID), sessionHash, ip).Scan(&code)
	if err == nil {
		return code, true, nil
	}
	if err != pgx.ErrNoRows {
		return "", false, err
	}
	err = pool.QueryRow(ctx, `SELECT code FROM view_traces WHERE session_hash=$1 AND file_id=$2`, sessionHash, fileID).Scan(&code)
	return code, false, err
}
