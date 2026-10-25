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
	watermarkAlpha = uint8(46) // ≈ 0.18 * 255
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
		e = e[:254]
	}
	return e + " · " + m.IP + " · " + m.At.UTC().Format("2006-01-02 15:04") + " UTC · " + m.Code
}

var wmFont = func() *opentype.Font {
	f, err := opentype.Parse(goregular.TTF)
	if err != nil {
		panic(err)
	}
	return f
}()

// Apply returns a copy of img with the mark tiled over it at 30°.
// ponytail: tile is rebuilt per call (~ms); cache by (text,size) if it ever shows in profiles.
func Apply(img image.Image, m Mark) *image.RGBA {
	b := img.Bounds()
	out := image.NewRGBA(b)
	stddraw.Draw(out, b, img, b.Min, stddraw.Src)

	size := math.Max(14, float64(b.Dx()/45))
	face, err := opentype.NewFace(wmFont, &opentype.FaceOptions{Size: size, DPI: 72, Hinting: font.HintingNone})
	if err != nil {
		return out
	}
	defer face.Close()
	text := m.Text()
	tw := font.MeasureString(face, text).Ceil() + 4
	th := int(size*1.5) + 4

	// Two layers (dark offset 1px under white) on a transparent tile, full opacity.
	tile := image.NewRGBA(image.Rect(0, 0, tw, th))
	for _, l := range []struct {
		c      color.Color
		dx, dy int
	}{{color.RGBA{0x20, 0x20, 0x20, 0xff}, 1, 1}, {color.White, 0, 0}} {
		d := font.Drawer{Dst: tile, Src: image.NewUniform(l.c), Face: face,
			Dot: fixed.P(2+l.dx, int(size*1.1)+l.dy)}
		d.DrawString(text)
	}

	// Rotate 30° about the tile centre into a bounding box.
	sin, cos := math.Sin(math.Pi/6), math.Cos(math.Pi/6)
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

	// rotated text is a thin diagonal, so rows can overlap in bbox: step 1.6x wide, 0.6x tall.
	stepX, stepY := int(float64(rw)*1.6), int(float64(rh)*0.6)
	mask := image.NewUniform(color.Alpha{watermarkAlpha})
	row := 0
	for y := b.Min.Y - rh; y < b.Max.Y; y += stepY {
		off := 0
		if row%2 == 1 {
			off = stepX / 2
		}
		for x := b.Min.X - off; x < b.Max.X; x += stepX {
			r := image.Rect(x, y, x+rw, y+rh)
			stddraw.DrawMask(out, r, rot, image.Point{}, mask, image.Point{}, stddraw.Over)
		}
		row++
	}
	return out
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
