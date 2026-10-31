package mark

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/jpeg"
	"testing"
)

// exifJPEG encodes img as a JPEG whose APP1 Exif block carries orientation o in byte order bo.
func exifJPEG(t *testing.T, img image.Image, o uint16, bo binary.AppendByteOrder) []byte {
	t.Helper()
	var enc bytes.Buffer
	if err := jpeg.Encode(&enc, img, &jpeg.Options{Quality: 95}); err != nil {
		t.Fatal(err)
	}
	tiff := []byte("MM")
	if bo == binary.LittleEndian {
		tiff = []byte("II")
	}
	tiff = bo.AppendUint16(tiff, 42)
	tiff = bo.AppendUint32(tiff, 8)
	tiff = bo.AppendUint16(tiff, 2)                    // two entries
	tiff = append(bo.AppendUint16(tiff, 0x010F), 0, 2) // Make (ASCII), skipped
	tiff = append(tiff, make([]byte, 8)...)
	tiff = bo.AppendUint16(bo.AppendUint16(tiff, 0x0112), 3)
	tiff = bo.AppendUint32(tiff, 1)
	tiff = append(bo.AppendUint16(tiff, o), 0, 0, 0, 0, 0, 0)
	seg := append([]byte("Exif\x00\x00"), tiff...)
	app1 := binary.BigEndian.AppendUint16([]byte{0xFF, 0xE1}, uint16(len(seg)+2))
	out := append([]byte{0xFF, 0xD8}, app1...)
	out = append(out, seg...)
	return append(out, enc.Bytes()[2:]...)
}

// cornerImage is w x h white with a red 16x16 block at the top left.
func cornerImage(w, h int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			c := color.RGBA{255, 255, 255, 255}
			if x < 16 && y < 16 {
				c = color.RGBA{255, 0, 0, 255}
			}
			img.SetRGBA(x, y, c)
		}
	}
	return img
}

func isRed(c color.Color) bool {
	r, g, b, _ := c.RGBA()
	return r>>8 > 200 && g>>8 < 80 && b>>8 < 80
}

func TestDecodeImageAppliesOrientation(t *testing.T) {
	for _, c := range []struct {
		o          uint16
		bo         binary.AppendByteOrder
		w, h       int
		redX, redY int // where the source's top-left block lands
	}{
		{1, binary.BigEndian, 64, 32, 4, 4},
		{6, binary.BigEndian, 32, 64, 27, 4},    // rotate 90 CW: top-left -> top-right
		{6, binary.LittleEndian, 32, 64, 27, 4}, // same, Intel byte order
		{8, binary.LittleEndian, 32, 64, 4, 59}, // rotate 90 CCW: top-left -> bottom-left
		{3, binary.BigEndian, 64, 32, 59, 27},   // rotate 180
	} {
		img, err := DecodeImage(exifJPEG(t, cornerImage(64, 32), c.o, c.bo))
		if err != nil {
			t.Fatal(err)
		}
		if b := img.Bounds(); b.Dx() != c.w || b.Dy() != c.h {
			t.Fatalf("o=%d: %v", c.o, b)
		}
		if !isRed(img.At(c.redX, c.redY)) || isRed(img.At(c.w-1-c.redX, c.h-1-c.redY)) {
			t.Fatalf("o=%d: block not at (%d,%d)", c.o, c.redX, c.redY)
		}
	}
}

func TestOrientAllCases(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 3, 2))
	src.SetRGBA(0, 0, color.RGBA{9, 9, 9, 9})
	want := map[int][3]int{ // width, then where src (0,0) lands
		2: {3, 2, 0}, 3: {3, 2, 1}, 4: {3, 0, 1}, 5: {2, 0, 0}, 6: {2, 1, 0}, 7: {2, 1, 2}, 8: {2, 0, 2},
	}
	for o, w := range want {
		out := orient(src, o).(*image.RGBA)
		if out.Rect.Dx() != w[0] || out.RGBAAt(w[1], w[2]).A != 9 {
			t.Errorf("orientation %d: %v, marker not at (%d,%d)", o, out.Rect, w[1], w[2])
		}
	}
	if orient(src, 1) != image.Image(src) || orient(src, 9) != image.Image(src) {
		t.Error("orientations 1 and out-of-range must be no-ops")
	}
}

func TestExifOrientationHostile(t *testing.T) {
	good := exifJPEG(t, cornerImage(64, 32), 6, binary.BigEndian)
	if o := exifOrientation(good); o != 6 {
		t.Fatal(o)
	}
	for n := range len(good) { // every truncation: no panic, and either the tag or the default
		if o := exifOrientation(good[:n]); o != 1 && o != 6 {
			t.Fatalf("prefix %d: %d", n, o)
		}
	}
	bad := func(f func(b []byte)) []byte {
		b := bytes.Clone(good)
		f(b)
		return b
	}
	for name, b := range map[string][]byte{
		"app1 length past end":  bad(func(b []byte) { b[4], b[5] = 0xFF, 0xFF }),
		"app1 length < 2":       bad(func(b []byte) { b[4], b[5] = 0, 1 }),
		"ifd offset past end":   bad(func(b []byte) { copy(b[16:20], []byte{0xFF, 0xFF, 0xFF, 0xF0}) }),
		"huge count, no tag":    bad(func(b []byte) { b[20], b[21], b[35] = 0xFF, 0xFF, 0 }),
		"bad byte order":        bad(func(b []byte) { b[12] = 'X' }),
		"orientation 0":         bad(func(b []byte) { b[12+8+2+12+8], b[12+8+2+12+9] = 0, 0 }),
		"orientation type long": bad(func(b []byte) { b[12+8+2+12+3] = 4 }),
		"not a jpeg":            []byte("\x89PNG\r\n\x1a\n"),
		"marker garbage":        {0xFF, 0xD8, 0x00, 0x01, 0x02, 0x03},
	} {
		if o := exifOrientation(b); o != 1 {
			t.Errorf("%s: %d", name, o)
		}
	}
}
