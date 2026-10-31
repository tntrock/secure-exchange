package mark

import (
	"bytes"
	"encoding/binary"
	"image"
)

// DecodeImage decodes a JPEG or PNG and applies a JPEG's EXIF orientation, so the marks land on the
// upright picture (the re-encoded copy carries no EXIF; ICC profiles are dropped too).
func DecodeImage(data []byte) (image.Image, error) {
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	return orient(img, exifOrientation(data)), nil
}

// exifOrientation reads the Orientation tag (0x0112) from a JPEG's APP1 Exif block.
// Anything missing, malformed or out of range is 1 (upright).
func exifOrientation(b []byte) int {
	if len(b) < 2 || b[0] != 0xFF || b[1] != 0xD8 {
		return 1
	}
	for i := 2; i+4 <= len(b); {
		m := b[i+1]
		if b[i] != 0xFF || m == 0xDA || m == 0xD9 { // not a marker, or image data started
			return 1
		}
		n := int(binary.BigEndian.Uint16(b[i+2:]))
		if n < 2 || i+2+n > len(b) {
			return 1
		}
		if seg := b[i+4 : i+2+n]; m == 0xE1 && bytes.HasPrefix(seg, []byte("Exif\x00\x00")) {
			return tiffOrientation(seg[6:])
		}
		i += 2 + n
	}
	return 1
}

func tiffOrientation(t []byte) int {
	if len(t) < 8 {
		return 1
	}
	var bo binary.ByteOrder
	switch string(t[:2]) {
	case "II":
		bo = binary.LittleEndian
	case "MM":
		bo = binary.BigEndian
	default:
		return 1
	}
	off := uint64(bo.Uint32(t[4:]))
	if off+2 > uint64(len(t)) {
		return 1
	}
	ifd := t[off:]
	for k := range int(bo.Uint16(ifd)) {
		e := 2 + 12*k
		if e+12 > len(ifd) {
			return 1
		}
		if bo.Uint16(ifd[e:]) == 0x0112 {
			if v := int(bo.Uint16(ifd[e+8:])); bo.Uint16(ifd[e+2:]) == 3 && v >= 1 && v <= 8 { // SHORT
				return v
			}
			return 1
		}
	}
	return 1
}

// orient returns img turned upright for EXIF orientation o (2-8); other values return img as is.
func orient(img image.Image, o int) image.Image {
	if o < 2 || o > 8 {
		return img
	}
	src := toRGBA(img)
	w, h := src.Rect.Dx(), src.Rect.Dy()
	dw, dh := w, h
	if o >= 5 {
		dw, dh = h, w
	}
	dst := image.NewRGBA(image.Rect(0, 0, dw, dh))
	for y := range dh {
		for x := range dw {
			sx, sy := x, y
			switch o {
			case 2:
				sx = w - 1 - x
			case 3:
				sx, sy = w-1-x, h-1-y
			case 4:
				sy = h - 1 - y
			case 5:
				sx, sy = y, x
			case 6:
				sx, sy = y, h-1-x
			case 7:
				sx, sy = w-1-y, h-1-x
			case 8:
				sx, sy = w-1-y, x
			}
			copy(dst.Pix[y*dst.Stride+x*4:][:4], src.Pix[sy*src.Stride+sx*4:])
		}
	}
	return dst
}
