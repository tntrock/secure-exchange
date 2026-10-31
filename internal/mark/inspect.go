package mark

import (
	"bytes"
	"image"
	_ "image/jpeg" // registered for image.Decode
	_ "image/png"
	"strings"
)

// Found is a trace code read out of a file, and where it was found.
// Via is "metadata", "text_layer" or "invisible".
type Found struct{ Code, Via string }

// DefaultMaxPixels bounds Inspect's image decode (~20 B/px in memory).
const DefaultMaxPixels = 50_000_000

// NormalizeCode turns user input ("sx-7k3m 9zq4tb") into a bare 10-char code.
func NormalizeCode(s string) (string, bool) {
	s = strings.ToUpper(strings.Join(strings.Fields(s), ""))
	s = strings.TrimPrefix(s, "SX-")
	return s, codeValid.MatchString(s)
}

// Inspect reads trace codes from a PDF, OOXML/ODF zip, JPEG or PNG. Hostile input yields nothing.
func Inspect(data []byte) []Found { return InspectMax(data, DefaultMaxPixels) }

// InspectMax is Inspect with an explicit pixel cap; larger images are not decoded.
func InspectMax(data []byte, maxPixels int) []Found {
	var out []Found
	seen := map[string]bool{}
	add := func(via string, codes ...string) {
		for _, c := range codes {
			if !seen[c] {
				seen[c] = true
				out = append(out, Found{c, via})
			}
		}
	}
	switch {
	case bytes.HasPrefix(data, []byte("%PDF-")):
		meta, text := PDFCodes(data)
		add("metadata", meta...)
		add("text_layer", text...)
	case bytes.HasPrefix(data, []byte("PK\x03\x04")):
		add("metadata", ZipCodes(data)...)
	default:
		cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
		if err != nil || cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > maxPixels/cfg.Height {
			return nil
		}
		if img, _, err := image.Decode(bytes.NewReader(data)); err == nil {
			if c, ok := ExtractInvisible(img); ok {
				add("invisible", c)
			}
		}
	}
	return out
}
