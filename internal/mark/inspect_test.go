package mark

import (
	"bytes"
	"compress/zlib"
	"image/jpeg"
	"image/png"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestInspect(t *testing.T) {
	var jpg, pg bytes.Buffer
	img := EmbedInvisible(synthPhoto(1, 800, 600), testCode)
	jpeg.Encode(&jpg, img, &jpeg.Options{Quality: 90})
	png.Encode(&pg, img)
	docx, err := addMeta(t, mkZip(t, [][2]string{{"docProps/core.xml", "<cp:coreProperties></cp:coreProperties>"}}), false)
	if err != nil {
		t.Fatal(err)
	}
	pdfOld := makePDF(t, 1, 100, 100)
	for _, c := range []struct {
		name string
		data []byte
		want []Found
	}{
		{"pdf", pdfOld, []Found{{"ABCDEFGH12", "metadata"}}},
		{"docx", docx, []Found{{testCode, "metadata"}}},
		{"jpeg", jpg.Bytes(), []Found{{testCode, "invisible"}}},
		{"png", pg.Bytes(), []Found{{testCode, "invisible"}}},
		{"garbage", bytes.Repeat([]byte{7, 1, 9}, 500), nil},
		{"empty", nil, nil},
		{"bad pdf", []byte("%PDF-1.4 junk"), nil},
		{"bad zip", []byte("PK\x03\x04junk"), nil},
		{"bad jpeg", []byte("\xff\xd8\xff\xe0junk"), nil},
	} {
		if got := Inspect(c.data); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %+v want %+v", c.name, got, c.want)
		}
	}
}

func TestInspectTextLayerOnly(t *testing.T) {
	// a code that sits only in a content stream is text_layer, and metadata wins when both have it
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	io.WriteString(zw, strings.Repeat("0 0 m 1 1 l S ", 50)+"BT (SX-ABCDEFGH12) Tj ET")
	zw.Close()
	pdf := append([]byte("%PDF-1.4\n1 0 obj\n<<>>\nstream\n"), z.Bytes()...)
	pdf = append(pdf, "\nendstream\nendobj\n"...)
	if got := Inspect(pdf); !reflect.DeepEqual(got, []Found{{"ABCDEFGH12", "text_layer"}}) {
		t.Fatal(got)
	}
}

func TestInspectPixelCap(t *testing.T) {
	var pg bytes.Buffer
	png.Encode(&pg, EmbedInvisible(synthPhoto(1, 800, 600), testCode))
	if got := InspectMax(pg.Bytes(), 800*600-1); got != nil {
		t.Fatal("decoded over the pixel cap", got)
	}
	if got := InspectMax(pg.Bytes(), 800*600); len(got) != 1 {
		t.Fatal(got)
	}
}

func TestNormalizeCode(t *testing.T) {
	for in, want := range map[string]string{"sx-abcdefgh12": "ABCDEFGH12", " SX- 7k3m 9zq4tb ": testCode, testCode: testCode} {
		if got, ok := NormalizeCode(in); !ok || got != want {
			t.Errorf("%q: %q %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "SX-", "short", "ABCDEFGH1I", "ABCDEFGH123", "SX-SX-ABCDEFGH12"} {
		if _, ok := NormalizeCode(in); ok {
			t.Errorf("%q accepted", in)
		}
	}
}
