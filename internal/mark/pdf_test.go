package mark

import (
	"bytes"
	"compress/zlib"
	"context"
	"fmt"
	"image"
	"image/color"
	"io"
	"strings"
	"testing"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

func testPage(w, h int) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			img.Set(x, y, color.RGBA{uint8(x * 255 / w), uint8(y * 255 / h), uint8((x + y) % 256), 255})
		}
	}
	return img
}

func makePDF(t *testing.T, n, w, h int) []byte {
	t.Helper()
	var buf bytes.Buffer
	err := WritePagesPDF(&buf, n, func(int) (image.Image, error) { return testPage(w, h), nil }, "ABCDEFGH12")
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestWritePagesPDF(t *testing.T) {
	data := makePDF(t, 3, 1200, 900)
	if !bytes.HasPrefix(data, []byte("%PDF-1.4")) {
		t.Fatal("bad header")
	}
	n, err := api.PageCount(context.Background(), bytes.NewReader(data), model.NewStatelessConfiguration())
	if err != nil || n != 3 {
		t.Fatalf("PageCount = %d, %v", n, err)
	}
	meta, text := PDFCodes(data)
	if !contains(meta, "ABCDEFGH12") || !contains(text, "ABCDEFGH12") {
		t.Fatalf("meta=%v text=%v", meta, text)
	}
	imgs, err := api.ExtractImagesRaw(context.Background(), bytes.NewReader(data), []string{"1"}, model.NewStatelessConfiguration())
	if err != nil || len(imgs) == 0 {
		t.Fatalf("extract: %v %d", err, len(imgs))
	}
	for _, im := range imgs[0] {
		dec, _, err := image.Decode(im)
		if err != nil {
			t.Fatal(err)
		}
		code, ok := ExtractInvisible(dec)
		if !ok || code != "ABCDEFGH12" {
			t.Fatalf("invisible = %q, %v", code, ok)
		}
		return
	}
	t.Fatal("no image on page 1")
}

func TestAddPDFMeta(t *testing.T) {
	src := makePDF(t, 1, 400, 300)
	var out bytes.Buffer
	if err := AddPDFMeta(bytes.NewReader(src), &out, "ZZZZZZZZZZ"); err != nil {
		t.Fatal(err)
	}
	meta, _ := PDFCodes(out.Bytes())
	if !contains(meta, "ZZZZZZZZZZ") {
		t.Fatalf("meta=%v", meta)
	}
	if err := api.Validate(context.Background(), bytes.NewReader(out.Bytes()), model.NewStatelessConfiguration(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestPDFMetaCorruptInput(t *testing.T) {
	good := makePDF(t, 1, 400, 300)
	for _, in := range [][]byte{[]byte("%PDF-1.7\n垃圾"), good[:len(good)/2]} {
		var out bytes.Buffer
		if err := AddPDFMeta(bytes.NewReader(in), &out, "ABCDEFGH12"); err == nil {
			t.Error("want error")
		}
	}
	if m, _ := PDFCodes([]byte("%PDF-1.7\n垃圾")); len(m) != 0 {
		t.Errorf("meta = %v", m)
	}
}

func TestPDFCodesCompressedText(t *testing.T) {
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	_, _ = io.WriteString(zw, strings.Repeat("0 0 m 1 1 l S ", 50)+"BT /F1 8 Tf (SX-ABCDEFGH12) Tj ET")
	_ = zw.Close()
	var pdf bytes.Buffer
	pdf.WriteString("%PDF-1.4\n1 0 obj\n<< /Filter /FlateDecode /Length " + fmt.Sprint(z.Len()) + " >>\nstream\n")
	pdf.Write(z.Bytes())
	pdf.WriteString("\nendstream\nendobj\n")
	_, text := PDFCodes(pdf.Bytes())
	if !contains(text, "ABCDEFGH12") || strings.Contains(pdf.String(), "ABCDEFGH12") {
		t.Fatalf("text=%v", text)
	}
}

func TestWritePagesPDFXref(t *testing.T) {
	data := makePDF(t, 3, 200, 200)
	sx := bytes.LastIndex(data, []byte("startxref\n"))
	var xoff int
	fmt.Sscanf(string(data[sx+len("startxref\n"):]), "%d", &xoff)
	lines := strings.Split(string(data[xoff:]), "\n")
	var size int
	fmt.Sscanf(lines[1], "0 %d", &size)
	if size != 4+3*3+1 {
		t.Fatalf("size = %d", size)
	}
	for id := 1; id < size; id++ {
		var off int
		var gen int
		var kind string
		fmt.Sscanf(lines[2+id], "%d %d %s", &off, &gen, &kind)
		if kind != "n" || !bytes.HasPrefix(data[off:], []byte(fmt.Sprintf("%d 0 obj\n", id))) {
			t.Fatalf("xref entry %d bad: %q", id, lines[2+id])
		}
	}
	if err := api.Validate(context.Background(), bytes.NewReader(data), model.NewStatelessConfiguration(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidCodeRejected(t *testing.T) {
	var b bytes.Buffer
	if err := WritePagesPDF(&b, 1, func(int) (image.Image, error) { return testPage(10, 10), nil }, "A) /X (B"); err == nil {
		t.Error("WritePagesPDF accepted bad code")
	}
	if err := AddPDFMeta(bytes.NewReader(makePDF(t, 1, 200, 200)), &b, "bad"); err == nil {
		t.Error("AddPDFMeta accepted bad code")
	}
}

func TestPDFCodesInflateBudget(t *testing.T) {
	old := totalInflate
	totalInflate = 1000
	defer func() { totalInflate = old }()
	mk := func(code string) []byte {
		var z bytes.Buffer
		zw := zlib.NewWriter(&z)
		_, _ = io.WriteString(zw, strings.Repeat("0 0 m 1 1 l S ", 50)+"(SX-"+code+")")
		_ = zw.Close()
		return append(append([]byte("stream\n"), z.Bytes()...), []byte("\nendstream\n")...)
	}
	var pdf []byte
	pdf = append(pdf, mk("AAAAAAAAAA")...) // ~730 bytes inflated, within budget
	pdf = append(pdf, mk("BBBBBBBBBB")...) // exhausts budget
	pdf = append(pdf, mk("CCCCCCCCCC")...) // must not be scanned
	_, text := PDFCodes(pdf)
	if !contains(text, "AAAAAAAAAA") || contains(text, "CCCCCCCCCC") {
		t.Fatalf("text=%v", text)
	}
}
