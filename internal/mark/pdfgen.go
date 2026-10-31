package mark

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"io"
)

const pdfDPI = 110.0

// CountWriter counts the bytes written through it.
type CountWriter struct {
	W io.Writer
	N int64
}

func (c *CountWriter) Write(p []byte) (int, error) {
	n, err := c.W.Write(p)
	c.N += int64(n)
	return n, err
}

// WritePagesPDF streams an n-page PDF 1.4 (one JPEG per page, plus a hidden
// text layer and Info keys carrying "SX-<code>") to w.
func WritePagesPDF(w io.Writer, n int, page func(i int) (image.Image, error), code string) error {
	if !codeValid.MatchString(code) {
		return errors.New("pdf: invalid trace code")
	}
	cw := &CountWriter{W: w}
	offs := map[int]int64{}
	var err error
	pf := func(format string, a ...any) {
		if err == nil {
			_, err = fmt.Fprintf(cw, format, a...)
		}
	}
	obj := func(id int) { offs[id] = cw.N; pf("%d 0 obj\n", id) }
	tag := "SX-" + code

	pf("%%PDF-1.4\n%%\xe2\xe3\xcf\xd3\n")
	// objects: 1 Catalog, 2 Pages, 3 Info, 4 Font, page i: 5+3i (Page), +1 Contents, +2 Image
	for i := range n {
		if err != nil {
			return err
		}
		img, perr := page(i)
		if perr != nil {
			return perr
		}
		b := img.Bounds()
		var jb bytes.Buffer
		if e := jpeg.Encode(&jb, EmbedInvisible(img, code), &jpeg.Options{Quality: 85}); e != nil {
			return e
		}
		wpt, hpt := float64(b.Dx())*72/pdfDPI, float64(b.Dy())*72/pdfDPI
		content := fmt.Sprintf("q %.2f 0 0 %.2f 0 0 cm /Im0 Do Q\nBT 3 Tr /F1 8 Tf 10 10 Td (%s) Tj ET\n", wpt, hpt, tag)
		pg := 5 + 3*i
		obj(pg)
		pf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.2f %.2f] /Contents %d 0 R /Resources << /XObject << /Im0 %d 0 R >> /Font << /F1 4 0 R >> >> >>\nendobj\n", wpt, hpt, pg+1, pg+2)
		obj(pg + 1)
		pf("<< /Length %d >>\nstream\n%sendstream\nendobj\n", len(content), content)
		obj(pg + 2)
		pf("<< /Type /XObject /Subtype /Image /Width %d /Height %d /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length %d >>\nstream\n", b.Dx(), b.Dy(), jb.Len())
		if err == nil {
			_, err = cw.Write(jb.Bytes())
		}
		pf("\nendstream\nendobj\n")
	}
	obj(4)
	pf("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")
	obj(3)
	pf("<< /Producer (secure-exchange) /Keywords (%s) /sx_trace (%s) >>\nendobj\n", tag, tag)
	obj(2)
	pf("<< /Type /Pages /Count %d /Kids [", n)
	for i := range n {
		pf("%d 0 R ", 5+3*i)
	}
	pf("] >>\nendobj\n")
	obj(1)
	pf("<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
	size := 5 + 3*n
	xref := cw.N
	pf("xref\n0 %d\n0000000000 65535 f \n", size)
	for id := 1; id < size; id++ {
		pf("%010d 00000 n \n", offs[id])
	}
	pf("trailer\n<< /Size %d /Root 1 0 R /Info 3 0 R >>\nstartxref\n%d\n%%%%EOF\n", size, xref)
	return err
}
