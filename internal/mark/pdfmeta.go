package mark

import (
	"bytes"
	"compress/zlib"
	"context"
	"fmt"
	"io"
	"regexp"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

// codeRe matches an embedded trace code ("SX-" + 10 chars of the trace alphabet).
var codeRe = regexp.MustCompile(`SX-([0-9A-HJKMNP-TV-Z]{10})`)

const maxInflate = 16 << 20

// AddPDFMeta copies the PDF from r to w with an sx_trace property set to "SX-<code>".
func AddPDFMeta(r io.ReadSeeker, w io.Writer, code string) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("pdf meta: panic: %v", p)
		}
	}()
	return api.AddProperties(context.Background(), r, w, map[string]string{"sx_trace": "SX-" + code}, model.NewStatelessConfiguration())
}

func findCodes(b []byte) []string {
	var out []string
	for _, m := range codeRe.FindAllSubmatch(b, -1) {
		out = append(out, string(m[1]))
	}
	return out
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// PDFCodes returns trace codes found in PDF metadata and in page content streams.
// It never fails; hostile input just yields fewer results.
func PDFCodes(data []byte) (meta, text []string) {
	defer func() { _ = recover() }()
	meta = findCodes(data)
	func() {
		defer func() { _ = recover() }()
		props, err := api.Properties(context.Background(), bytes.NewReader(data), model.NewStatelessConfiguration())
		if err == nil {
			meta = append(meta, findCodes([]byte(props["sx_trace"]))...)
		}
	}()
	rest := data
	for {
		i := bytes.Index(rest, []byte("stream"))
		if i < 0 {
			break
		}
		rest = rest[i+len("stream"):]
		j := bytes.Index(rest, []byte("endstream"))
		if j < 0 {
			break
		}
		s := rest[:j]
		rest = rest[j+len("endstream"):]
		if len(s) == 0 {
			continue
		}
		raw := bytes.TrimLeft(s, "\r\n")
		if zr, err := zlib.NewReader(bytes.NewReader(raw)); err == nil {
			if dec, _ := io.ReadAll(io.LimitReader(zr, maxInflate)); len(dec) > 0 {
				text = append(text, findCodes(dec)...)
				continue
			}
		}
		text = append(text, findCodes(s)...)
	}
	return dedup(meta), dedup(text)
}
