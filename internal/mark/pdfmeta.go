package mark

import (
	"bytes"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

// codeRe matches an embedded trace code ("SX-" + 10 chars of the trace alphabet).
var codeRe = regexp.MustCompile(`SX-([0-9A-HJKMNP-TV-Z]{10})`)

// codeValid is the full-string form of codeRe's payload; guards PDF string injection.
var codeValid = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{10}$`)

const (
	maxInflate = 16 << 20
	pdfTimeout = 30 * time.Second
)

// totalInflate bounds all decompression done by one PDFCodes call (var so tests can shrink it).
var totalInflate int64 = 128 << 20

// AddPDFMeta copies the PDF from r to w with an sx_trace property set to "SX-<code>".
func AddPDFMeta(r io.ReadSeeker, w io.Writer, code string) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("pdf meta: panic: %v", p)
		}
	}()
	if !codeValid.MatchString(code) {
		return errors.New("pdf meta: invalid trace code")
	}
	ctx, cancel := context.WithTimeout(context.Background(), pdfTimeout)
	defer cancel()
	return api.AddProperties(ctx, r, w, map[string]string{"sx_trace": "SX-" + code}, model.NewStatelessConfiguration())
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

// PDFCodes returns trace codes found in PDF metadata and page content streams.
// It returns no error; results may be partial on hostile or oversized input.
func PDFCodes(data []byte) (meta, text []string) {
	defer func() { _ = recover() }()
	meta = findCodes(data)
	ctx, cancel := context.WithTimeout(context.Background(), pdfTimeout)
	defer cancel()
	func() {
		defer func() { _ = recover() }()
		props, err := api.Properties(ctx, bytes.NewReader(data), model.NewStatelessConfiguration())
		if err == nil {
			meta = append(meta, findCodes([]byte(props["sx_trace"]))...)
		}
	}()
	budget := totalInflate
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
			if dec, _ := io.ReadAll(io.LimitReader(zr, min(maxInflate, budget))); len(dec) > 0 {
				budget -= int64(len(dec))
				text = append(text, findCodes(dec)...)
				continue
			}
		}
		text = append(text, findCodes(s)...)
	}
	return dedup(meta), dedup(text)
}
