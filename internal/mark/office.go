package mark

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
)

// ErrNoProps means the zip has no core.xml/meta.xml (or no closing tag) to carry the code.
var ErrNoProps = errors.New("mark: no document properties to mark")

const maxMeta = 1 << 20

var emptyKeywordsRe = regexp.MustCompile(`<cp:keywords\s*/>`)

// readLimited reads at most maxMeta bytes; ok is false if the entry is larger.
func readLimited(f *zip.File) (b []byte, ok bool, err error) {
	rc, err := f.Open()
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = rc.Close() }()
	b, err = io.ReadAll(io.LimitReader(rc, maxMeta+1))
	return b, len(b) <= maxMeta, err
}

// AddZipMeta copies the zip (docx/odt) to w, adding "SX-<code>" as a keyword in
// docProps/core.xml (OOXML) or meta.xml (ODF). Other entries are copied raw,
// without recompression.
//
// It writes nothing to w until the target entry has been found, read and
// successfully modified in memory, so on ErrNoProps (or any earlier error) w is
// untouched and the caller can fall back to an unmarked download.
func AddZipMeta(ra io.ReaderAt, size int64, w io.Writer, code string, odf bool) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("zip meta: panic: %v", p)
		}
	}()
	if !codeValid.MatchString(code) {
		return errors.New("zip meta: invalid trace code")
	}
	zr, err := zip.NewReader(ra, size)
	if err != nil {
		return err
	}
	target := "docProps/core.xml"
	if odf {
		target = "meta.xml"
	}
	var tf *zip.File
	for _, f := range zr.File {
		if f.Name == target {
			tf = f
			break
		}
	}
	if tf == nil {
		return ErrNoProps
	}
	b, ok, err := readLimited(tf)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("zip meta: properties entry too large")
	}
	s, tag := string(b), "SX-"+code
	if odf {
		if s, ok = insertBefore(s, "</office:meta>", "<meta:keyword>"+tag+"</meta:keyword>"); !ok {
			return ErrNoProps
		}
	} else {
		s = emptyKeywordsRe.ReplaceAllString(s, "<cp:keywords></cp:keywords>")
		if s, ok = insertBefore(s, "</cp:keywords>", " "+tag); !ok {
			if s, ok = insertBefore(s, "</cp:coreProperties>", "<cp:keywords>"+tag+"</cp:keywords>"); !ok {
				return ErrNoProps
			}
		}
	}

	zw := zip.NewWriter(w)
	for _, f := range zr.File {
		if f == tf {
			h := f.FileHeader
			h.Method = zip.Deflate
			fw, err := zw.CreateHeader(&h)
			if err != nil {
				return err
			}
			if _, err := io.WriteString(fw, s); err != nil {
				return err
			}
			continue
		}
		raw, err := f.OpenRaw()
		if err != nil {
			return err
		}
		fw, err := zw.CreateRaw(&f.FileHeader)
		if err != nil {
			return err
		}
		if _, err := io.Copy(fw, raw); err != nil {
			return err
		}
	}
	return zw.Close()
}

// insertBefore inserts ins before the last occurrence of tag.
func insertBefore(s, tag, ins string) (string, bool) {
	i := strings.LastIndex(s, tag)
	if i < 0 {
		return s, false
	}
	return s[:i] + ins + s[i:], true
}

// ZipCodes returns trace codes found in OOXML/ODF property entries. It returns
// nil on any error and never panics.
func ZipCodes(data []byte) (out []string) {
	defer func() {
		if recover() != nil {
			out = nil
		}
	}()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil
	}
	var all []string
	for _, f := range zr.File {
		switch f.Name {
		case "docProps/core.xml", "docProps/custom.xml", "meta.xml":
			rc, err := f.Open()
			if err != nil {
				return nil
			}
			b, err := io.ReadAll(io.LimitReader(rc, maxMeta))
			_ = rc.Close()
			if err != nil {
				return nil
			}
			all = append(all, findCodes(b)...)
		}
	}
	return dedup(all)
}

type seekerAt struct {
	mu sync.Mutex
	rs io.ReadSeeker
}

func (s *seekerAt) ReadAt(p []byte, off int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.rs.Seek(off, io.SeekStart); err != nil {
		return 0, err
	}
	n, err := io.ReadFull(s.rs, p)
	if err == io.ErrUnexpectedEOF {
		err = io.EOF
	}
	return n, err
}

// readerAt adapts a ReadSeeker (e.g. sxcrypto.OpenPlain) to an io.ReaderAt.
func readerAt(rs io.ReadSeeker) io.ReaderAt { return &seekerAt{rs: rs} }
