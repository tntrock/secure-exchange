// Package preview decides which files can be previewed online and runs the
// render job queue that the worker drains.
package preview

import (
	"bytes"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/tntrock/secure-exchange/internal/config"
)

type Kind string

const (
	KindPages Kind = "pages"
	KindImage Kind = "image"
	KindVideo Kind = "video"
	KindNone  Kind = "none"
)

type Status string

const (
	StatusPending     Status = "pending"
	StatusReady       Status = "ready"
	StatusFailed      Status = "failed"
	StatusUnsupported Status = "unsupported"
	StatusTooLarge    Status = "too_large"
)

// HeadLen is how many leading plaintext bytes Classify needs.
const HeadLen = 512

func set(exts string) map[string]bool {
	m := map[string]bool{}
	for _, e := range strings.Fields(exts) {
		m[e] = true
	}
	return m
}

var (
	pageExts  = set(".pdf .doc .docx .odt .rtf .xls .xlsx .ods .csv .ppt .pptx .odp .txt .md .log .json .xml .yaml .yml .go .py .js .ts .java .c .cpp .h .cs .sh .sql .html .css")
	videoExts = set(".mp4 .mov .m4v .mkv .webm .avi")
	imageMIME = set("image/jpeg image/png image/gif image/webp image/bmp")
)

// Classify picks the preview kind of a file from its name, its first bytes
// (decrypted) and its size.
func Classify(name string, head []byte, size int64, cfg config.PreviewConfig) (Kind, Status) {
	ext := strings.ToLower(filepath.Ext(name))
	if size == 0 {
		return KindNone, StatusUnsupported
	}
	kind := KindNone
	switch {
	case pageExts[ext]:
		kind = KindPages
		if ext == ".pdf" && !bytes.HasPrefix(head, []byte("%PDF-")) {
			kind = KindNone
		}
	case videoExts[ext]:
		kind = KindVideo
	case imageMIME[http.DetectContentType(head)],
		(ext == ".tif" || ext == ".tiff") && (bytes.HasPrefix(head, []byte("II*\x00")) || bytes.HasPrefix(head, []byte("MM\x00*"))):
		kind = KindImage
	}
	switch {
	case kind == KindNone:
		return KindNone, StatusUnsupported
	case kind == KindVideo && size > cfg.MaxVideoBytes, kind != KindVideo && size > cfg.MaxBytes:
		return kind, StatusTooLarge
	}
	return kind, StatusPending
}
