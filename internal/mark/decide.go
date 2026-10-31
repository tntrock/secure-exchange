package mark

import (
	"bytes"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/tntrock/secure-exchange/internal/config"
	"github.com/tntrock/secure-exchange/internal/preview"
)

// Plan is how one download is marked.
type Plan struct {
	Method   Method
	OutName  string // download file name (Office rendered to pages becomes .pdf)
	Degraded bool   // watermark on, but not marked visibly
	Pending  bool   // pdf_pages needed, preview still rendering: never send the original
}

var (
	officeExts = map[string]bool{".doc": true, ".docx": true, ".odt": true, ".rtf": true, ".xls": true, ".xlsx": true,
		".ods": true, ".ppt": true, ".pptx": true, ".odp": true}
	ooxmlExts = map[string]bool{".docx": true, ".xlsx": true, ".pptx": true}
	odfExts   = map[string]bool{".odt": true, ".ods": true, ".odp": true}
)

// ImageMIME is "image/jpeg" or "image/png" when head sniffs as one, else "".
func ImageMIME(head []byte) string {
	if m := http.DetectContentType(head); m == "image/jpeg" || m == "image/png" {
		return m
	}
	return ""
}

// Decide picks the mark method for a download. pixels is width×height of an
// image (0 if unknown or not an image); p == nil means no preview.
func Decide(name string, head []byte, size int64, pixels int, p *preview.Preview, watermark bool, cfg config.MarkConfig) Plan {
	ext := strings.ToLower(filepath.Ext(name))
	plan := Plan{Method: None, OutName: name}
	status := preview.StatusUnsupported
	if p != nil {
		status = p.Status
	}
	pdf := ext == ".pdf" && bytes.HasPrefix(head, []byte("%PDF-"))
	switch {
	case pdf || officeExts[ext]:
		if watermark && status == preview.StatusReady {
			plan.Method, plan.OutName = PDFPages, strings.TrimSuffix(name, filepath.Ext(name))+".pdf"
			return plan
		}
		if watermark && status == preview.StatusPending {
			plan.Method, plan.Pending = PDFPages, true
			return plan
		}
		switch {
		case pdf && size <= cfg.MaxBytes:
			plan.Method = PDFMeta
		case ooxmlExts[ext]:
			plan.Method = OOXMLMeta
		case odfExts[ext]:
			plan.Method = ODFMeta
		}
	case ImageMIME(head) != "" && size <= cfg.MaxBytes && pixels <= cfg.MaxPixels:
		plan.Method = ImageInvisible
		if watermark {
			plan.Method = ImageVisible
		}
	}
	plan.Degraded = watermark && plan.Method != PDFPages && plan.Method != ImageVisible
	return plan
}
