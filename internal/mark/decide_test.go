package mark

import (
	"testing"

	"github.com/tntrock/secure-exchange/internal/config"
	"github.com/tntrock/secure-exchange/internal/preview"
)

func TestDecide(t *testing.T) {
	cfg := config.MarkConfig{MaxBytes: 1000, MaxPixels: 100, Policy: "warn"}
	pdf, png, jpg, gif := []byte("%PDF-1.7\n"), []byte("\x89PNG\r\n\x1a\n"), []byte("\xff\xd8\xff\xe0"), []byte("GIF89a")
	st := func(s preview.Status) *preview.Preview { return &preview.Preview{Kind: preview.KindPages, Status: s} }
	for _, c := range []struct {
		name   string
		file   string
		head   []byte
		size   int64
		pixels int
		p      *preview.Preview
		wm     bool
		want   Plan
	}{
		{"pdf ready wm", "a.pdf", pdf, 10, 0, st(preview.StatusReady), true, Plan{Method: PDFPages, OutName: "a.pdf"}},
		{"pdf pending wm", "a.pdf", pdf, 10, 0, st(preview.StatusPending), true, Plan{Method: PDFPages, OutName: "a.pdf", Pending: true}},
		{"pdf too_large wm", "a.pdf", pdf, 10, 0, st(preview.StatusTooLarge), true, Plan{Method: PDFMeta, OutName: "a.pdf", Degraded: true}},
		{"pdf over max off", "a.pdf", pdf, 1001, 0, st(preview.StatusReady), false, Plan{Method: None, OutName: "a.pdf"}},
		{"pdf off", "a.pdf", pdf, 10, 0, st(preview.StatusReady), false, Plan{Method: PDFMeta, OutName: "a.pdf"}},
		{"pdf name no magic", "a.pdf", []byte("hello"), 10, 0, nil, false, Plan{Method: None, OutName: "a.pdf"}},
		{"docx ready wm", "a.docx", nil, 10, 0, st(preview.StatusReady), true, Plan{Method: PDFPages, OutName: "a.pdf"}},
		{"docx failed wm", "a.docx", nil, 10, 0, st(preview.StatusFailed), true, Plan{Method: OOXMLMeta, OutName: "a.docx", Degraded: true}},
		{"docx nil preview wm", "a.DOCX", nil, 10, 0, nil, true, Plan{Method: OOXMLMeta, OutName: "a.DOCX", Degraded: true}},
		{"docx off", "a.docx", nil, 10, 0, st(preview.StatusReady), false, Plan{Method: OOXMLMeta, OutName: "a.docx"}},
		{"doc off", "a.doc", nil, 10, 0, st(preview.StatusReady), false, Plan{Method: None, OutName: "a.doc"}},
		{"doc failed wm", "a.doc", nil, 10, 0, st(preview.StatusFailed), true, Plan{Method: None, OutName: "a.doc", Degraded: true}},
		{"odt off", "a.odt", nil, 10, 0, st(preview.StatusReady), false, Plan{Method: ODFMeta, OutName: "a.odt"}},
		{"png wm", "a.png", png, 10, 50, nil, true, Plan{Method: ImageVisible, OutName: "a.png"}},
		{"jpg off", "a.jpg", jpg, 10, 50, nil, false, Plan{Method: ImageInvisible, OutName: "a.jpg"}},
		{"jpg pixels off", "a.jpg", jpg, 10, 101, nil, false, Plan{Method: None, OutName: "a.jpg"}},
		{"jpg pixels wm", "a.jpg", jpg, 10, 101, nil, true, Plan{Method: None, OutName: "a.jpg", Degraded: true}},
		{"jpg bytes wm", "a.jpg", jpg, 1001, 50, nil, true, Plan{Method: None, OutName: "a.jpg", Degraded: true}},
		{"gif off", "a.gif", gif, 10, 50, nil, false, Plan{Method: None, OutName: "a.gif"}},
		{"gif wm", "a.gif", gif, 10, 50, nil, true, Plan{Method: None, OutName: "a.gif", Degraded: true}},
		{"zip wm", "a.zip", []byte("PK\x03\x04"), 10, 0, nil, true, Plan{Method: None, OutName: "a.zip", Degraded: true}},
		{"zip off", "a.zip", []byte("PK\x03\x04"), 10, 0, nil, false, Plan{Method: None, OutName: "a.zip"}},
	} {
		if got := Decide(c.file, c.head, c.size, c.pixels, c.p, c.wm, cfg); got != c.want {
			t.Errorf("%s: got %+v want %+v", c.name, got, c.want)
		}
	}
}
