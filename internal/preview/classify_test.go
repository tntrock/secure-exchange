package preview

import (
	"testing"

	"github.com/tntrock/secure-exchange/internal/config"
)

func TestClassify(t *testing.T) {
	cfg := config.PreviewConfig{MaxBytes: 1000, MaxVideoBytes: 5000}
	png := []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
	tests := []struct {
		name string
		head []byte
		size int64
		kind Kind
		st   Status
	}{
		{"a.pdf", []byte("%PDF-1.7"), 10, KindPages, StatusPending},
		{"a.pdf", []byte("MZ"), 10, KindNone, StatusUnsupported},
		{"A.DOCX", nil, 10, KindPages, StatusPending},
		{"a.png", png, 10, KindImage, StatusPending},
		{"a.png", []byte("just some text"), 10, KindNone, StatusUnsupported},
		{"a.tiff", []byte("II*\x00rest"), 10, KindImage, StatusPending},
		{"a.tif", []byte("MM\x00*rest"), 10, KindImage, StatusPending},
		{"a.tiff", []byte("nope"), 10, KindNone, StatusUnsupported},
		{"a.mp4", nil, 10, KindVideo, StatusPending},
		{"a.zip", []byte("PK\x03\x04"), 10, KindNone, StatusUnsupported},
		{"empty.txt", nil, 0, KindNone, StatusUnsupported},
		{"a.pdf", []byte("%PDF-1.7"), 1001, KindPages, StatusTooLarge},
		{"a.png", png, 1001, KindImage, StatusTooLarge},
		{"a.mp4", nil, 5001, KindVideo, StatusTooLarge},
		{"a.mp4", nil, 5000, KindVideo, StatusPending}, // video limit, not MaxBytes
	}
	for _, tc := range tests {
		if k, s := Classify(tc.name, tc.head, tc.size, cfg); k != tc.kind || s != tc.st {
			t.Errorf("%s size %d: got %s/%s, want %s/%s", tc.name, tc.size, k, s, tc.kind, tc.st)
		}
	}
}
