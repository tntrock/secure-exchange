package preview

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParsePages(t *testing.T) {
	out := "Title:          x\nPages:          12\nEncrypted:      no\n"
	if n, err := parsePages([]byte(out)); err != nil || n != 12 {
		t.Fatalf("%d %v", n, err)
	}
	for _, bad := range []string{"Title: x\n", "Pages: abc\n", "Pages: 0\n"} {
		if _, err := parsePages([]byte(bad)); err == nil {
			t.Fatalf("%q: want error", bad)
		}
	}
}

func TestPageFilesSorted(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"p-10.png", "p-2.png", "p-1.png", "in.pdf"} {
		os.WriteFile(filepath.Join(dir, n), nil, 0o600)
	}
	files, err := pageFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range files {
		names = append(names, filepath.Base(f))
	}
	if strings.Join(names, ",") != "p-1.png,p-2.png,p-10.png" {
		t.Fatal(names)
	}
}

func TestParsePagesLastMatch(t *testing.T) {
	// a Title with an embedded newline must not spoof the page count
	out := "Title:          x\nPages:          1\nProducer:       y\nPages:          700\n"
	if n, err := parsePages([]byte(out)); err != nil || n != 700 {
		t.Fatalf("%d %v", n, err)
	}
}

func TestRenderScale(t *testing.T) {
	page := func(n int, size string) string {
		return fmt.Sprintf("Page %4d size: %s pts\nPage %4d rot:  0\n", n, size, n)
	}
	letter := page(1, "612 x 792") + page(2, "612 x 792")
	for _, c := range []struct {
		name, out string
		pages     int
		want      string
	}{
		{"normal", letter, 2, "-r 110"},
		{"one huge page", letter + page(3, "5000 x 300.5"), 3, "-scale-to 2000"},
		{"exponent form", page(1, "3e+06 x 400"), 1, "-scale-to 2000"},
		{"exponent but small", page(1, "6.12e+02 x 792"), 1, "-r 110"},
		{"truncated listing", letter, 3, "-scale-to 2000"},
		{"spoofed extra line", page(1, "612 x 792") + letter, 2, "-scale-to 2000"},
		{"unparsable", page(1, "abc x 792"), 1, "-scale-to 2000"},
		{"non-finite", page(1, "inf x 792"), 1, "-scale-to 2000"},
		{"zero", page(1, "0 x 792"), 1, "-scale-to 2000"},
		{"no sizes", "nothing", 1, "-scale-to 2000"},
	} {
		if got := strings.Join(renderScale([]byte(c.out), 110, c.pages), " "); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestToolErrOmitsOutput(t *testing.T) {
	err := toolErr("soffice", errors.New("exit status 3"), []byte("secret document text"))
	if err.Error() != "soffice: exit status 3" {
		t.Fatal(err)
	}
	if err := toolErr("pdftoppm", ErrTimeout, nil); err.Error() != "pdftoppm: timeout" || !errors.Is(err, ErrTimeout) {
		t.Fatal(err)
	}
	if err := toolErr("ffmpeg", errors.New("exit status 1"), []byte("x: No space left on device")); !errors.Is(err, errTooLarge) {
		t.Fatal(err)
	}
}
