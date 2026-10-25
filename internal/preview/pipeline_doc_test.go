package preview

import (
	"errors"
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
	letter := "Page    1 size: 612 x 792 pts (letter)\nPage    1 rot:  0\n"
	if got := strings.Join(renderScale([]byte(letter), 110), " "); got != "-r 110" {
		t.Fatal(got)
	}
	// one huge page anywhere (or a spoofed line: max only grows) switches to -scale-to
	huge := letter + "Page    2 size: 5000 x 300.5 pts\n"
	if got := strings.Join(renderScale([]byte(huge), 110), " "); got != "-scale-to 2000" {
		t.Fatal(got)
	}
	if got := strings.Join(renderScale([]byte("no sizes"), 110), " "); got != "-scale-to 2000" {
		t.Fatal("unknown size must be bounded:", got)
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
}
