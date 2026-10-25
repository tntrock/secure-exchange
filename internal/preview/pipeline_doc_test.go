package preview

import (
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
