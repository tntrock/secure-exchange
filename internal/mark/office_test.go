package mark

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func mkZip(t *testing.T, entries [][2]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		m := zip.Deflate
		if e[0] == "mimetype" {
			m = zip.Store
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: e[0], Method: m})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(w, e[1])
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func addMeta(t *testing.T, in []byte, odf bool) ([]byte, error) {
	t.Helper()
	var out bytes.Buffer
	err := AddZipMeta(bytes.NewReader(in), int64(len(in)), &out, testCode, odf)
	return out.Bytes(), err
}

func rawEntries(t *testing.T, b []byte) map[string][]byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	m := map[string][]byte{}
	for _, f := range zr.File {
		r, err := f.OpenRaw()
		if err != nil {
			t.Fatal(err)
		}
		m[f.Name], _ = io.ReadAll(r)
	}
	return m
}

func readEntry(t *testing.T, b []byte, name string) string {
	t.Helper()
	zr, _ := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	for _, f := range zr.File {
		if f.Name == name {
			r, _ := f.Open()
			s, _ := io.ReadAll(r)
			return string(s)
		}
	}
	t.Fatalf("no entry %s", name)
	return ""
}

func TestAddZipMetaOOXML(t *testing.T) {
	for name, core := range map[string]string{
		"with":  `<cp:coreProperties><cp:keywords>a, b</cp:keywords></cp:coreProperties>`,
		"empty": `<cp:coreProperties><cp:keywords/></cp:coreProperties>`,
		"attr":  `<cp:coreProperties><cp:keywords xml:lang="en"/></cp:coreProperties>`,
		"none":  `<cp:coreProperties><dc:title>x</dc:title></cp:coreProperties>`,
	} {
		t.Run(name, func(t *testing.T) {
			in := mkZip(t, [][2]string{{"[Content_Types].xml", "<Types/>"}, {"docProps/core.xml", core}, {"word/document.xml", "<doc/>"}})
			out, err := addMeta(t, in, false)
			if err != nil {
				t.Fatal(err)
			}
			got := readEntry(t, out, "docProps/core.xml")
			if !strings.Contains(got, "SX-"+testCode) {
				t.Fatalf("code missing: %s", got)
			}
			if name == "with" && !strings.Contains(got, "a, b SX-"+testCode+"</cp:keywords>") {
				t.Fatalf("keywords not preserved: %s", got)
			}
			if strings.Count(got, "<cp:keywords") != 1 {
				t.Fatalf("want exactly one keywords element: %s", got)
			}
			a, b := rawEntries(t, in), rawEntries(t, out)
			for _, n := range []string{"[Content_Types].xml", "word/document.xml"} {
				if !bytes.Equal(a[n], b[n]) {
					t.Fatalf("%s changed", n)
				}
			}
			if c := ZipCodes(out); len(c) != 1 || c[0] != testCode {
				t.Fatalf("ZipCodes = %v", c)
			}
		})
	}
}

func TestAddZipMetaODF(t *testing.T) {
	in := mkZip(t, [][2]string{{"mimetype", "application/vnd.oasis.opendocument.text"}, {"meta.xml", `<office:document-meta><office:meta></office:meta></office:document-meta>`}, {"content.xml", "<c/>"}})
	out, err := addMeta(t, in, true)
	if err != nil {
		t.Fatal(err)
	}
	zr, _ := zip.NewReader(bytes.NewReader(out), int64(len(out)))
	if zr.File[0].Name != "mimetype" || zr.File[0].Method != zip.Store {
		t.Fatalf("first entry = %s method %d", zr.File[0].Name, zr.File[0].Method)
	}
	if !strings.Contains(readEntry(t, out, "meta.xml"), "<meta:keyword>SX-"+testCode+"</meta:keyword></office:meta>") {
		t.Fatal("keyword not inserted")
	}
	if c := ZipCodes(out); len(c) != 1 || c[0] != testCode {
		t.Fatalf("ZipCodes = %v", c)
	}
}

func TestAddZipMetaNoProps(t *testing.T) {
	cases := map[string]struct {
		in  []byte
		odf bool
	}{
		"no entry":   {mkZip(t, [][2]string{{"a.txt", "x"}}), false},
		"no closing": {mkZip(t, [][2]string{{"docProps/core.xml", "<cp:coreProperties>"}}), false},
		"odf none":   {mkZip(t, [][2]string{{"mimetype", "m"}, {"meta.xml", "<x/>"}}), true},
	}
	for n, c := range cases {
		out, err := addMeta(t, c.in, c.odf)
		if !errors.Is(err, ErrNoProps) {
			t.Fatalf("%s: err = %v", n, err)
		}
		if len(out) != 0 {
			t.Fatalf("%s: wrote %d bytes before ErrNoProps", n, len(out))
		}
	}
}

func TestAddZipMetaBadCode(t *testing.T) {
	in := mkZip(t, [][2]string{{"docProps/core.xml", "<cp:coreProperties></cp:coreProperties>"}})
	var out bytes.Buffer
	if err := AddZipMeta(bytes.NewReader(in), int64(len(in)), &out, "bad<code", false); err == nil || out.Len() != 0 {
		t.Fatalf("err=%v written=%d", err, out.Len())
	}
}

func TestZipMetaCorruptInput(t *testing.T) {
	good := mkZip(t, [][2]string{{"docProps/core.xml", "<cp:coreProperties></cp:coreProperties>"}})
	for n, in := range map[string][]byte{"not zip": []byte("hello, not a zip"), "truncated": good[:len(good)-10], "empty": nil} {
		if _, err := addMeta(t, in, false); err == nil {
			t.Fatalf("%s: want error", n)
		}
		if ZipCodes(in) != nil {
			t.Fatalf("%s: ZipCodes want nil", n)
		}
	}
}

func TestZipCodesCap(t *testing.T) {
	// code placed after the 1 MiB cap must not be read
	big := strings.Repeat("a", 1<<20) + "SX-" + testCode
	if c := ZipCodes(mkZip(t, [][2]string{{"meta.xml", big}})); c != nil {
		t.Fatalf("got %v", c)
	}
	// oversized target is rejected by AddZipMeta (never partially modified)
	in := mkZip(t, [][2]string{{"docProps/core.xml", big + "</cp:coreProperties>"}})
	if _, err := addMeta(t, in, false); err == nil || errors.Is(err, ErrNoProps) {
		t.Fatalf("want non-ErrNoProps error, got %v", err)
	}
}

func TestReaderAt(t *testing.T) {
	ra := ReaderAt(strings.NewReader("hello world"))
	p := make([]byte, 5)
	if n, err := ra.ReadAt(p, 6); n != 5 || err != nil || string(p) != "world" {
		t.Fatalf("n=%d err=%v p=%q", n, err, p)
	}
	p = make([]byte, 8)
	if n, err := ra.ReadAt(p, 6); n != 5 || err != io.EOF {
		t.Fatalf("short read n=%d err=%v", n, err)
	}
	if n, err := ra.ReadAt(p, 11); n != 0 || err != io.EOF {
		t.Fatalf("at end n=%d err=%v", n, err)
	}
}
