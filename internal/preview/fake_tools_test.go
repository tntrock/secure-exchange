package preview

import (
	"bytes"
	"encoding/json"
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The test binary doubles as fake ffprobe/ffmpeg/soffice/pdfinfo/pdftoppm: when it
// runs under one of those names it acts per fake.json next to the executable. This
// drives the video and document pipelines (and Run) on any platform without the
// real tools; tools_*_test.go cover the real ones.
var fakeTools = map[string]func(cfg map[string]string, args []string) int{
	"ffprobe":  fakeFFprobe,
	"ffmpeg":   fakeFFmpeg,
	"soffice":  fakeSoffice,
	"pdfinfo":  fakePdfinfo,
	"pdftoppm": fakePdftoppm,
}

func TestMain(m *testing.M) {
	if f := fakeTools[strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe")]; f != nil {
		exe, _ := os.Executable()
		cfg := map[string]string{}
		if b, err := os.ReadFile(filepath.Join(filepath.Dir(exe), "fake.json")); err == nil {
			json.Unmarshal(b, &cfg)
		}
		// syscall.Exit skips exit hooks: a -cover build would print a GOCOVERDIR warning into the tool output
		syscall.Exit(f(cfg, os.Args[1:]))
	}
	os.Exit(m.Run())
}

// fakeToolsOnPath puts the fakes first on PATH, configured by cfg.
func fakeToolsOnPath(t *testing.T, cfg map[string]string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	for name := range fakeTools {
		dst := filepath.Join(bin, name+ext)
		if os.Link(self, dst) != nil {
			b, err := os.ReadFile(self)
			if err == nil {
				err = os.WriteFile(dst, b, 0o700)
			}
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	b, _ := json.Marshal(cfg)
	if err := os.WriteFile(filepath.Join(bin, "fake.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func argAfter(args []string, flag string) string {
	if i := slices.Index(args, flag); i >= 0 && i+1 < len(args) {
		return args[i+1]
	}
	return ""
}

// fail prints out and exits non-zero when cfg[key] is set.
func fakeFail(cfg map[string]string, key string) (int, bool) {
	if v, ok := cfg[key]; ok {
		if v == "sleep" {
			time.Sleep(30 * time.Second)
		}
		fmt.Fprint(os.Stderr, v)
		return 3, true
	}
	return 0, false
}

func fakeFFprobe(cfg map[string]string, args []string) int {
	if slices.Contains(args, "format=duration") {
		if c, ok := fakeFail(cfg, "fail.duration"); ok {
			return c
		}
		fmt.Println(cfg["duration"])
		return 0
	}
	if c, ok := fakeFail(cfg, "fail.size"); ok {
		return c
	}
	fmt.Println(cfg["size"])
	return 0
}

func fakeFFmpeg(cfg map[string]string, args []string) int {
	if c, ok := fakeFail(cfg, "fail.ffmpeg"); ok {
		return c
	}
	out := filepath.Dir(argAfter(args, "-hls_segment_filename"))
	var n int
	fmt.Sscan(cfg["segs"], &n)
	for i := range n {
		os.WriteFile(filepath.Join(out, fmt.Sprintf("s%05d.ts", i)), []byte(fmt.Sprintf("seg %d", i)), 0o600)
	}
	if pl, ok := cfg["playlist"]; ok {
		os.WriteFile(filepath.Join(out, "index.m3u8"), []byte(pl), 0o600)
	}
	return 0
}

func fakeSoffice(cfg map[string]string, args []string) int {
	if c, ok := fakeFail(cfg, "fail.soffice"); ok {
		return c
	}
	var n int
	fmt.Sscan(cfg["pdfs"], &n)
	for i := range n {
		os.WriteFile(filepath.Join(argAfter(args, "--outdir"), fmt.Sprintf("d%d.pdf", i)), []byte("%PDF"), 0o600)
	}
	return 0
}

func fakePdfinfo(cfg map[string]string, args []string) int {
	key := "pdfinfo"
	if slices.Contains(args, "-f") {
		key = "sizes"
	}
	if c, ok := fakeFail(cfg, "fail."+key); ok {
		return c
	}
	fmt.Print(cfg[key])
	return 0
}

func fakePdftoppm(cfg map[string]string, args []string) int {
	if c, ok := fakeFail(cfg, "fail.pdftoppm"); ok {
		return c
	}
	prefix := args[len(args)-1]
	for i, sz := range strings.Fields(cfg["pages"]) {
		var b []byte
		var w, h int
		if _, err := fmt.Sscanf(sz, "%dx%d", &w, &h); err == nil {
			var buf bytes.Buffer
			png.Encode(&buf, image.NewGray(image.Rect(0, 0, w, h)))
			b = buf.Bytes()
		} else {
			b = []byte(sz) // not an image
		}
		os.WriteFile(fmt.Sprintf("%s-%d.png", prefix, i+1), b, 0o600)
	}
	return 0
}

// pngSize decodes an item's PNG dimensions.
func pngSize(t *testing.T, b []byte) (int, int) {
	t.Helper()
	c, err := png.DecodeConfig(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return c.Width, c.Height
}
