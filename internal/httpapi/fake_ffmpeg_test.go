package httpapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tntrock/secure-exchange/internal/preview"
)

// When the test binary runs as "ffmpeg" it fakes the watermark burn, per the mode
// file next to it: "copy" writes "burned:" + stdin and saves the -vf argument to
// vf.txt, "fail" writes a long error and exits 1, "hang" never finishes.
// segment_tools_test.go covers the real ffmpeg.
func TestMain(m *testing.M) {
	if strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe") == "ffmpeg" {
		exe, _ := os.Executable()
		dir := filepath.Dir(exe)
		mode, _ := os.ReadFile(filepath.Join(dir, "mode"))
		code := 0
		switch string(mode) {
		case "copy":
			in, _ := io.ReadAll(os.Stdin)
			os.Stdout.Write(append([]byte("burned:"), in...))
			if i := slices.Index(os.Args, "-vf"); i > 0 {
				os.WriteFile(filepath.Join(dir, "vf.txt"), []byte(os.Args[i+1]), 0o600)
			}
		case "fail":
			os.Stderr.WriteString(strings.Repeat("e", 3000))
			code = 1
		case "hang":
			time.Sleep(time.Minute)
		}
		// syscall.Exit skips exit hooks: a -cover build would print a GOCOVERDIR warning to stderr
		syscall.Exit(code)
	}
	os.Exit(m.Run())
}

// fakeFFmpeg puts the fake first on PATH and returns its directory.
func fakeFFmpeg(t *testing.T, mode string) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	dst := filepath.Join(bin, "ffmpeg")
	if runtime.GOOS == "windows" {
		dst += ".exe"
	}
	if os.Link(self, dst) != nil {
		b, err := os.ReadFile(self)
		if err == nil {
			err = os.WriteFile(dst, b, 0o700)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bin, "mode"), []byte(mode), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return bin
}

func fontFile(t *testing.T) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "font.ttf")
	if err := os.WriteFile(f, []byte("font"), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestSegmentBurnFake(t *testing.T) {
	bin := fakeFFmpeg(t, "copy")
	font := fontFile(t)
	e, f, base := wmVideoShare(t, func(d *Deps) { d.FontFile = font })
	resp, b := e.get(t, base+"segments/1.ts")
	viewHeadersOK(t, resp, "video/mp2t")
	if string(b) != "burned:segment-1" {
		t.Fatal(string(b))
	}
	var code string
	e.pool.QueryRow(context.Background(), `SELECT code FROM view_traces WHERE file_id = $1`, f).Scan(&code)
	vf, _ := os.ReadFile(filepath.Join(bin, "vf.txt"))
	if code == "" || strings.Count(string(vf), "drawtext=fontfile="+filterQuote(font)) != 3 || !strings.Contains(string(vf), code) {
		t.Fatalf("code %q vf %q", code, vf)
	}
}

func TestBurnSegmentFakeErrors(t *testing.T) {
	s := &server{Deps: Deps{FontFile: fontFile(t)}}
	m := preview.Mark{Email: "r@y.com", IP: "1.2.3.4", At: time.Now(), Code: "ABCDEFGHJK"}

	fakeFFmpeg(t, "fail")
	var out bytes.Buffer
	err := s.burnSegment(context.Background(), &out, strings.NewReader("seg"), m)
	if err == nil || !strings.HasPrefix(err.Error(), "burn segment: exit status 1: eee") || len(err.Error()) > 1100 {
		t.Fatalf("err = %.80v (len %d)", err, len(fmt.Sprint(err)))
	}

	fakeFFmpeg(t, "hang")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := s.burnSegment(ctx, &out, strings.NewReader("seg"), m); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

func TestBurnSegmentCanceledWhileWaiting(t *testing.T) {
	for range cap(burnSlots) {
		burnSlots <- struct{}{}
	}
	defer func() {
		for range cap(burnSlots) {
			<-burnSlots
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := &server{}
	if err := s.burnSegment(ctx, io.Discard, strings.NewReader(""), preview.Mark{}); !errors.Is(err, errBusy) {
		t.Fatalf("err = %v", err)
	}
}
