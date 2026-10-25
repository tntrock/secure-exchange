//go:build tools

package httpapi

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tntrock/secure-exchange/internal/preview"
)

func ffprobeDuration(t *testing.T, path string) float64 {
	t.Helper()
	out, err := exec.Command("ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "default=nw=1:nk=1", path).Output()
	if err != nil {
		t.Fatal(err)
	}
	d, err := strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func firstFrame(t *testing.T, path string) []byte {
	t.Helper()
	out, err := exec.Command("ffmpeg", "-nostdin", "-loglevel", "error", "-i", path, "-frames:v", "1", "-f", "rawvideo", "-pix_fmt", "gray", "pipe:1").Output()
	if err != nil || len(out) == 0 {
		t.Fatal(err, len(out))
	}
	return out
}

func TestBurnSegment(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "in.ts")
	if out, err := exec.Command("ffmpeg", "-nostdin", "-loglevel", "error", "-f", "lavfi", "-i", "testsrc=duration=6:size=640x360:rate=25",
		"-f", "lavfi", "-i", "sine=duration=6", "-c:v", "libx264", "-pix_fmt", "yuv420p", "-c:a", "aac", "-shortest", "-f", "mpegts", src).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	in, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	s := &server{Deps: Deps{FontFile: "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"}}
	// filter metacharacters in the text must not break the filtergraph
	m := preview.Mark{Email: `o'k%{x}\y:z,[a];b@x.com`, IP: "2001:db8::1", At: time.Now(), Code: preview.NewTraceCode()}
	var buf bytes.Buffer
	if err := s.burnSegment(context.Background(), &buf, bytes.NewReader(in), m); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "out.ts")
	if err := os.WriteFile(dst, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if d := ffprobeDuration(t, dst); d < 5.5 || d > 6.5 {
		t.Fatalf("duration %.2f", d)
	}
	if bytes.Equal(firstFrame(t, src), firstFrame(t, dst)) {
		t.Fatal("first frame unchanged")
	}

	s.FontFile = filepath.Join(dir, "missing.ttf")
	if err := s.burnSegment(context.Background(), &bytes.Buffer{}, bytes.NewReader(in), m); err == nil {
		t.Fatal("missing font: no error")
	}
}
