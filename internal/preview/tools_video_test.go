//go:build tools

package preview

import (
	"crypto/rand"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/tntrock/secure-exchange/internal/config"
)

func makeVideo(t *testing.T, secs string) []byte {
	t.Helper()
	dir := t.TempDir()
	out := filepath.Join(dir, "v.mp4")
	if o, err := Run(ctx, dir, ffmpegTimeoutMin, "ffmpeg", "-nostdin", "-f", "lavfi", "-i", "testsrc=duration="+secs+":size=1280x720:rate=25",
		"-f", "lavfi", "-i", "sine=duration="+secs, "-c:v", "libx264", "-pix_fmt", "yuv420p", "-c:a", "aac", "-shortest", out); err != nil {
		t.Fatalf("%v: %s", err, o)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVideoPipeline(t *testing.T) {
	res, items, err := runPipeline(t, videoPipeline, config.PreviewConfig{MaxVideoSeconds: 100}, "in.mp4", makeVideo(t, "14"))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 || res.Kind != KindVideo || res.Height != 720 || res.Width != 1280 || math.Abs(float64(res.DurationMs)-14000) > 700 {
		t.Fatalf("%+v items %d", res, len(items))
	}
	want := []float64{6000, 6000, 2000}
	for i, it := range items {
		if it.kind != "segment" || it.idx != i || len(it.data) == 0 || math.Abs(float64(it.meta.DurationMs)-want[i]) > 500 {
			t.Fatalf("item %d: %s/%d %d bytes %dms", i, it.kind, it.idx, len(it.data), it.meta.DurationMs)
		}
	}
}

func TestVideoTooLong(t *testing.T) {
	_, items, err := runPipeline(t, videoPipeline, config.PreviewConfig{MaxVideoSeconds: 5}, "in.mp4", makeVideo(t, "8"))
	if !errors.Is(err, errTooLarge) || len(items) != 0 {
		t.Fatalf("err = %v items %d", err, len(items))
	}
}

func TestVideoCorrupt(t *testing.T) {
	junk := make([]byte, 4096)
	rand.Read(junk)
	_, items, err := runPipeline(t, videoPipeline, config.PreviewConfig{MaxVideoSeconds: 100}, "in.mp4", junk)
	if err == nil || errors.Is(err, errTooLarge) || len(items) != 0 {
		t.Fatalf("err = %v items %d", err, len(items))
	}
}

func TestVideoHLSInputRejected(t *testing.T) {
	// an HLS playlist named .mp4 must not make ffmpeg read other files by absolute path
	dir := t.TempDir()
	ts := filepath.Join(dir, "x.ts")
	if o, err := Run(ctx, dir, ffmpegTimeoutMin, "ffmpeg", "-nostdin", "-f", "lavfi", "-i", "testsrc=duration=2:size=320x240:rate=25", "-c:v", "libx264", ts); err != nil {
		t.Fatalf("%v: %s", err, o)
	}
	pl := "#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXTINF:2,\n" + ts + "\n#EXT-X-ENDLIST\n"
	_, items, err := runPipeline(t, videoPipeline, config.PreviewConfig{MaxVideoSeconds: 100}, "in.mp4", []byte(pl))
	if err == nil || len(items) != 0 {
		t.Fatalf("err = %v items %d", err, len(items))
	}
}
