package preview

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tntrock/secure-exchange/internal/config"
)

const fakePlaylist3 = "#EXTM3U\n#EXTINF:6.000000,\ns00000.ts\n#EXTINF:6.000000,\ns00001.ts\n#EXTINF:2.000000,\ns00002.ts\n#EXT-X-ENDLIST\n"

func goodVideo() map[string]string {
	return map[string]string{"duration": "14.0", "size": "1280x720", "segs": "3", "playlist": fakePlaylist3}
}

func TestVideoPipelineFake(t *testing.T) {
	fakeToolsOnPath(t, goodVideo())
	res, items, err := runPipeline(t, videoPipeline, config.PreviewConfig{MaxVideoSeconds: 100}, "in.mp4", []byte("v"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Kind != KindVideo || res.Width != 1280 || res.Height != 720 || res.DurationMs != 14000 || len(items) != 3 {
		t.Fatalf("%+v items %d", res, len(items))
	}
	for i, ms := range []int64{6000, 6000, 2000} {
		it := items[i]
		if it.kind != "segment" || it.idx != i || string(it.data) != "seg "+string(rune('0'+i)) ||
			it.meta.DurationMs != ms || it.meta.Width != 1280 || it.meta.Height != 720 {
			t.Fatalf("item %d: %+v", i, it)
		}
	}
}

func TestVideoPipelineFakeErrors(t *testing.T) {
	for _, c := range []struct {
		name     string
		set      map[string]string
		max      int
		tooLarge bool
		want     string
	}{
		{"probe fails", map[string]string{"fail.duration": "secret"}, 100, false, "ffprobe: exit status 3"},
		{"bad duration", map[string]string{"duration": "abc"}, 100, false, "ffprobe: bad duration"},
		{"zero duration", map[string]string{"duration": "0"}, 100, false, "ffprobe: bad duration"},
		{"too long", map[string]string{"duration": "200"}, 100, true, "200 seconds"},
		{"ffmpeg fails", map[string]string{"fail.ffmpeg": "x"}, 100, false, "ffmpeg: exit status 3"},
		{"ffmpeg disk full", map[string]string{"fail.ffmpeg": "No space left on device"}, 100, true, "work dir full"},
		{"no playlist", map[string]string{"playlist": "\x00"}, 100, false, "ffmpeg: no playlist"},
		{"missing segment", map[string]string{"segs": "2"}, 100, false, "ffmpeg: missing segment"},
		{"too many segments", map[string]string{"duration": "4"}, 5, true, "3 segments"},
		{"size probe fails", map[string]string{"fail.size": "x"}, 100, false, "ffprobe: exit status 3"},
		{"size unparsable", map[string]string{"size": "wide"}, 100, false, "ffprobe: bad size"},
		{"size too tall", map[string]string{"size": "1920x1080"}, 100, false, "ffprobe: bad size"},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg := goodVideo()
			for k, v := range c.set {
				cfg[k] = v
			}
			if cfg["playlist"] == "\x00" {
				delete(cfg, "playlist")
			}
			fakeToolsOnPath(t, cfg)
			_, items, err := runPipeline(t, videoPipeline, config.PreviewConfig{MaxVideoSeconds: c.max}, "in.mp4", []byte("v"))
			if err == nil || errors.Is(err, errTooLarge) != c.tooLarge || !strings.Contains(err.Error(), c.want) || len(items) != 0 {
				t.Fatalf("err = %v items %d", err, len(items))
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatalf("tool output leaked: %v", err)
			}
		})
	}
}

func TestVideoPipelinePutError(t *testing.T) {
	fakeToolsOnPath(t, goodVideo())
	dir := t.TempDir()
	in := filepath.Join(dir, "in.mp4")
	os.WriteFile(in, []byte("v"), 0o600)
	boom := errors.New("store down")
	put := func(string, int, io.Reader, int64, Item) error { return boom }
	_, err := videoPipeline(&jobEnv{ctx: ctx, cfg: config.PreviewConfig{MaxVideoSeconds: 100}, dir: dir, in: in, put: put})
	if !errors.Is(err, boom) || !strings.HasPrefix(err.Error(), "segment 0:") {
		t.Fatalf("err = %v", err)
	}
}

func TestVideoProbeTimeout(t *testing.T) {
	orig := ffprobeTimeout
	ffprobeTimeout = 300 * time.Millisecond
	defer func() { ffprobeTimeout = orig }()
	fakeToolsOnPath(t, map[string]string{"fail.duration": "sleep"})
	start := time.Now()
	_, _, err := runPipeline(t, videoPipeline, config.PreviewConfig{MaxVideoSeconds: 100}, "in.mp4", []byte("v"))
	if !errors.Is(err, ErrTimeout) || errors.Is(err, errTooLarge) || err.Error() != "ffprobe: timeout" {
		t.Fatalf("err = %v", err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("took %v", d)
	}
}

func TestRunCanceledContext(t *testing.T) {
	fakeToolsOnPath(t, nil)
	c, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := Run(c, t.TempDir(), time.Minute, "ffprobe"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func TestRunMissingProgram(t *testing.T) {
	if _, err := Run(ctx, t.TempDir(), time.Minute, "sx-no-such-program"); err == nil || errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v", err)
	}
	// not an exit status: the error is passed through
	if err := toolErr("x", errors.New("not found"), nil); err.Error() != "x: not found" {
		t.Fatal(err)
	}
}

func TestParsePlaylist(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "s00000.ts"), []byte("x"), 0o600)
	ok := "#EXTM3U\n#EXTINF:6.000000,\ns00000.ts\n#EXT-X-ENDLIST\n"
	if segs, err := parsePlaylist(ok, dir); err != nil || len(segs) != 1 || segs[0].ms != 6000 {
		t.Fatalf("%v %v", segs, err)
	}
	for _, bad := range []string{"", "#EXTINF:6,\n../s00000.ts\n", "#EXTINF:6,\ns00001.ts\n", "#EXTINF:x,\ns00000.ts\n", "#EXTINF:-1,\ns00000.ts\n", "s00000.ts\n"} {
		if _, err := parsePlaylist(bad, dir); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestSegmentCountCap(t *testing.T) {
	// header-claimed duration is untrusted: output beyond ceil(max/6)+1 segments fails closed
	if checkSegmentCount(3, 14) != nil || !errors.Is(checkSegmentCount(5, 14), errTooLarge) {
		t.Fatal("cap wrong")
	}
}
