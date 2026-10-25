package preview

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// External program limits; vars so tools tests can shorten them.
var (
	ffprobeTimeout   = 60 * time.Second
	ffmpegTimeoutMin = 600 * time.Second // ffmpeg gets max(this, 3 × video seconds)
)

var segNameRE = regexp.MustCompile(`^s\d{5}\.ts$`)

type segment struct {
	name string
	ms   int64
}

// videoPipeline transcodes a video to 6-second H.264/AAC MPEG-TS HLS segments (height ≤ 720), one item each.
func videoPipeline(e *jobEnv) (Result, error) {
	// file only: a hostile playlist/concat input must not reach network or other protocols
	in := []string{"-protocol_whitelist", "file"}
	o, err := Run(e.ctx, e.dir, ffprobeTimeout, "ffprobe", append(in, "-v", "error", "-show_entries", "format=duration",
		"-of", "default=noprint_wrappers=1:nokey=1", e.in)...)
	if err != nil {
		return Result{}, toolErr("ffprobe", err, o)
	}
	secs, err := strconv.ParseFloat(strings.TrimSpace(string(o)), 64)
	if err != nil || math.IsInf(secs, 0) || math.IsNaN(secs) || secs <= 0 {
		return Result{}, errors.New("ffprobe: bad duration")
	}
	if secs > float64(e.cfg.MaxVideoSeconds) {
		return Result{}, fmt.Errorf("%w: %.0f seconds", errTooLarge, secs)
	}
	out := filepath.Join(e.dir, "out")
	if err := os.Mkdir(out, 0o700); err != nil {
		return Result{}, err
	}
	timeout := max(ffmpegTimeoutMin, time.Duration(3*secs*float64(time.Second)))
	args := append(in, "-nostdin", "-i", e.in, "-map", "0:v:0", "-map", "0:a:0?", "-vf", "scale=-2:'min(720,ih)'",
		"-c:v", "libx264", "-force_key_frames", "expr:gte(t,n_forced*6)", "-preset", "veryfast", "-crf", "23", "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "128k", "-ac", "2",
		"-max_muxing_queue_size", "1024", "-threads", "2",
		"-f", "hls", "-hls_time", "6", "-hls_playlist_type", "vod", "-hls_segment_type", "mpegts",
		"-hls_segment_filename", filepath.Join(out, "s%05d.ts"), filepath.Join(out, "index.m3u8"))
	if o, err := Run(e.ctx, e.dir, timeout, "ffmpeg", args...); err != nil {
		return Result{}, toolErr("ffmpeg", err, o)
	}
	pl, err := os.ReadFile(filepath.Join(out, "index.m3u8"))
	if err != nil {
		return Result{}, errors.New("ffmpeg: no playlist")
	}
	segs, err := parsePlaylist(string(pl), out)
	if err != nil {
		return Result{}, err
	}
	res := Result{Kind: KindVideo}
	for i, s := range segs {
		p := filepath.Join(out, s.name)
		if i == 0 { // dimensions of what the viewer gets, not of the input
			if res.Width, res.Height, err = probeSize(e, p); err != nil {
				return Result{}, err
			}
		}
		f, err := os.Open(p)
		if err != nil {
			return Result{}, err
		}
		st, err := f.Stat()
		if err == nil {
			err = e.put("segment", i, f, st.Size(), Item{DurationMs: s.ms, Width: res.Width, Height: res.Height})
		}
		f.Close()
		if err != nil {
			return Result{}, fmt.Errorf("segment %d: %w", i, err)
		}
		os.Remove(p) // keep tmpfs use bounded
		res.DurationMs += s.ms
	}
	return res, nil
}

func probeSize(e *jobEnv, path string) (w, h int, err error) {
	o, err := Run(e.ctx, e.dir, ffprobeTimeout, "ffprobe", "-v", "error", "-select_streams", "v:0",
		"-show_entries", "stream=width,height", "-of", "csv=p=0:s=x", path)
	if err != nil {
		return 0, 0, toolErr("ffprobe", err, o)
	}
	if _, err := fmt.Sscanf(strings.TrimSpace(string(o)), "%dx%d", &w, &h); err != nil || w <= 0 || h <= 0 || h > 720 {
		return 0, 0, errors.New("ffprobe: bad size")
	}
	return w, h, nil
}

// parsePlaylist pairs each #EXTINF with the next non-comment line; anything but an
// existing sNNNNN.ts in dir is rejected (fail closed).
func parsePlaylist(pl, dir string) ([]segment, error) {
	var segs []segment
	dur := int64(-1)
	for _, line := range strings.Split(pl, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
		case strings.HasPrefix(line, "#EXTINF:"):
			v, _, _ := strings.Cut(strings.TrimPrefix(line, "#EXTINF:"), ",")
			sec, err := strconv.ParseFloat(v, 64)
			if err != nil || math.IsInf(sec, 0) || math.IsNaN(sec) || sec <= 0 {
				return nil, errors.New("ffmpeg: bad playlist duration")
			}
			dur = int64(math.Round(sec * 1000))
		case strings.HasPrefix(line, "#"):
		default:
			if dur < 0 || !segNameRE.MatchString(line) {
				return nil, errors.New("ffmpeg: bad playlist entry")
			}
			if _, err := os.Stat(filepath.Join(dir, line)); err != nil {
				return nil, errors.New("ffmpeg: missing segment")
			}
			segs = append(segs, segment{line, dur})
			dur = -1
		}
	}
	if len(segs) == 0 {
		return nil, errors.New("ffmpeg: empty playlist")
	}
	return segs, nil
}
