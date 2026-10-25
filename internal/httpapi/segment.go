package httpapi

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/tntrock/secure-exchange/internal/preview"
)

const burnTimeout = 30 * time.Second

// filterQuote makes s one literal option value in an ffmpeg filtergraph: backslash-escapes the
// option parser's specials (backslash, quote, colon), then single-quotes it for the graph parser,
// closing and reopening the quotes around each escaped quote (inside quotes nothing else is special).
func filterQuote(s string) string {
	s = strings.NewReplacer(`\`, `\\`, `'`, `\'`, `:`, `\:`).Replace(s)
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// drawtextEscape is filterQuote for drawtext's text=, which first expands % and \ sequences.
func drawtextEscape(s string) string {
	return filterQuote(strings.NewReplacer(`\`, `\\`, `%`, `\%`).Replace(s))
}

// burnSegment re-encodes one MPEG-TS segment from src with m drawn on three rows, into w.
// ponytail: 每次請求都重新燒入，同時觀看人數多時需改為快取或預先轉檔
func (s *server) burnSegment(ctx context.Context, w io.Writer, src io.Reader, m preview.Mark) error {
	// ffmpeg's fontconfig lookup would silently substitute another font for a missing file
	if _, err := os.Stat(s.FontFile); err != nil {
		return fmt.Errorf("burn segment: font: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, burnTimeout)
	defer cancel()
	dt := "drawtext=fontfile=" + filterQuote(s.FontFile) + ":text=" + drawtextEscape(m.Text()) +
		":fontsize=h/22:fontcolor=white@0.22:x=(w-tw)/2:y="
	vf := dt + "(h-th)/2," + dt + "h/5," + dt + "4*h/5"
	cmd := exec.CommandContext(ctx, "ffmpeg", "-nostdin", "-loglevel", "error",
		"-protocol_whitelist", "pipe", "-format_whitelist", "mpegts", "-f", "mpegts", "-copyts", "-i", "pipe:0",
		"-vf", vf, "-c:v", "libx264", "-preset", "ultrafast", "-crf", "26", "-c:a", "copy", "-threads", "2",
		"-muxdelay", "0", "-f", "mpegts", "pipe:1")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	var stderr strings.Builder
	cmd.Stdin, cmd.Stdout, cmd.Stderr = src, w, &stderr
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("burn segment: %w", ctx.Err())
		}
		msg := stderr.String()
		if len(msg) > 1024 {
			msg = msg[:1024]
		}
		return fmt.Errorf("burn segment: %w: %s", err, msg)
	}
	return nil
}
