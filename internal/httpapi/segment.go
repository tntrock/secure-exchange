package httpapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/tntrock/secure-exchange/internal/preview"
)

const burnTimeout = 30 * time.Second

// burnSlots bounds concurrent ffmpeg burns to one per CPU.
// ponytail: per-process semaphore, single node only; share it (or pre-render) when scaling out
var burnSlots = make(chan struct{}, runtime.NumCPU())

// burnWait is how long a request waits for a burn slot before it gets 503 busy (a var for tests).
var burnWait = 3 * time.Second

// errBusy means every burn slot stayed taken for burnWait (or until the request ended).
var errBusy = errors.New("burn segment: busy")

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
	// the request ctx ends only on disconnect (no server WriteTimeout), so the wait has its own bound
	timer := time.NewTimer(burnWait)
	defer timer.Stop()
	select {
	case burnSlots <- struct{}{}:
		defer func() { <-burnSlots }()
	case <-ctx.Done():
		return errBusy
	case <-timer.C:
		return errBusy
	}
	// ffmpeg's fontconfig lookup would silently substitute another font for a missing file
	if _, err := os.Stat(s.FontFile); err != nil {
		return fmt.Errorf("burn segment: font: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, burnTimeout)
	defer cancel()
	dt := "drawtext=fontfile=" + filterQuote(s.FontFile) + ":text=" + drawtextEscape(m.Text()) +
		":fontsize=h/22:fontcolor=white@0.22:x=max((w-tw)/2\\,0):y=" // max: long text keeps its left end (the trace code); \, escapes the graph's filter separator
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
