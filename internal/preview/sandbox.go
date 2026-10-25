package preview

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"time"
)

// ErrTimeout means an external program ran past its time limit and was killed.
var ErrTimeout = errors.New("preview: external program timed out")

// outputTail is how much of a program's combined stdout+stderr Run keeps.
const outputTail = 4 << 10

// Sandbox hands out per-job work directories under Root (a tmpfs: plaintext lives only there).
type Sandbox struct{ Root string }

// NewDir creates a fresh 0700 directory under Root; the caller must defer cleanup.
func (s Sandbox) NewDir() (dir string, cleanup func(), err error) {
	dir, err = os.MkdirTemp(s.Root, "job-") // MkdirTemp uses 0700
	if err != nil {
		return "", func() {}, err
	}
	return dir, func() { os.RemoveAll(dir) }, nil
}

// Run executes name in dir with an empty environment (PATH, HOME=dir), killing
// it (and on unix its whole process group) after timeout. It returns the last
// 4 KiB of combined output.
func Run(ctx context.Context, dir string, timeout time.Duration, name string, args ...string) ([]byte, error) {
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(tctx, name, args...)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir}
	out := &tail{}
	cmd.Stdout, cmd.Stderr = out, out
	cmd.WaitDelay = 5 * time.Second
	isolate(cmd)
	err := cmd.Run()
	reap(cmd)
	if tctx.Err() != nil {
		if ctx.Err() != nil {
			return out.buf, ctx.Err()
		}
		return out.buf, ErrTimeout
	}
	return out.buf, err
}

// tail keeps the last outputTail bytes written to it. exec serializes writes
// when Stdout and Stderr are the same writer.
type tail struct{ buf []byte }

func (t *tail) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if len(t.buf) > outputTail {
		t.buf = append(t.buf[:0], t.buf[len(t.buf)-outputTail:]...)
	}
	return len(p), nil
}
