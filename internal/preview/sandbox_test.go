package preview

import (
	"errors"
	"os"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tntrock/secure-exchange/internal/config"
)

func skipWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix-only")
	}
}

func TestRunKillsOnTimeout(t *testing.T) {
	skipWindows(t)
	start := time.Now()
	// the background sleep keeps the output pipe open: only a process-group kill ends it quickly
	_, err := Run(ctx, t.TempDir(), 200*time.Millisecond, "sh", "-c", "sleep 10 & sleep 10")
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %v", d)
	}
}

func TestRunCleanEnv(t *testing.T) {
	skipWindows(t)
	t.Setenv("SX_SECRET_FOR_TEST", "leak")
	dir := t.TempDir()
	out, err := Run(ctx, dir, 5*time.Second, "env")
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		k, v, _ := strings.Cut(l, "=")
		keys = append(keys, k)
		if k == "HOME" && v != dir {
			t.Fatalf("HOME = %q", v)
		}
	}
	sort.Strings(keys)
	if strings.Join(keys, ",") != "HOME,PATH" {
		t.Fatalf("env = %q", out)
	}
}

func TestRunOutputTail(t *testing.T) {
	skipWindows(t)
	out, err := Run(ctx, t.TempDir(), 5*time.Second, "sh", "-c", "head -c 10000 /dev/zero | tr '\\0' a; echo END >&2; exit 3")
	if err == nil || errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v", err)
	}
	if len(out) != 4096 || !strings.HasSuffix(string(out), "END\n") {
		t.Fatalf("len %d tail %q", len(out), out[max(0, len(out)-10):])
	}
}

func TestWorkDirRemovedOnFailure(t *testing.T) {
	root := t.TempDir()
	w := &Worker{Sandbox: Sandbox{Root: root}, Cfg: config.PreviewConfig{}}
	failing := func(_ *jobEnv) (Result, error) { return Result{}, errors.New("boom") }
	if _, err := w.render(ctx, failing, ".png", strings.NewReader("data"), nil); err == nil {
		t.Fatal("want error")
	}
	var sawInput bool
	panicking := func(e *jobEnv) (Result, error) {
		_, err := os.Stat(e.in)
		sawInput = err == nil
		panic("kaboom")
	}
	func() {
		defer func() { recover() }()
		w.render(ctx, panicking, ".png", strings.NewReader("data"), nil)
	}()
	if !sawInput {
		t.Fatal("input file not written")
	}
	if ents, _ := os.ReadDir(root); len(ents) != 0 {
		t.Fatalf("leftover work dirs: %d", len(ents))
	}
}
