package preview

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tntrock/secure-exchange/internal/blob"
	"github.com/tntrock/secure-exchange/internal/config"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
)

// errTooLarge marks a pipeline error that ends the preview as too_large.
var errTooLarge = errors.New("preview: over the preview limit")

var errInternal = errors.New("internal error")

const (
	pollInterval  = 2 * time.Second
	renewInterval = 60 * time.Second
	defaultLease  = 5 * time.Minute
)

// putFunc stores one plaintext artifact of exactly size bytes.
type putFunc func(kind string, idx int, r io.Reader, size int64, meta Item) error

// jobEnv is what a pipeline works with: the decrypted input at in, inside the work dir.
type jobEnv struct {
	ctx     context.Context
	cfg     config.PreviewConfig
	dir, in string
	put     putFunc
}

type pipeline func(*jobEnv) (Result, error)

var pipelines = map[Kind]pipeline{KindPages: docPipeline, KindImage: imagePipeline}

// Worker drains the render queue.
type Worker struct {
	Pool    *pgxpool.Pool
	Store   blob.Store
	Keys    *sxcrypto.Keyring
	Cfg     config.PreviewConfig
	Sandbox Sandbox
	Lease   time.Duration // 0 = 5 minutes
}

// Run processes jobs until ctx ends.
func (w *Worker) Run(ctx context.Context) {
	if w.Lease == 0 {
		w.Lease = defaultLease
	}
	for ctx.Err() == nil {
		j, err := Claim(ctx, w.Pool, w.Lease)
		if err != nil && ctx.Err() == nil {
			slog.Error("preview: claim", "err", err)
		}
		if j == nil {
			select {
			case <-ctx.Done():
			case <-time.After(pollInterval):
			}
			continue
		}
		w.runJob(ctx, j)
	}
}

// runJob renders one job while renewing its lease, then records the outcome.
func (w *Worker) runJob(ctx context.Context, j *Job) {
	jctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var lost atomic.Bool
	stop, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		t := time.NewTicker(renewInterval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				if err := Renew(jctx, w.Pool, j, w.Lease); errors.Is(err, ErrLeaseLost) {
					lost.Store(true)
					cancel()
					return
				} else if err != nil && jctx.Err() == nil {
					slog.Error("preview: renew lease", "job", j.ID, "err", err)
				}
			}
		}
	}()
	res, err := w.process(jctx, j)
	close(stop)
	<-stopped
	switch {
	case lost.Load():
		slog.Warn("preview: lease lost, result dropped", "job", j.ID)
		return
	case ctx.Err() != nil:
		return // shutting down: the lease expires and the job is retried
	}
	if err == nil {
		err = w.complete(ctx, j, res)
		if err == nil {
			return
		}
	}
	status := StatusFailed
	if errors.Is(err, errTooLarge) {
		status = StatusTooLarge
	}
	slog.Info("preview: job failed", "job", j.ID, "file", j.FileID, "status", status, "err", err)
	if ferr := Fail(ctx, w.Pool, j, status, err.Error()); ferr != nil {
		slog.Error("preview: record failure", "job", j.ID, "err", ferr)
	}
}

// complete marks the job done unless the file was deleted meanwhile.
func (w *Worker) complete(ctx context.Context, j *Job, res Result) error {
	var deleted bool
	if err := w.Pool.QueryRow(ctx, `SELECT deleted_at IS NOT NULL FROM files WHERE id = $1`, j.FileID).Scan(&deleted); err != nil {
		return err
	}
	if deleted {
		if err := DeleteItems(ctx, w.Pool, w.Store, j.FileID); err != nil {
			return err
		}
		return errors.New("file deleted")
	}
	if err := Complete(ctx, w.Pool, j, res); err != nil {
		slog.Error("preview: complete", "job", j.ID, "err", err)
		if errors.Is(err, ErrLeaseLost) {
			return nil // another attempt owns the job now
		}
		return err
	}
	return nil
}

var safeExt = regexp.MustCompile(`^\.[a-z0-9]{1,10}$`)

// process decrypts the file and runs its pipeline; a panic becomes errInternal.
func (w *Worker) process(ctx context.Context, j *Job) (res Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("preview: pipeline panic", "job", j.ID, "panic", r, "stack", string(debug.Stack()))
			res, err = Result{}, errInternal
		}
	}()
	var (
		name, key string
		size      int64
		wrapped   []byte
		keyID     int
		kind      Kind
	)
	if err := w.Pool.QueryRow(ctx, `SELECT f.name, f.size, f.wrapped_dek, f.key_id, f.storage_key, p.kind
		FROM files f JOIN file_previews p ON p.file_id = f.id WHERE f.id = $1`, j.FileID).
		Scan(&name, &size, &wrapped, &keyID, &key, &kind); err != nil {
		return Result{}, err
	}
	p := pipelines[kind]
	if p == nil {
		return Result{}, fmt.Errorf("no pipeline for kind %q", kind)
	}
	dek, err := w.Keys.UnwrapDEK(wrapped, keyID)
	if err != nil {
		return Result{}, err
	}
	src := sxcrypto.OpenPlain(ctx, func(ctx context.Context, off, length int64) (io.ReadCloser, error) {
		return w.Store.OpenRange(ctx, key, off, length)
	}, dek, j.FileID, size)
	defer src.Close()
	ext := strings.ToLower(filepath.Ext(name))
	if !safeExt.MatchString(ext) {
		ext = ""
	}
	put := func(kind string, idx int, r io.Reader, size int64, meta Item) error {
		_, err := PutItem(ctx, w.Pool, w.Store, w.Keys, j.FileID, kind, idx, r, size, meta)
		return err
	}
	return w.render(ctx, p, ext, src, put)
}

// render writes src to a fresh work dir as in<ext> and runs p there; the dir is
// removed afterwards, also on error or panic.
func (w *Worker) render(ctx context.Context, p pipeline, ext string, src io.Reader, put putFunc) (Result, error) {
	dir, cleanup, err := w.Sandbox.NewDir()
	defer cleanup()
	if err != nil {
		return Result{}, err
	}
	in := filepath.Join(dir, "in"+ext)
	f, err := os.OpenFile(in, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return Result{}, err
	}
	_, err = io.Copy(f, src)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return Result{}, fmt.Errorf("decrypt input: %w", err)
	}
	return p(&jobEnv{ctx: ctx, cfg: w.Cfg, dir: dir, in: in, put: put})
}
