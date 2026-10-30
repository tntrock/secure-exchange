package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/blob"
	"github.com/tntrock/secure-exchange/internal/config"
	"github.com/tntrock/secure-exchange/internal/db"
	"github.com/tntrock/secure-exchange/internal/httpapi"
	"github.com/tntrock/secure-exchange/internal/mail"
	"github.com/tntrock/secure-exchange/internal/preview"
	"github.com/tntrock/secure-exchange/internal/share"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
	"github.com/tntrock/secure-exchange/internal/upload"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}

// run dispatches a subcommand and returns the process exit code.
func run(ctx context.Context, args []string) int {
	cmd := "serve"
	if len(args) > 0 {
		cmd = args[0]
	}
	cmds := map[string]func(context.Context) error{"serve": serve, "rotate-keys": rotateKeys, "worker": worker}
	f, ok := cmds[cmd]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		return 2
	}
	if err := f(ctx); err != nil {
		slog.Error("fatal", "err", err)
		return 1
	}
	return 0
}

func serve(ctx context.Context) error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	keys, err := sxcrypto.ParseKeyring(cfg.MasterKeys, cfg.ActiveKeyID)
	if err != nil {
		return fmt.Errorf("master keys: %w", err)
	}
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	users := auth.NewUsers(pool, keys)
	if err := users.EnsureInitialAdmin(ctx, cfg.InitAdminEmail, cfg.InitAdminPassword); err != nil {
		return fmt.Errorf("initial admin: %w", err)
	}
	store, err := blob.New(cfg)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.StagingDir, 0o700); err != nil {
		return fmt.Errorf("staging dir: %w", err)
	}
	go func() {
		if n, err := preview.Backfill(ctx, pool, store, keys, cfg.Preview); err != nil {
			slog.Error("preview backfill", "err", err)
		} else {
			slog.Info("preview backfill", "files", n)
		}
	}()
	auditLog := audit.New(pool)
	outbox := mail.NewOutbox(pool, keys, mail.NewSMTP(cfg.SMTP))
	go outbox.Run(ctx)
	go upload.RunJanitor(ctx, pool, store, cfg.StagingDir, 24*time.Hour)
	handler := httpapi.NewServer(httpapi.Deps{
		Users: users, Sessions: auth.NewSessions(pool), Audit: auditLog,
		Pool: pool, Keys: keys, Store: store, Shares: share.NewService(pool, outbox, keys, cfg.BaseURL, cfg.ShareMaxDays),
		TrustedProxies: cfg.TrustedProxies, SessionTTL: cfg.SessionTTL, CodeDelay: 300 * time.Millisecond,
		FontFile: cfg.FontFile,
		Uploads:  upload.NewHandler(pool, keys, store, auditLog, cfg.StagingDir, cfg.MaxFileSize, cfg.TrustedProxies, cfg.Preview),
	})
	srv := &http.Server{Addr: cfg.Listen, Handler: handler, ReadHeaderTimeout: 10 * time.Second}

	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	slog.Info("listening", "addr", cfg.Listen)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// worker drains the preview render queue. SX_WORKER_TMP must already exist (a tmpfs
// mount): it is never created here, so plaintext cannot land on a real disk by accident.
func worker(ctx context.Context) error {
	cfg, err := config.LoadWorker(os.Getenv)
	if err != nil {
		return err
	}
	keys, err := sxcrypto.ParseKeyring(cfg.MasterKeys, cfg.ActiveKeyID)
	if err != nil {
		return fmt.Errorf("master keys: %w", err)
	}
	// non-dumpable: sandboxed children run as this uid and must not read /proc/<pid>/environ (keys)
	if err := preview.NoDump(); err != nil {
		return fmt.Errorf("prctl PR_SET_DUMPABLE: %w", err)
	}
	if cfg.WorkerTmp, err = filepath.Abs(cfg.WorkerTmp); err != nil {
		return fmt.Errorf("SX_WORKER_TMP: %w", err)
	}
	if fi, err := os.Stat(cfg.WorkerTmp); err != nil || !fi.IsDir() {
		return fmt.Errorf("SX_WORKER_TMP %q must be an existing directory (tmpfs)", cfg.WorkerTmp)
	}
	if os.Getenv("SX_WORKER_ALLOW_NON_TMPFS") != "1" {
		if err := preview.CheckTmpfs(cfg.WorkerTmp); err != nil {
			return fmt.Errorf("SX_WORKER_TMP: %w (set SX_WORKER_ALLOW_NON_TMPFS=1 only for development)", err)
		}
	}
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	store, err := blob.New(cfg)
	if err != nil {
		return err
	}
	slog.Info("preview worker started", "tmp", cfg.WorkerTmp)
	(&preview.Worker{Pool: pool, Store: store, Keys: keys, Cfg: cfg.Preview, Sandbox: preview.Sandbox{Root: cfg.WorkerTmp}}).Run(ctx)
	return nil
}

// rotateKeys re-wraps/re-seals all stored secrets under the active master key.
func rotateKeys(ctx context.Context) error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	keys, err := sxcrypto.ParseKeyring(cfg.MasterKeys, cfg.ActiveKeyID)
	if err != nil {
		return fmt.Errorf("master keys: %w", err)
	}
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	n, err := sxcrypto.RotateAll(ctx, pool, keys)
	if err != nil {
		return err
	}
	if err := audit.New(pool).Append(ctx, audit.Event{
		ActorType: "system", ActorID: "rotate-keys", Action: audit.ActKeyRotate,
		TargetType: "keyring", TargetID: fmt.Sprint(keys.ActiveID()), Result: "ok",
		Detail: map[string]any{"count": n, "active_key_id": keys.ActiveID()},
	}); err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	fmt.Printf("rotated %d values to key %d\n", n, keys.ActiveID())
	return nil
}
