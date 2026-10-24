package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/blob"
	"github.com/tntrock/secure-exchange/internal/config"
	"github.com/tntrock/secure-exchange/internal/db"
	"github.com/tntrock/secure-exchange/internal/httpapi"
	"github.com/tntrock/secure-exchange/internal/mail"
	"github.com/tntrock/secure-exchange/internal/share"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
	"github.com/tntrock/secure-exchange/internal/upload"
)

func main() { os.Exit(run(os.Args[1:])) }

// run dispatches a subcommand and returns the process exit code.
func run(args []string) int {
	cmd := "serve"
	if len(args) > 0 {
		cmd = args[0]
	}
	cmds := map[string]func() error{"serve": serve, "rotate-keys": rotateKeys}
	f, ok := cmds[cmd]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		return 2
	}
	if err := f(); err != nil {
		slog.Error("fatal", "err", err)
		return 1
	}
	return 0
}

func serve() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	keys, err := sxcrypto.ParseKeyring(cfg.MasterKeys, cfg.ActiveKeyID)
	if err != nil {
		return fmt.Errorf("master keys: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
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
	auditLog := audit.New(pool)
	outbox := mail.NewOutbox(pool, keys, mail.NewSMTP(cfg.SMTP))
	go outbox.Run(ctx)
	go upload.RunJanitor(ctx, pool, store, cfg.StagingDir, 24*time.Hour)
	handler := httpapi.NewServer(httpapi.Deps{
		Users: users, Sessions: auth.NewSessions(pool), Audit: auditLog,
		Pool: pool, Keys: keys, Store: store, Shares: share.NewService(pool, outbox, keys, cfg.BaseURL, cfg.ShareMaxDays),
		TrustedProxies: cfg.TrustedProxies, SessionTTL: cfg.SessionTTL,
		Uploads: upload.NewHandler(pool, keys, store, auditLog, cfg.StagingDir, cfg.MaxFileSize, cfg.TrustedProxies),
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

// rotateKeys re-wraps/re-seals all stored secrets under the active master key.
func rotateKeys() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	keys, err := sxcrypto.ParseKeyring(cfg.MasterKeys, cfg.ActiveKeyID)
	if err != nil {
		return fmt.Errorf("master keys: %w", err)
	}
	ctx := context.Background()
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
