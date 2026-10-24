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
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
	"github.com/tntrock/secure-exchange/internal/upload"
)

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	if cmd != "serve" {
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		os.Exit(2)
	}
	if err := serve(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
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
	go upload.RunJanitor(ctx, pool, cfg.StagingDir, 24*time.Hour)
	handler := httpapi.NewServer(httpapi.Deps{
		Users: users, Sessions: auth.NewSessions(pool), Audit: auditLog,
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
