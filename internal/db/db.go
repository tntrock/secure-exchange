// Package db opens the PostgreSQL pool and applies embedded migrations.
package db

import (
	"context"
	"embed"
	"fmt"
	"hash/fnv"
	"io/fs"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Open connects to url, runs all pending migrations and returns the pool.
func Open(ctx context.Context, url string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("db: parse url: %w", err)
	}
	return OpenConfig(ctx, cfg)
}

// OpenConfig is Open with a prepared pool config (used by testdb to set search_path).
func OpenConfig(ctx context.Context, cfg *pgxpool.Config) (*pgxpool.Pool, error) {
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("db: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: ping: %w", err)
	}
	if err := migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}

func migrate(ctx context.Context, pool *pgxpool.Pool) error {
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()
	fsys, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return err
	}
	// Serialize concurrent starts (serve + worker) on one schema; the lock id is per
	// schema so separate schemas (parallel tests) do not wait on each other.
	var schema string
	if err := pool.QueryRow(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		return fmt.Errorf("db: migrate: %w", err)
	}
	h := fnv.New64a()
	h.Write([]byte("secure-exchange migrate " + schema))
	locker, err := lock.NewPostgresSessionLocker(lock.WithLockID(int64(h.Sum64())), lock.WithLockTimeout(1, 300)) //nolint:gosec // G115: wrap-around is fine, any 64-bit lock id works
	if err != nil {
		return err
	}
	p, err := goose.NewProvider(goose.DialectPostgres, sqlDB, fsys, goose.WithSessionLocker(locker))
	if err != nil {
		return fmt.Errorf("db: migrate: %w", err)
	}
	if _, err := p.Up(ctx); err != nil {
		return fmt.Errorf("db: migrate: %w", err)
	}
	return nil
}
