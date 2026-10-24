package upload

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tntrock/secure-exchange/internal/blob"
)

// RunJanitor removes abandoned uploads (no progress for maxAge) every 10
// minutes until ctx is done.
func RunJanitor(ctx context.Context, pool *pgxpool.Pool, store blob.Store, stagingDir string, maxAge time.Duration) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		sweep(ctx, pool, store, stagingDir, maxAge)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// sweep deletes stale upload rows with their staging files, then staging
// files older than maxAge that have no row (left by a crash after completion).
func sweep(ctx context.Context, pool *pgxpool.Pool, store blob.Store, stagingDir string, maxAge time.Duration) {
	rows, err := pool.Query(ctx, `DELETE FROM uploads WHERE updated_at < now() - $1::interval RETURNING id`, maxAge)
	if err != nil {
		slog.Error("upload janitor", "err", err)
		return
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		slog.Error("upload janitor", "err", err)
	}
	for _, id := range ids {
		remove(filepath.Join(stagingDir, id.String()))
		// a finish that failed after Put leaves a blob; no files row can claim it once the upload row is gone
		if err := store.Delete(ctx, id.String()); err != nil {
			slog.Error("upload janitor: delete blob", "id", id, "err", err)
		}
	}

	ents, err := os.ReadDir(stagingDir)
	if err != nil {
		slog.Error("upload janitor", "err", err)
		return
	}
	cutoff := time.Now().Add(-maxAge)
	for _, e := range ents {
		id, err := uuid.Parse(e.Name())
		info, ierr := e.Info()
		if err != nil || ierr != nil || !info.ModTime().Before(cutoff) {
			continue
		}
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM uploads WHERE id = $1)`, id).Scan(&exists); err == nil && !exists {
			remove(filepath.Join(stagingDir, e.Name()))
		}
	}
}

func remove(path string) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		slog.Error("upload janitor: remove", "path", path, "err", err)
	}
}
