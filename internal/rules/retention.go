package rules

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/blob"
	"github.com/tntrock/secure-exchange/internal/preview"
)

// RunRetention sweeps every `every` until ctx is done.
func (s *Service) RunRetention(ctx context.Context, store blob.Store, log *audit.Log, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if _, err := s.SweepRetention(ctx, store, log); err != nil {
			slog.Error("retention sweep", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// SweepRetention deletes files whose every share (and request, if any) ended more than RetentionDays ago.
// Files never shared and not received through a request are kept. Returns the number of files deleted.
func (s *Service) SweepRetention(ctx context.Context, store blob.Store, log *audit.Log) (int, error) {
	r, err := s.Get(ctx)
	if err != nil || r.RetentionDays <= 0 {
		return 0, err
	}
	rows, err := s.pool.Query(ctx, `SELECT f.id FROM files f
		WHERE f.deleted_at IS NULL
		  AND (f.request_id IS NOT NULL OR EXISTS (SELECT 1 FROM share_files WHERE file_id = f.id))
		  AND NOT EXISTS (SELECT 1 FROM share_files sf JOIN shares sh ON sh.id = sf.share_id
		        WHERE sf.file_id = f.id AND coalesce(sh.revoked_at, sh.expires_at) >= now() - make_interval(days => $1))
		  AND (f.request_id IS NULL OR EXISTS (SELECT 1 FROM upload_requests q WHERE q.id = f.request_id
		        AND coalesce(q.revoked_at, q.expires_at) < now() - make_interval(days => $1)))`, r.RetentionDays)
	if err != nil {
		return 0, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return 0, err
	}
	n := 0
	for _, id := range ids {
		var key string
		// claim: only one instance wins the row
		err := s.pool.QueryRow(ctx, `UPDATE files SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL RETURNING storage_key`, id).Scan(&key)
		if err == pgx.ErrNoRows {
			continue
		}
		if err != nil {
			return n, err
		}
		n++
		if err := store.Delete(ctx, key); err != nil {
			slog.Error("retention: delete blob", "file", id, "err", err)
		}
		if err := preview.DeleteItems(ctx, s.pool, store, id); err != nil {
			slog.Error("retention: delete preview items", "file", id, "err", err)
		}
		if err := log.Append(ctx, audit.Event{ActorType: "system", ActorID: "retention", Action: audit.ActRetentionDelete,
			TargetType: "file", TargetID: id.String(), Result: "ok", Detail: map[string]any{"retention_days": r.RetentionDays}}); err != nil {
			slog.Error("retention: audit", "file", id, "err", err)
		}
	}
	return n, nil
}
