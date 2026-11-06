package rules

import (
	"context"
	"errors"
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
	rows, err := s.pool.Query(ctx, `SELECT f.id FROM files f WHERE f.deleted_at IS NULL AND `+eligible, r.RetentionDays)
	if err != nil {
		return 0, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return 0, err
	}
	afterCandidates()
	n := 0
	for _, id := range ids {
		key, ok, err := s.claim(ctx, id, r.RetentionDays)
		if err != nil {
			return n, err
		}
		if !ok {
			continue
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

// eligible is the retention predicate on files f ($1 = days): shared or received through a request,
// and every share and the request ended more than $1 days ago.
const eligible = `(f.request_id IS NOT NULL OR EXISTS (SELECT 1 FROM share_files WHERE file_id = f.id))
	  AND NOT EXISTS (SELECT 1 FROM share_files sf JOIN shares sh ON sh.id = sf.share_id
	        WHERE sf.file_id = f.id AND least(coalesce(sh.revoked_at, sh.expires_at), sh.expires_at) >= now() - make_interval(days => $1))
	  AND (f.request_id IS NULL OR EXISTS (SELECT 1 FROM upload_requests q WHERE q.id = f.request_id
	        AND least(coalesce(q.revoked_at, q.expires_at), q.expires_at) < now() - make_interval(days => $1)))`

// afterCandidates lets tests act between candidate selection and the claim.
var afterCandidates = func() {}

// claim locks the file row, re-checks eligibility under a fresh snapshot (share.Create takes FOR SHARE on
// the same row, so a concurrent new share either commits first and is seen here, or sees deleted_at), then marks it deleted.
func (s *Service) claim(ctx context.Context, id uuid.UUID, days int) (key string, ok bool, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", false, err
	}
	defer tx.Rollback(ctx)
	if err := tx.QueryRow(ctx, `SELECT storage_key FROM files WHERE id = $1 AND deleted_at IS NULL FOR UPDATE`, id).Scan(&key); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, nil
		}
		return "", false, err
	}
	var still bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM files f WHERE f.id = $2 AND `+eligible+`)`, days, id).Scan(&still); err != nil || !still {
		return "", false, err
	}
	if _, err := tx.Exec(ctx, `UPDATE files SET deleted_at = now() WHERE id = $1`, id); err != nil {
		return "", false, err
	}
	return key, true, tx.Commit(ctx)
}
