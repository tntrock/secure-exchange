package preview

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tntrock/secure-exchange/internal/blob"
	"github.com/tntrock/secure-exchange/internal/config"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
)

// maxAttempts is how many times a job may be claimed before it is failed.
const maxAttempts = 3

var ErrNoPreview = errors.New("preview: no preview row")

// Querier is satisfied by pgx.Tx and *pgxpool.Pool.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type Job struct {
	ID, FileID uuid.UUID
	Attempts   int
}

type Result struct {
	Kind                     Kind
	PageCount, Width, Height int
	DurationMs               int64
}

type Preview struct {
	Kind                     Kind
	Status                   Status
	PageCount, Width, Height int
	DurationMs               int64
}

// Enqueue records the classification of a file; a pending one also gets a render job.
func Enqueue(ctx context.Context, q Querier, fileID uuid.UUID, kind Kind, status Status) error {
	if _, err := q.Exec(ctx, `INSERT INTO file_previews (file_id, kind, status) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, fileID, kind, status); err != nil {
		return err
	}
	if status != StatusPending {
		return nil
	}
	_, err := q.Exec(ctx, `INSERT INTO render_jobs (id, file_id, status) VALUES ($1,$2,'queued') ON CONFLICT DO NOTHING`, uuid.New(), fileID)
	return err
}

// Backfill classifies files that predate previews. Returns how many were added.
func Backfill(ctx context.Context, pool *pgxpool.Pool, store blob.Store, keys *sxcrypto.Keyring, cfg config.PreviewConfig) (int, error) {
	type file struct {
		id        uuid.UUID
		name, key string
		size      int64
		wrapped   []byte
		keyID     int
	}
	rows, err := pool.Query(ctx, `SELECT f.id, f.name, f.size, f.wrapped_dek, f.key_id, f.storage_key FROM files f
		WHERE f.deleted_at IS NULL AND NOT EXISTS (SELECT 1 FROM file_previews p WHERE p.file_id = f.id)`)
	if err != nil {
		return 0, err
	}
	var files []file
	for rows.Next() {
		var f file
		if err := rows.Scan(&f.id, &f.name, &f.size, &f.wrapped, &f.keyID, &f.key); err != nil {
			rows.Close()
			return 0, err
		}
		files = append(files, f)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	n := 0
	for _, f := range files {
		dek, err := keys.UnwrapDEK(f.wrapped, f.keyID)
		if err != nil {
			return n, err
		}
		r := sxcrypto.OpenPlain(ctx, func(ctx context.Context, off, length int64) (io.ReadCloser, error) {
			return store.OpenRange(ctx, f.key, off, length)
		}, dek, f.id, f.size)
		head := make([]byte, min(HeadLen, f.size))
		_, err = io.ReadFull(r, head)
		r.Close()
		if err != nil {
			return n, err
		}
		kind, status := Classify(f.name, head, f.size, cfg)
		if err := Enqueue(ctx, pool, f.id, kind, status); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// Claim leases the next job (queued, or running with an expired lease), or
// returns nil, nil when there is none. Jobs out of attempts are failed.
func Claim(ctx context.Context, pool *pgxpool.Pool, lease time.Duration) (*Job, error) {
	for {
		j, done, err := claimOne(ctx, pool, lease)
		if err != nil || done {
			return j, err
		}
	}
}

// claimOne returns done=false when it only failed an exhausted job and the caller should look again.
func claimOne(ctx context.Context, pool *pgxpool.Pool, lease time.Duration) (*Job, bool, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, true, err
	}
	defer tx.Rollback(ctx)
	j := &Job{}
	err = tx.QueryRow(ctx, `SELECT id, file_id, attempts FROM render_jobs
		WHERE status = 'queued' OR (status = 'running' AND lease_until < now())
		ORDER BY (status = 'queued') DESC, created_at LIMIT 1 FOR UPDATE SKIP LOCKED`).Scan(&j.ID, &j.FileID, &j.Attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, true, nil
	}
	if err != nil {
		return nil, true, err
	}
	if j.Attempts >= maxAttempts {
		if err := fail(ctx, tx, j.ID, j.FileID, StatusFailed, "too many attempts"); err != nil {
			return nil, true, err
		}
		return nil, false, tx.Commit(ctx)
	}
	j.Attempts++
	if _, err := tx.Exec(ctx, `UPDATE render_jobs SET status = 'running', attempts = $2, lease_until = now() + make_interval(secs => $3), updated_at = now() WHERE id = $1`,
		j.ID, j.Attempts, lease.Seconds()); err != nil {
		return nil, true, err
	}
	return j, true, tx.Commit(ctx)
}

func Renew(ctx context.Context, pool *pgxpool.Pool, jobID uuid.UUID, lease time.Duration) error {
	_, err := pool.Exec(ctx, `UPDATE render_jobs SET lease_until = now() + make_interval(secs => $2), updated_at = now() WHERE id = $1 AND status = 'running'`,
		jobID, lease.Seconds())
	return err
}

// Complete marks the preview ready and the job done in one transaction.
func Complete(ctx context.Context, pool *pgxpool.Pool, jobID, fileID uuid.UUID, r Result) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE file_previews SET kind = $2, status = 'ready', page_count = $3, width = $4, height = $5, duration_ms = $6, error = '', updated_at = now() WHERE file_id = $1`,
		fileID, r.Kind, r.PageCount, r.Width, r.Height, r.DurationMs); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE render_jobs SET status = 'done', lease_until = NULL, updated_at = now() WHERE id = $1`, jobID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Fail ends a job with preview status failed or too_large.
func Fail(ctx context.Context, pool *pgxpool.Pool, jobID, fileID uuid.UUID, status Status, msg string) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := fail(ctx, tx, jobID, fileID, status, msg); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func fail(ctx context.Context, q Querier, jobID, fileID uuid.UUID, status Status, msg string) error {
	msg = strings.ReplaceAll(strings.ToValidUTF8(msg, "�"), "\x00", "")
	if utf8.RuneCountInString(msg) > 500 {
		msg = string([]rune(msg)[:500])
	}
	if _, err := q.Exec(ctx, `UPDATE file_previews SET status = $2, error = $3, updated_at = now() WHERE file_id = $1`, fileID, status, msg); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `UPDATE render_jobs SET status = 'failed', error = $2, lease_until = NULL, updated_at = now() WHERE id = $1`, jobID, msg)
	return err
}

func GetStatus(ctx context.Context, q Querier, fileID uuid.UUID) (*Preview, error) {
	p := &Preview{}
	err := q.QueryRow(ctx, `SELECT kind, status, page_count, width, height, duration_ms FROM file_previews WHERE file_id = $1`, fileID).
		Scan(&p.Kind, &p.Status, &p.PageCount, &p.Width, &p.Height, &p.DurationMs)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoPreview
	}
	return p, err
}
