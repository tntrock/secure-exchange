package scan

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/blob"
	"github.com/tntrock/secure-exchange/internal/config"
	"github.com/tntrock/secure-exchange/internal/mail"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
)

const (
	pollInterval = 2 * time.Second
	defaultLease = 30 * time.Minute
	maxAttempts  = 5
	retryDelay   = "30 seconds"
)

// Worker drains the scan queue.
type Worker struct {
	Pool    *pgxpool.Pool
	Store   blob.Store
	Keys    *sxcrypto.Keyring
	Outbox  *mail.Outbox // enqueue only: built with a nil sender, Run never called in the worker
	Audit   *audit.Log
	Cfg     config.ScanConfig
	BaseURL string
	Lease   time.Duration // 0 = 30 minutes
}

// Run scans queued files until ctx ends.
func (w *Worker) Run(ctx context.Context) {
	for ctx.Err() == nil {
		ok, err := w.RunOnce(ctx)
		if err != nil && ctx.Err() == nil {
			slog.Error("scan", "err", err)
		}
		if ok {
			continue
		}
		select {
		case <-ctx.Done():
		case <-time.After(pollInterval):
		}
	}
}

// file is what a scan needs to know about the claimed file.
type file struct {
	id              uuid.UUID
	name, key       string
	size            int64
	wrapped         []byte
	keyID, attempts int
	deleted         bool
	owner, uploader string
	requestID       uuid.UUID
}

// RunOnce claims and scans one file; false means the queue is empty.
func (w *Worker) RunOnce(ctx context.Context) (bool, error) {
	lease := w.Lease
	if lease == 0 {
		lease = defaultLease
	}
	f := &file{}
	err := w.Pool.QueryRow(ctx, `UPDATE scan_jobs SET attempts = attempts + 1, lease_until = now() + make_interval(secs => $1)
		WHERE file_id = (SELECT file_id FROM scan_jobs
		  WHERE lease_until IS NULL OR lease_until < now()
		  ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED)
		RETURNING file_id, attempts`, lease.Seconds()).Scan(&f.id, &f.attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := w.Pool.QueryRow(ctx, `SELECT f.name, f.size, f.wrapped_dek, f.key_id, f.storage_key, f.deleted_at IS NOT NULL,
			o.email, COALESCE(f.request_id, '00000000-0000-0000-0000-000000000000'), COALESCE(u.email, '')
		FROM files f JOIN users o ON o.id = f.owner_id LEFT JOIN request_uploaders u ON u.id = f.uploader_id
		WHERE f.id = $1`, f.id).Scan(&f.name, &f.size, &f.wrapped, &f.keyID, &f.key, &f.deleted, &f.owner, &f.requestID, &f.uploader); err != nil {
		return true, w.retry(ctx, f, err)
	}
	if f.deleted {
		return true, w.finish(ctx, f, "", "") // finish drops the job of a deleted file
	}
	if f.size > w.Cfg.MaxBytes {
		return true, w.finish(ctx, f, "skipped", "")
	}
	// the scan must end before the lease does, or another worker may claim the file meanwhile
	sctx, cancel := context.WithTimeout(ctx, lease-time.Minute)
	defer cancel()
	v, err := w.scan(sctx, f)
	switch {
	case ctx.Err() != nil:
		return true, ctx.Err() // shutting down: the lease expires and the job is retried
	case errors.Is(err, ErrUnavailable):
		_, err = w.Pool.Exec(ctx, `UPDATE scan_jobs SET attempts = attempts - 1, lease_until = now() + interval '`+retryDelay+`' WHERE file_id = $1 AND attempts = $2`, f.id, f.attempts)
		return true, err
	case err != nil:
		slog.Warn("scan: attempt failed", "file", f.id, "attempt", f.attempts, "err", err)
		return true, w.retry(ctx, f, err)
	case v.Infected:
		return true, w.finish(ctx, f, "infected", v.Signature)
	}
	return true, w.finish(ctx, f, "clean", "")
}

// scan streams the decrypted file to clamd; the plaintext lives only in memory on the way.
func (w *Worker) scan(ctx context.Context, f *file) (Verdict, error) {
	dek, err := w.Keys.UnwrapDEK(f.wrapped, f.keyID)
	if err != nil {
		return Verdict{}, err
	}
	src := sxcrypto.OpenPlain(ctx, func(ctx context.Context, off, length int64) (io.ReadCloser, error) {
		return w.Store.OpenRange(ctx, f.key, off, length)
	}, dek, f.id, f.size)
	defer src.Close()
	return Scan(ctx, w.Cfg.ClamdAddr, src)
}

// retry backs the job off, or fails the file with err once attempts are used up.
func (w *Worker) retry(ctx context.Context, f *file, err error) error {
	if f.attempts >= maxAttempts {
		return w.finish(ctx, f, "error", cleanMsg(err.Error()))
	}
	_, err = w.Pool.Exec(ctx, `UPDATE scan_jobs SET lease_until = now() + interval '`+retryDelay+`' WHERE file_id = $1 AND attempts = $2`, f.id, f.attempts)
	return err
}

// finish records the final status, drops the job and enqueues the notices in one transaction. A file
// deleted in the meantime only loses its job. status "" means the file is known to be deleted.
func (w *Worker) finish(ctx context.Context, f *file, status, result string) error {
	tx, err := w.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var deleted bool
	if err := tx.QueryRow(ctx, `SELECT deleted_at IS NOT NULL FROM files WHERE id = $1 FOR UPDATE`, f.id).Scan(&deleted); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM scan_jobs WHERE file_id = $1 AND attempts = $2`, f.id, f.attempts)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 { // re-claimed by another worker: its attempt records the result
		return nil
	}
	if deleted {
		return tx.Commit(ctx)
	}
	if _, err := tx.Exec(ctx, `UPDATE files SET scan_status = $2, scan_result = $3 WHERE id = $1`, f.id, status, result); err != nil {
		return err
	}
	to, subject, body := []string{f.owner}, "", ""
	var adminBody string // admins cannot open the owner's request page, so their copy has no link
	url := w.BaseURL + "/requests/" + f.requestID.String()
	switch status {
	case "clean", "skipped":
		subject, body = mail.NotifyIntakeUpload(f.uploader, f.name, url, status == "skipped")
	case "infected":
		subject, body = mail.NotifyInfected(f.uploader, f.name, result, url)
		_, adminBody = mail.NotifyInfected(f.uploader, f.name, result, "")
		rows, err := tx.Query(ctx, `SELECT email FROM users WHERE role = 'admin' AND NOT disabled ORDER BY email`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var e string
			if err := rows.Scan(&e); err != nil {
				rows.Close()
				return err
			}
			to = append(to, e)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
	case "error":
		subject, body = mail.NotifyScanError(f.uploader, f.name, url)
	}
	seen := map[string]bool{}
	for i, addr := range to {
		if k := strings.ToLower(addr); !seen[k] {
			seen[k] = true
			b := body
			if i > 0 && adminBody != "" { // to[0] is the owner
				b = adminBody
			}
			if err := w.Outbox.Enqueue(ctx, tx, mail.Message{To: addr, Subject: subject, Body: b}); err != nil {
				return err
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	ev := audit.Event{ActorType: "system", ActorID: "scanner", Action: audit.ActFileScan, TargetType: "file", TargetID: f.id.String(), Result: status}
	if status == "infected" {
		ev.Detail = map[string]any{"signature": result}
	}
	if err := w.Audit.Append(ctx, ev); err != nil {
		slog.Error("scan: audit", "file", f.id, "err", err)
	}
	return nil
}

// cleanMsg makes an error text safe to store: valid UTF-8, no NULs, at most 200 runes.
func cleanMsg(msg string) string {
	msg = strings.ReplaceAll(strings.ToValidUTF8(msg, "�"), "\x00", "")
	if utf8.RuneCountInString(msg) > 200 {
		msg = string([]rune(msg)[:200])
	}
	return msg
}
