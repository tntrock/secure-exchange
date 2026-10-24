package mail

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tntrock/secure-exchange/internal/sxcrypto"
)

// Querier lets callers enqueue inside their own transaction (pgx.Tx and *pgxpool.Pool both fit).
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

type Outbox struct {
	pool   *pgxpool.Pool
	keys   *sxcrypto.Keyring
	sender Sender
	wake   chan struct{}
}

func NewOutbox(pool *pgxpool.Pool, keys *sxcrypto.Keyring, sender Sender) *Outbox {
	return &Outbox{pool: pool, keys: keys, sender: sender, wake: make(chan struct{}, 1)}
}

// Enqueue stores m with its subject and body sealed; To stays in to_addr.
func (o *Outbox) Enqueue(ctx context.Context, q Querier, m Message) error {
	if strings.ContainsAny(m.To, "\r\n") || strings.ContainsAny(m.Subject, "\r\n") {
		return fmt.Errorf("mail: CR/LF in To or Subject")
	}
	id := uuid.New()
	plain, err := json.Marshal(map[string]string{"subject": m.Subject, "body": m.Body})
	if err != nil {
		return err
	}
	sealed, err := o.keys.Seal(plain, []byte("mail:"+id.String()))
	if err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `INSERT INTO mail_outbox (id, to_addr, body_sealed) VALUES ($1,$2,$3)`, id, m.To, sealed); err != nil {
		return err
	}
	select {
	case o.wake <- struct{}{}:
	default:
	}
	return nil
}

// Run delivers due mail every 5 seconds (or right after an Enqueue) until ctx ends.
func (o *Outbox) Run(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		if _, err := o.runOnce(ctx); err != nil && ctx.Err() == nil {
			slog.Error("mail outbox", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-o.wake:
		}
	}
}

func (o *Outbox) runOnce(ctx context.Context) (int, error) {
	tx, err := o.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT id, to_addr, body_sealed, attempts FROM mail_outbox
		WHERE sent_at IS NULL AND attempts < 10 AND next_attempt_at <= now()
		ORDER BY next_attempt_at LIMIT 20 FOR UPDATE SKIP LOCKED`)
	if err != nil {
		return 0, err
	}
	type row struct {
		id       uuid.UUID
		to       string
		sealed   []byte
		attempts int
	}
	var due []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.to, &r.sealed, &r.attempts); err != nil {
			return 0, err
		}
		due = append(due, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	sent := 0
	// Bookkeeping must survive shutdown, or already-delivered mail would be re-sent.
	dctx := context.WithoutCancel(ctx)
	// ponytail: the tx (row locks) is held while sending up to 20 messages; fine for a
	// single instance, move sending out of the tx if mail volume or SMTP latency grows.
	for _, r := range due {
		if ctx.Err() != nil {
			break
		}
		sendErr := o.deliver(ctx, r.id, r.to, r.sealed)
		if sendErr != nil && ctx.Err() != nil {
			break // interrupted by shutdown, not a real failure
		}
		// savepoint, so one failed UPDATE doesn't abort the whole batch
		sp, err := tx.Begin(dctx)
		if err != nil {
			return sent, err
		}
		if sendErr == nil {
			sent++
			_, err = sp.Exec(dctx, `UPDATE mail_outbox SET sent_at = now(), last_error = '' WHERE id = $1`, r.id)
		} else {
			// cut on a rune boundary: Postgres rejects invalid UTF-8
			msg := strings.ToValidUTF8(truncate(sendErr.Error(), 500), "")
			slog.Warn("mail send failed", "id", r.id, "attempts", r.attempts+1, "err", sendErr)
			_, err = sp.Exec(dctx, `UPDATE mail_outbox SET attempts = attempts + 1, last_error = $2,
				next_attempt_at = now() + least(power(2, attempts + 1) * interval '1 minute', interval '6 hours')
				WHERE id = $1`, r.id, msg)
		}
		if err == nil {
			err = sp.Commit(dctx)
		} else {
			sp.Rollback(dctx)
		}
		if err != nil {
			slog.Error("mail outbox bookkeeping failed", "id", r.id, "err", err)
		}
	}
	if err := tx.Commit(dctx); err != nil {
		return sent, err
	}
	// ponytail: 寄送紀錄只留 7 天
	if _, err := o.pool.Exec(dctx, `DELETE FROM mail_outbox WHERE sent_at < now() - interval '7 days'`); err != nil {
		slog.Error("mail outbox cleanup failed", "err", err)
	}
	return sent, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (o *Outbox) deliver(ctx context.Context, id uuid.UUID, to string, sealed []byte) error {
	plain, err := o.keys.Open(sealed, []byte("mail:"+id.String()))
	if err != nil {
		return fmt.Errorf("unseal: %w", err)
	}
	var sm struct{ Subject, Body string }
	if err := json.Unmarshal(plain, &sm); err != nil {
		return err
	}
	return o.sender.Send(ctx, Message{To: to, Subject: sm.Subject, Body: sm.Body})
}
