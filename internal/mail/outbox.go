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
	rows, err := tx.Query(ctx, `SELECT id, to_addr, body_sealed FROM mail_outbox
		WHERE sent_at IS NULL AND attempts < 10 AND next_attempt_at <= now()
		ORDER BY next_attempt_at LIMIT 20 FOR UPDATE SKIP LOCKED`)
	if err != nil {
		return 0, err
	}
	type row struct {
		id     uuid.UUID
		to     string
		sealed []byte
	}
	var due []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.to, &r.sealed); err != nil {
			return 0, err
		}
		due = append(due, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	sent := 0
	// ponytail: the tx (row locks) is held while sending up to 20 messages; fine for a
	// single instance, move sending out of the tx if mail volume or SMTP latency grows.
	for _, r := range due {
		if sendErr := o.deliver(ctx, r.id, r.to, r.sealed); sendErr == nil {
			sent++
			_, err = tx.Exec(ctx, `UPDATE mail_outbox SET sent_at = now(), last_error = '' WHERE id = $1`, r.id)
		} else {
			msg := sendErr.Error()
			if len(msg) > 500 {
				msg = msg[:500]
			}
			_, err = tx.Exec(ctx, `UPDATE mail_outbox SET attempts = attempts + 1, last_error = $2,
				next_attempt_at = now() + least(power(2, attempts + 1) * interval '1 minute', interval '6 hours')
				WHERE id = $1`, r.id, msg)
		}
		if err != nil {
			return 0, err
		}
	}
	// ponytail: 寄送紀錄只留 7 天
	if _, err := tx.Exec(ctx, `DELETE FROM mail_outbox WHERE sent_at < now() - interval '7 days'`); err != nil {
		return 0, err
	}
	return sent, tx.Commit(ctx)
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
