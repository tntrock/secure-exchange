// Package purge periodically deletes expired sessions, login codes and dead mail.
package purge

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tntrock/secure-exchange/internal/mail"
)

// grace keeps just-expired rows around a day so a late request still gets "expired", not "unknown".
const grace = "24 hours"

// stmts are the DELETEs, keyed by the table name reported in Once's result.
var stmts = []struct{ table, sql string }{
	{"sessions", `DELETE FROM sessions WHERE expires_at < now() - interval '` + grace + `'`},
	{"share_sessions", `DELETE FROM share_sessions WHERE expires_at < now() - interval '` + grace + `'`},
	{"request_sessions", `DELETE FROM request_sessions WHERE expires_at < now() - interval '` + grace + `'`},
	{"share_otps", `DELETE FROM share_otps WHERE expires_at < now() - interval '` + grace + `'`},
	{"request_otps", `DELETE FROM request_otps WHERE expires_at < now() - interval '` + grace + `'`},
	// given-up mail only; sent rows are trimmed by the mailer itself
	{"mail_outbox", `DELETE FROM mail_outbox WHERE sent_at IS NULL AND attempts >= $1 AND created_at < now() - interval '30 days'`},
	{"vendor_share_views", `DELETE FROM vendor_share_views v WHERE NOT EXISTS (
		SELECT 1 FROM shares s WHERE s.id = v.share_id AND s.expires_at >= now() - interval '` + grace + `')`},
}

// Run purges once at start and then every `every` until ctx is done.
func Run(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if n, err := Once(ctx, pool); err != nil {
			log.Error("purge", "err", err)
		} else if len(n) > 0 {
			log.Info("purge", "deleted", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Once runs every DELETE and returns the non-zero deleted counts per table.
func Once(ctx context.Context, pool *pgxpool.Pool) (map[string]int64, error) {
	out := map[string]int64{}
	for _, s := range stmts {
		args := []any{}
		if s.table == "mail_outbox" {
			args = append(args, mail.MaxAttempts)
		}
		tag, err := pool.Exec(ctx, s.sql, args...)
		if err != nil {
			return out, err
		}
		if n := tag.RowsAffected(); n > 0 {
			out[s.table] = n
		}
	}
	return out, nil
}
