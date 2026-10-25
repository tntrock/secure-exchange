// Package mailtest reads back mail queued in the outbox, for tests.
package mailtest

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tntrock/secure-exchange/internal/mail"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
)

// Messages returns every outbox row (sent or not), unsealed, oldest first.
func Messages(t testing.TB, pool *pgxpool.Pool, keys *sxcrypto.Keyring) []mail.Message {
	t.Helper()
	rows, err := pool.Query(context.Background(), `SELECT id, to_addr, body_sealed FROM mail_outbox ORDER BY created_at, id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []mail.Message
	for rows.Next() {
		var id uuid.UUID
		var to string
		var sealed []byte
		if err := rows.Scan(&id, &to, &sealed); err != nil {
			t.Fatal(err)
		}
		plain, err := keys.Open(sealed, []byte("mail:"+id.String()))
		if err != nil {
			t.Fatal(err)
		}
		var sm struct{ Subject, Body string }
		if err := json.Unmarshal(plain, &sm); err != nil {
			t.Fatal(err)
		}
		out = append(out, mail.Message{To: to, Subject: sm.Subject, Body: sm.Body})
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}
