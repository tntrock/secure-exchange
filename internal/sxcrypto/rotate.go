package sxcrypto

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const rotateBatch = 500

// maxRotatePasses bounds how often RotateAll repeats while old-key values remain.
const maxRotatePasses = 3

// afterPass is a test hook, called after each full pass.
var afterPass func(pass int)

// RotateAll moves every master-key-protected value to the active key: it re-wraps
// the wrapped_dek of every row in dekTables (uploads, files, preview_items) and
// re-seals every column in sealedCols (users.totp_secret_sealed, uploads.hash_state,
// mail_outbox.body_sealed, shares.token_sealed). Values already on the active key
// are skipped. Returns the number of values rewritten. Blob contents (files and
// preview artifacts) are untouched: only the DEKs that encrypt them change.
//
// Uploads are rotated before files so an upload finishing mid-run (which copies
// its DEK into files) is caught by the files step or the residual check; the
// run repeats up to maxRotatePasses times until nothing old remains.
func RotateAll(ctx context.Context, pool *pgxpool.Pool, keys *Keyring) (int, error) {
	total := 0
	for pass := 1; ; pass++ {
		n, err := rotatePass(ctx, pool, keys)
		total += n
		if err != nil {
			return total, err
		}
		if afterPass != nil {
			afterPass(pass)
		}
		left, err := residual(ctx, pool, keys)
		if err != nil {
			return total, err
		}
		if left == "" {
			return total, nil
		}
		if pass == maxRotatePasses {
			return total, fmt.Errorf("rotate: values still on old keys after %d passes (%s); stop writers and retry", pass, left)
		}
	}
}

// sealedCols lists every Seal-ed column (aad = prefix + row id); rotation and residual share it.
var sealedCols = []struct{ table, col, aad string }{
	{"users", "totp_secret_sealed", "totp:"},
	{"uploads", "hash_state", "uploadhash:"},
	{"mail_outbox", "body_sealed", "mail:"},
	{"shares", "token_sealed", "sharetoken:"},
}

// dekTables lists every table with wrapped_dek/key_id columns; uploads first so a finishing upload is caught later.
var dekTables = []string{"uploads", "files", "preview_items"}

func rotatePass(ctx context.Context, pool *pgxpool.Pool, keys *Keyring) (int, error) {
	total := 0
	for _, t := range dekTables {
		n, err := rotateDEKs(ctx, pool, keys, t)
		total += n
		if err != nil {
			return total, fmt.Errorf("rotate %s.wrapped_dek: %w", t, err)
		}
	}
	for _, s := range sealedCols {
		n, err := rotateSealed(ctx, pool, keys, s.table, s.col, s.aad)
		total += n
		if err != nil {
			return total, fmt.Errorf("rotate %s.%s: %w", s.table, s.col, err)
		}
	}
	return total, nil
}

// residual describes values not on the active key ("" when none).
func residual(ctx context.Context, pool *pgxpool.Pool, keys *Keyring) (string, error) {
	prefix := binary.BigEndian.AppendUint32(nil, uint32(keys.ActiveID())) //nolint:gosec // G115: key ids are validated positive and small at parse
	desc, total := "", 0
	for _, t := range dekTables {
		var n int
		if err := pool.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %s WHERE key_id <> $1`, t), keys.ActiveID()).Scan(&n); err != nil {
			return "", err
		}
		desc += fmt.Sprintf("%s=%d ", t, n)
		total += n
	}
	desc = strings.TrimSuffix(desc, " ")
	for _, s := range sealedCols {
		var n int
		if err := pool.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %s WHERE %s IS NOT NULL AND substring(%s from 1 for 4) <> $1`, s.table, s.col, s.col), prefix).Scan(&n); err != nil {
			return "", err
		}
		desc += fmt.Sprintf(" %s.%s=%d", s.table, s.col, n)
		total += n
	}
	if total == 0 {
		return "", nil
	}
	return desc, nil
}

// batch runs fn in a tx; table/column names come from constants above.
func batch(ctx context.Context, pool *pgxpool.Pool, fn func(pgx.Tx) (int, error)) (int, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	n, err := fn(tx)
	if err != nil {
		return 0, err
	}
	return n, tx.Commit(ctx)
}

func rotateDEKs(ctx context.Context, pool *pgxpool.Pool, keys *Keyring, table string) (int, error) {
	total := 0
	for {
		n, err := batch(ctx, pool, func(tx pgx.Tx) (int, error) {
			rows, err := tx.Query(ctx, fmt.Sprintf(
				`SELECT id, wrapped_dek, key_id FROM %s WHERE key_id <> $1 ORDER BY id LIMIT %d FOR UPDATE`,
				table, rotateBatch), keys.ActiveID())
			if err != nil {
				return 0, err
			}
			type row struct {
				id      uuid.UUID
				wrapped []byte
				keyID   int
			}
			var got []row
			for rows.Next() {
				var r row
				if err := rows.Scan(&r.id, &r.wrapped, &r.keyID); err != nil {
					return 0, err
				}
				got = append(got, r)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return 0, err
			}
			for _, r := range got {
				dek, err := keys.UnwrapDEK(r.wrapped, r.keyID)
				if err != nil {
					return 0, fmt.Errorf("row %s: %w", r.id, err)
				}
				w, kid, err := keys.WrapDEK(dek)
				if err != nil {
					return 0, err
				}
				if _, err := tx.Exec(ctx, fmt.Sprintf(`UPDATE %s SET wrapped_dek=$1, key_id=$2 WHERE id=$3`, table), w, kid, r.id); err != nil {
					return 0, err
				}
			}
			return len(got), nil
		})
		if err != nil {
			return total, err
		}
		total += n
		if n == 0 {
			return total, nil
		}
	}
}

// rotateSealed re-seals Seal-ed values; keyset pagination by id, skipping values
// whose key-ID prefix is already active.
func rotateSealed(ctx context.Context, pool *pgxpool.Pool, keys *Keyring, table, col, aadPrefix string) (int, error) {
	total, last := 0, uuid.Nil
	for {
		n, done, err := func() (int, bool, error) {
			var n int
			var done bool
			n, err := batch(ctx, pool, func(tx pgx.Tx) (int, error) {
				rows, err := tx.Query(ctx, fmt.Sprintf(
					`SELECT id, %s FROM %s WHERE %s IS NOT NULL AND id > $1 ORDER BY id LIMIT %d FOR UPDATE`,
					col, table, col, rotateBatch), last)
				if err != nil {
					return 0, err
				}
				type row struct {
					id     uuid.UUID
					sealed []byte
				}
				var got []row
				for rows.Next() {
					var r row
					if err := rows.Scan(&r.id, &r.sealed); err != nil {
						return 0, err
					}
					got = append(got, r)
				}
				rows.Close()
				if err := rows.Err(); err != nil {
					return 0, err
				}
				done = len(got) < rotateBatch
				cnt := 0
				for _, r := range got {
					last = r.id
					if len(r.sealed) >= 4 && int(binary.BigEndian.Uint32(r.sealed)) == keys.ActiveID() {
						continue
					}
					aad := []byte(aadPrefix + r.id.String())
					plain, err := keys.Open(r.sealed, aad)
					if err != nil {
						return 0, fmt.Errorf("row %s: %w", r.id, err)
					}
					s, err := keys.Seal(plain, aad)
					if err != nil {
						return 0, err
					}
					if _, err := tx.Exec(ctx, fmt.Sprintf(`UPDATE %s SET %s=$1 WHERE id=$2`, table, col), s, r.id); err != nil {
						return 0, err
					}
					cnt++
				}
				return cnt, nil
			})
			return n, done, err
		}()
		total += n
		if err != nil {
			return total, err
		}
		if done {
			return total, nil
		}
	}
}
