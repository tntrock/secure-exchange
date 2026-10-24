package sxcrypto

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const rotateBatch = 500

// RotateAll re-wraps every files/uploads DEK and re-seals users.totp_secret_sealed
// and uploads.hash_state under the active key. Rows already on the active key
// are skipped. Returns the number of values rewritten. File contents are untouched.
const maxRotatePasses = 3

// afterPass is a test hook, called after each full pass.
var afterPass func(pass int)

// RotateAll re-wraps every uploads/files DEK and re-seals users.totp_secret_sealed
// and uploads.hash_state under the active key. Values already on the active key
// are skipped. Returns the number of values rewritten. File contents are untouched.
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

func rotatePass(ctx context.Context, pool *pgxpool.Pool, keys *Keyring) (int, error) {
	total := 0
	for _, t := range []string{"uploads", "files"} {
		n, err := rotateDEKs(ctx, pool, keys, t)
		total += n
		if err != nil {
			return total, fmt.Errorf("rotate %s.wrapped_dek: %w", t, err)
		}
	}
	for _, s := range []struct{ table, col, aad string }{
		{"users", "totp_secret_sealed", "totp:"},
		{"uploads", "hash_state", "uploadhash:"},
	} {
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
	prefix := binary.BigEndian.AppendUint32(nil, uint32(keys.ActiveID()))
	var files, uploads, totp, hash int
	err := pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM files WHERE key_id <> $1),
		(SELECT count(*) FROM uploads WHERE key_id <> $1),
		(SELECT count(*) FROM users WHERE totp_secret_sealed IS NOT NULL AND substring(totp_secret_sealed from 1 for 4) <> $2),
		(SELECT count(*) FROM uploads WHERE substring(hash_state from 1 for 4) <> $2)`,
		keys.ActiveID(), prefix).Scan(&files, &uploads, &totp, &hash)
	if err != nil {
		return "", err
	}
	if files+uploads+totp+hash == 0 {
		return "", nil
	}
	return fmt.Sprintf("files=%d uploads=%d totp=%d hash_state=%d", files, uploads, totp, hash), nil
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
