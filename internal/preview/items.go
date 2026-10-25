package preview

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tntrock/secure-exchange/internal/blob"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
)

var ErrNoItem = errors.New("preview: no such item")

var errStopped = errors.New("preview: put finished")

// Item is one encrypted preview artifact (a page image, an image, a video segment).
type Item struct {
	ID                 uuid.UUID
	Kind               string
	Idx, Width, Height int
	Size, DurationMs   int64
}

// PutItem streams r (exactly size plaintext bytes) into the blob store sealed
// under a fresh DEK and records the row, replacing any item at (fileID, kind, idx).
// Width/Height/DurationMs come from meta. The storage key is the item id.
func PutItem(ctx context.Context, pool *pgxpool.Pool, store blob.Store, keys *sxcrypto.Keyring, fileID uuid.UUID, kind string, idx int, r io.Reader, size int64, meta Item) (Item, error) {
	dek, wrapped, keyID, err := keys.NewDEK()
	if err != nil {
		return Item{}, err
	}
	id := uuid.New()
	key := id.String()
	count := sxcrypto.ChunkCount(size)

	pr, pw := io.Pipe()
	errc := make(chan error, 1) // the writer's terminal error (nil = whole item sealed and r exhausted)
	go func() {
		buf := make([]byte, sxcrypto.ChunkSize)
		for i := int64(0); i < count; i++ {
			n := min(size-i*sxcrypto.ChunkSize, sxcrypto.ChunkSize)
			if _, err := io.ReadFull(r, buf[:n]); err != nil {
				err = fmt.Errorf("preview: item shorter than %d bytes: %w", size, err)
				pw.CloseWithError(err)
				errc <- err
				return
			}
			if _, err := pw.Write(sxcrypto.SealChunk(dek, id, uint64(i), i == count-1, buf[:n])); err != nil {
				errc <- err
				return
			}
		}
		if n, _ := r.Read(buf[:1]); n > 0 {
			err := fmt.Errorf("preview: item longer than %d bytes", size)
			pw.CloseWithError(err)
			errc <- err
			return
		}
		pw.Close()
		errc <- nil
	}()
	del := func() {
		if err := store.Delete(context.WithoutCancel(ctx), key); err != nil {
			slog.Error("preview: delete partial blob", "key", key, "err", err)
		}
	}
	err = store.Put(ctx, key, pr, size+16*count)
	if err == nil {
		err = errStopped
	}
	pr.CloseWithError(err) // unblock the writer if Put stopped early
	werr := <-errc         // join: r is no longer used after this
	if err == errStopped {
		err = nil
	}
	if err == nil {
		err = werr // Put may succeed on a truncated read (S3 multipart reads exact sizes)
	}
	if err != nil {
		del()
		return Item{}, err
	}

	it := Item{ID: id, Kind: kind, Idx: idx, Width: meta.Width, Height: meta.Height, Size: size, DurationMs: meta.DurationMs}
	oldKey, err := replaceRow(ctx, pool, fileID, it, key, wrapped, keyID)
	if err != nil {
		del()
		return Item{}, err
	}
	if oldKey != "" {
		if err := store.Delete(context.WithoutCancel(ctx), oldKey); err != nil {
			slog.Error("preview: delete replaced blob", "key", oldKey, "err", err)
		}
	}
	return it, nil
}

func replaceRow(ctx context.Context, pool *pgxpool.Pool, fileID uuid.UUID, it Item, key string, wrapped []byte, keyID int) (oldKey string, err error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	err = tx.QueryRow(ctx, `SELECT storage_key FROM preview_items WHERE file_id=$1 AND kind=$2 AND idx=$3 FOR UPDATE`, fileID, it.Kind, it.Idx).Scan(&oldKey)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	if oldKey != "" {
		if _, err := tx.Exec(ctx, `DELETE FROM preview_items WHERE file_id=$1 AND kind=$2 AND idx=$3`, fileID, it.Kind, it.Idx); err != nil {
			return "", err
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO preview_items (id, file_id, kind, idx, storage_key, size, wrapped_dek, key_id, width, height, duration_ms)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, it.ID, fileID, it.Kind, it.Idx, key, it.Size, wrapped, keyID, it.Width, it.Height, it.DurationMs); err != nil {
		return "", err
	}
	return oldKey, tx.Commit(ctx)
}

// OpenItem returns a seekable plaintext view of an item, or ErrNoItem.
func OpenItem(ctx context.Context, pool *pgxpool.Pool, store blob.Store, keys *sxcrypto.Keyring, fileID uuid.UUID, kind string, idx int) (io.ReadSeekCloser, Item, error) {
	var (
		it      Item
		key     string
		wrapped []byte
		keyID   int
	)
	err := pool.QueryRow(ctx, `SELECT id, kind, idx, width, height, size, duration_ms, storage_key, wrapped_dek, key_id
		FROM preview_items WHERE file_id=$1 AND kind=$2 AND idx=$3`, fileID, kind, idx).
		Scan(&it.ID, &it.Kind, &it.Idx, &it.Width, &it.Height, &it.Size, &it.DurationMs, &key, &wrapped, &keyID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, Item{}, ErrNoItem
	}
	if err != nil {
		return nil, Item{}, err
	}
	dek, err := keys.UnwrapDEK(wrapped, keyID)
	if err != nil {
		return nil, Item{}, err
	}
	open := func(ctx context.Context, off, length int64) (io.ReadCloser, error) {
		return store.OpenRange(ctx, key, off, length)
	}
	return sxcrypto.OpenPlain(ctx, open, dek, it.ID, it.Size), it, nil
}

// ListItems returns the items of one kind ordered by idx.
func ListItems(ctx context.Context, pool *pgxpool.Pool, fileID uuid.UUID, kind string) ([]Item, error) {
	rows, err := pool.Query(ctx, `SELECT id, kind, idx, width, height, size, duration_ms
		FROM preview_items WHERE file_id=$1 AND kind=$2 ORDER BY idx`, fileID, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Item
	for rows.Next() {
		var it Item
		if err := rows.Scan(&it.ID, &it.Kind, &it.Idx, &it.Width, &it.Height, &it.Size, &it.DurationMs); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// DeleteItems removes every item row of a file, then its blobs (best-effort, logged).
func DeleteItems(ctx context.Context, pool *pgxpool.Pool, store blob.Store, fileID uuid.UUID) error {
	rows, err := pool.Query(ctx, `DELETE FROM preview_items WHERE file_id=$1 RETURNING storage_key`, fileID)
	if err != nil {
		return err
	}
	keys, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, k := range keys {
		if err := store.Delete(ctx, k); err != nil {
			slog.Error("preview: delete item blob", "key", k, "err", err)
		}
	}
	return nil
}
