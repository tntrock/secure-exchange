// Package upload implements resumable tus 1.0.0 uploads (core, creation,
// termination). Data is sealed chunk by chunk before it reaches the staging
// file, so plaintext never touches disk.
package upload

import (
	"context"
	"crypto/sha256"
	"encoding"
	"encoding/base64"
	"errors"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/blob"
	"github.com/tntrock/secure-exchange/internal/httpapi"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
)

const (
	tusVersion = "1.0.0"
	maxMetaLen = 255 // bytes kept of client-supplied filename / filetype
	// a PATCH that stalls this long between body reads is cut off, freeing its upload lock
	chunkReadTimeout = 60 * time.Second
)

type handler struct {
	pool       *pgxpool.Pool
	keys       *sxcrypto.Keyring
	store      blob.Store
	audit      *audit.Log
	stagingDir string
	maxSize    int64
	trusted    []netip.Prefix
	mux        *http.ServeMux

	// ponytail: in-process lock — single instance only; use a lease column for multi-instance
	mu     sync.Mutex
	active map[uuid.UUID]bool // uploads with a PATCH/DELETE in progress
}

// NewHandler serves the tus endpoint at /api/uploads/. The caller must put
// the user in the request context (auth.WithUser) and create stagingDir.
func NewHandler(pool *pgxpool.Pool, keys *sxcrypto.Keyring, store blob.Store, audit *audit.Log, stagingDir string, maxSize int64, trusted []netip.Prefix) http.Handler {
	h := &handler{pool: pool, keys: keys, store: store, audit: audit, stagingDir: stagingDir, maxSize: maxSize, trusted: trusted, mux: http.NewServeMux(), active: map[uuid.UUID]bool{}}
	h.mux.HandleFunc("OPTIONS /api/uploads/", h.options)
	h.mux.HandleFunc("POST /api/uploads/{$}", h.create)
	h.mux.HandleFunc("HEAD /api/uploads/{id}", h.head)
	h.mux.HandleFunc("PATCH /api/uploads/{id}", h.patch)
	h.mux.HandleFunc("DELETE /api/uploads/{id}", h.delete)
	return h
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Tus-Resumable", tusVersion)
	if r.Method != http.MethodOptions && r.Header.Get("Tus-Resumable") != tusVersion {
		w.Header().Set("Tus-Version", tusVersion)
		w.WriteHeader(http.StatusPreconditionFailed)
		return
	}
	if auth.UserFrom(r.Context()) == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	h.mux.ServeHTTP(w, r)
}

func (h *handler) options(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Tus-Version", tusVersion)
	w.Header().Set("Tus-Extension", "creation,termination")
	w.Header().Set("Tus-Max-Size", strconv.FormatInt(h.maxSize, 10))
	w.WriteHeader(http.StatusNoContent)
}

type upload struct {
	id                uuid.UUID
	owner             uuid.UUID
	name, contentType string
	size, offset      int64
	wrappedDEK        []byte
	keyID             int
	hashState         []byte
}

func (h *handler) stagingPath(id uuid.UUID) string { return filepath.Join(h.stagingDir, id.String()) }

// sealedLen is the ciphertext length of the first off plaintext bytes of a
// size-byte file; off is a chunk boundary or size.
func sealedLen(off, size int64) int64 {
	if off < size {
		return off / sxcrypto.ChunkSize * sxcrypto.SealedChunkSize
	}
	n := sxcrypto.ChunkCount(size)
	return (n-1)*sxcrypto.SealedChunkSize + size - (n-1)*sxcrypto.ChunkSize + 16
}

func fail(w http.ResponseWriter, msg string, err error) {
	slog.Error("upload: "+msg, "err", err)
	w.WriteHeader(http.StatusInternalServerError)
}

// parseMeta decodes tus Upload-Metadata ("key b64,key b64").
func parseMeta(s string) (map[string]string, bool) {
	m := map[string]string{}
	for _, kv := range strings.Split(s, ",") {
		if kv = strings.TrimSpace(kv); kv == "" {
			continue
		}
		k, v, _ := strings.Cut(kv, " ")
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, false
		}
		// text columns reject invalid UTF-8 and NUL
		m[k] = httpapi.Truncate(strings.ReplaceAll(strings.ToValidUTF8(string(b), "�"), "\x00", ""), maxMetaLen)
	}
	return m, true
}

func (h *handler) create(w http.ResponseWriter, r *http.Request) {
	size, err := strconv.ParseInt(r.Header.Get("Upload-Length"), 10, 64)
	if err != nil || size < 0 {
		w.WriteHeader(http.StatusBadRequest) // also covers Upload-Defer-Length, which is unsupported
		return
	}
	if size > h.maxSize {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	meta, ok := parseMeta(r.Header.Get("Upload-Metadata"))
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ctype := meta["filetype"]
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	dek, wrapped, keyID, err := h.keys.NewDEK()
	if err != nil {
		fail(w, "new dek", err)
		return
	}
	u := &upload{id: uuid.New(), owner: auth.UserFrom(r.Context()).ID, name: meta["filename"], contentType: ctype,
		size: size, wrappedDEK: wrapped, keyID: keyID}
	if u.hashState, err = h.sealHash(u.id, sha256.New()); err != nil {
		fail(w, "seal hash state", err)
		return
	}

	f, err := os.OpenFile(h.stagingPath(u.id), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fail(w, "create staging", err)
		return
	}
	if size == 0 { // the single, empty last chunk; offset 0 == size means "complete"
		_, err = f.Write(sxcrypto.SealChunk(dek, u.id, 0, true, nil))
		if err == nil {
			err = f.Sync()
		}
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		_, err = h.pool.Exec(r.Context(), `INSERT INTO uploads (id, owner_id, name, content_type, size, wrapped_dek, key_id, hash_state)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, u.id, u.owner, u.name, u.contentType, u.size, u.wrappedDEK, u.keyID, u.hashState)
	}
	if err != nil {
		os.Remove(h.stagingPath(u.id))
		fail(w, "create", err)
		return
	}
	w.Header().Set("Location", "/api/uploads/"+u.id.String())
	if size == 0 {
		if err := h.finish(r, u, sha256.New()); err != nil {
			fail(w, "finish", err)
			return
		}
		w.Header().Set("X-SX-File-ID", u.id.String())
	}
	w.WriteHeader(http.StatusCreated)
}

// sealHash encrypts the marshalled sha256 state: it carries the unprocessed
// tail of the plaintext (up to 63 bytes) in the clear.
func (h *handler) sealHash(id uuid.UUID, sum hash.Hash) ([]byte, error) {
	state, err := sum.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		return nil, err
	}
	return h.keys.Seal(state, []byte("uploadhash:"+id.String()))
}

func (h *handler) openHash(u *upload) (hash.Hash, error) {
	state, err := h.keys.Open(u.hashState, []byte("uploadhash:"+u.id.String()))
	if err != nil {
		return nil, err
	}
	sum := sha256.New()
	return sum, sum.(encoding.BinaryUnmarshaler).UnmarshalBinary(state)
}

// load returns the caller's upload named in the path, or nil if it does not
// exist or belongs to someone else.
func (h *handler) load(r *http.Request) (*upload, error) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return nil, nil
	}
	u := &upload{id: id}
	err = h.pool.QueryRow(r.Context(), `SELECT owner_id, name, content_type, size, "offset", wrapped_dek, key_id, hash_state
		FROM uploads WHERE id = $1 AND owner_id = $2`, id, auth.UserFrom(r.Context()).ID).
		Scan(&u.owner, &u.name, &u.contentType, &u.size, &u.offset, &u.wrappedDEK, &u.keyID, &u.hashState)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return u, err
}

// tryLock marks id busy so requests on one upload never interleave; false
// means another request holds it. Release with unlock.
func (h *handler) tryLock(id uuid.UUID) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.active[id] {
		return false
	}
	h.active[id] = true
	return true
}

func (h *handler) unlock(id uuid.UUID) {
	h.mu.Lock()
	delete(h.active, id)
	h.mu.Unlock()
}

func (h *handler) head(w http.ResponseWriter, r *http.Request) {
	u, err := h.load(r)
	if err != nil {
		fail(w, "head", err)
		return
	}
	if u == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if u.offset == u.size { // a finish failed earlier: complete it now, or the client would report success with no file
		if !h.tryLock(u.id) {
			w.WriteHeader(http.StatusConflict)
			return
		}
		defer h.unlock(u.id)
		if u, err = h.load(r); err != nil || u == nil { // re-read under the lock
			if err != nil {
				fail(w, "head", err)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
			return
		}
		sum, err := h.openHash(u)
		if err == nil {
			err = h.finish(r, u, sum)
		}
		if err != nil {
			fail(w, "finish", err)
			return
		}
		w.Header().Set("X-SX-File-ID", u.id.String())
	}
	w.Header().Set("Upload-Offset", strconv.FormatInt(u.offset, 10))
	w.Header().Set("Upload-Length", strconv.FormatInt(u.size, 10))
	w.WriteHeader(http.StatusOK)
}

func (h *handler) patch(w http.ResponseWriter, r *http.Request) {
	u, err := h.load(r)
	if err != nil {
		fail(w, "patch", err)
		return
	}
	if u == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if r.Header.Get("Content-Type") != "application/offset+octet-stream" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}
	off, err := strconv.ParseInt(r.Header.Get("Upload-Offset"), 10, 64)
	if err != nil || off < 0 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !h.tryLock(u.id) {
		w.WriteHeader(http.StatusConflict)
		return
	}
	defer h.unlock(u.id)
	if u, err = h.load(r); err != nil || u == nil { // re-read under the lock
		if err != nil {
			fail(w, "patch", err)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
		return
	}
	if off != u.offset || (off%sxcrypto.ChunkSize != 0 && off != u.size) {
		w.WriteHeader(http.StatusConflict)
		return
	}

	// DB work must not be lost to a client hanging up after a chunk was appended.
	ctx := context.WithoutCancel(r.Context())
	sum, err := h.openHash(u)
	if err != nil {
		fail(w, "hash state", err)
		return
	}
	rc := http.NewResponseController(w)
	defer rc.SetReadDeadline(time.Time{})
	if err := h.appendChunks(ctx, rc, u, r.Body, sum); err != nil {
		fail(w, "append", err)
		return
	}
	if u.offset == u.size {
		if err := h.finish(r, u, sum); err != nil {
			fail(w, "finish", err)
			return
		}
		w.Header().Set("X-SX-File-ID", u.id.String())
	}
	w.Header().Set("Upload-Offset", strconv.FormatInt(u.offset, 10))
	w.WriteHeader(http.StatusNoContent)
}

// appendChunks seals whole chunks from body onto the staging file, advancing
// u.offset; a trailing partial chunk (body ended early) is discarded.
func (h *handler) appendChunks(ctx context.Context, rc *http.ResponseController, u *upload, body io.Reader, sum hash.Hash) error {
	f, err := os.OpenFile(h.stagingPath(u.id), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	// Ciphertext past the DB offset is a chunk written before a crash; drop it
	// so no chunk index is ever sealed twice into stored data.
	want := sealedLen(u.offset, u.size)
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.Size() < want {
		return errors.New("staging file shorter than recorded offset")
	}
	if st.Size() > want {
		if err := f.Truncate(want); err != nil {
			return err
		}
	}
	if _, err := f.Seek(want, io.SeekStart); err != nil {
		return err
	}
	dek, err := h.keys.UnwrapDEK(u.wrappedDEK, u.keyID)
	if err != nil {
		return err
	}
	buf := make([]byte, sxcrypto.ChunkSize)
	for u.offset < u.size {
		n := min(sxcrypto.ChunkSize, u.size-u.offset)
		if err := rc.SetReadDeadline(time.Now().Add(chunkReadTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
			return err
		}
		if _, err := io.ReadFull(body, buf[:n]); err != nil {
			return nil // short or broken body: keep what is committed
		}
		sum.Write(buf[:n])
		next := u.offset + n
		if _, err := f.Write(sxcrypto.SealChunk(dek, u.id, uint64(u.offset/sxcrypto.ChunkSize), next == u.size, buf[:n])); err != nil {
			return err
		}
		if err := f.Sync(); err != nil {
			return err
		}
		state, err := h.sealHash(u.id, sum)
		if err != nil {
			return err
		}
		tag, err := h.pool.Exec(ctx, `UPDATE uploads SET "offset" = $2, hash_state = $3, updated_at = now() WHERE id = $1`, u.id, next, state)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errors.New("upload row vanished")
		}
		u.offset = next
	}
	return nil
}

// finish moves the complete staging file into the blob store and turns the
// upload into a file with the same id.
func (h *handler) finish(r *http.Request, u *upload, sum hash.Hash) error {
	ctx := context.WithoutCancel(r.Context())
	key := u.id.String()
	f, err := os.Open(h.stagingPath(u.id))
	if err != nil {
		return err
	}
	err = h.store.Put(ctx, key, f, sealedLen(u.size, u.size))
	f.Close()
	if err != nil {
		return err
	}
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Re-read the DEK under lock: key rotation may have re-wrapped it since PATCH began.
	if err := tx.QueryRow(ctx, `SELECT wrapped_dek, key_id FROM uploads WHERE id = $1 FOR UPDATE`, u.id).Scan(&u.wrappedDEK, &u.keyID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO files (id, owner_id, name, content_type, size, sha256, wrapped_dek, key_id, storage_key)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, u.id, u.owner, u.name, u.contentType, u.size, sum.Sum(nil), u.wrappedDEK, u.keyID, key); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM uploads WHERE id = $1`, u.id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("upload row vanished")
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if err := os.Remove(h.stagingPath(u.id)); err != nil {
		slog.Error("upload: remove staging", "id", key, "err", err) // the janitor sweeps orphans
	}
	if err := h.audit.Append(ctx, audit.Event{ActorType: "user", ActorID: u.owner.String(),
		IP: httpapi.ClientIP(r, h.trusted), UserAgent: httpapi.UserAgent(r), Action: audit.ActUpload,
		TargetType: "file", TargetID: key, Result: "ok", Detail: map[string]any{"name": u.name, "size": u.size}}); err != nil {
		slog.Error("audit append", "action", audit.ActUpload, "err", err)
	}
	return nil
}

func (h *handler) delete(w http.ResponseWriter, r *http.Request) {
	u, err := h.load(r)
	if err != nil {
		fail(w, "delete", err)
		return
	}
	if u == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if !h.tryLock(u.id) {
		w.WriteHeader(http.StatusConflict)
		return
	}
	defer h.unlock(u.id)
	tag, err := h.pool.Exec(r.Context(), `DELETE FROM uploads WHERE id = $1 AND owner_id = $2`, u.id, u.owner)
	if err != nil {
		fail(w, "delete", err)
		return
	}
	if tag.RowsAffected() == 0 { // completed or deleted while we waited for the lock
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if err := os.Remove(h.stagingPath(u.id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Error("upload: remove staging", "id", u.id, "err", err)
	}
	w.WriteHeader(http.StatusNoContent)
}
