package preview

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tntrock/secure-exchange/internal/blob"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
)

type itemEnv struct {
	pool  *pgxpool.Pool
	store blob.Store
	dir   string
	keys  *sxcrypto.Keyring
	file  uuid.UUID
}

func newItemEnv(t *testing.T) *itemEnv {
	t.Helper()
	pool, owner := newPool(t)
	k := make([]byte, 32)
	rand.Read(k)
	keys, err := sxcrypto.ParseKeyring("1:"+base64.StdEncoding.EncodeToString(k), 1)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store, err := blob.NewLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	return &itemEnv{pool, store, dir, keys, addFile(t, pool, owner, "f", 1, []byte("x"), 1, "")}
}

func (e *itemEnv) put(t *testing.T, idx int, data []byte) Item {
	t.Helper()
	it, err := PutItem(ctx, e.pool, e.store, e.keys, e.file, "page", idx, bytes.NewReader(data), int64(len(data)), Item{Width: 3, Height: 4})
	if err != nil {
		t.Fatal(err)
	}
	return it
}

func (e *itemEnv) blobCount() int {
	ents, _ := os.ReadDir(e.dir)
	return len(ents)
}

func TestPutOpenItemRoundTrip(t *testing.T) {
	e := newItemEnv(t)
	data := make([]byte, 5<<19) // 2.5 MiB
	rand.Read(data)
	it := e.put(t, 0, data)
	if it.Size != int64(len(data)) || it.Width != 3 || it.Kind != "page" {
		t.Fatalf("%+v", it)
	}
	rc, got, err := OpenItem(ctx, e.pool, e.store, e.keys, e.file, "page", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if got.ID != it.ID || got.Height != 4 {
		t.Fatalf("%+v", got)
	}
	all, err := io.ReadAll(rc)
	if err != nil || !bytes.Equal(all, data) {
		t.Fatal("round trip mismatch", err)
	}
	off := int64(1<<20 + 123)
	if _, err := rc.Seek(off, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	mid := make([]byte, 1000)
	if _, err := io.ReadFull(rc, mid); err != nil || !bytes.Equal(mid, data[off:off+1000]) {
		t.Fatal("seek read mismatch", err)
	}
}

func TestItemBlobEncrypted(t *testing.T) {
	e := newItemEnv(t)
	e.put(t, 0, bytes.Repeat([]byte("SECRETPLAINTEXT"), 1000))
	ents, _ := os.ReadDir(e.dir)
	if len(ents) != 1 {
		t.Fatal(len(ents))
	}
	raw, _ := os.ReadFile(filepath.Join(e.dir, ents[0].Name()))
	if bytes.Contains(raw, []byte("SECRETPLAINTEXT")) {
		t.Fatal("plaintext in blob")
	}
}

func TestPutItemReplaces(t *testing.T) {
	e := newItemEnv(t)
	old := e.put(t, 0, []byte("old"))
	nw := e.put(t, 0, []byte("newer"))
	items, err := ListItems(ctx, e.pool, e.file, "page")
	if err != nil || len(items) != 1 || items[0].ID != nw.ID {
		t.Fatalf("%v %+v", err, items)
	}
	if _, err := os.Stat(filepath.Join(e.dir, old.ID.String())); !os.IsNotExist(err) {
		t.Fatal("old blob still there")
	}
	if e.blobCount() != 1 {
		t.Fatal(e.blobCount())
	}
}

func TestPutItemSizeMismatch(t *testing.T) {
	e := newItemEnv(t)
	for _, c := range []struct{ have, claim int }{{10, 20}, {20, 10}} {
		_, err := PutItem(ctx, e.pool, e.store, e.keys, e.file, "page", 0, bytes.NewReader(make([]byte, c.have)), int64(c.claim), Item{})
		if err == nil {
			t.Fatal("want error")
		}
	}
	if items, _ := ListItems(ctx, e.pool, e.file, "page"); len(items) != 0 || e.blobCount() != 0 {
		t.Fatal("leftovers", len(items), e.blobCount())
	}
}

func TestListItemsOrdered(t *testing.T) {
	e := newItemEnv(t)
	e.put(t, 2, []byte("c"))
	e.put(t, 0, []byte("a"))
	e.put(t, 1, []byte("b"))
	items, _ := ListItems(ctx, e.pool, e.file, "page")
	if len(items) != 3 || items[0].Idx != 0 || items[2].Idx != 2 {
		t.Fatalf("%+v", items)
	}
}

func TestDeleteItems(t *testing.T) {
	e := newItemEnv(t)
	e.put(t, 0, []byte("a"))
	e.put(t, 1, []byte("b"))
	if err := DeleteItems(ctx, e.pool, e.store, e.file); err != nil {
		t.Fatal(err)
	}
	if items, _ := ListItems(ctx, e.pool, e.file, "page"); len(items) != 0 || e.blobCount() != 0 {
		t.Fatal("leftovers")
	}
}

func TestOpenItemMissing(t *testing.T) {
	e := newItemEnv(t)
	if _, _, err := OpenItem(ctx, e.pool, e.store, e.keys, e.file, "page", 9); !errors.Is(err, ErrNoItem) {
		t.Fatal(err)
	}
}
