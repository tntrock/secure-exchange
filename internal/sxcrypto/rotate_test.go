package sxcrypto_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"

	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/db/testdb"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
)

func b64key(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }

func ring(t *testing.T, spec string, active int) *sxcrypto.Keyring {
	t.Helper()
	r, err := sxcrypto.ParseKeyring(spec, active)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRotateRewrapsAndStillDecrypts(t *testing.T) {
	ctx := context.Background()
	pool := testdb.New(t)
	k1 := ring(t, "1:"+b64key(1), 1)
	k12 := ring(t, "1:"+b64key(1)+",2:"+b64key(2), 2)
	k2 := ring(t, "2:"+b64key(2), 2)

	users := auth.NewUsers(pool, k1)
	u, err := users.Create(ctx, "a@example.com", "A", "staff", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	uri, err := users.BeginTOTP(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	pu, _ := url.Parse(uri)
	secret := pu.Query().Get("secret")
	code, _ := totp.GenerateCode(secret, time.Now())
	if err := users.EnableTOTP(ctx, u.ID, code); err != nil {
		t.Fatal(err)
	}

	// file under key 1
	plain := []byte("hello rotation")
	fid := uuid.New()
	dek, wrapped, kid, err := k1.NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO files (id, owner_id, name, content_type, size, sha256, wrapped_dek, key_id, storage_key)
		VALUES ($1,$2,'f','text/plain',$3,'\x00',$4,$5,'k')`, fid, u.ID, len(plain), wrapped, kid); err != nil {
		t.Fatal(err)
	}
	ct := sxcrypto.SealChunk(dek, fid, 0, true, plain)

	// in-progress upload under key 1 with sealed hash state
	uid := uuid.New()
	_, uw, ukid, _ := k1.NewDEK()
	hs, _ := k1.Seal([]byte("state"), []byte("uploadhash:"+uid.String()))
	if _, err := pool.Exec(ctx, `INSERT INTO uploads (id, owner_id, name, content_type, size, wrapped_dek, key_id, hash_state)
		VALUES ($1,$2,'u','text/plain',10,$3,$4,$5)`, uid, u.ID, uw, ukid, hs); err != nil {
		t.Fatal(err)
	}

	n, err := sxcrypto.RotateAll(ctx, pool, k12)
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 { // file dek, upload dek, totp, hash_state
		t.Fatalf("rotated %d, want 4", n)
	}
	if n, err = sxcrypto.RotateAll(ctx, pool, k12); err != nil || n != 0 {
		t.Fatalf("second run n=%d err=%v, want 0", n, err)
	}

	var bad int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM files WHERE key_id<>2)+(SELECT count(*) FROM uploads WHERE key_id<>2)`).Scan(&bad); err != nil || bad != 0 {
		t.Fatalf("rows not on key 2: %d %v", bad, err)
	}

	// key-2-only keyring reads everything
	var w2 []byte
	var k2id int
	if err := pool.QueryRow(ctx, `SELECT wrapped_dek, key_id FROM files WHERE id=$1`, fid).Scan(&w2, &k2id); err != nil {
		t.Fatal(err)
	}
	dek2, err := k2.UnwrapDEK(w2, k2id)
	if err != nil {
		t.Fatal(err)
	}
	opener := func(_ context.Context, off, length int64) (io.ReadCloser, error) {
		return io.NopCloser(io.NewSectionReader(bytes.NewReader(ct), off, length)), nil
	}
	got, err := io.ReadAll(sxcrypto.OpenPlain(ctx, opener, dek2, fid, int64(len(plain))))
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("read back %q %v", got, err)
	}
	var hs2 []byte
	if err := pool.QueryRow(ctx, `SELECT hash_state FROM uploads WHERE id=$1`, uid).Scan(&hs2); err != nil {
		t.Fatal(err)
	}
	if st, err := k2.Open(hs2, []byte("uploadhash:"+uid.String())); err != nil || string(st) != "state" {
		t.Fatalf("hash_state: %q %v", st, err)
	}
	next, _ := totp.GenerateCode(secret, time.Now().Add(30*time.Second))
	if !auth.NewUsers(pool, k2).CheckTOTP(ctx, u.ID, next) {
		t.Fatal("CheckTOTP failed with key-2-only keyring")
	}
}

func insertOldFile(t *testing.T, pool *pgxpool.Pool, k1 *sxcrypto.Keyring, owner uuid.UUID) {
	t.Helper()
	_, w, kid, _ := k1.NewDEK()
	if _, err := pool.Exec(context.Background(), `INSERT INTO files (id, owner_id, name, content_type, size, sha256, wrapped_dek, key_id, storage_key)
		VALUES ($1,$2,'f','x',0,'\x00',$3,$4,'k')`, uuid.New(), owner, w, kid); err != nil {
		t.Fatal(err)
	}
}

// A key-1 row appearing after a pass (e.g. an old server finishing an upload)
// is picked up by the residual check's follow-up pass.
func TestRotateCatchesRowAppearingMidRun(t *testing.T) {
	ctx := context.Background()
	pool := testdb.New(t)
	k1 := ring(t, "1:"+b64key(1), 1)
	k12 := ring(t, "1:"+b64key(1)+",2:"+b64key(2), 2)
	u, err := auth.NewUsers(pool, k1).Create(ctx, "a@example.com", "A", "staff", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	insertOldFile(t, pool, k1, u.ID)
	sxcrypto.SetAfterPass(func(pass int) {
		if pass == 1 {
			insertOldFile(t, pool, k1, u.ID)
		}
	})
	t.Cleanup(func() { sxcrypto.SetAfterPass(nil) })
	n, err := sxcrypto.RotateAll(ctx, pool, k12)
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v, want 2 nil", n, err)
	}
}

// If old rows keep appearing, RotateAll gives up after 3 passes with an error naming the counts.
func TestRotateErrorsWhenResidualPersists(t *testing.T) {
	ctx := context.Background()
	pool := testdb.New(t)
	k1 := ring(t, "1:"+b64key(1), 1)
	k12 := ring(t, "1:"+b64key(1)+",2:"+b64key(2), 2)
	u, err := auth.NewUsers(pool, k1).Create(ctx, "a@example.com", "A", "staff", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	sxcrypto.SetAfterPass(func(int) { insertOldFile(t, pool, k1, u.ID) })
	t.Cleanup(func() { sxcrypto.SetAfterPass(nil) })
	_, err = sxcrypto.RotateAll(ctx, pool, k12)
	if err == nil || !strings.Contains(err.Error(), "files=1") {
		t.Fatalf("err = %v, want residual error naming files=1", err)
	}
}
