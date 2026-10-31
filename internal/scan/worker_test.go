package scan

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/blob"
	"github.com/tntrock/secure-exchange/internal/config"
	"github.com/tntrock/secure-exchange/internal/db/testdb"
	"github.com/tntrock/secure-exchange/internal/mail"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
)

var ctx = context.Background()

type env struct {
	pool  *pgxpool.Pool
	keys  *sxcrypto.Keyring
	store blob.Store
	w     *Worker
	owner uuid.UUID
	reqID uuid.UUID
	upl   uuid.UUID
}

func newEnv(t *testing.T, clamd string) *env {
	t.Helper()
	pool := testdb.New(t)
	k := make([]byte, 32)
	rand.Read(k)
	keys, err := sxcrypto.ParseKeyring("1:"+base64.StdEncoding.EncodeToString(k), 1)
	if err != nil {
		t.Fatal(err)
	}
	store, err := blob.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e := &env{pool: pool, keys: keys, store: store, owner: uuid.New(), reqID: uuid.New(), upl: uuid.New()}
	e.user(t, e.owner, "owner@example.com", "staff", false)
	if _, err := pool.Exec(ctx, `INSERT INTO upload_requests (id, owner_id, token_hash, token_sealed, expires_at, max_files, max_total_bytes)
		VALUES ($1,$2,'\x01','\x01', now() + interval '1 day', 5, 1000)`, e.reqID, e.owner); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO request_uploaders (id, request_id, email) VALUES ($1,$2,'vendor@example.org')`, e.upl, e.reqID); err != nil {
		t.Fatal(err)
	}
	e.w = &Worker{Pool: pool, Store: store, Keys: keys, Outbox: mail.NewOutbox(pool, keys, nil), Audit: audit.New(pool),
		Cfg: config.ScanConfig{ClamdAddr: clamd, MaxBytes: 1 << 20}, BaseURL: "https://sx.example"}
	return e
}

func (e *env) user(t *testing.T, id uuid.UUID, email, role string, disabled bool) {
	t.Helper()
	if _, err := e.pool.Exec(ctx, `INSERT INTO users (id, email, role, disabled) VALUES ($1,$2,$3,$4)`, id, email, role, disabled); err != nil {
		t.Fatal(err)
	}
}

// file stores plain encrypted like an upload does, as a pending external upload with a scan job.
func (e *env) file(t *testing.T, plain []byte) uuid.UUID {
	t.Helper()
	dek, wrapped, keyID, _ := e.keys.NewDEK()
	id := uuid.New()
	var sealed bytes.Buffer
	n := sxcrypto.ChunkCount(int64(len(plain)))
	for i := int64(0); i < n; i++ {
		chunk := plain[i*sxcrypto.ChunkSize : min(int64(len(plain)), (i+1)*sxcrypto.ChunkSize)]
		sealed.Write(sxcrypto.SealChunk(dek, id, uint64(i), i == n-1, chunk))
	}
	if err := e.store.Put(ctx, id.String(), &sealed, int64(sealed.Len())); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.Exec(ctx, `INSERT INTO files (id, owner_id, name, content_type, size, sha256, wrapped_dek, key_id, storage_key, request_id, uploader_id, scan_status)
		VALUES ($1,$2,'doc.txt','x',$3,'\x00',$4,$5,$6,$7,$8,'pending')`, id, e.owner, len(plain), wrapped, keyID, id.String(), e.reqID, e.upl); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.Exec(ctx, `INSERT INTO scan_jobs (file_id) VALUES ($1)`, id); err != nil {
		t.Fatal(err)
	}
	return id
}

func (e *env) status(t *testing.T, id uuid.UUID) (status, result string) {
	t.Helper()
	if err := e.pool.QueryRow(ctx, `SELECT scan_status, scan_result FROM files WHERE id = $1`, id).Scan(&status, &result); err != nil {
		t.Fatal(err)
	}
	return
}

func (e *env) count(t *testing.T, sql string, args ...any) (n int) {
	t.Helper()
	if err := e.pool.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return
}

// mails returns the recipients and decrypted bodies of the queued mail.
func (e *env) mails(t *testing.T) (to []string, bodies []string) {
	t.Helper()
	rows, err := e.pool.Query(ctx, `SELECT id, to_addr, body_sealed FROM mail_outbox ORDER BY to_addr`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var addr string
		var sealed []byte
		if err := rows.Scan(&id, &addr, &sealed); err != nil {
			t.Fatal(err)
		}
		plain, err := e.keys.Open(sealed, []byte("mail:"+id.String()))
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]string
		json.Unmarshal(plain, &m)
		to, bodies = append(to, addr), append(bodies, m["body"])
	}
	return
}

func (e *env) run(t *testing.T) {
	t.Helper()
	if ok, err := e.w.RunOnce(ctx); err != nil || !ok {
		t.Fatalf("RunOnce: %v %v", ok, err)
	}
}

func TestScanCleanNotifiesOwner(t *testing.T) {
	f := newFakeClamd(t, "stream: OK")
	e := newEnv(t, f.addr)
	id := e.file(t, []byte("hello"))
	e.run(t)
	if s, _ := e.status(t, id); s != "clean" {
		t.Fatal(s)
	}
	if e.count(t, `SELECT count(*) FROM scan_jobs`) != 0 {
		t.Fatal("job left")
	}
	to, bodies := e.mails(t)
	if len(to) != 1 || to[0] != "owner@example.com" || !strings.Contains(bodies[0], "https://sx.example/requests/"+e.reqID.String()) ||
		!strings.Contains(bodies[0], "vendor@example.org") {
		t.Fatalf("%v %v", to, bodies)
	}
	if e.count(t, `SELECT count(*) FROM audit_log WHERE action = 'file.scan' AND actor_type = 'system' AND actor_id = 'scanner' AND target_id = $1 AND result = 'clean'`, id.String()) != 1 {
		t.Fatal("audit row")
	}
	if ok, err := e.w.RunOnce(ctx); ok || err != nil {
		t.Fatalf("empty queue: %v %v", ok, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.total != 5 {
		t.Fatalf("clamd got %d bytes", f.total)
	}
}

func TestScanInfectedNotifiesOwnerAndAdmins(t *testing.T) {
	f := newFakeClamd(t, "stream: Eicar-Test-Signature FOUND")
	e := newEnv(t, f.addr)
	e.user(t, uuid.New(), "a1@example.com", "admin", false)
	e.user(t, uuid.New(), "a2@example.com", "admin", false)
	e.user(t, uuid.New(), "off@example.com", "admin", true)
	e.user(t, uuid.New(), "staff@example.com", "staff", false)
	id := e.file(t, []byte("evil"))
	e.run(t)
	s, r := e.status(t, id)
	if s != "infected" || r != "Eicar-Test-Signature" {
		t.Fatal(s, r)
	}
	to, bodies := e.mails(t)
	if strings.Join(to, ",") != "a1@example.com,a2@example.com,owner@example.com" || !strings.Contains(bodies[0], "Eicar-Test-Signature") {
		t.Fatalf("%v", to)
	}
	var detail string
	e.pool.QueryRow(ctx, `SELECT detail::text FROM audit_log WHERE action = 'file.scan'`).Scan(&detail)
	if !strings.Contains(detail, "Eicar-Test-Signature") {
		t.Fatal(detail)
	}
}

func TestScanInfectedOwnerIsAdminOnce(t *testing.T) {
	f := newFakeClamd(t, "stream: X FOUND")
	e := newEnv(t, f.addr)
	e.pool.Exec(ctx, `UPDATE users SET role = 'admin' WHERE id = $1`, e.owner)
	e.file(t, []byte("evil"))
	e.run(t)
	if to, _ := e.mails(t); len(to) != 1 {
		t.Fatal(to)
	}
}

func TestScanSkippedOverMax(t *testing.T) {
	f := newFakeClamd(t, "stream: OK")
	e := newEnv(t, f.addr)
	e.w.Cfg.MaxBytes = 10
	id := e.file(t, []byte("0123456789a"))
	e.run(t)
	if s, _ := e.status(t, id); s != "skipped" {
		t.Fatal(s)
	}
	if f.connections() != 0 {
		t.Fatal("clamd contacted")
	}
	to, bodies := e.mails(t)
	if len(to) != 1 || !strings.Contains(bodies[0], "not virus-scanned") {
		t.Fatalf("%v %v", to, bodies)
	}
}

func TestScanClamdDownKeepsAttempts(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	e := newEnv(t, addr)
	id := e.file(t, []byte("hello"))
	e.run(t)
	if s, _ := e.status(t, id); s != "pending" {
		t.Fatal(s)
	}
	var attempts int
	var future bool
	e.pool.QueryRow(ctx, `SELECT attempts, lease_until > now() FROM scan_jobs WHERE file_id = $1`, id).Scan(&attempts, &future)
	if attempts != 0 || !future {
		t.Fatal(attempts, future)
	}
	if ok, _ := e.w.RunOnce(ctx); ok {
		t.Fatal("job claimed during backoff")
	}
	if e.count(t, `SELECT count(*) FROM mail_outbox`) != 0 {
		t.Fatal("mail")
	}
}

func TestScanErrorAfterFiveAttempts(t *testing.T) {
	f := newFakeClamd(t, "Something went wrong. ERROR")
	e := newEnv(t, f.addr)
	id := e.file(t, []byte("hello"))
	for i := 1; i <= 5; i++ {
		if s, _ := e.status(t, id); s != "pending" {
			t.Fatalf("attempt %d: %s", i, s)
		}
		e.run(t)
		if i < 5 {
			if _, err := e.pool.Exec(ctx, `UPDATE scan_jobs SET lease_until = now() - interval '1s'`); err != nil {
				t.Fatal(err)
			}
		}
	}
	s, r := e.status(t, id)
	if s != "error" || !strings.Contains(r, "Something went wrong") {
		t.Fatal(s, r)
	}
	if e.count(t, `SELECT count(*) FROM scan_jobs`) != 0 {
		t.Fatal("job left")
	}
	to, _ := e.mails(t)
	if len(to) != 1 || to[0] != "owner@example.com" {
		t.Fatal(to)
	}
}

func TestScanDeletedFile(t *testing.T) {
	f := newFakeClamd(t, "stream: OK")
	e := newEnv(t, f.addr)
	id := e.file(t, []byte("hello"))
	e.pool.Exec(ctx, `UPDATE files SET deleted_at = now() WHERE id = $1`, id)
	e.run(t)
	if s, _ := e.status(t, id); s != "pending" {
		t.Fatal(s)
	}
	if e.count(t, `SELECT count(*) FROM scan_jobs`) != 0 || e.count(t, `SELECT count(*) FROM mail_outbox`) != 0 ||
		e.count(t, `SELECT count(*) FROM audit_log WHERE action = 'file.scan'`) != 0 || f.connections() != 0 {
		t.Fatal("deleted file was processed")
	}
}

func TestCleanMsg(t *testing.T) {
	long := strings.Repeat("é", 300) + "\x00\xff"
	if got := cleanMsg(long); len([]rune(got)) != 200 || !utf8.ValidString(got) || strings.Contains(got, "\x00") {
		t.Fatal(len([]rune(got)))
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	f := newFakeClamd(t, "stream: OK")
	e := newEnv(t, f.addr)
	id := e.file(t, []byte("hello"))
	c, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { e.w.Run(c); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s, _ := e.status(t, id); s == "clean" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
	if s, _ := e.status(t, id); s != "clean" {
		t.Fatal(s)
	}
}

func TestScanMissingBlobRetries(t *testing.T) {
	f := newFakeClamd(t, "stream: OK")
	e := newEnv(t, f.addr)
	id := e.file(t, []byte("hello"))
	e.store.Delete(ctx, id.String())
	e.run(t)
	var attempts int
	var future bool
	e.pool.QueryRow(ctx, `SELECT attempts, lease_until > now() FROM scan_jobs WHERE file_id = $1`, id).Scan(&attempts, &future)
	if s, _ := e.status(t, id); s != "pending" || attempts != 1 || !future {
		t.Fatal(s, attempts, future)
	}
}

func TestScanFileDeletedDuringScan(t *testing.T) {
	f := newFakeClamd(t, "stream: Eicar FOUND")
	e := newEnv(t, f.addr)
	id := e.file(t, []byte("hello"))
	f.onConn = func() { e.pool.Exec(ctx, `UPDATE files SET deleted_at = now() WHERE id = $1`, id) }
	e.run(t)
	if s, _ := e.status(t, id); s != "pending" {
		t.Fatal(s)
	}
	if e.count(t, `SELECT count(*) FROM scan_jobs`) != 0 || e.count(t, `SELECT count(*) FROM mail_outbox`) != 0 ||
		e.count(t, `SELECT count(*) FROM audit_log WHERE action = 'file.scan'`) != 0 {
		t.Fatal("deleted file was recorded")
	}
}

func TestScanBadKeyRetries(t *testing.T) {
	f := newFakeClamd(t, "stream: OK")
	e := newEnv(t, f.addr)
	id := e.file(t, []byte("hello"))
	e.pool.Exec(ctx, `UPDATE files SET wrapped_dek = '\x00' WHERE id = $1`, id)
	e.run(t)
	if s, _ := e.status(t, id); s != "pending" || f.connections() != 0 {
		t.Fatal(s)
	}
}

func TestRunOnceDBError(t *testing.T) {
	e := newEnv(t, "127.0.0.1:1")
	e.pool.Close()
	if _, err := e.w.RunOnce(ctx); err == nil {
		t.Fatal("no error")
	}
}
