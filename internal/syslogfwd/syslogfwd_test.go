package syslogfwd

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/config"
	"github.com/tntrock/secure-exchange/internal/db/testdb"
)

type msg struct {
	ID   int64  `json:"id"`
	Hash string `json:"hash"`
}

func parseMsg(t *testing.T, b []byte) msg {
	t.Helper()
	i := strings.IndexByte(string(b), '{')
	if !strings.HasPrefix(string(b), "<110>1 ") || i < 0 {
		t.Fatalf("bad message %q", b)
	}
	var m msg
	if err := json.Unmarshal(b[i:], &m); err != nil {
		t.Fatalf("json %q: %v", b[i:], err)
	}
	return m
}

func appendRows(t *testing.T, pool *pgxpool.Pool, n int) {
	t.Helper()
	l := audit.New(pool)
	for i := range n {
		if err := l.Append(context.Background(), audit.Event{ActorType: "user", ActorID: "u", Action: audit.ActLoginOK,
			Result: "ok", Detail: map[string]any{"i": i}}); err != nil {
			t.Fatal(err)
		}
	}
}

type cursor struct {
	last         int64
	lastOK, fail *time.Time
	lastErr      string
}

func readCursor(t *testing.T, pool *pgxpool.Pool) cursor {
	t.Helper()
	var c cursor
	if err := pool.QueryRow(context.Background(), `SELECT last_id, last_ok_at, failing_since, last_error FROM syslog_cursor`).
		Scan(&c.last, &c.lastOK, &c.fail, &c.lastErr); err != nil {
		t.Fatal(err)
	}
	return c
}

func maxID(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	var id int64
	if err := pool.QueryRow(context.Background(), `SELECT max(id) FROM audit_log`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// tcpReader accepts connections on l and sends each octet-counted frame to the returned channel.
func tcpReader(t *testing.T, l net.Listener) <-chan []byte {
	t.Helper()
	ch := make(chan []byte, 100)
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					s, err := r.ReadString(' ')
					if err != nil {
						return
					}
					n, err := strconv.Atoi(strings.TrimSpace(s))
					if err != nil {
						t.Errorf("bad length %q", s)
						return
					}
					b := make([]byte, n)
					if _, err := io.ReadFull(r, b); err != nil {
						return
					}
					ch <- b
				}
			}()
		}
	}()
	return ch
}

func recv(t *testing.T, ch <-chan []byte) []byte {
	t.Helper()
	select {
	case b := <-ch:
		return b
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for a frame")
		return nil
	}
}

func TestFormat(t *testing.T) {
	at := time.Date(2026, 11, 7, 1, 2, 3, 4000, time.UTC)
	e := audit.Entry{ID: 7, At: at, Hash: []byte{0xab, 0xcd}, PrevHash: []byte{1},
		Event: audit.Event{Action: "share.create", Result: "ok", Detail: map[string]any{"a": 1}}}
	out := string(Format(e, "host"))
	if want := "<110>1 2026-11-07T01:02:03.000004Z host secure-exchange - share.create - {"; !strings.HasPrefix(out, want) {
		t.Fatalf("got %q", out)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out[strings.IndexByte(out, '{'):]), &m); err != nil {
		t.Fatal(err)
	}
	if m["id"] != float64(7) || m["hash"] != hex.EncodeToString(e.Hash) || m["prev_hash"] != "01" ||
		m["at"] != "2026-11-07T01:02:03.000004Z" || m["detail"].(map[string]any)["a"] != float64(1) {
		t.Fatalf("json %v", m)
	}
	e.Event.Result = "fail"
	if out := string(Format(e, "")); !strings.HasPrefix(out, "<108>1 2026-11-07T01:02:03.000004Z - secure-exchange ") {
		t.Fatalf("fail/empty host: %q", out)
	}
	e.Event.Result = "denied"
	if out := string(Format(e, "h")); !strings.HasPrefix(out, "<108>1 ") {
		t.Fatalf("denied: %q", out)
	}
	e.Event.Action = ""
	if out := string(Format(e, "h")); !strings.HasPrefix(out, "<108>1 2026-11-07T01:02:03.000004Z h secure-exchange - - - {") {
		t.Fatalf("empty action: %q", out)
	}
	e.Event.Action = strings.Repeat("x", 40)
	if out := string(Format(e, "h")); !strings.Contains(out, " - "+strings.Repeat("x", 32)+" - {") {
		t.Fatalf("long action: %q", out)
	}
}

func TestForwarderTCPOctetCounting(t *testing.T) {
	ctx := context.Background()
	pool := testdb.New(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ch := tcpReader(t, l)
	appendRows(t, pool, 3)
	f := &Forwarder{Pool: pool, Cfg: config.SyslogConfig{Addr: l.Addr().String(), Transport: "tcp"}, Host: "h"}
	defer f.close()
	if n, err := f.Step(ctx); n != 3 || err != nil {
		t.Fatalf("step: %d %v", n, err)
	}
	var ids []int64
	for range 3 {
		ids = append(ids, parseMsg(t, recv(t, ch)).ID)
	}
	if ids[0] >= ids[1] || ids[1] >= ids[2] {
		t.Fatalf("ids %v", ids)
	}
	if c := readCursor(t, pool); c.last != ids[2] || c.lastOK == nil || c.fail != nil {
		t.Fatalf("cursor %+v want %d", c, ids[2])
	}
	// the live conn is reused for the next batch
	appendRows(t, pool, 1)
	if n, err := f.Step(ctx); n != 1 || err != nil {
		t.Fatalf("step2: %d %v", n, err)
	}
	if m := parseMsg(t, recv(t, ch)); m.ID != ids[2]+1 {
		t.Fatalf("id %d", m.ID)
	}
}

func selfSigned(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestForwarderTLSWithCA(t *testing.T) {
	ctx := context.Background()
	pool := testdb.New(t)
	cert, pemBytes := selfSigned(t)
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	ch := tcpReader(t, l)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	appendRows(t, pool, 1)

	bad := &Forwarder{Pool: pool, Cfg: config.SyslogConfig{Addr: l.Addr().String(), Transport: "tls"}}
	if n, err := bad.Step(ctx); n != 0 || err == nil || !strings.Contains(err.Error(), "unknown authority") {
		t.Fatalf("no CA: %d %v", n, err)
	}
	if c := readCursor(t, pool); c.last != 0 || c.fail == nil || !strings.Contains(c.lastErr, "unknown authority") {
		t.Fatalf("cursor %+v", c)
	}

	f := &Forwarder{Pool: pool, Cfg: config.SyslogConfig{Addr: l.Addr().String(), Transport: "tls", CAFile: ca}}
	defer f.close()
	if n, err := f.Step(ctx); n != 1 || err != nil {
		t.Fatalf("with CA: %d %v", n, err)
	}
	if m := parseMsg(t, recv(t, ch)); m.ID != maxID(t, pool) {
		t.Fatalf("id %d", m.ID)
	}

	missing := &Forwarder{Pool: pool, Cfg: config.SyslogConfig{Addr: l.Addr().String(), Transport: "tls", CAFile: ca + ".nope"}}
	appendRows(t, pool, 1)
	if _, err := missing.Step(ctx); err == nil {
		t.Fatal("missing CA file must fail")
	}
}

func TestForwarderUDP(t *testing.T) {
	ctx := context.Background()
	pool := testdb.New(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	appendRows(t, pool, 2)
	f := &Forwarder{Pool: pool, Cfg: config.SyslogConfig{Addr: pc.LocalAddr().String(), Transport: "udp"}, Host: "h"}
	defer f.close()
	if n, err := f.Step(ctx); n != 2 || err != nil {
		t.Fatalf("step: %d %v", n, err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64<<10)
	var prev int64
	for range 2 {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		if m := parseMsg(t, buf[:n]); m.ID <= prev {
			t.Fatalf("id %d after %d", m.ID, prev)
		} else {
			prev = m.ID
		}
	}
}

func TestForwarderResumesAfterOutage(t *testing.T) {
	ctx := context.Background()
	pool := testdb.New(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	appendRows(t, pool, 2)
	cfg := config.SyslogConfig{Addr: addr, Transport: "tcp"}
	f := &Forwarder{Pool: pool, Cfg: cfg}
	defer f.close()
	if n, err := f.Step(ctx); n != 0 || err == nil {
		t.Fatalf("outage step: %d %v", n, err)
	}
	if c := readCursor(t, pool); c.last != 0 || c.fail == nil || c.lastErr == "" {
		t.Fatalf("cursor %+v", c)
	}
	first := readCursor(t, pool).fail
	if _, err := f.Step(ctx); err == nil {
		t.Fatal("still down")
	}
	if c := readCursor(t, pool); !c.fail.Equal(*first) {
		t.Fatalf("failing_since moved: %v -> %v", first, c.fail)
	}

	for i := 0; ; i++ {
		if l, err = net.Listen("tcp", addr); err == nil {
			break
		}
		if i == 50 {
			t.Skipf("cannot re-listen on %s: %v", addr, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	ch := tcpReader(t, l)
	if n, err := f.Step(ctx); n != 2 || err != nil {
		t.Fatalf("recovered step: %d %v", n, err)
	}
	recv(t, ch)
	recv(t, ch)
	if c := readCursor(t, pool); c.last != maxID(t, pool) || c.fail != nil || c.lastErr != "" || c.lastOK == nil {
		t.Fatalf("cursor %+v", c)
	}
	restarted := &Forwarder{Pool: pool, Cfg: cfg}
	defer restarted.close()
	if n, err := restarted.Step(ctx); n != 0 || err != nil {
		t.Fatalf("restart step: %d %v", n, err)
	}
}

func TestForwarderSingleSender(t *testing.T) {
	ctx := context.Background()
	pool := testdb.New(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ch := tcpReader(t, l)
	appendRows(t, pool, 1)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(7462)`).Scan(&ok); err != nil || !ok {
		t.Fatalf("lock: %v %v", ok, err)
	}
	f := &Forwarder{Pool: pool, Cfg: config.SyslogConfig{Addr: l.Addr().String(), Transport: "tcp"}}
	defer f.close()
	if n, err := f.Step(ctx); n != 0 || err != nil {
		t.Fatalf("locked step: %d %v", n, err)
	}
	select {
	case b := <-ch:
		t.Fatalf("sent %q", b)
	case <-time.After(200 * time.Millisecond):
	}
	if c := readCursor(t, pool); c.last != 0 {
		t.Fatalf("cursor %+v", c)
	}
}

func TestRun(t *testing.T) {
	pool := testdb.New(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ch := tcpReader(t, l)
	appendRows(t, pool, 3)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		// Batch 2 forces a full batch then a short one.
		(&Forwarder{Pool: pool, Cfg: config.SyslogConfig{Addr: l.Addr().String(), Transport: "tcp"},
			Interval: 10 * time.Millisecond, Retry: 10 * time.Millisecond, Batch: 2}).Run(ctx)
		close(done)
	}()
	for range 3 {
		recv(t, ch)
	}
	appendRows(t, pool, 1)
	recv(t, ch)
	// the frame is written before the commit; wait for the cursor before stopping
	for i := 0; readCursor(t, pool).last != maxID(t, pool) && i < 100; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
	if c := readCursor(t, pool); c.last != maxID(t, pool) {
		t.Fatalf("cursor %+v", c)
	}
}

func TestRunRetriesOnError(t *testing.T) {
	pool := testdb.New(t)
	appendRows(t, pool, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		(&Forwarder{Pool: pool, Cfg: config.SyslogConfig{Addr: "127.0.0.1:1", Transport: "tcp"}, Retry: 10 * time.Millisecond}).Run(ctx)
		close(done)
	}()
	// refused loopback connects can take seconds on Windows: poll instead of a fixed timeout
	for i := 0; readCursor(t, pool).fail == nil && i < 500; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	if c := readCursor(t, pool); c.last != 0 || c.fail == nil || c.lastErr == "" {
		t.Fatalf("cursor %+v", c)
	}
}

func TestForwarderRedialsAfterPeerClose(t *testing.T) {
	ctx := context.Background()
	pool := testdb.New(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	first := make(chan []byte, 1)
	go func() { // first conn: read one frame, then the "server restarts" and closes it
		c, err := l.Accept()
		if err != nil {
			return
		}
		r := bufio.NewReader(c)
		s, _ := r.ReadString(' ')
		n, _ := strconv.Atoi(strings.TrimSpace(s))
		b := make([]byte, n)
		_, _ = io.ReadFull(r, b)
		c.Close()
		first <- b
	}()
	appendRows(t, pool, 1)
	f := &Forwarder{Pool: pool, Cfg: config.SyslogConfig{Addr: l.Addr().String(), Transport: "tcp"}}
	defer f.close()
	if n, err := f.Step(ctx); n != 1 || err != nil {
		t.Fatalf("step1: %d %v", n, err)
	}
	recv(t, first)
	time.Sleep(100 * time.Millisecond) // let the FIN reach the client
	ch := tcpReader(t, l)
	appendRows(t, pool, 2)
	n, err := f.Step(ctx)
	if err != nil {
		if c := readCursor(t, pool); c.last != maxID(t, pool)-2 {
			t.Fatalf("cursor moved past unsent rows: %+v", c)
		}
		return
	}
	if n != 2 {
		t.Fatalf("step2: %d", n)
	}
	a, b := parseMsg(t, recv(t, ch)), parseMsg(t, recv(t, ch))
	if a.ID != maxID(t, pool)-1 || b.ID != maxID(t, pool) {
		t.Fatalf("ids %d %d", a.ID, b.ID)
	}
}

func TestGetStatusAlert(t *testing.T) {
	ctx := context.Background()
	pool := testdb.New(t)
	appendRows(t, pool, 3)
	now := time.Now()
	if _, err := pool.Exec(ctx, `UPDATE syslog_cursor SET last_id = $1, failing_since = $2, last_error = 'boom'`,
		maxID(t, pool)-2, now.Add(-16*time.Minute)); err != nil {
		t.Fatal(err)
	}
	s, err := GetStatus(ctx, pool, true, now)
	if err != nil || !s.Enabled || !s.Alert || s.Pending != 2 || s.LastError != "boom" || s.FailingSince == nil || s.LastOKAt != nil {
		t.Fatalf("status %+v %v", s, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE syslog_cursor SET failing_since = $1`, now.Add(-16*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if s, err := GetStatus(ctx, pool, false, now); err != nil || s.Alert || s.Enabled {
		t.Fatalf("status %+v %v", s, err)
	}
	b, _ := json.Marshal(Status{})
	if string(b) != `{"enabled":false,"pending":0,"last_ok_at":null,"failing_since":null,"last_error":"","alert":false}` {
		t.Fatalf("json %s", b)
	}
}
