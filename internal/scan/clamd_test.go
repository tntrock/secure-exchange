package scan

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
)

// fakeClamd answers every INSTREAM connection with reply and records what it received.
type fakeClamd struct {
	addr   string
	mu     sync.Mutex
	conns  int
	total  int
	maxLen int
	cmd    string
	onConn func() // runs when a client connects; set it with setOnConn
}

func (f *fakeClamd) setOnConn(fn func()) {
	f.mu.Lock()
	f.onConn = fn
	f.mu.Unlock()
}

func newFakeClamd(t *testing.T, reply string) *fakeClamd {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	f := &fakeClamd{addr: l.Addr().String()}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go f.serve(c, reply)
		}
	}()
	return f
}

func (f *fakeClamd) serve(c net.Conn, reply string) {
	defer c.Close()
	f.mu.Lock()
	f.conns++
	onConn := f.onConn
	f.mu.Unlock()
	if onConn != nil {
		onConn()
	}
	cmd := make([]byte, len("zINSTREAM\x00"))
	if _, err := io.ReadFull(c, cmd); err != nil {
		return
	}
	total, maxLen := 0, 0
	for {
		var n [4]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return
		}
		l := int(binary.BigEndian.Uint32(n[:]))
		if l == 0 {
			break
		}
		if _, err := io.CopyN(io.Discard, c, int64(l)); err != nil {
			return
		}
		total += l
		maxLen = max(maxLen, l)
	}
	f.mu.Lock()
	f.total, f.maxLen, f.cmd = total, maxLen, string(cmd)
	f.mu.Unlock()
	c.Write([]byte(reply + "\x00"))
}

func (f *fakeClamd) connections() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.conns
}

func TestScanClean(t *testing.T) {
	f := newFakeClamd(t, "stream: OK")
	v, err := Scan(context.Background(), f.addr, bytes.NewReader(make([]byte, 3<<20)))
	if err != nil || v != (Verdict{}) {
		t.Fatalf("%+v %v", v, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.total != 3<<20 || f.maxLen > 1<<20 || f.cmd != "zINSTREAM\x00" {
		t.Fatalf("total %d maxLen %d cmd %q", f.total, f.maxLen, f.cmd)
	}
}

func TestScanFound(t *testing.T) {
	f := newFakeClamd(t, "stream: Eicar-Test-Signature FOUND")
	v, err := Scan(context.Background(), f.addr, bytes.NewReader([]byte("x")))
	if err != nil || v != (Verdict{true, "Eicar-Test-Signature"}) {
		t.Fatalf("%+v %v", v, err)
	}
}

func TestScanErrorReply(t *testing.T) {
	f := newFakeClamd(t, "INSTREAM size limit exceeded. ERROR")
	_, err := Scan(context.Background(), f.addr, bytes.NewReader([]byte("x")))
	if err == nil || errors.Is(err, ErrUnavailable) {
		t.Fatalf("%v", err)
	}
}

func TestScanDialFail(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	if _, err := Scan(context.Background(), addr, bytes.NewReader(nil)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("%v", err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestScanReaderError(t *testing.T) {
	f := newFakeClamd(t, "stream: OK")
	_, err := Scan(context.Background(), f.addr, errReader{})
	if err == nil || errors.Is(err, ErrUnavailable) {
		t.Fatalf("%v", err)
	}
}

// clamd answers early (size limit) and hangs up while the client is still sending.
func TestScanEarlyReply(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		io.CopyN(io.Discard, c, 20)
		c.Write([]byte("INSTREAM size limit exceeded. ERROR\x00"))
		c.Close()
	}()
	_, err = Scan(context.Background(), l.Addr().String(), io.LimitReader(zeros{}, 64<<20))
	if err == nil || errors.Is(err, ErrUnavailable) {
		t.Fatalf("%v", err)
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestScanRealClamd(t *testing.T) {
	addr := os.Getenv("SX_TEST_CLAMD_ADDR")
	if addr == "" {
		t.Skip("SX_TEST_CLAMD_ADDR not set")
	}
	eicar := `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
	v, err := Scan(context.Background(), addr, bytes.NewReader([]byte(eicar)))
	if err != nil || !v.Infected {
		t.Fatalf("%+v %v", v, err)
	}
	if v, err = Scan(context.Background(), addr, bytes.NewReader([]byte("hello"))); err != nil || v.Infected {
		t.Fatalf("%+v %v", v, err)
	}
}
