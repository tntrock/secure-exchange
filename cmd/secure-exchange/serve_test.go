package main

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/db/testdb"
	"github.com/tntrock/secure-exchange/internal/preview"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
)

// setBaseEnv points the commands at pool's isolated schema with a valid web + worker config.
func setBaseEnv(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	dbURL, _ := url.Parse(testURL(t))
	q := dbURL.Query()
	q.Set("search_path", pool.Config().ConnConfig.RuntimeParams["search_path"])
	dbURL.RawQuery = q.Encode()
	dir := t.TempDir()
	for k, v := range map[string]string{
		"SX_DATABASE_URL":           dbURL.String(),
		"SX_BASE_URL":               "https://sx.example.com",
		"SX_MASTER_KEYS":            "1:" + key(1),
		"SX_ACTIVE_KEY_ID":          "1",
		"SX_SMTP_HOST":              "localhost",
		"SX_SMTP_PORT":              "1",
		"SX_SMTP_TLS":               "none",
		"SX_SMTP_FROM":              "noreply@sx.example.com",
		"SX_STORAGE":                "local",
		"SX_STORAGE_DIR":            filepath.Join(dir, "blobs"),
		"SX_STAGING_DIR":            filepath.Join(dir, "staging"),
		"SX_WORKER_TMP":             dir,
		"SX_WORKER_ALLOW_NON_TMPFS": "1",
		"SX_LISTEN":                 "127.0.0.1:0",
		"SX_INIT_ADMIN_EMAIL":       "",
		"SX_INIT_ADMIN_PASSWORD":    "",
	} {
		t.Setenv(k, v)
	}
}

// syncBuf is a goroutine-safe log sink: serve's background goroutines may still log
// while the test reads it.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// captureLog routes slog.Default into a buffer until the test ends.
func captureLog(t *testing.T) *syncBuf {
	t.Helper()
	buf := &syncBuf{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

// runExpectFail runs args and asserts exit 1 with want in the fatal log line.
func runExpectFail(t *testing.T, ctx context.Context, args []string, want string) {
	t.Helper()
	logs := captureLog(t)
	if got := run(ctx, args); got != 1 {
		t.Fatalf("exit %d, want 1", got)
	}
	if !strings.Contains(logs.String(), want) {
		t.Fatalf("log missing %q:\n%s", want, logs)
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func TestServeStartsAndShutsDown(t *testing.T) {
	pool := testdb.New(t)
	setBaseEnv(t, pool)
	t.Setenv("SX_INIT_ADMIN_EMAIL", "admin@example.com")
	t.Setenv("SX_INIT_ADMIN_PASSWORD", "correct-horse-battery")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var done chan int
	// freeAddr's port can be taken between its Close and serve's Listen: retry on a listen error.
	for attempt := 1; ; attempt++ {
		addr := freeAddr(t)
		t.Setenv("SX_LISTEN", addr)
		logs := captureLog(t)
		done = make(chan int, 1)
		go func() { done <- run(ctx, nil) }() // no args = serve
		if waitHealthy(t, addr, done) {
			break
		}
		if attempt == 3 || !strings.Contains(logs.String(), "listen tcp") {
			t.Fatalf("serve exited early:\n%s", logs)
		}
	}

	var role string
	if err := pool.QueryRow(context.Background(), `SELECT role FROM users WHERE email='admin@example.com'`).Scan(&role); err != nil || role != "admin" {
		t.Fatalf("initial admin: %q %v", role, err)
	}
	if fi, err := os.Stat(os.Getenv("SX_STAGING_DIR")); err != nil || !fi.IsDir() {
		t.Fatalf("staging dir not created: %v", err)
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit %d after shutdown, want 0", code)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("serve did not shut down")
	}
}

// waitHealthy polls /healthz until 200 (true) or until serve exits early (false).
func waitHealthy(t *testing.T, addr string, done <-chan int) bool {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		resp, err := http.Get("http://" + addr + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("healthz %d", resp.StatusCode)
			}
			return true
		}
		select {
		case <-done:
			return false
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("server never came up: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestServeErrors(t *testing.T) {
	pool := testdb.New(t)
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		env  map[string]string
		want string // proves which step failed
	}{
		{"missing config", map[string]string{"SX_DATABASE_URL": ""}, "SX_DATABASE_URL is required"},
		{"active key missing", map[string]string{"SX_ACTIVE_KEY_ID": "9"}, "master keys:"},
		{"bad database url", map[string]string{"SX_DATABASE_URL": "postgres://%zz"}, "db: parse url"},
		{"weak initial admin password", map[string]string{"SX_INIT_ADMIN_EMAIL": "a@example.com", "SX_INIT_ADMIN_PASSWORD": "x"}, "initial admin:"},
		{"storage dir under a file", map[string]string{"SX_STORAGE_DIR": filepath.Join(file, "blobs")}, `err="mkdir `},
		{"staging dir under a file", map[string]string{"SX_STAGING_DIR": filepath.Join(file, "staging")}, "staging dir:"},
		{"listen fails", map[string]string{"SX_LISTEN": "127.0.0.1:99999"}, "listen tcp"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			setBaseEnv(t, pool)
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel() // stops the background goroutines serve started
			runExpectFail(t, ctx, []string{"serve"}, c.want)
		})
	}
}

func TestWorker(t *testing.T) {
	pool := testdb.New(t)
	t.Run("runs until canceled", func(t *testing.T) {
		setBaseEnv(t, pool)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan int, 1)
		go func() { done <- run(ctx, []string{"worker"}) }()
		select {
		case code := <-done:
			t.Fatalf("worker exited early with %d", code)
		case <-time.After(2 * time.Second):
		}
		cancel()
		select {
		case code := <-done:
			if code != 0 {
				t.Fatalf("exit %d, want 0", code)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("worker did not stop")
		}
	})

	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		env  map[string]string
		want string // proves which step failed
	}{
		{"missing config", map[string]string{"SX_MASTER_KEYS": ""}, "SX_MASTER_KEYS is required"},
		{"active key missing", map[string]string{"SX_ACTIVE_KEY_ID": "9"}, "master keys:"},
		{"tmp missing", map[string]string{"SX_WORKER_TMP": filepath.Join(file, "nope")}, "must be an existing directory"},
		{"tmp is a file", map[string]string{"SX_WORKER_TMP": file}, "must be an existing directory"},
		{"bad database url", map[string]string{"SX_DATABASE_URL": "postgres://%zz"}, "db: parse url"},
		// SX_WORKER_TMP is a t.TempDir on disk, not a tmpfs; the DB URL stays valid so only CheckTmpfs can fail
		{"tmpfs enforced", map[string]string{"SX_WORKER_ALLOW_NON_TMPFS": ""}, "is not a tmpfs"},
		{"storage dir under a file", map[string]string{"SX_STORAGE_DIR": filepath.Join(file, "blobs")}, `err="mkdir `},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			setBaseEnv(t, pool)
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			want := c.want
			if c.name == "tmpfs enforced" && preview.CheckTmpfs(os.Getenv("SX_WORKER_TMP")) == nil {
				// off Linux (no-op) or TempDir really is a tmpfs: the check passes, so prove
				// the worker moved on to the next step instead of running forever
				t.Setenv("SX_DATABASE_URL", "postgres://%zz")
				want = "db: parse url"
			}
			runExpectFail(t, context.Background(), []string{"worker"}, want)
		})
	}
}

func TestRotateKeysErrors(t *testing.T) {
	pool := testdb.New(t)
	k1, _ := sxcrypto.ParseKeyring("1:"+key(1), 1)
	us := auth.NewUsers(pool, k1)
	u, err := us.Create(context.Background(), "a@example.com", "A", "staff", "password-12345")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := us.BeginTOTP(context.Background(), u.ID); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{"missing config", map[string]string{"SX_DATABASE_URL": ""}, "SX_DATABASE_URL is required"},
		{"active key missing", map[string]string{"SX_ACTIVE_KEY_ID": "9"}, "master keys:"},
		{"bad database url", map[string]string{"SX_DATABASE_URL": "postgres://%zz"}, "db: parse url"},
		// key 1 sealed the TOTP secret but is no longer in the keyring
		{"old key dropped", map[string]string{"SX_MASTER_KEYS": "2:" + key(2), "SX_ACTIVE_KEY_ID": "2"}, "keyring: unknown key id 1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			setBaseEnv(t, pool)
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			runExpectFail(t, context.Background(), []string{"rotate-keys"}, c.want)
		})
	}
}
