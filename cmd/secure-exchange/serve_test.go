package main

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/db/testdb"
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
	addr := freeAddr(t)
	t.Setenv("SX_LISTEN", addr)
	t.Setenv("SX_INIT_ADMIN_EMAIL", "admin@example.com")
	t.Setenv("SX_INIT_ADMIN_PASSWORD", "correct-horse-battery")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan int, 1)
	go func() { done <- run(ctx, nil) }() // no args = serve

	deadline := time.Now().Add(15 * time.Second)
	for {
		resp, err := http.Get("http://" + addr + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("healthz %d", resp.StatusCode)
			}
			break
		}
		select {
		case code := <-done:
			t.Fatalf("serve exited early with %d", code)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("server never came up: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
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

func TestServeErrors(t *testing.T) {
	pool := testdb.New(t)
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		env  map[string]string
	}{
		{"missing config", map[string]string{"SX_DATABASE_URL": ""}},
		{"active key missing", map[string]string{"SX_ACTIVE_KEY_ID": "9"}},
		{"bad database url", map[string]string{"SX_DATABASE_URL": "postgres://%zz"}},
		{"weak initial admin password", map[string]string{"SX_INIT_ADMIN_EMAIL": "a@example.com", "SX_INIT_ADMIN_PASSWORD": "x"}},
		{"storage dir under a file", map[string]string{"SX_STORAGE_DIR": filepath.Join(file, "blobs")}},
		{"staging dir under a file", map[string]string{"SX_STAGING_DIR": filepath.Join(file, "staging")}},
		{"listen fails", map[string]string{"SX_LISTEN": "127.0.0.1:99999"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			setBaseEnv(t, pool)
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel() // stops the background goroutines serve started
			if got := run(ctx, []string{"serve"}); got != 1 {
				t.Fatalf("exit %d, want 1", got)
			}
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
	}{
		{"missing config", map[string]string{"SX_MASTER_KEYS": ""}},
		{"active key missing", map[string]string{"SX_ACTIVE_KEY_ID": "9"}},
		{"tmp missing", map[string]string{"SX_WORKER_TMP": filepath.Join(file, "nope")}},
		{"tmp is a file", map[string]string{"SX_WORKER_TMP": file}},
		{"bad database url", map[string]string{"SX_DATABASE_URL": "postgres://%zz"}},
		// tmpfs check enforced: fails on a non-tmpfs Linux dir, otherwise the bad URL fails next
		{"tmpfs enforced", map[string]string{"SX_WORKER_ALLOW_NON_TMPFS": "", "SX_DATABASE_URL": "postgres://%zz"}},
		{"storage dir under a file", map[string]string{"SX_STORAGE_DIR": filepath.Join(file, "blobs")}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			setBaseEnv(t, pool)
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			if got := run(context.Background(), []string{"worker"}); got != 1 {
				t.Fatalf("exit %d, want 1", got)
			}
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
	for name, env := range map[string]map[string]string{
		"missing config":   {"SX_DATABASE_URL": ""},
		"bad database url": {"SX_DATABASE_URL": "postgres://%zz"},
		// key 1 sealed the TOTP secret but is no longer in the keyring
		"old key dropped": {"SX_MASTER_KEYS": "2:" + key(2), "SX_ACTIVE_KEY_ID": "2"},
	} {
		t.Run(name, func(t *testing.T) {
			setBaseEnv(t, pool)
			for k, v := range env {
				t.Setenv(k, v)
			}
			if got := run(context.Background(), []string{"rotate-keys"}); got != 1 {
				t.Fatalf("exit %d, want 1", got)
			}
		})
	}
}
