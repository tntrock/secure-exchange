package blob

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/tntrock/secure-exchange/internal/config"
)

func TestNew(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "blobs")
	s, err := New(&config.Config{Storage: "local", StorageDir: dir})
	if _, ok := s.(*Local); err != nil || !ok {
		t.Fatalf("local: %T %v", s, err)
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Fatalf("storage dir not created: %v", err)
	}
	s, err = New(&config.Config{Storage: "s3", S3: config.S3Config{Endpoint: "localhost:9", Bucket: "b"}})
	if _, ok := s.(*S3); err != nil || !ok {
		t.Fatalf("s3: %T %v", s, err)
	}
	if _, err := New(&config.Config{Storage: "ftp"}); err == nil || !strings.Contains(err.Error(), "unknown storage") {
		t.Fatalf("unknown storage: %v", err)
	}
	if _, err := NewS3(config.S3Config{Endpoint: "http://bad/endpoint"}); err == nil {
		t.Fatal("invalid S3 endpoint accepted")
	}
}

func TestLocalErrors(t *testing.T) {
	ctx := context.Background()
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLocal(filepath.Join(file, "sub")); err == nil {
		t.Fatal("NewLocal under a file succeeded")
	}

	dir := t.TempDir()
	s, err := NewLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	key := uuid.NewString()
	leftovers := func() {
		t.Helper()
		if _, err := os.Stat(filepath.Join(dir, key+".tmp")); !os.IsNotExist(err) {
			t.Fatalf("tmp file left behind: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dir, key)); !os.IsNotExist(err) {
			t.Fatalf("object created: %v", err)
		}
	}

	if err := s.Put(ctx, key, bytes.NewReader([]byte("abc")), 5); err == nil || !strings.Contains(err.Error(), "expected 5") {
		t.Fatalf("short write: %v", err)
	}
	leftovers()
	if err := s.Put(ctx, key, io.MultiReader(strings.NewReader("ab"), iotest{}), 5); !errors.Is(err, errRead) {
		t.Fatalf("reader error: %v", err)
	}
	leftovers()
	if err := os.Mkdir(filepath.Join(dir, key+".tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, key, strings.NewReader("x"), 1); err == nil {
		t.Fatal("Put succeeded when the tmp path is a directory")
	}
	os.Remove(filepath.Join(dir, key+".tmp"))

	if _, err := s.OpenRange(ctx, "../x", 0, 1); err == nil {
		t.Fatal("OpenRange accepted an invalid key")
	}
	if err := s.Delete(ctx, "../x"); err == nil {
		t.Fatal("Delete accepted an invalid key")
	}
	if err := s.Delete(ctx, uuid.NewString()); err != nil {
		t.Fatalf("deleting a missing object: %v", err)
	}
	// a non-empty directory under the key cannot be removed
	if err := os.MkdirAll(filepath.Join(dir, key, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, key); err == nil {
		t.Fatal("Delete of a non-empty directory succeeded")
	}
}

var errRead = errors.New("read failed")

type iotest struct{}

func (iotest) Read([]byte) (int, error) { return 0, errRead }

func TestS3InvalidKeys(t *testing.T) {
	s, err := NewS3(config.S3Config{Endpoint: "localhost:9", Bucket: "b"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Put(ctx, "../x", strings.NewReader("x"), 1); err == nil {
		t.Fatal("Put accepted an invalid key")
	}
	if _, err := s.OpenRange(ctx, "../x", 0, 1); err == nil {
		t.Fatal("OpenRange accepted an invalid key")
	}
	if err := s.Delete(ctx, "../x"); err == nil {
		t.Fatal("Delete accepted an invalid key")
	}
}
