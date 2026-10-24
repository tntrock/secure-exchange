package blob

// S3 test env vars (skipped when SX_TEST_S3_ENDPOINT is unset); matches the
// minio service in docker-compose.dev.yml:
//
//	SX_TEST_S3_ENDPOINT=localhost:59000
//	SX_TEST_S3_ACCESS_KEY=sxminio   (default)
//	SX_TEST_S3_SECRET_KEY=sxminio123 (default)

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/tntrock/secure-exchange/internal/config"
)

func testStore(t *testing.T, s Store) {
	ctx := context.Background()
	data := make([]byte, 3<<20)
	rand.Read(data)
	key := uuid.NewString()

	if err := s.Put(ctx, key, bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatal(err)
	}
	rc, err := s.OpenRange(ctx, key, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rc)
	rc.Close()
	if err != nil || !bytes.Equal(got, data[1:11]) {
		t.Fatalf("range mismatch: %v", err)
	}
	if rc, err := s.OpenRange(ctx, key, int64(len(data))-5, 10); err == nil {
		rc.Close()
		t.Fatal("out-of-range OpenRange should fail")
	}
	if err := s.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if rc, err := s.OpenRange(ctx, key, 0, 1); err == nil {
		rc.Close()
		t.Fatal("OpenRange after Delete should fail")
	}
	if err := s.Put(ctx, "../x", bytes.NewReader(data[:10]), 10); err == nil {
		t.Fatal("invalid key should fail")
	}
}

func TestLocal(t *testing.T) {
	s, err := NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	testStore(t, s)
}

func TestS3(t *testing.T) {
	ep := os.Getenv("SX_TEST_S3_ENDPOINT")
	if ep == "" {
		t.Skip("SX_TEST_S3_ENDPOINT not set")
	}
	get := func(k, d string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return d
	}
	cfg := config.S3Config{
		Endpoint:  ep,
		Bucket:    "sx-test",
		AccessKey: get("SX_TEST_S3_ACCESS_KEY", "sxminio"),
		SecretKey: get("SX_TEST_S3_SECRET_KEY", "sxminio123"),
		Region:    "us-east-1",
	}
	mc, err := minio.New(cfg.Endpoint, &minio.Options{Creds: credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, "")})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if ok, err := mc.BucketExists(ctx, cfg.Bucket); err != nil {
		t.Fatal(err)
	} else if !ok {
		if err := mc.MakeBucket(ctx, cfg.Bucket, minio.MakeBucketOptions{Region: cfg.Region}); err != nil {
			t.Fatal(err)
		}
	}
	s, err := NewS3(cfg)
	if err != nil {
		t.Fatal(err)
	}
	testStore(t, s)
}
