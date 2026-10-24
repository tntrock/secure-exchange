package blob

import (
	"context"
	"io"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/tntrock/secure-exchange/internal/config"
)

type S3 struct {
	c      *minio.Client
	bucket string
}

func NewS3(cfg config.S3Config) (*S3, error) {
	c, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
		Region: cfg.Region,
	})
	if err != nil {
		return nil, err
	}
	return &S3{c: c, bucket: cfg.Bucket}, nil
}

func (s *S3) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	if err := checkKey(key); err != nil {
		return err
	}
	// Known size lets the SDK stream multipart parts without buffering the object.
	_, err := s.c.PutObject(ctx, s.bucket, key, r, size, minio.PutObjectOptions{})
	return err
}

func (s *S3) OpenRange(ctx context.Context, key string, off, length int64) (io.ReadCloser, error) {
	if err := checkKey(key); err != nil {
		return nil, err
	}
	st, err := s.c.StatObject(ctx, s.bucket, key, minio.StatObjectOptions{})
	if err != nil {
		return nil, err
	}
	if err := checkRange(off, length, st.Size); err != nil {
		return nil, err
	}
	if length == 0 {
		return io.NopCloser(strings.NewReader("")), nil
	}
	var opts minio.GetObjectOptions
	if err := opts.SetRange(off, off+length-1); err != nil {
		return nil, err
	}
	return s.c.GetObject(ctx, s.bucket, key, opts)
}

func (s *S3) Delete(ctx context.Context, key string) error {
	if err := checkKey(key); err != nil {
		return err
	}
	return s.c.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{})
}
