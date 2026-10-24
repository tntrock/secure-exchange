// Package blob stores already-encrypted file data, streaming on Put.
package blob

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/tntrock/secure-exchange/internal/config"
)

type Store interface {
	Put(ctx context.Context, key string, r io.Reader, size int64) error
	OpenRange(ctx context.Context, key string, off, length int64) (io.ReadCloser, error)
	Delete(ctx context.Context, key string) error
}

var keyRE = regexp.MustCompile(`^[a-f0-9-]+$`)

func checkKey(key string) error {
	if !keyRE.MatchString(key) {
		return fmt.Errorf("blob: invalid key %q", key)
	}
	return nil
}

func checkRange(off, length, size int64) error {
	if off < 0 || length < 0 || off+length > size {
		return fmt.Errorf("blob: range %d+%d outside object of size %d", off, length, size)
	}
	return nil
}

func New(cfg *config.Config) (Store, error) {
	switch cfg.Storage {
	case "local":
		return NewLocal(cfg.StorageDir)
	case "s3":
		return NewS3(cfg.S3)
	}
	return nil, fmt.Errorf("blob: unknown storage %q", cfg.Storage)
}

type Local struct{ dir string }

func NewLocal(dir string) (*Local, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Local{dir: dir}, nil
}

func (l *Local) Put(_ context.Context, key string, r io.Reader, size int64) (err error) {
	if err := checkKey(key); err != nil {
		return err
	}
	final := filepath.Join(l.dir, key)
	tmp := final + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(tmp)
		}
	}()
	n, err := io.Copy(f, r)
	if err != nil {
		return err
	}
	if n != size {
		return fmt.Errorf("blob: wrote %d bytes, expected %d", n, size)
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, final)
}

type sectionFile struct {
	*io.SectionReader
	f *os.File
}

func (s sectionFile) Close() error { return s.f.Close() }

func (l *Local) OpenRange(_ context.Context, key string, off, length int64) (io.ReadCloser, error) {
	if err := checkKey(key); err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Join(l.dir, key))
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err == nil {
		err = checkRange(off, length, st.Size())
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return sectionFile{io.NewSectionReader(f, off, length), f}, nil
}

func (l *Local) Delete(_ context.Context, key string) error {
	if err := checkKey(key); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(l.dir, key)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
