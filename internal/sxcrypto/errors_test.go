package sxcrypto

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/google/uuid"
)

func TestChunkBadDEK(t *testing.T) {
	bad := []byte("short")
	id := uuid.New()
	if _, err := OpenChunk(bad, id, 0, true, make([]byte, 32)); err == nil {
		t.Fatal("OpenChunk accepted a bad DEK")
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("SealChunk did not panic on a bad DEK")
			}
		}()
		SealChunk(bad, id, 0, true, nil)
	}()
	r := OpenPlain(context.Background(), readerOpener(nil), bad, id, 10)
	if _, err := r.Read(make([]byte, 10)); err == nil {
		t.Fatal("Read succeeded with a bad DEK")
	}
}

func TestOpenPlainErrors(t *testing.T) {
	dek, id := testDEK(t), uuid.New()
	plain := make([]byte, ChunkSize+10)
	ct := sealAll(dek, id, plain)

	errOpen := errors.New("storage down")
	r := OpenPlain(context.Background(), func(context.Context, int64, int64) (io.ReadCloser, error) { return nil, errOpen }, dek, id, int64(len(plain)))
	if _, err := r.Read(make([]byte, 1)); !errors.Is(err, errOpen) {
		t.Fatalf("opener error: %v", err)
	}

	ct[len(ct)-1] ^= 1 // tamper with the last chunk's tag
	r = OpenPlain(context.Background(), readerOpener(ct), dek, id, int64(len(plain)))
	if _, err := r.Seek(ChunkSize, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Read(make([]byte, 1)); err == nil {
		t.Fatal("tampered chunk decrypted")
	}

	if _, err := r.Seek(0, 99); err == nil {
		t.Fatal("invalid whence accepted")
	}
	if _, err := r.Seek(-1, io.SeekStart); err == nil {
		t.Fatal("negative position accepted")
	}
}

func TestKeyringOpenRejects(t *testing.T) {
	r, err := ParseKeyring("1:"+k(1), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Open([]byte{0, 0}, nil); err == nil {
		t.Fatal("too-short value opened")
	}
	if _, err := r.Open([]byte{0, 0, 0, 7, 1, 2, 3}, nil); err == nil {
		t.Fatal("unknown key id opened")
	}
}
