package sxcrypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/google/uuid"
)

const (
	ChunkSize       = 1 << 20
	SealedChunkSize = ChunkSize + 16
)

// ChunkCount is the number of chunks for a plaintext of size bytes. An empty
// file still has one (empty, last) chunk so truncation to nothing is detected.
func ChunkCount(size int64) int64 {
	if size == 0 {
		return 1
	}
	return (size + ChunkSize - 1) / ChunkSize
}

func chunkAEAD(dek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// chunkNonceAAD: nonce = 0^4 || index BE; AAD = fileID || index BE || last.
// The nonce is deterministic because every file has its own DEK.
func chunkNonceAAD(fileID uuid.UUID, index uint64, last bool) (nonce, aad []byte) {
	nonce = binary.BigEndian.AppendUint64(make([]byte, 4, 12), index)
	aad = binary.BigEndian.AppendUint64(append(make([]byte, 0, 25), fileID[:]...), index)
	if last {
		return nonce, append(aad, 1)
	}
	return nonce, append(aad, 0)
}

// SealChunk encrypts one chunk. It panics on an invalid DEK (programmer error).
func SealChunk(dek []byte, fileID uuid.UUID, index uint64, last bool, plain []byte) []byte {
	g, err := chunkAEAD(dek)
	if err != nil {
		panic("sxcrypto: SealChunk: " + err.Error())
	}
	nonce, aad := chunkNonceAAD(fileID, index, last)
	return g.Seal(nil, nonce, plain, aad)
}

func OpenChunk(dek []byte, fileID uuid.UUID, index uint64, last bool, sealed []byte) ([]byte, error) {
	g, err := chunkAEAD(dek)
	if err != nil {
		return nil, err
	}
	return openChunk(g, fileID, index, last, sealed)
}

func openChunk(g cipher.AEAD, fileID uuid.UUID, index uint64, last bool, sealed []byte) ([]byte, error) {
	nonce, aad := chunkNonceAAD(fileID, index, last)
	plain, err := g.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, fmt.Errorf("sxcrypto: chunk %d: %w", index, err)
	}
	return plain, nil
}

// RangeOpener returns ciphertext bytes [off, off+length).
type RangeOpener func(ctx context.Context, off, length int64) (io.ReadCloser, error)

// OpenPlain returns a seekable plaintext view of an encrypted file of
// plaintext length size, suitable for http.ServeContent.
func OpenPlain(ctx context.Context, open RangeOpener, dek []byte, fileID uuid.UUID, size int64) io.ReadSeekCloser {
	return &plainReader{ctx: ctx, open: open, dek: dek, fileID: fileID, size: size, count: ChunkCount(size)}
}

type plainReader struct {
	ctx    context.Context
	open   RangeOpener
	dek    []byte
	fileID uuid.UUID
	size   int64
	count  int64
	pos    int64

	g        cipher.AEAD
	rc       io.ReadCloser // ciphertext stream positioned at chunk next
	next     int64
	plain    []byte // decrypted chunk at plaintext offset plainOff
	plainOff int64
	sealed   []byte
}

func (r *plainReader) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		offset += r.pos
	case io.SeekEnd:
		offset += r.size
	default:
		return 0, errors.New("sxcrypto: invalid whence")
	}
	if offset < 0 {
		return 0, errors.New("sxcrypto: negative position")
	}
	r.pos = offset
	return offset, nil
}

func (r *plainReader) Read(p []byte) (int, error) {
	if r.pos >= r.size {
		return 0, io.EOF
	}
	if r.plain == nil || r.pos < r.plainOff || r.pos >= r.plainOff+int64(len(r.plain)) {
		if err := r.load(r.pos / ChunkSize); err != nil {
			return 0, err
		}
	}
	n := copy(p, r.plain[r.pos-r.plainOff:])
	r.pos += int64(n)
	return n, nil
}

// load decrypts chunk idx into r.plain, (re)opening the ciphertext stream
// from idx to end of file unless it is already positioned there.
func (r *plainReader) load(idx int64) error {
	if r.g == nil {
		g, err := chunkAEAD(r.dek)
		if err != nil {
			return err
		}
		r.g = g
	}
	if r.rc == nil || r.next != idx {
		r.Close()
		off := idx * SealedChunkSize
		total := (r.count-1)*SealedChunkSize + (r.size - (r.count-1)*ChunkSize) + 16
		rc, err := r.open(r.ctx, off, total-off)
		if err != nil {
			return err
		}
		r.rc, r.next = rc, idx
	}
	last := idx == r.count-1
	n := int64(SealedChunkSize)
	if last {
		n = r.size - idx*ChunkSize + 16
	}
	if r.sealed == nil {
		r.sealed = make([]byte, SealedChunkSize)
	}
	if _, err := io.ReadFull(r.rc, r.sealed[:n]); err != nil {
		r.Close()
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return fmt.Errorf("sxcrypto: chunk %d: %w", idx, err)
	}
	plain, err := openChunk(r.g, r.fileID, uint64(idx), last, r.sealed[:n])
	if err != nil {
		r.Close()
		return err
	}
	r.plain, r.plainOff, r.next = plain, idx*ChunkSize, idx+1
	return nil
}

func (r *plainReader) Close() error {
	if r.rc == nil {
		return nil
	}
	err := r.rc.Close()
	r.rc = nil
	return err
}
