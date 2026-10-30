package sxcrypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/google/uuid"
)

func testDEK(t *testing.T) []byte {
	t.Helper()
	dek := make([]byte, keyLen)
	if _, err := rand.Read(dek); err != nil {
		t.Fatal(err)
	}
	return dek
}

// sealAll encrypts plain chunk by chunk the way an uploader would.
func sealAll(dek []byte, id uuid.UUID, plain []byte) []byte {
	n := ChunkCount(int64(len(plain)))
	var out []byte
	for i := int64(0); i < n; i++ {
		end := min((i+1)*ChunkSize, int64(len(plain)))
		out = append(out, SealChunk(dek, id, uint64(i), i == n-1, plain[i*ChunkSize:end])...)
	}
	return out
}

func readerOpener(ct []byte) RangeOpener {
	r := bytes.NewReader(ct)
	return func(_ context.Context, off, length int64) (io.ReadCloser, error) {
		return io.NopCloser(io.NewSectionReader(r, off, length)), nil
	}
}

func TestChunkRoundTrip(t *testing.T) {
	dek, id := testDEK(t), uuid.New()
	for i := uint64(0); i < 3; i++ {
		plain := []byte{byte(i), 1, 2, 3}
		got, err := OpenChunk(dek, id, i, i == 2, SealChunk(dek, id, i, i == 2, plain))
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("index %d: got %v, %v", i, got, err)
		}
	}
}

func TestChunkSwapDetected(t *testing.T) {
	dek, id := testDEK(t), uuid.New()
	sealed := SealChunk(dek, id, 1, false, []byte("hello"))
	if _, err := OpenChunk(dek, id, 2, false, sealed); err == nil {
		t.Error("wrong index accepted")
	}
	if _, err := OpenChunk(dek, id, 1, true, sealed); err == nil {
		t.Error("wrong last flag accepted")
	}
	if _, err := OpenChunk(dek, uuid.New(), 1, false, sealed); err == nil {
		t.Error("wrong fileID accepted")
	}
}

func TestChunkCount(t *testing.T) {
	for size, want := range map[int64]int64{0: 1, 1: 1, ChunkSize: 1, ChunkSize + 1: 2, 3 * ChunkSize: 3} {
		if got := ChunkCount(size); got != want {
			t.Errorf("ChunkCount(%d) = %d, want %d", size, got, want)
		}
	}
}

func TestOpenPlainSeek(t *testing.T) {
	dek, id := testDEK(t), uuid.New()
	size := int64(2*ChunkSize + ChunkSize/2)
	plain := make([]byte, size)
	rand.Read(plain)
	calls := 0
	base := readerOpener(sealAll(dek, id, plain))
	opener := func(ctx context.Context, off, length int64) (io.ReadCloser, error) {
		calls++
		return base(ctx, off, length)
	}
	r := OpenPlain(context.Background(), opener, dek, id, size)
	defer r.Close()
	for _, off := range []int64{0, ChunkSize - 1, ChunkSize, 2*ChunkSize + 7, size - 1} {
		if _, err := r.Seek(off, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		want := plain[off:min(off+100, size)]
		got := make([]byte, len(want))
		if _, err := io.ReadFull(r, got); err != nil {
			t.Fatalf("off %d: %v", off, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("off %d: mismatch", off)
		}
	}

	// Full sequential read: one opener call, then EOF.
	r.Seek(0, io.SeekStart)
	calls = 0
	all, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(all, plain) {
		t.Fatalf("ReadAll: len %d err %v", len(all), err)
	}
	if calls != 1 {
		t.Errorf("sequential read opened %d ranges, want 1", calls)
	}

	// Seek whence variants and bounds.
	if pos, _ := r.Seek(-10, io.SeekEnd); pos != size-10 {
		t.Errorf("SeekEnd: %d", pos)
	}
	if pos, _ := r.Seek(5, io.SeekCurrent); pos != size-5 {
		t.Errorf("SeekCurrent: %d", pos)
	}
	if _, err := r.Seek(-1, io.SeekStart); err == nil {
		t.Error("negative position accepted")
	}
	r.Seek(size+10, io.SeekStart)
	if n, err := r.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Errorf("past end: %d, %v", n, err)
	}
}

func TestOpenPlainTruncated(t *testing.T) {
	dek, id := testDEK(t), uuid.New()
	size := int64(2*ChunkSize + 10)
	plain := make([]byte, size)
	ct := sealAll(dek, id, plain)
	for name, cut := range map[string][]byte{
		"missing last chunk": ct[:2*SealedChunkSize],
		"short last chunk":   ct[:len(ct)-1],
	} {
		r := OpenPlain(context.Background(), readerOpener(cut), dek, id, size)
		_, err := io.ReadAll(r)
		if err == nil {
			t.Errorf("%s: no error", name)
		}
		r.Close()
	}
}

func TestEmptyFile(t *testing.T) {
	dek, id := testDEK(t), uuid.New()
	ct := sealAll(dek, id, nil)
	if ChunkCount(0) != 1 || len(ct) != 16 {
		t.Fatalf("empty file: %d chunks, %d bytes", ChunkCount(0), len(ct))
	}
	r := OpenPlain(context.Background(), readerOpener(ct), dek, id, 0)
	defer r.Close()
	got, err := io.ReadAll(r)
	if err != nil || len(got) != 0 {
		t.Fatalf("got %d bytes, %v", len(got), err)
	}
}
