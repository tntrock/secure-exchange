// Package scan virus-scans external uploads with clamd and records the verdict.
package scan

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// ErrUnavailable means clamd could not be reached: not the file's fault.
var ErrUnavailable = errors.New("scan: clamd unreachable")

type Verdict struct {
	Infected  bool
	Signature string // e.g. "Eicar-Test-Signature" when Infected
}

const (
	chunkSize   = 1 << 20
	scanTimeout = 20 * time.Minute
)

// Scan streams r to clamd at addr with zINSTREAM (length-prefixed chunks of at most 1 MiB, then a
// zero length) and parses the reply. A dial error wraps ErrUnavailable.
func Scan(ctx context.Context, addr string, r io.Reader) (Verdict, error) {
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return Verdict{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(scanTimeout))
	defer context.AfterFunc(ctx, func() { conn.Close() })()

	sendErr := stream(conn, r)
	if sendErr != nil {
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)) // only a reply already sent is of interest
	}
	// clamd may answer (and hang up) before the end, e.g. when its size limit is hit: prefer its reply
	reply, rerr := bufio.NewReader(conn).ReadString(0)
	if rerr != nil && reply == "" {
		if sendErr != nil {
			return Verdict{}, sendErr
		}
		return Verdict{}, fmt.Errorf("scan: read reply: %w", rerr)
	}
	reply = strings.TrimSpace(strings.TrimRight(reply, "\x00"))
	switch {
	case strings.HasSuffix(reply, " FOUND"):
		return Verdict{true, strings.TrimSuffix(strings.TrimPrefix(reply, "stream: "), " FOUND")}, nil
	case reply == "stream: OK" && sendErr == nil:
		return Verdict{}, nil
	}
	return Verdict{}, fmt.Errorf("scan: clamd replied %q", reply)
}

// stream sends the INSTREAM command and r's data, ending with a zero-length chunk.
func stream(w io.Writer, r io.Reader) error {
	if _, err := io.WriteString(w, "zINSTREAM\x00"); err != nil {
		return err
	}
	buf := make([]byte, 4+chunkSize)
	for {
		n, err := io.ReadFull(r, buf[4:])
		if n > 0 {
			binary.BigEndian.PutUint32(buf, uint32(n)) //nolint:gosec // n <= chunkSize
			if _, werr := w.Write(buf[:4+n]); werr != nil {
				return werr
			}
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return err
		}
	}
	_, err := w.Write([]byte{0, 0, 0, 0})
	return err
}
