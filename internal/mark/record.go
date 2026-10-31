// Package mark records marked downloads and traces leaked copies back to them.
package mark

import (
	"context"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/tntrock/secure-exchange/internal/preview"
)

type Method string

const (
	PDFPages       Method = "pdf_pages"
	PDFMeta        Method = "pdf_meta"
	ImageVisible   Method = "image_visible"
	ImageInvisible Method = "image_invisible"
	OOXMLMeta      Method = "ooxml_meta"
	ODFMeta        Method = "odf_meta"
	None           Method = "none"
)

type Download struct {
	FileID, ShareID, RecipientID uuid.UUID
	Method                       Method
	IP, UserAgent                string
}

// Querier is preview.Querier plus multi-row reads.
type Querier interface {
	preview.Querier
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// Start records a download and returns its trace code. Marked methods always get a
// fresh code; None reuses the (recipient, file) row so repeats do not pile up.
func Start(ctx context.Context, q preview.Querier, d Download) (string, error) {
	ip, ua := cut(d.IP, 64), cut(d.UserAgent, 512)
	var code string
	err := q.QueryRow(ctx, `INSERT INTO download_traces (code, file_id, share_id, recipient_id, method, ip, user_agent)
		VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (recipient_id, file_id) WHERE method = 'none' DO NOTHING RETURNING code`,
		preview.NewTraceCode(), d.FileID, d.ShareID, d.RecipientID, string(d.Method), ip, ua).Scan(&code)
	if errors.Is(err, pgx.ErrNoRows) {
		err = q.QueryRow(ctx, `SELECT code FROM download_traces WHERE recipient_id=$1 AND file_id=$2 AND method='none'`,
			d.RecipientID, d.FileID).Scan(&code)
	}
	return code, err
}

// Complete stores the hash and size of the bytes actually delivered.
func Complete(ctx context.Context, q preview.Querier, code string, sum []byte, size int64) error {
	_, err := q.Exec(ctx, `UPDATE download_traces SET sha256=$2, size=$3, completed_at=now() WHERE code=$1`, code, sum, size)
	return err
}

type Hit struct {
	Source         string     `json:"source"` // "download", "view" or "file"
	Via            string     `json:"via"`    // "metadata", "text_layer", "invisible", "sha256" or "code"; set by the caller
	Code           string     `json:"code"`
	FileID         uuid.UUID  `json:"file_id"`
	FileName       string     `json:"file_name"`
	ShareID        *uuid.UUID `json:"share_id"`
	OwnerEmail     string     `json:"owner_email"`
	RecipientEmail string     `json:"recipient_email"`
	IP             string     `json:"ip"`
	At             time.Time  `json:"at"`
	Method         string     `json:"method"`
}

const (
	dlSelect = `SELECT 'download', t.code, f.id, f.name, t.share_id, o.email, COALESCE(r.email,''), t.ip, t.created_at, t.method
		FROM download_traces t JOIN files f ON f.id=t.file_id JOIN users o ON o.id=f.owner_id
		LEFT JOIN share_recipients r ON r.id=t.recipient_id `
	viewSelect = `SELECT 'view', t.code, f.id, f.name, t.share_id, o.email, COALESCE(r.email,''), t.ip, t.created_at, ''
		FROM view_traces t JOIN files f ON f.id=t.file_id JOIN users o ON o.id=f.owner_id
		LEFT JOIN share_recipients r ON r.id=t.recipient_id `
)

func scan(rows pgx.Rows, err error) ([]Hit, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var hits []Hit
	for rows.Next() {
		var h Hit
		if err := rows.Scan(&h.Source, &h.Code, &h.FileID, &h.FileName, &h.ShareID, &h.OwnerEmail, &h.RecipientEmail, &h.IP, &h.At, &h.Method); err != nil {
			return nil, err
		}
		hits = append(hits, h)
	}
	return hits, rows.Err()
}

// ByCode finds download and view traces carrying code.
func ByCode(ctx context.Context, q Querier, code string) ([]Hit, error) {
	return scan(q.Query(ctx, dlSelect+`WHERE t.code=$1 UNION ALL `+viewSelect+`WHERE t.code=$1`, code))
}

// BySHA finds downloads whose delivered bytes hash to sum, and live files whose
// original hashes to sum together with their unmarked downloads.
func BySHA(ctx context.Context, q Querier, sum []byte) ([]Hit, error) {
	return scan(q.Query(ctx, dlSelect+`WHERE t.sha256=$1
		UNION ALL SELECT 'file', '', f.id, f.name, NULL::uuid, o.email, '', '', f.created_at, ''
			FROM files f JOIN users o ON o.id=f.owner_id WHERE f.sha256=$1 AND f.deleted_at IS NULL
		UNION ALL `+dlSelect+`WHERE t.method='none' AND f.sha256=$1 AND f.deleted_at IS NULL AND t.sha256 IS DISTINCT FROM $1`, sum))
}

// cut truncates s to at most n bytes on a rune boundary (Postgres rejects invalid UTF-8).
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
