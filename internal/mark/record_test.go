package mark

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tntrock/secure-exchange/internal/db/testdb"
)

var ctx = context.Background()

type fx struct {
	pool                      *pgxpool.Pool
	owner, file, share, recip uuid.UUID
}

func setup(t *testing.T) fx {
	t.Helper()
	f := fx{pool: testdb.New(t), owner: uuid.New(), file: uuid.New(), share: uuid.New(), recip: uuid.New()}
	for _, s := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO users (id, email, role) VALUES ($1,'o@example.com','staff')`, []any{f.owner}},
		{`INSERT INTO files (id, owner_id, name, content_type, size, sha256, wrapped_dek, key_id, storage_key)
			VALUES ($1,$2,'a.pdf','x',1,'\xaa','\x01',1,'k')`, []any{f.file, f.owner}},
		{`INSERT INTO shares (id, owner_id, token_hash, token_sealed, allow_download, watermark, expires_at)
			VALUES ($1,$2,'\x01','\x01',true,true,now()+interval '1 day')`, []any{f.share, f.owner}},
		{`INSERT INTO share_recipients (id, share_id, email) VALUES ($1,$2,'r@example.com')`, []any{f.recip, f.share}},
	} {
		if _, err := f.pool.Exec(ctx, s.sql, s.args...); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f fx) dl(m Method) Download {
	return Download{FileID: f.file, ShareID: f.share, RecipientID: f.recip, Method: m, IP: "1.2.3.4", UserAgent: "ua"}
}

func count(t *testing.T, f fx) (n int) {
	t.Helper()
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM download_traces`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestStartMarkedAlwaysNew(t *testing.T) {
	f := setup(t)
	a, err := Start(ctx, f.pool, f.dl(PDFMeta))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Start(ctx, f.pool, f.dl(PDFMeta))
	if err != nil {
		t.Fatal(err)
	}
	if a == b || count(t, f) != 2 {
		t.Fatalf("a=%s b=%s rows=%d", a, b, count(t, f))
	}
}

func TestStartUnmarkedReuses(t *testing.T) {
	f := setup(t)
	a, err := Start(ctx, f.pool, f.dl(None))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Start(ctx, f.pool, f.dl(None))
	if err != nil {
		t.Fatal(err)
	}
	if a != b || count(t, f) != 1 {
		t.Fatalf("a=%s b=%s rows=%d", a, b, count(t, f))
	}
}

func TestStartTruncates(t *testing.T) {
	f := setup(t)
	d := f.dl(PDFMeta)
	d.IP, d.UserAgent = strings.Repeat("a", 100), strings.Repeat("b", 600)
	code, err := Start(ctx, f.pool, d)
	if err != nil {
		t.Fatal(err)
	}
	var ip, ua int
	if err := f.pool.QueryRow(ctx, `SELECT length(ip), length(user_agent) FROM download_traces WHERE code=$1`, code).Scan(&ip, &ua); err != nil {
		t.Fatal(err)
	}
	if ip != 64 || ua != 512 {
		t.Fatalf("ip=%d ua=%d", ip, ua)
	}
}

func TestByCodeFindsDownloadAndView(t *testing.T) {
	f := setup(t)
	code, err := Start(ctx, f.pool, f.dl(PDFPages))
	if err != nil {
		t.Fatal(err)
	}
	hits, err := ByCode(ctx, f.pool, code)
	if err != nil || len(hits) != 1 {
		t.Fatalf("hits=%v err=%v", hits, err)
	}
	h := hits[0]
	if h.Source != "download" || h.RecipientEmail != "r@example.com" || h.IP != "1.2.3.4" || h.OwnerEmail != "o@example.com" ||
		h.FileName != "a.pdf" || h.Method != "pdf_pages" || h.ShareID == nil || *h.ShareID != f.share {
		t.Fatalf("hit=%+v", h)
	}

	if _, err := f.pool.Exec(ctx, `INSERT INTO view_traces (code, file_id, share_id, recipient_id, session_hash, ip)
		VALUES ('VIEWCODE01',$1,$2,$3,'\x01','5.6.7.8')`, f.file, f.share, f.recip); err != nil {
		t.Fatal(err)
	}
	hits, err = ByCode(ctx, f.pool, "VIEWCODE01")
	if err != nil || len(hits) != 1 || hits[0].Source != "view" || hits[0].IP != "5.6.7.8" || hits[0].RecipientEmail != "r@example.com" {
		t.Fatalf("hits=%+v err=%v", hits, err)
	}

	hits, err = ByCode(ctx, f.pool, "NOPE")
	if err != nil || len(hits) != 0 {
		t.Fatalf("hits=%v err=%v", hits, err)
	}
}

func TestBySHA(t *testing.T) {
	f := setup(t)
	code, err := Start(ctx, f.pool, f.dl(PDFMeta))
	if err != nil {
		t.Fatal(err)
	}
	sum := []byte{0xde, 0xad}
	if err := Complete(ctx, f.pool, code, sum, 42); err != nil {
		t.Fatal(err)
	}
	if _, err := Start(ctx, f.pool, f.dl(None)); err != nil {
		t.Fatal(err)
	}

	hits, err := BySHA(ctx, f.pool, sum)
	if err != nil || len(hits) != 1 || hits[0].Source != "download" || hits[0].Code != code {
		t.Fatalf("hits=%+v err=%v", hits, err)
	}

	hits, err = BySHA(ctx, f.pool, []byte{0xaa})
	if err != nil || len(hits) != 2 {
		t.Fatalf("hits=%+v err=%v", hits, err)
	}
	src := map[string]int{}
	for _, h := range hits {
		src[h.Source]++
		if h.Source == "download" && h.Method != "none" {
			t.Fatalf("download hit method = %q, want none", h.Method)
		}
	}
	if src["file"] != 1 || src["download"] != 1 {
		t.Fatalf("sources=%v", src)
	}

	if _, err := f.pool.Exec(ctx, `UPDATE files SET deleted_at=now()`); err != nil {
		t.Fatal(err)
	}
	if hits, err = BySHA(ctx, f.pool, []byte{0xaa}); err != nil || len(hits) != 0 {
		t.Fatalf("deleted: hits=%+v err=%v", hits, err)
	}
}

func TestStartTruncatesOnRuneBoundary(t *testing.T) {
	f := setup(t)
	d := f.dl(PDFMeta)
	d.UserAgent = strings.Repeat("a", 511) + "€€" // 3-byte rune straddles byte 512
	code, err := Start(ctx, f.pool, d)
	if err != nil {
		t.Fatal(err)
	}
	var ua string
	if err := f.pool.QueryRow(ctx, `SELECT user_agent FROM download_traces WHERE code=$1`, code).Scan(&ua); err != nil {
		t.Fatal(err)
	}
	if !utf8.ValidString(ua) || len(ua) > 512 {
		t.Fatalf("len=%d valid=%v", len(ua), utf8.ValidString(ua))
	}
}
