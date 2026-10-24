package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"

	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
)

// putFile seals plain like the upload path does and inserts the files row.
func (e *env) putFile(t *testing.T, owner uuid.UUID, name string, plain []byte) uuid.UUID {
	t.Helper()
	dek, wrapped, keyID, err := e.keys.NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	n := sxcrypto.ChunkCount(int64(len(plain)))
	var ct []byte
	for i := int64(0); i < n; i++ {
		end := min((i+1)*sxcrypto.ChunkSize, int64(len(plain)))
		ct = append(ct, sxcrypto.SealChunk(dek, id, uint64(i), i == n-1, plain[i*sxcrypto.ChunkSize:end])...)
	}
	ctx := context.Background()
	if err := e.store.Put(ctx, id.String(), bytes.NewReader(ct), int64(len(ct))); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(plain)
	if _, err := e.pool.Exec(ctx, `INSERT INTO files (id, owner_id, name, content_type, size, sha256, wrapped_dek, key_id, storage_key)
		VALUES ($1,$2,$3,'text/html',$4,$5,$6,$7,$8)`, id, owner, name, len(plain), sum[:], wrapped, keyID, id.String()); err != nil {
		t.Fatal(err)
	}
	return id
}

func (e *env) get(t *testing.T, path string, hdr ...string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest("GET", e.ts.URL+path, nil)
	for i := 0; i < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := e.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func TestListOwnFilesOnly(t *testing.T) {
	e := newEnv(t)
	a, b := e.user(t, "a@x.com"), e.user(t, "b@x.com")
	e.putFile(t, a.ID, "first", []byte("1"))
	e.putFile(t, a.ID, "second", []byte("22"))
	e.putFile(t, b.ID, "theirs", []byte("3"))
	e.login(t, "a@x.com", pw)
	resp, body := e.get(t, "/api/files")
	var got []struct {
		Name, SHA256 string
		Size         int64
		ContentType  string `json:"content_type"`
		CreatedAt    string `json:"created_at"`
	}
	if resp.StatusCode != 200 || json.Unmarshal(body, &got) != nil || len(got) != 2 {
		t.Fatal(resp.StatusCode, string(body))
	}
	sum := sha256.Sum256([]byte("22"))
	if got[0].Name != "second" || got[1].Name != "first" || got[0].Size != 2 || got[0].SHA256 != hex.EncodeToString(sum[:]) || got[0].CreatedAt == "" {
		t.Fatalf("%+v", got)
	}
}

func TestDownloadRanges(t *testing.T) {
	e := newEnv(t)
	u := e.user(t, "a@x.com")
	plain := make([]byte, 5<<20)
	rand.Read(plain)
	id := e.putFile(t, u.ID, "big.bin", plain)
	e.login(t, "a@x.com", pw)
	p := "/api/files/" + id.String() + "/content"
	n := int64(len(plain))
	for _, c := range []struct {
		rng        string
		start, end int64
	}{{"bytes=0-0", 0, 0}, {"bytes=1048575-1048576", 1048575, 1048576}, {"bytes=-1", n - 1, n - 1}, {"bytes=4194304-", 4194304, n - 1}} {
		resp, body := e.get(t, p, "Range", c.rng)
		if resp.StatusCode != 206 || !bytes.Equal(body, plain[c.start:c.end+1]) {
			t.Fatalf("%s: %d len=%d", c.rng, resp.StatusCode, len(body))
		}
	}
	if resp, _ := e.get(t, p, "Range", "bytes=99999999-"); resp.StatusCode != 416 {
		t.Fatal(resp.StatusCode)
	}
	resp, body := e.get(t, p)
	if resp.StatusCode != 200 || !bytes.Equal(body, plain) || resp.Header.Get("Content-Type") != "application/octet-stream" ||
		resp.Header.Get("Cache-Control") != "private, no-store" {
		t.Fatal(resp.StatusCode, resp.Header)
	}
	// audit: every 200/206 served (4 ranges + full), not the 416
	ents, _ := e.audit.List(context.Background(), audit.Filter{Action: audit.ActDownload, Limit: 50})
	if len(ents) != 5 {
		t.Fatalf("want 5 download audits, got %d", len(ents))
	}
}

func TestDownloadFilenameHeader(t *testing.T) {
	e := newEnv(t)
	u := e.user(t, "a@x.com")
	e.login(t, "a@x.com", pw)
	name := "報價單 \"v2\"/../" + string(rune(92)) + string(rune(1)) + ".pdf"
	id := e.putFile(t, u.ID, name, []byte("x"))
	resp, _ := e.get(t, "/api/files/"+id.String()+"/content")
	want := `attachment; filename="___ _v2_...pdf"; filename*=UTF-8''%E5%A0%B1%E5%83%B9%E5%96%AE%20%22v2%22...pdf`
	if cd := resp.Header.Get("Content-Disposition"); cd != want {
		t.Fatalf("%q want %q", cd, want)
	}
	_, params, err := mime.ParseMediaType(resp.Header.Get("Content-Disposition"))
	if err != nil || params["filename"] != "報價單 \"v2\"...pdf" {
		t.Fatalf("%q %v", params["filename"], err)
	}

	id = e.putFile(t, u.ID, "a"+string(rune(13))+string(rune(10))+"Set-Cookie: x=1.txt", []byte("x"))
	resp, _ = e.get(t, "/api/files/"+id.String()+"/content")
	cd := resp.Header.Get("Content-Disposition")
	_, params, err = mime.ParseMediaType(cd)
	if strings.ContainsAny(cd, "\r\n") || err != nil || params["filename"] != "aSet-Cookie: x=1.txt" || resp.Header.Get("Set-Cookie") != "" {
		t.Fatalf("%q %q %v", cd, params["filename"], err)
	}
}

func TestDeleteThenGone(t *testing.T) {
	e := newEnv(t)
	u := e.user(t, "a@x.com")
	id := e.putFile(t, u.ID, "f", []byte("data"))
	e.login(t, "a@x.com", pw)
	if resp, _ := e.do(t, "DELETE", "/api/files/"+id.String(), nil); resp.StatusCode != 204 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := e.get(t, "/api/files/"+id.String()+"/content"); resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ := e.do(t, "DELETE", "/api/files/"+id.String(), nil); resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}
	if _, body := e.get(t, "/api/files"); strings.TrimSpace(string(body)) != "[]" {
		t.Fatal(string(body))
	}
	if rc, err := e.store.OpenRange(context.Background(), id.String(), 0, 1); err == nil {
		rc.Close()
		t.Fatal("blob still exists")
	}
	if ents, _ := e.audit.List(context.Background(), audit.Filter{Action: audit.ActDelete, Limit: 5}); len(ents) != 1 {
		t.Fatal(len(ents))
	}
}

func TestOtherUserFile404(t *testing.T) {
	e := newEnv(t)
	a := e.user(t, "a@x.com")
	e.user(t, "b@x.com")
	id := e.putFile(t, a.ID, "f", []byte("data"))
	e.login(t, "b@x.com", pw)
	for _, p := range []string{id.String() + "/content", "not-a-uuid/content"} {
		if resp, _ := e.get(t, "/api/files/"+p); resp.StatusCode != 404 {
			t.Fatal(p, resp.StatusCode)
		}
	}
	if resp, _ := e.do(t, "DELETE", "/api/files/"+id.String(), nil); resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}
	e.login(t, "a@x.com", pw)
	if resp, _ := e.get(t, "/api/files/"+id.String()+"/content"); resp.StatusCode != 200 {
		t.Fatal("owner lost access", resp.StatusCode)
	}
}

func TestDownloadAuditByServedStatus(t *testing.T) {
	e := newEnv(t)
	u := e.user(t, "a@x.com")
	plain := []byte("0123456789abcdefghijklmnopqrstuvwxyz")
	id := e.putFile(t, u.ID, "f", plain)
	e.login(t, "a@x.com", pw)
	p := "/api/files/" + id.String() + "/content"
	sum := sha256.Sum256(plain)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	count := func() int {
		ents, _ := e.audit.List(context.Background(), audit.Filter{Action: audit.ActDownload, Limit: 50})
		return len(ents)
	}
	for i, c := range []struct {
		hdr    []string
		status int
		audit  bool
	}{
		{nil, 200, true},
		{[]string{"Range", "bytes=5-", "If-Range", `"nope"`}, 200, true},
		{[]string{"Range", "bytes=1-,1-"}, 200, true},
		{[]string{"Range", "bytes=10-20"}, 206, true},
		{[]string{"Range", "bytes=99999999-"}, 416, false},
		{[]string{"Range", "bytes=5-", "If-Range", etag}, 206, true},
	} {
		before := count()
		resp, _ := e.get(t, p, c.hdr...)
		if resp.StatusCode != c.status || (c.status < 400 && resp.Header.Get("ETag") != etag) {
			t.Fatalf("case %d: %d etag=%q", i, resp.StatusCode, resp.Header.Get("ETag"))
		}
		if got := count() - before; (got == 1) != c.audit || got > 1 {
			t.Fatalf("case %d: %d audits", i, got)
		}
	}
	ents, _ := e.audit.List(context.Background(), audit.Filter{Action: audit.ActDownload, Limit: 1})
	if d := ents[0].Event.Detail; d["status"] != float64(206) || d["range"] != "bytes 5-35/36" {
		t.Fatalf("%v", d)
	}
}

func TestUnknownAPIIsJSON404AndSPAServed(t *testing.T) {
	e := newEnv(t)
	resp, body := e.get(t, "/api/unknown")
	if resp.StatusCode != 404 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") || !strings.Contains(string(body), "not_found") {
		t.Fatal(resp.StatusCode, resp.Header.Get("Content-Type"), string(body))
	}
	if resp, _ := e.get(t, "/files"); resp.StatusCode == 405 || strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		t.Fatal("SPA route not served by webui", resp.StatusCode)
	}
}
