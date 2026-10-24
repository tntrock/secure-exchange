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
	// audit: full download + bytes=0-0 only
	ents, _ := e.audit.List(context.Background(), audit.Filter{Action: audit.ActDownload, Limit: 50})
	if len(ents) != 2 {
		t.Fatalf("want 2 download audits, got %d", len(ents))
	}
}

func TestDownloadFilenameHeader(t *testing.T) {
	e := newEnv(t)
	u := e.user(t, "a@x.com")
	id := e.putFile(t, u.ID, "報價單 \"v2\"/../"+string(rune(92))+string(rune(1))+".pdf", []byte("x"))
	e.login(t, "a@x.com", pw)
	resp, _ := e.get(t, "/api/files/"+id.String()+"/content")
	cd := resp.Header.Get("Content-Disposition")
	typ, params, err := mime.ParseMediaType(cd)
	if err != nil || typ != "attachment" || params["filename"] != params["filename*"] && !strings.HasPrefix(cd, `attachment; filename="`) {
		t.Fatal(cd, err)
	}
	if want := "報價單 \"v2\"...pdf"; params["filename"] != want {
		t.Fatalf("%q want %q (%s)", params["filename"], want, cd)
	}
	if !strings.Contains(cd, `filename="___ "v2"`) && !strings.Contains(cd, "filename*=UTF-8''%E5%A0%B1") {
		t.Fatal(cd)
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
