package httpapi_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tntrock/secure-exchange/internal/audit"
	"github.com/tntrock/secure-exchange/internal/auth"
	"github.com/tntrock/secure-exchange/internal/blob"
	"github.com/tntrock/secure-exchange/internal/config"
	"github.com/tntrock/secure-exchange/internal/db/testdb"
	"github.com/tntrock/secure-exchange/internal/httpapi"
	"github.com/tntrock/secure-exchange/internal/sxcrypto"
	"github.com/tntrock/secure-exchange/internal/upload"
)

// TestEndToEnd wires the real tus handler into the server: login, resumable
// upload, list, download (full and ranged), delete, and the audit trail.
func TestEndToEnd(t *testing.T) {
	pool := testdb.New(t)
	k := make([]byte, 32)
	rand.Read(k)
	keys, err := sxcrypto.ParseKeyring("1:"+base64.StdEncoding.EncodeToString(k), 1)
	if err != nil {
		t.Fatal(err)
	}
	store, err := blob.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	users, log := auth.NewUsers(pool, keys), audit.New(pool)
	if _, err := users.Create(context.Background(), "a@x.com", "A", "staff", "password-12345"); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewTLSServer(httpapi.NewServer(httpapi.Deps{
		Users: users, Sessions: auth.NewSessions(pool), Audit: log, SessionTTL: time.Hour,
		Pool: pool, Keys: keys, Store: store,
		Uploads: upload.NewHandler(pool, keys, store, log, t.TempDir(), 1<<30, nil, config.PreviewConfig{MaxBytes: 1 << 30, MaxVideoBytes: 1 << 30}),
	}))
	defer ts.Close()
	c := ts.Client()
	c.Jar, _ = cookiejar.New(nil)

	do := func(method, path string, body []byte, hdr ...string) (*http.Response, []byte) {
		t.Helper()
		req, _ := http.NewRequest(method, ts.URL+path, bytes.NewReader(body))
		req.Header.Set("Origin", ts.URL)
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}
	tus := func(method, path string, body []byte, hdr ...string) *http.Response {
		t.Helper()
		resp, _ := do(method, path, body, append([]string{"Tus-Resumable", "1.0.0"}, hdr...)...)
		return resp
	}

	if resp, b := do("POST", "/api/auth/login", []byte(`{"email":"a@x.com","password":"password-12345"}`), "Content-Type", "application/json"); resp.StatusCode != 200 {
		t.Fatalf("login: %d %s", resp.StatusCode, b)
	}

	data := make([]byte, 5*sxcrypto.ChunkSize/2)
	rand.Read(data)
	meta := "filename " + base64.StdEncoding.EncodeToString([]byte("e2e.bin"))
	resp := tus("POST", "/api/uploads/", nil, "Upload-Length", strconv.Itoa(len(data)), "Upload-Metadata", meta)
	if resp.StatusCode != 201 {
		t.Fatalf("create: %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	id := loc[strings.LastIndex(loc, "/")+1:]
	patch := func(off int, part []byte) *http.Response {
		return tus("PATCH", loc, part, "Content-Type", "application/offset+octet-stream", "Upload-Offset", strconv.Itoa(off))
	}
	// the first PATCH is cut off mid-chunk; only the whole chunk is kept
	if resp := patch(0, data[:3*sxcrypto.ChunkSize/2]); resp.StatusCode != 204 || resp.Header.Get("Upload-Offset") != strconv.Itoa(sxcrypto.ChunkSize) {
		t.Fatalf("patch 1: %d %v", resp.StatusCode, resp.Header)
	}
	resp = tus("HEAD", loc, nil)
	off, _ := strconv.Atoi(resp.Header.Get("Upload-Offset"))
	if resp.StatusCode != 200 || off != sxcrypto.ChunkSize {
		t.Fatalf("head: %d %v", resp.StatusCode, resp.Header)
	}
	if resp := patch(off, data[off:]); resp.StatusCode != 204 || resp.Header.Get("X-SX-File-ID") != id {
		t.Fatalf("patch 2: %d %v", resp.StatusCode, resp.Header)
	}

	resp, b := do("GET", "/api/files", nil)
	var files []struct{ ID, Name, SHA256 string }
	json.Unmarshal(b, &files)
	sum := sha256.Sum256(data)
	if resp.StatusCode != 200 || len(files) != 1 || files[0].ID != id || files[0].Name != "e2e.bin" || files[0].SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("list: %d %s", resp.StatusCode, b)
	}

	content := "/api/files/" + id + "/content"
	if resp, b := do("GET", content, nil); resp.StatusCode != 200 || sha256.Sum256(b) != sum {
		t.Fatalf("download: %d len=%d", resp.StatusCode, len(b))
	}
	lo, hi := sxcrypto.ChunkSize-10, sxcrypto.ChunkSize+10 // spans a chunk boundary
	if resp, b := do("GET", content, nil, "Range", "bytes="+strconv.Itoa(lo)+"-"+strconv.Itoa(hi)); resp.StatusCode != 206 || !bytes.Equal(b, data[lo:hi+1]) {
		t.Fatalf("range: %d len=%d", resp.StatusCode, len(b))
	}

	if resp, _ := do("DELETE", "/api/files/"+id, nil); resp.StatusCode != 204 {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	if resp, _ := do("GET", content, nil); resp.StatusCode != 404 {
		t.Fatalf("download after delete: %d", resp.StatusCode)
	}

	ctx := context.Background()
	for action, want := range map[string]int{audit.ActUpload: 1, audit.ActDownload: 2, audit.ActDelete: 1} {
		ents, err := log.List(ctx, audit.Filter{Action: action})
		if err != nil || len(ents) != want || ents[0].Event.TargetID != id {
			t.Fatalf("audit %s: %v %d", action, err, len(ents))
		}
	}
	if bad, err := log.Verify(ctx); err != nil || bad != 0 {
		t.Fatalf("audit chain: bad=%d err=%v", bad, err)
	}
}
