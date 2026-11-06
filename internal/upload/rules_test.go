package upload

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"strconv"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/tntrock/secure-exchange/internal/rules"
)

func (e *env) setRules(f func(r *rules.Rules)) {
	e.t.Helper()
	ctx := context.Background()
	r, err := e.rules.Get(ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	f(&r)
	tx, err := e.pool.Begin(ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.rules.Update(ctx, tx, r); err != nil {
		e.t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) addFile(owner uuid.UUID, size int64, deleted bool) {
	e.t.Helper()
	id := uuid.New()
	if _, err := e.pool.Exec(context.Background(), `INSERT INTO files (id, owner_id, name, content_type, size, sha256, wrapped_dek, key_id, storage_key, deleted_at)
		VALUES ($1,$2,'f','x/y',$3,'\x00','\x00',1,$5, CASE WHEN $4 THEN now() END)`, id, owner, size, deleted, id.String()); err != nil {
		e.t.Fatal(err)
	}
}

func TestStaffMaxFileBytes(t *testing.T) {
	e := newEnv(t)
	e.setRules(func(r *rules.Rules) { r.MaxFileBytes = 10 })
	if c, b := e.staffCreate(11); c != 403 || b != "file_too_large" {
		t.Fatalf("%d %q", c, b)
	}
	if c, _ := e.staffCreate(10); c != 201 {
		t.Fatal(c)
	}
}

func TestStaffQuota(t *testing.T) {
	e := newEnv(t)
	e.setRules(func(r *rules.Rules) { r.QuotaBytes = 100 })
	a := e.users["a"].ID
	e.addFile(a, 60, false)
	if c, b := e.staffCreate(41); c != 403 || b != "storage_full" {
		t.Fatalf("%d %q", c, b)
	}
	if c, _ := e.staffCreate(40); c != 201 {
		t.Fatal(c)
	}
	e.addFile(a, 500, true) // soft-deleted does not count
	if c, b := e.staffCreate(1); c != 403 || b != "storage_full" {
		t.Fatalf("full: %d %q", c, b)
	}
}

func TestQuotaSoftDeletedFreesSpace(t *testing.T) {
	e := newEnv(t)
	e.setRules(func(r *rules.Rules) { r.QuotaBytes = 100 })
	e.addFile(e.users["a"].ID, 60, true)
	if c, _ := e.staffCreate(100); c != 201 {
		t.Fatal(c)
	}
}

func TestVendorRules(t *testing.T) {
	e := newEnv(t)
	v := e.vendor("v", "b")
	e.shareTo(e.users["a"].ID, v.ID)
	rcpt := e.users["a"].ID.String()
	create := func(name string, size int64) string {
		meta := "filename " + base64.StdEncoding.EncodeToString([]byte(name)) + ",recipient " + base64.StdEncoding.EncodeToString([]byte(rcpt))
		resp, body := e.vreq("v", "POST", "/api/vendor/uploads/", nil, "Upload-Length", strconv.FormatInt(size, 10), "Upload-Metadata", meta)
		if resp.StatusCode == http.StatusCreated {
			return "ok"
		}
		return body
	}
	e.setRules(func(r *rules.Rules) { r.UploadExts = []string{"pdf"} })
	if got := create("a.exe", 1); got != "ext_not_allowed" {
		t.Fatal(got)
	}
	if got := create("a.pdf", 1); got != "ok" {
		t.Fatal(got)
	}
	e.setRules(func(r *rules.Rules) { r.UploadExts = nil; r.UploadMaxBytes = 5 })
	if got := create("a.pdf", 6); got != "file_too_large" {
		t.Fatal(got)
	}
	e.setRules(func(r *rules.Rules) { r.UploadMaxBytes = 0; r.QuotaBytes = 100 })
	e.addFile(e.users["a"].ID, 100, false)
	if got := create("a.pdf", 1); got != "recipient_storage_full" {
		t.Fatal(got)
	}
}

func TestIntakeStricterExtWins(t *testing.T) {
	e := newEnv(t)
	e.setRules(func(r *rules.Rules) { r.UploadExts = []string{"pdf"} })
	var rid uuid.UUID
	a := e.extUploader("x@example.com", []string{"exe"}, 3, &rid)
	if resp, body := e.extCreate(a, "tok", "a.exe", 5); resp.StatusCode != 403 || body != "ext_not_allowed" {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
}

func TestQuotaConcurrentCreates(t *testing.T) {
	e := newEnv(t)
	e.setRules(func(r *rules.Rules) { r.QuotaBytes = 50 })
	const n = 10
	var wg sync.WaitGroup
	start := make(chan struct{})
	codes := make([]int, n)
	bodies := make([]string, n)
	for i := range codes {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; codes[i], bodies[i] = e.staffCreate(10) }()
	}
	close(start)
	wg.Wait()
	ok := 0
	for i, c := range codes {
		if c == 201 {
			ok++
		} else if c != 403 || bodies[i] != "storage_full" {
			t.Fatalf("%d %q", c, bodies[i])
		}
	}
	if ok != 5 {
		t.Fatalf("%d succeeded, want 5", ok)
	}
}

func (e *env) staffCreate(size int64) (int, string) {
	e.t.Helper()
	meta := "filename " + base64.StdEncoding.EncodeToString([]byte("s.txt"))
	r, _ := http.NewRequest("POST", e.ts.URL+"/api/uploads/", nil)
	r.Header.Set("X-Test-User", "a")
	r.Header.Set("Tus-Resumable", "1.0.0")
	r.Header.Set("Upload-Length", strconv.FormatInt(size, 10))
	r.Header.Set("Upload-Metadata", meta)
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		e.t.Error(err)
		return 0, ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}
