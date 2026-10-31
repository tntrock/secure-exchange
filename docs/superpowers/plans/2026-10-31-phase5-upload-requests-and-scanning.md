# Phase 5: Upload Request Links and ClamAV Scanning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Staff can create upload request links. External uploaders verify by email code and upload files (resumable) into the staff member's space. Every externally uploaded file is scanned by ClamAV, and infected files are quarantined.

**Architecture:**
- **`internal/intake`** owns upload requests, uploader OTPs and uploader sessions. It mirrors the one-time-share flow in `internal/share/access.go`, using its own tables.
- **Uploads** go through the existing tus handler, mounted a second time at `/api/r/{token}/uploads/`. The handler learns who is uploading from either `auth.UserFrom` (staff) or `intake.AccessFrom` (external).
- **Finished external uploads** become ordinary `files` rows owned by the request's owner, with `scan_status = 'pending'` and a `scan_jobs` row.
- **Scanning:** a new `internal/scan` loop runs in the `worker` process. It decrypts each pending file and streams it to clamd (INSTREAM), then records the result and queues email notifications.
- **Gating:** files that are not scan-clean cannot be downloaded, previewed or shared by their owner.

**Tech Stack:**
- Go: pgx/v5 and goose. The clamd protocol is hand-written; no new Go dependency.
- React 19, vitest, tus-js-client 4.3.1 (already installed).
- ClamAV image `clamav/clamav:1.4`.

**Spec:** `docs/superpowers/specs/2026-10-24-secure-exchange-design.md`. Sections: §5.3 (intake), §5.8 (audit), §5.9 (notifications), §6 (rate limits, sessions, tokens), §6.1 (tus, scale), §11 phase 5.

## Global Constraints

**Spec requirements:**
- §5.3 Uploaders are an email list per link and verify with the one-time-share code mechanism (6 digits, 10 min, single use, 5 tries, rate-limited per email and IP).
- §5.3 A link sets an expiry, a max file count, a max total size, allowed extensions and a message.
- §5.3 Files go straight into the staff member's space, and the staff member is notified.
- §5.3 Every external upload is scanned by ClamAV. Infected files are quarantined (not downloadable) and both the staff member and the admins are notified.
- §5.1 Unknown emails get the same answer as listed ones ("if you are on the list you will receive a code").
- §6 Link tokens carry ≥128 bits of randomness; only their hash is stored. Cookies are HttpOnly, Secure and SameSite. Code request, code verify and upload are rate-limited.
- §6.1 Uploads stay chunked, sealed and resumable via tus. Plaintext never touches the app's disk.

**Project rules:**
- No new Go module dependencies. No new npm dependencies.
- Every UI string exists in both `web/src/i18n/en.json` and `web/src/i18n/zh-TW.json`. `keys.test.ts` enforces this.
- CI gates are test, lint and coverage. Total Go coverage must stay ≥ 90%, and the web vitest thresholds must stay green.
- Lint locally with:
  `MSYS_NO_PATHCONV=1 docker run --rm -v "$PWD:/app" -w /app golangci/golangci-lint:v2.15.0 golangci-lint run --build-tags tools ./...`
- DB tests use `testdb.New(t)`, which needs `SX_TEST_DATABASE_URL` (dev Postgres on host port 55432).
- `-race` runs only in a `golang:1.26` container: the host has no cgo.
- Every new sealed column gets an entry in `sxcrypto.sealedCols`.
- Audit events use `s.record` (httpapi) or `audit.Log.Append` (worker). `TargetID`s are UUID strings.

## Review Focus

1. **The uploader's session or the request ends in the middle of a multi-hour tus upload.** Later PATCHes must be refused (401 or 410). Files already completed stay. The page tells the uploader that the session ended, instead of showing a silent "failed". Tests: Task 3 `TestIntakePatchAfterRevoke`, Task 6 `upload failure re-checks session`.
2. **Two uploads are created at once and race past `max_files` or `max_total_bytes`.** The request row is locked (`FOR UPDATE`), so the second one is refused. Test: Task 1 `TestCheckUploadSerialises`.
3. **Cross-ownership.** Uploader A cannot touch uploader B's upload. Staff cannot HEAD, PATCH, DELETE or finish an external upload through `/api/uploads/`. Uploads never cross request tokens. Test: Task 3 `TestIntakeUploadIsolation`.
4. **The owner deletes a file while its scan is pending.** The job ends quietly: no email and no error loop. Test: Task 4 `TestScanDeletedFile`.
5. **clamd is unreachable**, for example while ClamAV downloads its signatures on first start. The job is retried and its attempts are not used up. Test: Task 4 `TestScanClamdDownKeepsAttempts`.

---

### Task 1: Schema, config and the intake service

**Files:**
- Create: `internal/db/migrations/0005_intake.sql`
- Create: `internal/intake/intake.go` (requests: create, list, get, revoke, validation)
- Create: `internal/intake/access.go` (landing, codes, sessions, `CheckUpload`, `Usage`, context helpers)
- Modify: `internal/mail/templates.go` (four templates)
- Modify: `internal/audit/audit.go` (actions)
- Modify: `internal/sxcrypto/rotate.go` (`sealedCols`)
- Modify: `internal/config/config.go` (scan settings)
- Test: `internal/intake/intake_test.go`, `internal/intake/access_test.go`, `internal/config/config_test.go`, `internal/mail/templates_test.go` (or the existing mail test file)

**Interfaces:**
- **Produces, intake types and the service:**

```go
package intake

var (
	ErrNotFound, ErrGone, ErrBadCode, ErrUnauthorized error
	ErrExtNotAllowed, ErrTooManyFiles, ErrQuotaExceeded             error
)
type ValidationError struct{ Field, Code string } // codes: required, too_many, invalid, out_of_range

type Request struct {
	ID, OwnerID           uuid.UUID
	OwnerName, OwnerEmail string // OwnerName = display_name, or email when empty (as share does)
	Message               string
	ExpiresAt             time.Time
	MaxFiles              int
	MaxTotalBytes         int64
	AllowedExts           []string // lower-case, no dot; empty = any
	RevokedAt             *time.Time
	CreatedAt             time.Time
	FileCount             int   // files received (deleted ones included)
	TotalBytes            int64 // their sizes
	Uploaders             []Uploader // filled by Get only
	URL                   string     // baseURL + "/r/" + token; filled by Get only (opens token_sealed)
}
type Uploader struct {
	ID                           uuid.UUID
	Email                        string
	FirstOpenedAt, LastAccessAt *time.Time
}
type CreateInput struct {
	Emails        []string
	ExpiresAt     time.Time
	MaxFiles      int
	MaxTotalBytes int64
	AllowedExts   []string
	Message       string
}
type Access struct { // a verified uploader's view of one request
	Request  *Request
	Uploader Uploader
}

func NewService(pool *pgxpool.Pool, outbox *mail.Outbox, keys *sxcrypto.Keyring, baseURL string, maxDays int) *Service
func (s *Service) Create(ctx context.Context, owner *auth.User, in CreateInput) (*Request, error)
func (s *Service) List(ctx context.Context, ownerID uuid.UUID) ([]Request, error)
func (s *Service) Get(ctx context.Context, ownerID, id uuid.UUID) (*Request, error) // ErrNotFound if not the caller's
func (s *Service) Revoke(ctx context.Context, ownerID, id uuid.UUID) error
func (s *Service) Landing(ctx context.Context, token string, ip netip.Addr) (*Request, error)
func (s *Service) RequestCode(ctx context.Context, token, email string, ip netip.Addr) (sent bool, err error)
func (s *Service) VerifyCode(ctx context.Context, token, email, code string, ip netip.Addr, ua string) (session string, a *Access, err error)
func (s *Service) Authorize(ctx context.Context, session string, ip netip.Addr) (*Access, error)
func (s *Service) Logout(ctx context.Context, session string) error
```

- **Produces, upload limits and context helpers:**

```go
// CheckUpload locks the request row (SELECT ... FOR UPDATE inside tx) and refuses a new upload of
// size bytes named name. Usage counts files (deleted included) plus in-progress uploads.
func CheckUpload(ctx context.Context, tx pgx.Tx, a *Access, name string, size int64) error
func Usage(ctx context.Context, q Querier, requestID uuid.UUID) (files int, bytes int64, err error)
func WithAccess(ctx context.Context, a *Access) context.Context
func AccessFrom(ctx context.Context) *Access // nil when absent
```

- **Produces, mail templates** (bilingual zh/en like the others, each returning subject and body):
  - `mail.UploadInvitation(url, senderName, message string, expires time.Time)`
  - `mail.NotifyIntakeUpload(uploader, fileName, requestURL string, skipped bool)`. When `skipped`, the body says the file was not virus-scanned because it is over the scan size limit.
  - `mail.NotifyInfected(uploader, fileName, signature, requestURL string)`
  - `mail.NotifyScanError(uploader, fileName, requestURL string)`
- **Produces, audit constants:**
  - `ActRequestCreate = "request.create"`
  - `ActRequestRevoke = "request.revoke"`
  - `ActRequestOTPRequest = "request.otp.request"`
  - `ActRequestOTPVerify = "request.otp.verify"`
  - `ActFileScan = "file.scan"`
- **Produces, config:**
  - `config.ScanConfig{ClamdAddr string; MaxBytes int64}` on `Config.Scan`.
  - Env: `SX_CLAMD_ADDR` (default `clamav:3310`) and `SX_SCAN_MAX_BYTES`. The default is `1 << 30`, and the value must be from 1 to `4000 << 20`.
  - Both are loaded for the web server and the worker.
  - `SX_BASE_URL` becomes required for the worker too, because it builds the links in notification emails.

- [ ] **Step 1: Write migration `0005_intake.sql`**

```sql
-- +goose Up
CREATE TABLE upload_requests (
  id uuid PRIMARY KEY, owner_id uuid NOT NULL REFERENCES users,
  token_hash bytea NOT NULL UNIQUE, token_sealed bytea NOT NULL, message text NOT NULL DEFAULT '',
  expires_at timestamptz NOT NULL, max_files int NOT NULL CHECK (max_files > 0),
  max_total_bytes bigint NOT NULL CHECK (max_total_bytes > 0), allowed_exts text[] NOT NULL DEFAULT '{}',
  revoked_at timestamptz, created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX upload_requests_owner ON upload_requests (owner_id, created_at DESC);
CREATE TABLE request_uploaders (
  id uuid PRIMARY KEY, request_id uuid NOT NULL REFERENCES upload_requests ON DELETE CASCADE,
  email text NOT NULL, first_opened_at timestamptz, last_access_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now());
CREATE UNIQUE INDEX request_uploaders_email ON request_uploaders (request_id, lower(email));
CREATE TABLE request_otps (
  id uuid PRIMARY KEY, uploader_id uuid NOT NULL REFERENCES request_uploaders ON DELETE CASCADE,
  code_hash bytea NOT NULL, attempts int NOT NULL DEFAULT 0, used_at timestamptz,
  expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE request_sessions (
  token_hash bytea PRIMARY KEY, uploader_id uuid NOT NULL REFERENCES request_uploaders ON DELETE CASCADE,
  ip text NOT NULL, user_agent text NOT NULL,
  expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
ALTER TABLE uploads ADD COLUMN request_id uuid REFERENCES upload_requests, ADD COLUMN uploader_id uuid REFERENCES request_uploaders;
ALTER TABLE files ADD COLUMN request_id uuid REFERENCES upload_requests, ADD COLUMN uploader_id uuid REFERENCES request_uploaders,
  ADD COLUMN scan_status text NOT NULL DEFAULT 'none' CHECK (scan_status IN ('none','pending','clean','infected','skipped','error')),
  ADD COLUMN scan_result text NOT NULL DEFAULT '';
CREATE INDEX files_request ON files (request_id) WHERE request_id IS NOT NULL;
CREATE TABLE scan_jobs (
  file_id uuid PRIMARY KEY REFERENCES files ON DELETE CASCADE, attempts int NOT NULL DEFAULT 0,
  lease_until timestamptz, created_at timestamptz NOT NULL DEFAULT now());

-- +goose Down
DROP TABLE scan_jobs;
ALTER TABLE files DROP COLUMN scan_result, DROP COLUMN scan_status, DROP COLUMN uploader_id, DROP COLUMN request_id;
ALTER TABLE uploads DROP COLUMN uploader_id, DROP COLUMN request_id;
DROP TABLE request_sessions, request_otps, request_uploaders, upload_requests;
```

`scan_status` values:
- `none`: staff upload, not scanned.
- `pending`: waiting for a scan.
- `clean`: scanned, nothing found.
- `infected`: quarantined.
- `skipped`: larger than `SX_SCAN_MAX_BYTES`, released with a warning.
- `error`: clamd failed on this file 5 times; blocked.

The owner may download, preview and share only `none`, `clean` and `skipped` (Task 5).

- [ ] **Step 2: Write the failing intake tests**

Use `testdb.New(t)`, a test user, and `mailtest` or an outbox read like `internal/share`'s tests do. Use a fake clock (`s.now`) where expiry matters.

`intake_test.go`:
- **`TestCreateValidation`**: table-driven, expecting a `*ValidationError` with the given `Field`/`Code`:
  - no emails → `emails/required`;
  - 51 emails → `emails/too_many`;
  - `expires_at` 30 min ahead → `expires_at/out_of_range`;
  - `maxDays + 1` → `expires_at/out_of_range`;
  - `MaxFiles` 0 or 1001 → `max_files/out_of_range`;
  - `MaxTotalBytes` 0 → `max_total_bytes/out_of_range`;
  - `AllowedExts` `["p/df"]` → `allowed_exts/invalid`;
  - 51 extensions → `allowed_exts/too_many`;
  - a 2001-rune message → `message/too_many`.
- **`TestCreateNormalisesExts`**: `[".PDF", "pdf", " Docx "]` is stored as `["pdf","docx"]`.
- **`TestCreateSendsInvitations`**: two emails produce two outbox rows addressed to them. The opened body contains `baseURL + "/r/"`. `Get` returns the same `URL`.
- **`TestListGetRevokeOwnerOnly`**: another owner's `Get`/`Revoke` returns `ErrNotFound`. After `Revoke`, `Landing` returns `ErrGone`.

`access_test.go`:
- **`TestCodeFlow`**:
  - `RequestCode` for a listed email returns `sent=true`; for an unlisted one, `sent=false` and no error.
  - `VerifyCode` with a wrong code 5 times, then the right code → `ErrBadCode`.
  - A fresh code → a session; `Authorize(session)` returns an `Access` with the right `Uploader.Email`.
  - `first_opened_at` is set.
  - `Logout` makes `Authorize` return `ErrUnauthorized`.
- **`TestSessionTTL`**: the session expires at `min(now + 24h, request.ExpiresAt)`. After that, `Authorize` returns `ErrUnauthorized`.
- **`TestAuthorizeRechecks`**: revoke the request, or move the clock past expiry → `ErrGone`.
- **`TestCheckUpload`**: request `MaxFiles: 2, MaxTotalBytes: 100, AllowedExts: ["pdf"]`:
  - `"a.PDF", 60` → nil, then insert an `uploads` row of size 60 with `request_id`;
  - `"b.exe", 1` → `ErrExtNotAllowed`; `"noext", 1` → `ErrExtNotAllowed`;
  - `"b.pdf", 41` → `ErrQuotaExceeded`; `"b.pdf", 40` → nil, then insert;
  - `"c.pdf", 0` → `ErrTooManyFiles`.
  - `Usage` returns `(2, 100)`.
  - With empty `AllowedExts`, any name passes the extension check.
- **`TestCheckUploadSerialises`**:
  - Two goroutines each begin a tx, call `CheckUpload` for 60 of 100 bytes, insert an upload row and commit.
  - Exactly one gets `ErrQuotaExceeded`.
  - Use a barrier so both start before either commits; the row lock makes the second wait.

- [ ] **Step 3: Run the tests and confirm they fail**

Run: `go test ./internal/intake/`
Expected: FAIL (the package does not exist).

- [ ] **Step 4: Implement `internal/intake`**

Follow `internal/share` closely:
- `normEmails`, the token scheme (32 random bytes → base64url; SHA-256 stored; sealed with AAD `"requesttoken:" + id`), `check` (revoked or expired → `ErrGone`).
- OTP constants: `otpTTL` 10m, `otpAttempts` 5, `otpsPerHour` 10, `otpsPerDay` 20.
- The verify transaction shape.

Differences from share:
- **No view counting.** No first-open email.
- **Session TTL** is `min(24h, until ExpiresAt)`. Uploads take hours.
- **No IP allow list.** The spec gives upload requests none (§5.3), so there is no `ErrIPDenied`. Do not add one.
- **Ranges:**
  - `max_files` 1–1000;
  - `max_total_bytes` 1–`1<<50`;
  - extensions: trim, lower-case, strip one leading `.`, must match `^[a-z0-9]{1,10}$`, deduplicate, at most 50;
  - message ≤ 2000 runes;
  - emails ≤ 50;
  - expiry from now+1h to now+`maxDays`.
- **`Usage`** sums:

```sql
SELECT count(*), COALESCE(sum(size),0) FROM (
  SELECT size FROM files WHERE request_id = $1
  UNION ALL SELECT size FROM uploads WHERE request_id = $1) t
```

- **`CheckUpload`** order: extension, then `SELECT 1 FROM upload_requests WHERE id = $1 FOR UPDATE`, then `Usage`, then count and bytes.
  - Extension: `strings.TrimPrefix(strings.ToLower(filepath.Ext(name)), ".")` must be in the list (when the list is non-empty).
- **Add** `{"upload_requests", "token_sealed", "requesttoken:"}` to `sxcrypto.sealedCols`, and extend that package's rotation test to cover it.
- **Mail templates and audit constants** as in Interfaces.
- **Config:**
  - `ScanConfig` and its env vars in `load`, for both modes.
  - `SX_BASE_URL` becomes `req` in worker mode.
  - Config tests: `SX_SCAN_MAX_BYTES=4194304001` → error; the defaults are as stated; the worker without `SX_BASE_URL` → error.

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `go test ./internal/intake/ ./internal/config/ ./internal/mail/ ./internal/sxcrypto/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/db/migrations/0005_intake.sql internal/intake internal/mail internal/audit internal/sxcrypto internal/config
git commit -m "feat(intake): upload request schema, service and uploader codes"
```

---

### Task 2: Upload request HTTP API

**Files:**
- Create: `internal/httpapi/requests_handlers.go` (staff endpoints and uploader endpoints)
- Modify: `internal/httpapi/server.go` (`Deps.Requests *intake.Service`, routes)
- Modify: `cmd/secure-exchange/main.go` (construct `intake.NewService`)
- Test: `internal/httpapi/requests_test.go`

**Interfaces:**
- **Consumes:** Task 1's `intake.Service`, `intake.WithAccess`, `intake.Usage` and the audit constants.
- **Produces, staff routes** (all `requireUser`):
  - `POST /api/requests`
    - Body: `{emails, expires_at, max_files, max_total_bytes, allowed_exts, message}`.
    - Returns 201 with the detail object.
    - On a validation error, returns 422 `{"error":"invalid","field":…,"code":…}`, the same body shape `shareErr` produces.
  - `GET /api/requests` returns a list of objects:
    `{id, created_at, expires_at, revoked, expired, file_count, total_bytes, max_files, max_total_bytes, uploader_count}`.
  - `GET /api/requests/{id}` returns the list fields plus:
    - `url`, `message`, `allowed_exts`;
    - `uploaders: [{id, email, first_opened_at, last_access_at}]`;
    - `files: [{id, name, size, uploader_email, created_at, scan_status, scan_result, deleted}]`, newest first.
  - `POST /api/requests/{id}/revoke` returns 204.
- **Produces, uploader routes** (no staff login):
  - `GET /api/r/{token}` returns `{owner_name, message, expires_at, max_files, max_total_bytes, allowed_exts}`.
  - `POST /api/r/{token}/code` and `POST /api/r/{token}/verify` behave exactly like `/api/s/{token}/code|verify`:
    - wrapped in `recipIP` (padded and per-IP limited);
    - `/code` also uses `s.codeLimit` keyed by token and email.
    - `/verify` sets cookie `sx_intake` (HttpOnly, Secure, SameSite Strict, Path `/`, MaxAge = seconds until the session expires) and returns the files body below.
  - `GET /api/r/{token}/files` (`requireUploader`) returns `{files: [{id, name, size, created_at}], files_left, bytes_left}`. The files are the caller's own uploads for this request.
  - `POST /api/r/{token}/logout` clears the cookie and returns 204.
- **Produces, middleware:** `func (s *server) requireUploader(next http.HandlerFunc) http.Handler`.
  - Reads the `sx_intake` cookie, then calls `Requests.Authorize`.
  - Checks that the session's request matches the `{token}` path value (token hash equality, as in `requireRecipient`).
  - Puts the access on the context with `intake.WithAccess`.
  - Task 3 mounts tus behind it.
- **Errors:** `intakeErr` maps:
  - `ErrNotFound` → 404 `not_found`;
  - `ErrGone` → 410 `gone`;
  - `ErrBadCode` → 401 `invalid_code`;
  - `ErrUnauthorized` → 401 `unauthorized`;
  - `ErrExtNotAllowed` → 403 `ext_not_allowed`;
  - `ErrTooManyFiles` → 403 `too_many_files`;
  - `ErrQuotaExceeded` → 403 `quota_exceeded`;
  - anything else → 500.
- **Audit:**
  - `request.create` and `request.revoke`: actor user, target `request`.
  - `request.otp.request` (result `ok`, or `ignored` when not sent) and `request.otp.verify` (`ok`, or `fail` with reason): actor type `uploader`, actor id the email, target `request`.

- [ ] **Step 1: Write the failing tests in `requests_test.go`**

Use `newEnv` from `auth_test.go`. Add `Requests` to the env's Deps the way `Shares` is wired.

- **`TestRequestCreateListGetRevoke`**:
  - create → 201, and the `url` contains `/r/`;
  - list has 1 entry;
  - get shows 2 uploaders;
  - revoke → 204;
  - the landing for that token → 410.
- **`TestRequestCreateInvalid`**: `max_files: 0` → 422 with `field == "max_files"`.
- **`TestRequestOtherOwner404`**: another staff user's GET and revoke → 404.
- **`TestUploaderLandingAndCode`**:
  - the landing shows `allowed_exts`;
  - `/code` for an unlisted email → 200 `{"sent":true}`, and its audit row has result `ignored`;
  - for a listed email → 200 and one outbox row.
- **`TestUploaderVerifySetsCookie`**:
  - read the code from the outbox (as share tests do);
  - `/verify` → 200, with a `Set-Cookie: sx_intake=…; HttpOnly; Secure; SameSite=Strict` header;
  - `/files` with the cookie → `files_left == max_files`.
- **`TestUploaderCookieWrongToken`**: request A's session cookie on request B's `/files` → 401.
- **`TestUploaderVerifyRateLimited`**: the 11th `/verify` from one IP in quick succession → 429. This reuses the per-IP limiter, so set `CodeDelay` to 0 in the env.

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./internal/httpapi/ -run 'Request|Uploader'`
Expected: FAIL.

- [ ] **Step 3: Implement the handlers, `requireUploader`, the routes and `main.go` wiring.**

The detail `files` come from one query:

```sql
SELECT f.id, f.name, f.size, u.email, f.created_at, f.scan_status, f.scan_result, f.deleted_at IS NOT NULL
FROM files f JOIN request_uploaders u ON u.id = f.uploader_id
WHERE f.request_id = $1
ORDER BY f.created_at DESC
```

Add `Get`'s owner check before it.

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `go test ./internal/httpapi/ -run 'Request|Uploader'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/httpapi cmd/secure-exchange/main.go
git commit -m "feat(httpapi): upload request and uploader endpoints"
```

---

### Task 3: External uploads through tus

**Files:**
- Modify: `internal/upload/tus.go`
- Modify: `internal/httpapi/server.go` (mount `/api/r/{token}/uploads/` behind `requireUploader` and a per-IP limiter)
- Test: `internal/upload/intake_test.go` (new), plus existing `tus_test.go` tweaks if the constructor changes

**Interfaces:**
- **Consumes:** `intake.AccessFrom`, `intake.CheckUpload`, Task 2's `requireUploader`, and the intake error values.
- **Produces:**
  - **Routes:** the tus handler also serves `/api/r/{token}/uploads/` and `/api/r/{token}/uploads/{id}`, for OPTIONS, POST, HEAD, PATCH and DELETE.
  - **`Location`** is `r.URL.Path + id` for both mounts; the POST path ends in `/`.
  - **Caller identity:** `auth.UserFrom(ctx)` means staff (owner = user, `request_id`/`uploader_id` NULL). `intake.AccessFrom(ctx)` means external (owner = `Request.OwnerID`, request and uploader set). With neither, 401.
  - **`load`** matches `id = $1 AND owner_id = $2 AND uploader_id IS NOT DISTINCT FROM $3`, so staff and uploaders never see each other's uploads.
  - **External `create`:** inside one tx, runs `intake.CheckUpload`, then `INSERT INTO uploads (..., request_id, uploader_id)`. Errors become 403 with a plain-text body equal to the error code (`ext_not_allowed`, `too_many_files` or `quota_exceeded`). tus-js-client surfaces the body to the page.
  - **`finish`**, for external uploads:
    - inserts `files` with `request_id`, `uploader_id` and `scan_status = 'pending'`, plus `INSERT INTO scan_jobs (file_id) VALUES ($1)` in the same tx;
    - the audit event has actor type `uploader`, actor id the uploader email, and detail `{"name", "size", "request_id"}`.
  - **Staff uploads** are unchanged (`scan_status` defaults to `none`).

- [ ] **Step 1: Write the failing tests in `intake_test.go`**

Build the handler with a fake context-injecting wrapper that does `intake.WithAccess` (the HTTP middleware is already covered by Task 2). Reuse the tus helpers in `tus_test.go`.

- **`TestIntakeUploadCreatesPendingFile`**:
  - POST, then PATCH the whole body.
  - `files` row: `owner_id` = request owner, `request_id`/`uploader_id` set, `scan_status = 'pending'`.
  - A `scan_jobs` row exists.
  - The `Location` starts with `/api/r/<token>/uploads/`.
- **`TestIntakeUploadLimits`**: `AllowedExts ["pdf"]`, `MaxFiles 1`:
  - `x.exe` → 403 body `ext_not_allowed`;
  - `a.pdf` → 201;
  - a second `b.pdf` → 403 body `too_many_files`.
- **`TestIntakeUploadIsolation`**: create an upload as uploader A, then:
  - uploader B's HEAD and PATCH → 404;
  - staff (owner) HEAD via `/api/uploads/{id}` → 404;
  - the reverse: a staff upload HEAD as uploader A → 404.
- **`TestIntakePatchAfterRevoke`** (through the real `httpapi` server, in `internal/httpapi/requests_test.go` if that is simpler):
  - verify, POST, PATCH chunk 1, revoke the request;
  - the next PATCH → 410;
  - the `uploads` row offset is unchanged.
- **`TestStaffUploadStillNone`**: an existing-style staff upload → `scan_status = 'none'`, and no `scan_jobs` row.

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./internal/upload/ ./internal/httpapi/ -run 'Intake|StaffUpload'`
Expected: FAIL.

- [ ] **Step 3: Implement.**
  - Add an `uploader_id`/`request_id` pair to the `upload` struct.
  - Resolve the caller in `ServeHTTP` instead of checking `auth.UserFrom` alone.
  - Move `create`'s INSERT into a tx when the caller is external.
  - Mount in `server.go`:
    `mux.Handle("/api/r/{token}/uploads/", perIPUpload(s.requireUploader(s.Uploads.ServeHTTP)))`
    - `perIPUpload` is `rateLimit(s.ip, rate.Every(time.Second), 120)`. The spec rate-limits uploads, and one tus PATCH per 64 MiB chunk stays far below this.
  - Check `upload/janitor.go`: stale external uploads must be swept like staff ones. Its DELETE is by id, so this should need no change; confirm it with a test row.

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `go test ./internal/upload/ ./internal/httpapi/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/upload internal/httpapi
git commit -m "feat(upload): external uploads via request links with limits"
```

---

### Task 4: ClamAV scanning

**Files:**
- Create: `internal/scan/clamd.go` (INSTREAM client)
- Create: `internal/scan/worker.go` (queue claim, scan, record, notify)
- Modify: `cmd/secure-exchange/main.go` (`worker` runs the scan loop alongside the preview worker)
- Modify: `docker-compose.yml` (clamav service, `updates` network, worker `SX_BASE_URL`)
- Create: `clamd.conf` (repo root, next to `Caddyfile`)
- Modify: `docker-compose.dev.yml` (clamav under `profiles: [scan]`, host port 53310)
- Modify: `.env.example`, `README.md`, `README.zh-TW.md` (a ClamAV section)
- Test: `internal/scan/clamd_test.go`, `internal/scan/worker_test.go`

**Interfaces:**
- **Consumes:**
  - `config.ScanConfig`;
  - the `files.scan_*` columns and `scan_jobs`;
  - the `mail.Notify*` templates;
  - `audit.ActFileScan`;
  - `sxcrypto.OpenPlain` (as in `preview.readHead`), with the full file streamed.
- **Produces:**

```go
package scan

var ErrUnavailable = errors.New("scan: clamd unreachable") // dial failure: not the file's fault

type Verdict struct {
	Infected  bool
	Signature string // e.g. "Eicar-Test-Signature" when Infected
}

// Scan streams r to clamd at addr with zINSTREAM (4-byte big-endian length-prefixed chunks of
// at most 1 MiB, then a zero length) and parses the reply:
//   "stream: OK"          → Verdict{}
//   "stream: <sig> FOUND" → Verdict{true, sig}
//   anything else (e.g. "INSTREAM size limit exceeded. ERROR") → error
// A dial error wraps ErrUnavailable.
func Scan(ctx context.Context, addr string, r io.Reader) (Verdict, error)

type Worker struct {
	Pool    *pgxpool.Pool
	Store   blob.Store
	Keys    *sxcrypto.Keyring
	Outbox  *mail.Outbox // enqueue only: built with a nil sender, Run never called in the worker
	Audit   *audit.Log
	Cfg     config.ScanConfig
	BaseURL string
	Lease   time.Duration // 0 = 30 minutes
}
func (w *Worker) Run(ctx context.Context) // poll every 2s like preview.Worker
func (w *Worker) RunOnce(ctx context.Context) (bool, error) // one claim+scan; false = queue empty (tests drive this)
```

- **Claim:** a single statement:

```sql
UPDATE scan_jobs SET attempts = attempts + 1, lease_until = now() + make_interval(secs => $1)
WHERE file_id = (SELECT file_id FROM scan_jobs
  WHERE lease_until IS NULL OR lease_until < now()
  ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED)
RETURNING file_id, attempts
```

- **Outcomes**, each recorded in one tx that locks the file row:
  - **File already `deleted_at`:** delete the job. No email, no audit.
  - **`size > Cfg.MaxBytes`:** `skipped`, without contacting clamd.
  - **Clean:** `clean`.
  - **Found:** `infected`, with `scan_result` = the signature.
  - **`ErrUnavailable`:** `UPDATE scan_jobs SET attempts = attempts - 1, lease_until = now() + interval '30 seconds'`. The file status is unchanged and the attempts are not used up.
  - **Other error with attempts < 5:** `lease_until = now() + interval '30 seconds'`.
  - **Other error at attempt 5:** `error`, with `scan_result` = the cleaned message (≤ 200 runes).
  - **Final statuses** delete the `scan_jobs` row and update `files.scan_status`/`scan_result`.
- **Emails**, enqueued in the same tx:
  - `clean` and `skipped`: `NotifyIntakeUpload` to the owner (`skipped` passed through).
  - `infected`: `NotifyInfected` to the owner and to every `users` row with `role = 'admin' AND NOT disabled`, deduplicated by address.
  - `error`: `NotifyScanError` to the owner.
  - `requestURL` = `BaseURL + "/requests/" + request_id`.
- **Audit** after the commit: `file.scan`, actor type `system`, actor id `scanner`, target `file`, result = the final status, detail `{"signature"}` when infected.
- **Plaintext:** it exists only in memory, in the stream between the decrypting reader and the TCP connection. The clamd connection gets a deadline of `ctx` plus 20 minutes, and the scan context is the claimed lease minus a minute.

- [ ] **Step 1: Write the failing tests**

`clamd_test.go`:
- Start a fake clamd: a `net.Listen("tcp", "127.0.0.1:0")` goroutine that reads `zINSTREAM\0`, reads the length-prefixed chunks up to the zero length and records the total bytes, then writes a canned reply plus `\0`.
- **`TestScanClean`**: 3 MiB input → the fake receives exactly 3 MiB in chunks of ≤ 1 MiB; returns `Verdict{}`.
- **`TestScanFound`**: reply `stream: Eicar-Test-Signature FOUND` → `Verdict{true, "Eicar-Test-Signature"}`.
- **`TestScanErrorReply`**: reply `INSTREAM size limit exceeded. ERROR` → an error that is not `ErrUnavailable`.
- **`TestScanDialFail`**: a closed port → `errors.Is(err, ErrUnavailable)`.
- **`TestScanRealClamd`**: skipped unless `SX_TEST_CLAMD_ADDR` is set. The EICAR string (`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`) must come back with `Infected == true`.

`worker_test.go` (testdb). Insert a file the way `preview`'s tests do: encrypted into a `blob.NewLocal` temp store, with a `scan_jobs` row, and a request, uploader and owner. Point `Cfg.ClamdAddr` at a fake clamd.
- **`TestScanCleanNotifiesOwner`**: `clean`, the job row is gone, one outbox row to the owner, one `file.scan` audit row.
- **`TestScanInfectedNotifiesOwnerAndAdmins`**: two admins plus the owner (who is not an admin) → `infected`, `scan_result` = the signature, three outbox rows.
- **`TestScanSkippedOverMax`**: `MaxBytes` = 10 and the file is 11 bytes → `skipped`. The fake clamd saw no connection. The email is sent with `skipped`.
- **`TestScanClamdDownKeepsAttempts`**: the address is a closed port. After `RunOnce`, the status is still `pending`, `attempts == 0`, and `lease_until` is in the future.
- **`TestScanErrorAfterFiveAttempts`**: the fake replies with an ERROR every time. Run 5 claims, expiring the lease between runs with `UPDATE scan_jobs SET lease_until = now() - interval '1s'` → `error`, and one email.
- **`TestScanDeletedFile`**: `deleted_at` is set → the job is gone, the status is still `pending`, there are 0 outbox rows, and the fake saw no connection.

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./internal/scan/`
Expected: FAIL.

- [ ] **Step 3: Implement `internal/scan` and wire it in `main.go`'s `worker`**

`go (&scan.Worker{...}).Run(ctx)` runs before the blocking preview `Run`. Build `audit.New(pool)` and `mail.NewOutbox(pool, keys, nil)`.

- [ ] **Step 4: Add deployment**

`docker-compose.yml`:

```yaml
  # Virus scanner for external uploads. Needs the internet for signature updates (freshclam),
  # so it sits on its own egress network, never on sx (whose subnet is a trusted proxy range).
  clamav:
    image: clamav/clamav:1.4
    restart: unless-stopped
    volumes:
      - clamdb:/var/lib/clamav
      - ./clamd.conf:/etc/clamav/clamd.conf:ro
    tmpfs:
      - /tmp:size=1200m,mode=1777 # clamd spools INSTREAM data here: scanned plaintext stays in RAM
    mem_limit: 4g
    memswap_limit: 4g
    networks: [backend, updates]
```

- Add `clamdb:` to volumes.
- Add the network `updates: {}`.
- Add `SX_BASE_URL: https://${SX_DOMAIN:?…}` to the worker's `environment`.
- Add `depends_on: clamav: {condition: service_started}` to the worker.

`clamd.conf`: start from the image's own file:

```bash
docker run --rm --entrypoint cat clamav/clamav:1.4 /etc/clamav/clamd.conf
```

Keep its settings and set:
- `TCPSocket 3310`
- `TemporaryDirectory /tmp`
- `StreamMaxLength 1100M`
- `MaxFileSize 1100M`
- `MaxScanSize 4000M`
- `Foreground yes`

Comment that `StreamMaxLength`, `MaxFileSize` and the `/tmp` tmpfs must stay ≥ `SX_SCAN_MAX_BYTES`. Check it with:

```bash
docker run --rm -v "$PWD/clamd.conf:/etc/clamav/clamd.conf:ro" --entrypoint clamconf clamav/clamav:1.4
```

The output must report no config error.

`docker-compose.dev.yml`: the same service under `profiles: [scan]`, publishing `53310:3310`.

`.env.example`: `SX_SCAN_MAX_BYTES`, with a comment.

README (en and zh-TW), a ClamAV section covering:
- external uploads are scanned;
- the first start downloads signatures (several minutes), and pending files wait;
- files over `SX_SCAN_MAX_BYTES` are released unscanned with a warning;
- how to raise the limit (all three places in `clamd.conf`);
- clamd needs ~1.5–3 GB RAM.

- [ ] **Step 5: Run the tests and confirm they pass**

```bash
go test ./internal/scan/ ./cmd/...
docker compose -f docker-compose.dev.yml --profile scan up -d clamav
```

Wait until `docker compose -f docker-compose.dev.yml logs clamav` shows that clamd is listening. Then:

```bash
SX_TEST_CLAMD_ADDR=localhost:53310 go test ./internal/scan/ -run Real
```

Expected: PASS. Also run `docker compose config -q` to validate both compose files.

- [ ] **Step 6: Commit**

```bash
git add internal/scan cmd/secure-exchange/main.go docker-compose.yml docker-compose.dev.yml clamd.conf .env.example README.md README.zh-TW.md
git commit -m "feat(scan): ClamAV scanning of external uploads with quarantine and notices"
```

---

### Task 5: Scan gating for owners

**Files:**
- Modify: `internal/httpapi/files_handlers.go` (list fields, `ownFile` loads the scan status, new `ownCleanFile`)
- Modify: `internal/httpapi/preview_handlers.go` (the `own` wrapper uses `ownCleanFile`)
- Modify: `internal/share/share.go` (`Create` refuses unscanned or quarantined files)
- Modify: `internal/httpapi/shares_handlers.go` only if `shareErr` needs the new code mapped (it already passes `ValidationError` through)
- Test: `internal/httpapi/scan_gate_test.go`, `internal/share/share_test.go`

**Interfaces:**
- **Consumes:** the `files.scan_status`, `scan_result` and `request_id` columns.
- **Produces:**
  - `GET /api/files` items gain `scan_status`, `scan_result` and `request_id` (null for staff uploads).
  - `fileRow.scan string`.
  - `func (s *server) ownCleanFile(w http.ResponseWriter, r *http.Request) (*fileRow, bool)`: `ownFile`, then:
    - `pending` → 409 `scan_pending`;
    - `infected` → 403 `quarantined`;
    - `error` → 403 `scan_failed`;
    - `none`, `clean` and `skipped` pass.
  - `downloadFile` and owner previews use it. `deleteFile` keeps `ownFile`, so quarantined files can be deleted.
  - `share.Service.Create` → `invalid("file_ids", "not_scanned")` when any file's `scan_status` is not in `('none','clean','skipped')`. The check goes in the same tx as the ownership count.

- [ ] **Step 1: Write the failing tests**

`scan_gate_test.go`: insert files directly with each status.
- **`TestOwnerDownloadGate`**:
  - `pending` → 409 `scan_pending`;
  - `infected` → 403 `quarantined`;
  - `error` → 403 `scan_failed`;
  - `clean`, `skipped` and `none` → 200.
- **`TestOwnerPreviewGate`**: `GET /api/files/{id}/preview` for `infected` → 403.
- **`TestDeleteQuarantined`**: DELETE on an `infected` file → 204.
- **`TestListFilesScanFields`**: the list shows `scan_status: "infected"` and the signature in `scan_result`.

`share_test.go`:
- **`TestCreateRejectsUnscanned`**: `pending` → `file_ids/not_scanned`, and likewise for `infected`.

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./internal/httpapi/ ./internal/share/ -run 'Gate|Quarantined|ScanFields|Unscanned'`
Expected: FAIL.

- [ ] **Step 3: Implement as in Interfaces.**

- [ ] **Step 4: Run the full Go suite, lint and coverage**

```bash
go test ./... -coverprofile=c.out
go tool cover -func=c.out | tail -1
```

Expected: PASS, total ≥ 90%. Then run the lint command from Global Constraints; expected: 0 issues.

- [ ] **Step 5: Commit**

```bash
git add internal/httpapi internal/share
git commit -m "feat: block unscanned and quarantined files from download, preview and sharing"
```

---

### Task 6: Web UI and docs

**Files:**
- Create: `web/src/pages/Requests.tsx` (list plus a "new request" form inline at the top)
- Create: `web/src/pages/RequestDetail.tsx`
- Create: `web/src/pages/intake/Upload.tsx` (external `/r/:token`)
- Modify:
  - `web/src/main.tsx`: routes `/requests`, `/requests/:id`, `/r/:token`.
  - `web/src/components/Shell.tsx`: nav link.
  - `web/src/components/Uploader.tsx`: new props.
  - `web/src/pages/Files.tsx`: scan badge; disabled actions.
  - `web/src/api.ts`.
  - `web/src/i18n/en.json`, `web/src/i18n/zh-TW.json`.
  - `README.md`, `README.zh-TW.md`: an "Upload requests" section.
- Test: `Requests.test.tsx`, `RequestDetail.test.tsx`, `intake/Upload.test.tsx`, plus updates to `Uploader.test.tsx`, `Files.test.tsx` and `Shell.test.tsx`

**Interfaces:**
- **Consumes:** Task 2's JSON shapes, Task 3's tus routes and 403 bodies, and Task 5's file fields.
- **Produces:**
  - `api.ts`: types `UploadRequest`, `UploadRequestDetail`, `IntakeLanding` and `IntakeFiles`. Methods:
    - `requests()`, `request(id)`, `createRequest(body)`, `revokeRequest(id)`;
    - `intakeLanding(token)`, `intakeCode(token, email)`, `intakeVerify(token, email, code)`, `intakeFiles(token)`, `intakeLogout(token)`.
  - `FileInfo` gains `scan_status`, `scan_result` and `request_id`.
  - `Uploader` props:

```ts
{
  onDone: () => void;
  endpoint?: string;                        // default "/api/uploads/"
  accept?: string;                          // e.g. ".pdf,.docx"
  check?: (f: File) => string | null;       // i18n key → file rejected before upload
  onError?: (status: number, body: string) => void;
}
```

- **Behaviour:**
  - **Requests page:**
    - Form fields: emails (comma or newline separated), expiry (date input, default +7 days), max files (default 10), max total size in GB (default 10), allowed extensions (comma separated, optional), message.
    - The table shows created, expires, status, files `n / max`, size `used / max`, and a link to the detail.
  - **Detail page:**
    - The link URL with a copy button, the uploaders, and the files with a scan badge. Badge keys: `scan.pending`, `scan.clean`, `scan.infected` (with the signature), `scan.skipped`, `scan.error`.
    - A revoke button that asks for confirmation first.
  - **Files page:**
    - Same scan badge, shown for rows with `request_id`.
    - The download link, view button and share checkbox are disabled unless `scan_status` is one of `none`, `clean` or `skipped`.
    - Polls every 5 s while any file is `pending`, extending the existing `anyPending` condition.
  - **External upload page** (`/r/:token`):
    - Same three-step flow and error mapping as `recipient/Access.tsx`: landing/email, then code, then upload. Show the landing message, the owner name and the expiry.
    - The upload step shows limits (allowed extensions, files left, size left) and an `Uploader` with `endpoint = /api/r/${token}/uploads/`.
    - The `accept` attribute comes from the extensions.
    - `check` rejects by extension, by `files_left`, and by `bytes_left` minus the sizes queued in this session.
    - Below it, a list of "your uploaded files".
    - On `onDone`, refresh the list.
    - On `onError`:
      - 403 `ext_not_allowed`, `too_many_files` or `quota_exceeded` → the matching message;
      - 401 or 410 → re-fetch `/files`; if that 401s, go back to the email step with `sessionEnded`.
    - A logout button.
  - **Shell:** a "Requests" nav link next to Shares.

- [ ] **Step 1: Write the failing tests**

Use the vitest + testing-library style of `Access.test.tsx`; mock `api` and `tus-js-client` the way the existing tests do.

- **`Requests.test.tsx`**:
  - `creates a request with parsed emails and exts`: `createRequest` receives `emails ["a@x.com","b@y.com"]`, `allowed_exts ["pdf","docx"]` and `max_total_bytes 10 * 1024 ** 3`.
  - `lists requests with usage`.
- **`RequestDetail.test.tsx`**:
  - `shows infected badge with signature`;
  - `revoke asks for confirmation`.
- **`intake/Upload.test.tsx`**:
  - `email → code → upload step shows limits`;
  - `rejects disallowed extension before upload`: no `Upload` is constructed, and the message is shown;
  - `upload failure re-checks session`: `onError(401)` and then a 401 from `intakeFiles` → the email step with the session-ended text;
  - `quota error shows message`: `onError(403, "quota_exceeded")`.
- **`Uploader.test.tsx`**: `uses endpoint prop`; `check rejects file`.
- **`Files.test.tsx`**: `quarantined file has no download or share`; `pending scan polls`.

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `cd web && npx vitest run`
Expected: FAIL in the new tests.

- [ ] **Step 3: Implement the components, routes, api and i18n (both languages)**

Then add the README "Upload requests" section, in English and zh-TW: how to create a link, what uploaders see, the limits, the scan states and what each means for the staff member.

- [ ] **Step 4: Run the tests and confirm they pass**

```bash
cd web && npx vitest run --coverage && npx tsc -b
```

Expected: all tests pass, coverage thresholds pass, and `tsc` is clean.

- [ ] **Step 5: Commit**

```bash
git add web README.md README.zh-TW.md
git commit -m "feat(web): upload request pages, external upload page, scan status"
```
