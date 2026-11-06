# Phase 7.1 — Admin Enforcement Rules Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the nine site-wide admin rules of spec §3, enforce them server-side at creation and at every access, and add an admin page to edit them.

**Architecture:** A new `internal/rules` package owns one row of rules in table `site_rules` and the pure matchers (domain, IP, extension). Every enforcement point reads the row fresh from PostgreSQL on each check, with no cache, so a change applies immediately on every app instance. Share access applies the rules in one choke point inside `internal/share/access.go`. External IP limits are one HTTP middleware placed on the external route groups. Retention is a sweeper goroutine in the app process.

**Tech Stack:** Go 1.26, pgx/v5, goose; React 19 + TS, vitest, react-i18next.

**Spec:** `docs/superpowers/specs/2026-11-07-phase7-admin-design.md` (§3, §9). Parent: `docs/superpowers/specs/2026-10-24-secure-exchange-design.md` §5.7.

## Global Constraints

- Every rule is checked on the server. A UI lock is only a hint, and an API call must never bypass a rule (parent spec anti-goal).
- **Existing shares obey the stricter rule at every view and download:**
  - forced watermark adds a watermark;
  - a download ban makes a share view-only;
  - a blocked or non-allowed domain denies that recipient.
- Shares are never deleted because of a rule change. Owners get one digest mail each.
- The download ban has **no exemptions**. It covers one-time shares and vendor shares. Staff downloading their own files are not affected.
- External limits (extensions, size) apply to both upload-request uploads and vendor uploads. A request's own `allowed_exts` and `max_total_bytes` still apply on top, so the stricter one wins.
- External uploads count against the receiving staff member's quota. Soft-deleted files do not count.
- Retention covers:
  - files referenced by ≥1 share;
  - files received through an upload request.

  It never covers vendor-direct uploads or staff files that were never shared.
- The global IP list gates only external endpoints: recipient, uploader, vendor and invite. An empty list means unrestricted. Client IP comes from the existing `ClientIP`/`SX_TRUSTED_PROXIES`.
- When the block and allow lists overlap, block wins. Domain rules also apply to vendor-account emails.
- `SX_SHARE_MAX_DAYS` only seeds the row when it is first created. `SX_MAX_FILE_SIZE` stays the hard cap: `max_file_bytes` may only be lower.
- Every rule change writes audit `rules.update` with `detail {before, after}`. Retention deletions write audit `file.retention_delete`, actor type `system`.
- UI strings go in both `web/src/i18n/en.json` and `zh-TW.json`; `keys.test.ts` enforces matching key sets.
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Never force-push.
- Go tests need `SX_TEST_DATABASE_URL`. Locally use `postgres://sx:sx@localhost:55432/sx?sslmode=disable`.

## Rulings made while planning

- **Max days and the size limits apply only at creation.** They are creation limits, not properties a live share "violates". Existing longer or larger shares keep running. The download, watermark and domain rules are re-checked at every access.
- **A locked option is rejected, not coerced.** If `allow_download=true` while downloads are banned, or `watermark=false` while the watermark is forced, the API returns 422 `allow_download/locked` or `watermark/locked`. The stored row then always tells the truth.
- **The tightening digest is computed synchronously** in the PUT request, not in a background job. The site has hundreds of users, so this is cheap, and the response returns `affected_shares`. Spec §9 said "background". This is simpler and gives the same result.
- **An IP change is not "share-specific" and sends no digest.** Only download, watermark and domain changes do.
- **Domain matching:** an entry `example.com` matches `example.com` and any subdomain (`a.example.com`).
- **No admin-only GET.** `GET /api/rules` (any staff) returns the whole rules object, for the share dialog's locks and hints. Nothing in it is secret from staff.

## Review Focus

1. **A share created before the download ban.** The recipient's file list must show `allow_download:false`, and `GET …/content` must return 403 `view_only`. This also applies to vendor shares.
2. **An unpreviewable file in a share once downloads are banned.** The recipient UI shows "blocked by admin", not a broken viewer. Creating a new share with that file returns 422 `file_ids/not_previewable`.
3. **A vendor whose email domain is blocked after the vendor was created.** Their existing share access returns 403 `domain_blocked` (vendor path).
4. **A tus upload whose declared `Upload-Length` would exceed the owner's quota by a single byte.** It is refused. Concurrent uploads must not both slip through (the owner row is locked).
5. **A file shared twice, where one share ended long ago and the other is still active.** Retention must not delete it.

---

### Task 1: `internal/rules` package and migration

**Files:**
- Create: `internal/db/migrations/0007_rules.sql`
- Create: `internal/rules/rules.go`
- Test: `internal/rules/rules_test.go`

**Interfaces:**
- Produces:
  ```go
  type Rules struct {
      ForceWatermark   bool           `json:"force_watermark"`
      ForbidDownload   bool           `json:"forbid_download"`
      ShareMaxDays     int            `json:"share_max_days"`     // 1..365
      ShareDefaultDays int            `json:"share_default_days"` // 1..ShareMaxDays
      MaxFileBytes     int64          `json:"max_file_bytes"`     // 0 = only the SX_MAX_FILE_SIZE cap
      MaxShareBytes    int64          `json:"max_share_bytes"`    // 0 = unlimited
      DomainBlock      []string       `json:"domain_block"`
      DomainAllow      []string       `json:"domain_allow"`
      ExternalIPAllow  []netip.Prefix `json:"external_ip_allow"`
      UploadExts       []string       `json:"upload_exts"`        // lowercase, no dot; empty = any
      UploadMaxBytes   int64          `json:"upload_max_bytes"`   // 0 = unlimited
      QuotaBytes       int64          `json:"quota_bytes"`        // 0 = unlimited
      RetentionDays    int            `json:"retention_days"`     // 0 = never
  }
  type ValidationError struct{ Field, Code string } // Error() "rules: <field> <code>"
  type Service struct{ /* pool, hardMaxFile */ }
  func New(pool *pgxpool.Pool, hardMaxFile int64) *Service
  func (s *Service) Seed(ctx context.Context, shareMaxDays int) error // INSERT … ON CONFLICT DO NOTHING; slog.Warn if the existing max differs
  func (s *Service) Get(ctx context.Context) (Rules, error)
  func (s *Service) Update(ctx context.Context, tx pgx.Tx, r Rules) (before Rules, err error) // validates and normalises r in place
  func (s *Service) HardMaxFile() int64
  func (r Rules) DomainAllowed(email string) bool
  func (r Rules) IPAllowed(ip netip.Addr) bool
  func (r Rules) ExtAllowed(name string) bool
  func ParsePrefixes(ss []string, max int) ([]netip.Prefix, error) // moved from share.parseIPs: bare IP or CIDR, masked
  ```

- [ ] **Step 1: Write the migration.**
  - Table `site_rules`, one row:
    ```sql
    id int PRIMARY KEY CHECK (id = 1)
    force_watermark bool, forbid_download bool
    share_max_days int, share_default_days int
    max_file_bytes bigint, max_share_bytes bigint
    domain_block text[], domain_allow text[]
    external_ip_allow cidr[]
    upload_exts text[], upload_max_bytes bigint
    quota_bytes bigint, retention_days int
    updated_at timestamptz
    ```
  - Everything is `NOT NULL` with defaults: false / 0 / `'{}'`. `share_default_days` defaults to 7.
  - Down: `DROP TABLE site_rules`.

- [ ] **Step 2: Write failing tests in `rules_test.go`.**
  - `TestSeedOnceAndGet`:
    - `Seed(ctx, 30)` then `Get` → `ShareMaxDays==30`, `ShareDefaultDays==7`.
    - `Seed(ctx, 90)` → `Get` still returns 30.
    - With `Seed(ctx, 5)` on an empty table → `ShareDefaultDays==5` (the default is `min(7, max)`).
  - `TestUpdateValidates`, table-driven. Each case expects a `*ValidationError` with the field and code shown:

    | Input | Field | Code |
    |---|---|---|
    | `ShareMaxDays 0` | `share_max_days` | `out_of_range` |
    | `ShareMaxDays 366` | `share_max_days` | `out_of_range` |
    | `ShareDefaultDays > ShareMaxDays` | `share_default_days` | `out_of_range` |
    | `MaxFileBytes > hardMaxFile` | `max_file_bytes` | `out_of_range` |
    | any negative byte field | (that field) | `out_of_range` |
    | `RetentionDays 3651` | `retention_days` | `out_of_range` |
    | `DomainBlock ["bad domain"]` | `domain_block` | `invalid` |
    | more than 200 domains | (that list) | `too_many` |
    | `UploadExts ["ex e"]` | `upload_exts` | `invalid` |

    A valid update normalises:
    - `" Example.COM "` → `"example.com"`;
    - `".PDF"` → `"pdf"`;
    - duplicates are dropped.

    It returns the previous rules as `before`.
  - `TestDomainAllowed`:
    - block `["evil.com"]` denies `a@evil.com` and `a@x.evil.com`, but not `a@notevil.com`;
    - allow `["corp.com"]` denies `a@other.com`;
    - allow `["corp.com"]` plus block `["corp.com"]` denies `a@corp.com`;
    - empty lists allow everything.
  - `TestIPAllowed`: an empty list allows; `10.0.0.0/8` allows `10.1.2.3` and the IPv4-mapped `::ffff:10.1.2.3`, and denies `192.168.1.1`.
  - `TestExtAllowed`: `["pdf"]` allows `a.PDF` and denies `a.exe` and `noext`; an empty list allows everything.

- [ ] **Step 3: Run the tests.**
  - Run: `go test ./internal/rules/`
  - Expected: FAIL (package does not exist).

- [ ] **Step 4: Implement `rules.go`.**
  - `Get` is a single `SELECT … WHERE id=1`.
  - `Update`:
    - runs `SELECT … FOR UPDATE` in `tx` to read `before`;
    - validates;
    - runs `UPDATE … , updated_at=now()`.
  - Move `parseIPs` out of `internal/share/share.go:212` into `ParsePrefixes`, and make share call it (no behaviour change; share's existing tests still pass).
  - `ExternalIPAllow` allows at most 100 entries, error `external_ip_allow/too_many` or `invalid`.
  - Domain validity: lowercase, `[a-z0-9.-]`, at least one dot, length ≤ 253.
  - Extensions: `[a-z0-9]{1,16}`.

- [ ] **Step 5: Run the tests.**
  - Run: `go test ./internal/rules/ ./internal/share/`
  - Expected: PASS.

- [ ] **Step 6: Commit.**
  - Message: `feat(rules): site rules table, service and matchers`.

### Task 2: Wire rules in and enforce at creation (shares, vendors, intake)

**Files:**
- Modify:
  - `cmd/secure-exchange/main.go`
  - `internal/httpapi/server.go` (add `Rules *rules.Service` to `Deps`)
  - `internal/share/share.go`
  - `internal/intake/intake.go`
  - `internal/vendor/vendor.go`
  - `internal/httpapi/shares_handlers.go`
  - `internal/httpapi/auth_test.go` (`newEnv` builds the rules service)
- Test:
  - `internal/share/rules_test.go`
  - `internal/vendor/vendor_test.go`
  - `internal/intake/` (the existing test file covering request expiry)

**Interfaces:**
- Consumes: Task 1 `rules.Service`, `Rules` and its matchers.
- Produces:
  - `share.NewService(pool, outbox, keys, baseURL string, rules *rules.Service)`. This replaces `maxDays int`.
  - `intake.NewService(pool, outbox, keys, baseURL string, rules *rules.Service)`. The request expiry limit becomes `Rules.ShareMaxDays`.
  - `vendor.NewService(pool, users, sessions, outbox, baseURL, mode string, rules *rules.Service)`.
  - `httpapi.Deps.Rules *rules.Service`.
  - main calls `rules.New(pool, cfg.MaxFileSize)` and then `Seed(ctx, cfg.ShareMaxDays)` before serving.

- [ ] **Step 1: Write failing tests in `internal/share/rules_test.go`.**
  - Set the rules through `Update` in a tx.
  - Expected validation errors from `Create`:

    | Rule set | Input | Field / code |
    |---|---|---|
    | `ForbidDownload` | `AllowDownload:true` | `allow_download` / `locked` |
    | `ForceWatermark` | `Watermark:false` | `watermark` / `locked` |
    | `ShareMaxDays=3` | `ExpiresAt` now+4d | `expires_at` / `out_of_range` |
    | `MaxShareBytes=10` | two files of 6 bytes | `file_ids` / `too_large` |
    | `DomainBlock ["evil.com"]` | `Emails ["a@evil.com"]` | `emails` / `domain_blocked` |
    | (same) | via `AddRecipients` | `emails` / `domain_blocked` |
    | (same) | `VendorIDs` of a vendor `v@evil.com` | `vendor_ids` / `domain_blocked` |

  - `ForbidDownload` plus a file whose preview status is `unsupported` returns `file_ids/not_previewable`. This is the existing check, which runs because `allow_download` must be false.
- [ ] **Step 2: Write failing tests in vendor and intake.**
  - In `vendor_test.go`: `DomainAllow ["corp.com"]`, then `Create` with `x@other.com` returns `email/domain_blocked`.
  - In intake: with `ShareMaxDays=3`, a request expiring now+4d is rejected with its existing out-of-range error.
- [ ] **Step 3: Run the tests.**
  - Run: `go test ./internal/share/ ./internal/vendor/ ./internal/intake/`
  - Expected: FAIL.
- [ ] **Step 4: Implement.**
  - Domain checks:
    - In `share.recipients()` (share.go:109), the single choke point for Create and AddRecipients: check each email with `DomainAllowed`, and each vendor's `Email`.
    - In `vendor.Create`, check the email after `mail.ValidAddress`.
  - The size check sums `files.size` of the share's file ids.
  - Update every `NewService` caller, including the tests' constructors.
- [ ] **Step 5: Run the tests.**
  - Run: `go test ./...`
  - Expected: PASS.
- [ ] **Step 6: Commit.**
  - Message: `feat(rules): enforce rules when creating shares, requests and vendors`.

### Task 3: Enforce at access time (download ban, watermark, domain, external IP)

**Files:**
- Modify:
  - `internal/share/access.go`
  - `internal/httpapi/server.go` (route wrapping)
  - `internal/httpapi/middleware.go`
  - `internal/httpapi/auth_handlers.go` (vendor login)
  - `internal/httpapi/recipient_handlers.go` (error map, list JSON)
  - `internal/httpapi/vendor_shares_handlers.go` (list JSON)
- Test:
  - `internal/httpapi/rules_access_test.go`

**Interfaces:**
- Consumes: `Deps.Rules`, `Rules.DomainAllowed`, `Rules.IPAllowed`.
- Produces:
  - `share.ErrDomainBlocked`, mapped by `recipientErr` to 403 `{"error":"domain_blocked"}`.
  - `func (s *Service) enforce(ctx context.Context, sh *Share, email string) error`. It loads the rules, sets `sh.AllowDownload = sh.AllowDownload && !r.ForbidDownload` and `sh.Watermark = sh.Watermark || r.ForceWatermark`, then returns `ErrDomainBlocked` when `email != "" && !r.DomainAllowed(email)`.
  - `func (s *server) external(next http.Handler) http.Handler`. It returns 403 `{"error":"ip_denied"}` when `!rules.IPAllowed(s.addr(r))`.
  - The recipient and vendor file-list JSON gain `"download_forbidden": bool`, which is `Rules.ForbidDownload`.

- [ ] **Step 1: Write failing tests in `rules_access_test.go`.**
  - `TestBanAppliesToExistingShare`:
    - `mkShare` (allow_download:true, watermark:false);
    - the admin sets `ForbidDownload` and `ForceWatermark` through `e.deps.Rules.Update`;
    - the recipient verifies;
    - the file list has `allow_download:false`, `watermark:true` and `download_forbidden:true`;
    - content returns 403 `view_only`.
  - `TestBanAppliesToVendorShare`: the same, through `/api/vendor/shares/{id}/files/{fid}/content`.
  - `TestDomainBlockedAfterShare`:
    - share to `r@evil.com`;
    - block `evil.com`;
    - verify returns 403 `domain_blocked`.
    - A vendor `v@evil.com`'s `GET /api/vendor/shares/{id}` returns 403 `domain_blocked`.
  - `TestExternalIPAllow`:
    - set `ExternalIPAllow [10.0.0.0/8]` and use `newEnv` with a trusted-proxy mod;
    - with `X-Forwarded-For: 192.168.1.1`:
      - `GET /api/s/{token}` returns 403 `ip_denied`;
      - `/api/r/{token}` returns 403;
      - `/api/invite/{token}` returns 403;
      - `/api/vendor/shares` returns 403;
      - vendor login returns 403 `ip_denied`;
    - staff login and `/api/files` still return 200;
    - with `10.1.1.1` the recipient landing works.
- [ ] **Step 2: Run the tests.**
  - Run: `go test ./internal/httpapi/ -run 'Ban|DomainBlocked|ExternalIP'`
  - Expected: FAIL.
- [ ] **Step 3: Implement.**
  - Call `enforce` once `sh` is loaded and the email is known:
    - `RequestCode` and `VerifyCode`: with the typed email. `RequestCode` stays silent on failure, so it must not reveal the denial.
    - `Authorize`: with the recipient email.
    - `VendorAccess`: with the vendor's email.
    - `Landing`: with an empty email, flags only.
  - Wrap with `external` every route under:
    - `/api/s/`
    - `/api/r/` (including the tus routes)
    - `/api/vendor/` (including the tus routes)
    - `/api/invite/`
  - In `login`, when the authenticated user's `Role == "vendor"` and the IP is not allowed, return 403 `ip_denied`. Do this before the session is created.
- [ ] **Step 4: Run the tests.**
  - Run: `go test ./internal/httpapi/ ./internal/share/`
  - Expected: PASS.
- [ ] **Step 5: Commit.**
  - Message: `feat(rules): apply rules at every view, download and external request`.

### Task 4: Upload limits and quota in tus

**Files:**
- Modify:
  - `internal/upload/tus.go`
  - `cmd/secure-exchange/main.go` (pass rules to `upload.NewHandler`)
- Test:
  - `internal/upload/` (the existing tus test file; add `rules_test.go` next to it)

**Interfaces:**
- Consumes: `rules.Service.Get`, `Rules.ExtAllowed`.
- Produces: `upload.NewHandler(pool, keys, store, audit, stagingDir string, maxSize int64, trusted, pcfg, rules *rules.Service)`. New `forbid` codes, each a 403 with a text/plain body:
  - `file_too_large`
  - `ext_not_allowed` (reused)
  - `storage_full` (staff's own upload)
  - `recipient_storage_full` (external upload)

- [ ] **Step 1: Write failing tests in `internal/upload/rules_test.go`.**
  - A staff upload with `MaxFileBytes=10` and Upload-Length 11 returns 403 `file_too_large`.
  - A staff upload with `QuotaBytes=100`:
    - the owner already has a 60-byte file, and an upload of 41 returns `storage_full`;
    - an upload of 40 is accepted;
    - a soft-deleted 60-byte file frees its space.
  - Two concurrent creates of 30 each, against 50 remaining: exactly one succeeds.
  - A vendor upload to staff with `UploadExts ["pdf"]` and filename `a.exe` returns `ext_not_allowed`.
  - The same vendor upload with `UploadMaxBytes=5` and length 6 returns `file_too_large`.
  - When the receiving staff member is over quota, the upload returns `recipient_storage_full`.
  - An intake uploader whose request allows `exe` while the site allows only `pdf` gets `ext_not_allowed`, because the stricter rule wins.
- [ ] **Step 2: Run the tests.**
  - Run: `go test ./internal/upload/`
  - Expected: FAIL.
- [ ] **Step 3: Implement.**
  - Do the size and extension checks in `create`, before `insertUpload`. The external checks apply when `u.uploaderID != nil` or the caller is a vendor.
  - Do the quota check inside `insertUpload`'s tx:
    - lock the owner with `SELECT 1 FROM users WHERE id=$1 FOR UPDATE`;
    - sum `files.size` where `deleted_at IS NULL`, plus `uploads.size` of the rows still in progress, plus the new size;
    - compare the result with `QuotaBytes`.
- [ ] **Step 4: Run the tests.**
  - Run: `go test ./internal/upload/ ./internal/httpapi/`
  - Expected: PASS.
- [ ] **Step 5: Commit.**
  - Message: `feat(rules): upload size, extension and quota limits`.

### Task 5: Rules API, audit, tightening digest

**Files:**
- Create: `internal/httpapi/rules_handlers.go`
- Modify:
  - `internal/httpapi/server.go`
  - `internal/audit/audit.go` (add `ActRulesUpdate = "rules.update"` and `ActRetentionDelete = "file.retention_delete"`)
  - `internal/mail/templates.go`
- Test: `internal/httpapi/rules_handlers_test.go`

**Interfaces:**
- Consumes:
  - `rules.Service.Get` and `Update`
  - `mail.Outbox.Enqueue`
  - `s.record`
- Produces:
  - `GET /api/rules` (`requireUser`) returns 200 with the `Rules` JSON.
  - `PUT /api/admin/rules` (`requireAdmin`), with a `Rules` JSON body:
    - returns 200 `{"rules": Rules, "affected_shares": int}`;
    - returns 422 `{"error":"validation","field","code"}` on invalid input.
  - `func RulesTightened(lines []string) (subject, body string)` in mail. It is bilingual, like the other templates. Each line is `"<share URL> — <reason>"`.
  - Reason keys:
    - `download` ("downloads are now forbidden" / 「已禁止下載」)
    - `watermark`
    - `domain`

- [ ] **Step 1: Write failing tests in `rules_handlers_test.go`.**
  - A staff `PUT` returns 403.
  - A staff `GET` returns 200.
  - An admin `PUT` with `share_max_days:0` returns 422 `share_max_days/out_of_range`.
  - Digest test:
    - owner A has two active shares with `allow_download:true`;
    - owner B has one with `watermark:false`;
    - a revoked share of A's also has `allow_download:true`;
    - the admin sets `forbid_download` and `force_watermark` → `affected_shares==3`;
    - the `mail.Recorder` holds exactly one mail to A and one to B;
    - A's mail lists 2 lines.
  - The audit holds `rules.update` with `detail.before.forbid_download==false` and `detail.after.forbid_download==true`.
  - A second identical `PUT` gives `affected_shares==0` and sends no mail.
- [ ] **Step 2: Run the tests.**
  - Run: `go test ./internal/httpapi/ -run Rules`
  - Expected: FAIL.
- [ ] **Step 3: Implement.**
  - In one tx: `Update`, then compute the affected active shares, then enqueue one mail per owner, then commit, then audit.
  - "Active" means `revoked_at IS NULL AND expires_at > now()`.
  - A share is affected when one of these was newly turned on or changed by this update:
    - newly `forbid_download` and `allow_download`;
    - newly `force_watermark` and `NOT watermark`;
    - the domain lists changed, and any active recipient email (including the vendor's `users.email`) is now denied.
  - Count each share once, with all its reasons.
- [ ] **Step 4: Run the tests.**
  - Run: `go test ./internal/httpapi/`
  - Expected: PASS.
- [ ] **Step 5: Commit.**
  - Message: `feat(rules): admin rules API with audit and owner digest`.

### Task 6: Retention sweeper

**Files:**
- Create: `internal/rules/retention.go`
- Modify: `cmd/secure-exchange/main.go` (`go rules.RunRetention(ctx, pool, store, audit, time.Hour)`)
- Test: `internal/rules/retention_test.go`

**Interfaces:**
- Consumes:
  - `Service.Get`
  - `blob.Store.Delete`
  - `preview.DeleteItems(ctx, pool, store, fileID)`
  - `audit.Log.Append`
- Produces:
  - `func (s *Service) SweepRetention(ctx context.Context, store blob.Store, log *audit.Log) (int, error)`, which returns the number of files deleted.
  - `func (s *Service) RunRetention(ctx context.Context, store blob.Store, log *audit.Log, every time.Duration)`. It follows the janitor loop pattern of `internal/upload/janitor.go`.

- [ ] **Step 1: Write failing tests in `retention_test.go`.**
  - With `RetentionDays=0`, the sweep deletes nothing.
  - With `RetentionDays=7`, the sweep deletes exactly:
    - a file whose only share was revoked 8 days ago;
    - a file of an upload request that expired 8 days ago.

    It keeps:
    - a file whose share ended 6 days ago;
    - a file with one share ended 30 days ago and one still active;
    - a request file that is also in an active share;
    - a never-shared staff file;
    - a vendor-direct upload (`files.vendor_id` set), never shared.
  - Each deleted file has `deleted_at` set, its blob gone, and an audit row `file.retention_delete` with `actor_type "system"`.
  - A second sweep returns 0.
- [ ] **Step 2: Run the tests.**
  - Run: `go test ./internal/rules/ -run Retention`
  - Expected: FAIL.
- [ ] **Step 3: Implement.**
  - A file is a candidate when `deleted_at IS NULL` and it has ≥1 `share_files` row or `request_id IS NOT NULL`.
  - Every share referencing it has `coalesce(revoked_at, expires_at) < now() - N days`. If the file has a `request_id`, that request's `coalesce(revoked_at, expires_at) < now() - N days`.
  - Claim each file with `UPDATE files SET deleted_at=now() WHERE id=$1 AND deleted_at IS NULL RETURNING storage_key`. Several app instances are then safe without a lock.
  - Then delete the blob and the preview items, and write the audit row.
- [ ] **Step 4: Run the tests.**
  - Run: `go test ./internal/rules/`
  - Expected: PASS.
- [ ] **Step 5: Commit.**
  - Message: `feat(rules): retention sweeper`.

### Task 7: Web — admin rules page, share dialog locks, error messages

**Files:**
- Create:
  - `web/src/pages/admin/Rules.tsx`
  - `web/src/pages/admin/Rules.test.tsx`
- Modify:
  - `web/src/api.ts`: add `Rules` interface, `api.rules()`, `api.saveRules(r)`.
  - `web/src/main.tsx`: add route `/admin/rules`.
  - `web/src/components/Shell.tsx`: add the admin link `nav.rules`.
  - `web/src/components/ShareDialog.tsx` and its test.
  - The vendor-create form in `web/src/pages/Vendors.tsx`.
  - The recipient and vendor file lists (wherever `allow_download` and preview state are rendered under `web/src/pages/recipient` and `web/src/pages/vendor`).
  - The upload error mapping for tus errors (`Uploader.tsx` and the intake and vendor upload pages).
  - `web/src/i18n/en.json` and `zh-TW.json`.

**Interfaces:**
- Consumes: `GET /api/rules`, and `PUT /api/admin/rules` with its response and error shapes from Task 5. The new error codes come from Tasks 2–4.

- [ ] **Step 1: Write failing tests.**
  - `Rules.test.tsx`:
    - the page loads and shows the values;
    - editing `share_max_days` and saving calls `saveRules` with the edited value;
    - lists are textareas, one entry per line;
    - sizes are entered in MiB and sent as bytes;
    - a 422 response shows `rules.error.share_max_days.out_of_range`;
    - after saving, it shows "affected_shares: N".
  - `ShareDialog.test.tsx`:
    - with `forbid_download:true`, the allow-download checkbox is disabled and unchecked;
    - with `force_watermark:true`, the watermark checkbox is disabled and checked;
    - both show the text `share.lockedByAdmin` (「由管理員設定」 / "Set by administrator");
    - the default expiry is now + `share_default_days`;
    - the error `emails/domain_blocked` renders its message.
  - The recipient list test: when `download_forbidden` is true and the file is not previewable, it shows `recipient.blockedByAdmin` (「此檔案目前無法存取（管理員已禁止下載）」).
- [ ] **Step 2: Run the tests.**
  - Run: `cd web && npx vitest run`
  - Expected: FAIL.
- [ ] **Step 3: Implement.**
  - The admin page form has every `Rules` field. Group it into the sections: Sharing, Recipients, External uploads, Storage.
  - Show a warning under the IP field (`rules.ipHint`): "External users can then only connect from these networks".
  - Add i18n keys in both files for:
    - `share.error.*` new codes: `allow_download.locked`, `watermark.locked`, `emails.domain_blocked`, `vendor_ids.domain_blocked`, `file_ids.too_large`
    - `vendors` `email.domain_blocked`
    - the upload codes `file_too_large`, `storage_full`, `recipient_storage_full`
    - `recipient.error.domain_blocked`
    - `recipient.error.ip_denied`, if it does not already exist
- [ ] **Step 4: Run the tests and build.**
  - Run: `cd web && npx vitest run && npm run build && npx tsc --noEmit`
  - Expected: PASS.
- [ ] **Step 5: Commit.**
  - Message: `feat(web): admin rules page and rule-aware share dialog`.

### Task 8: Docs

**Files:**
- Modify:
  - `docs/admin-manual.md`
  - `docs/user-manual.md`
  - `.env.example`
  - `README.md` and `README.en.md` (feature list line)

- [ ] **Step 1: Update the admin manual.**
  - Add a section 「強制規則」 that lists each rule, what it affects, and its "stricter wins on existing shares" behaviour.
  - Also cover:
    - the digest mail;
    - retention scope;
    - that the IP list affects only external users.
  - Note that `SX_SHARE_MAX_DAYS` now only seeds the first value.
- [ ] **Step 2: Update the user manual.**
  - Explain the greyed-out 「由管理員設定」 options, the new error messages, and that recipients may see 「此檔案目前無法存取」.
- [ ] **Step 3: Update `.env.example` and the READMEs.**
  - Comment on `SX_SHARE_MAX_DAYS`: "initial value only; change it on the admin rules page".
  - Comment on `SX_MAX_FILE_SIZE`: "hard ceiling".
  - Add the README feature bullet.
- [ ] **Step 4: Commit.**
  - Message: `docs: admin enforcement rules`.
