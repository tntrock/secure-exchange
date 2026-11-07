# Phase 8.1: Security & Audit Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the security and audit-accuracy gaps parked during phases 1–7 (spec §3.2) before v1.0.

**Architecture:** Small targeted fixes in existing handlers (`internal/httpapi`), one new periodic purge loop (`internal/purge`) started from `cmd/secure-exchange/main.go` next to the existing janitor/retention loops, and compose hardening. No new dependencies.

**Tech Stack:** Go 1.27, pgx/v5, goose migrations, docker compose.

**Spec:** `docs/superpowers/specs/2026-11-07-phase8-release-design.md` (§3.1, §3.2). Parent: `docs/superpowers/specs/2026-10-24-secure-exchange-design.md`.

## Global Constraints

- Go statement coverage stays ≥ 90% in CI (`scripts/covergate.sh`); aim for ≥ 91.5% locally because CI counts more statements.
- `golangci-lint` v2 (`.golangci.yml`) must pass, including staticcheck ST1005 (error strings: no capital first letter, no trailing punctuation/`...`) and goimports with `-local github.com/tntrock/secure-exchange` (stdlib / third-party / module imports in separate groups).
- DB tests need `SX_TEST_DATABASE_URL='postgres://sx:sx@localhost:55432/sx?sslmode=disable'` (dev compose `docker compose -f docker-compose.dev.yml up -d postgres`). Host has no cgo: no `-race` locally.
- Never call pool-based `rules.Get` while holding a transaction (use `GetTx`) — pool starvation deadlock.
- Every new user-facing behaviour that the admin manual describes gets a short note in `docs/admin-manual.md` (zh-TW). English manuals arrive in PR 8.4; do not create them here.
- Each task first confirms the problem still exists (the spec says items may already be fixed); if already fixed, write the pinning test only and say so in the report.
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. A file whose scan is `pending`/`infected`/`error` reached through a share link must be refused for **both** download and preview, for one-time recipients **and** vendors — pinned in Task 1.
2. A half-logged-in session (password ok, TOTP not yet entered) left in a browser must stop working after 10 minutes, but completing TOTP must give a normal full-length session — pinned in Task 2.
3. A vendor outside the allowed IP range with the **correct** password must get exactly the same response as with a wrong password — pinned in Task 2.
4. The purge must never delete a live row (unexpired session/OTP, unsent outbox row still retrying) — pinned in Task 3.
5. An LDAP directory returning a malformed email (`"bob"`, `"a@b\r\nBcc:x"`) must not create an account — pinned in Task 5.

---

### Task 1: Scan gate on recipient and vendor serving paths

**Files:**
- Modify: `internal/httpapi/recipient_download.go` (SELECT at ~21-47 must read `f.scan_status`)
- Modify: `internal/httpapi/preview_handlers.go` (`sharedFile` ~102-120)
- Test: `internal/httpapi/scan_gate_test.go`

**Interfaces:**
- Consumes: existing `scanRefusal(scan string) (int, string)` (`files_handlers.go:224`) — returns non-zero status for anything not `none|clean|skipped`.

- [ ] **Step 1: Write failing tests** `TestRecipientDownloadRefusesUnscanned` and `TestSharedPreviewRefusesUnscanned`: create a share containing a file, then `UPDATE files SET scan_status=$1` for each of `pending`, `infected`, `error`; assert the one-time recipient download (`/api/s/{token}/files/{fid}/content`), the vendor download (`/api/vendor/shares/{id}/files/{fid}/content`) and the recipient/vendor preview endpoints return the same status/code pair `scanRefusal` returns for that value. Also assert `clean`, `skipped` and `none` still serve 200.
- [ ] **Step 2: Run** `go test ./internal/httpapi -run 'Refuses(Unscanned)' -v` — Expected: FAIL (200 returned).
- [ ] **Step 3: Implement**: add `f.scan_status` to both SELECTs and call `scanRefusal` before any bytes or preview items are served; the refusal is audited the same way the owner path (`ownCleanFile`) audits it, if it does.
- [ ] **Step 4: Run** `go test ./internal/httpapi -v -run 'Scan|Recipient|Preview'` — Expected: PASS.
- [ ] **Step 5: Commit** `fix: refuse unscanned files on recipient and vendor paths`.

### Task 2: Login hardening — short pending-MFA session, IPv6 /64 rate-limit key, vendor IP oracle

**Files:**
- Modify: `internal/httpapi/auth_handlers.go` (`login` ~52-84), `internal/auth/sessions.go` (`MarkMFA`), `internal/httpapi/middleware.go` (limiter key), `internal/httpapi/server.go` (limiter construction ~79, ~116, ~175)
- Test: `internal/httpapi/auth_test.go`, `internal/auth/sessions_test.go`, `internal/httpapi/rules_access_test.go`

**Interfaces:**
- Produces: `const PendingMFATTL = 10 * time.Minute` in `internal/auth`; `func rateKey(r *http.Request) string` in `internal/httpapi` (or a method on server if `ClientIP` needs the trusted list) returning the IPv4 address as-is and the IPv6 address masked to /64 (`netip.PrefixFrom(a, 64).Masked().String()`).
- `MarkMFA` signature gains the full TTL: `func (s *Sessions) MarkMFA(ctx context.Context, token string, ttl time.Duration) error` — sets `mfa_passed=true` and `expires_at = now() + ttl`. Update all callers.

- [ ] **Step 1: Write failing tests**
  - `TestPendingMFASessionShortTTL`: login as a TOTP-enabled user; read the session's `expires_at`; assert it is within `PendingMFATTL` (+ a few seconds) of now. Then complete TOTP; assert `expires_at` ≈ now + `SessionTTL`.
  - Same for a forced-TOTP enrolment half session (site rule `force_totp`).
  - `TestRateKeyIPv6Slash64`: `2001:db8:1:2::1` and `2001:db8:1:2:ffff::9` give the same key; `2001:db8:1:3::1` differs; `192.0.2.7` stays `192.0.2.7`; IPv4-mapped `::ffff:192.0.2.7` gives `192.0.2.7`.
  - `TestVendorIPDeniedSameAsBadPassword`: site rule restricts vendor IPs; a vendor from a denied IP with the **correct** password gets status and JSON body byte-identical to a vendor with a wrong password from the same IP (401 `invalid_credentials`). The audit row for the correct-password case still records reason `ip_denied`.
- [ ] **Step 2: Run** `go test ./internal/httpapi ./internal/auth -run 'PendingMFA|RateKey|VendorIPDenied' -v` — Expected: FAIL.
- [ ] **Step 3: Implement**: pass `auth.PendingMFATTL` to `Sessions.Create` when `!full`; pass `s.SessionTTL` to `MarkMFA`; key every `rateLimit(...)` with the /64 helper; in `login`, map a vendor IP denial to the same 401 `invalid_credentials` response while auditing `ip_denied` in the detail. Ruling: the spec says "不洩漏帳密正確"; a 401 for denied IPs is the only response that leaks neither the password result nor that the email is a vendor account. Vendor-facing docs in `docs/user-manual.md` that mention an IP error message are updated to say login fails from disallowed networks.
- [ ] **Step 4: Run** `go test ./internal/httpapi ./internal/auth` — Expected: PASS (fix any existing test that asserted 403 `ip_denied` on vendor login).
- [ ] **Step 5: Commit** `fix: short pending-MFA sessions, /64 rate-limit keys, no vendor IP oracle`.

### Task 3: Periodic purge of expired rows

**Files:**
- Create: `internal/purge/purge.go`, `internal/purge/purge_test.go`
- Modify: `cmd/secure-exchange/main.go` (start next to `upload.RunJanitor`, ~line 98-104); remove the `ponytail: expired rows are never purged` comment in `internal/auth/sessions.go:33`
- Modify: `docs/admin-manual.md` (one paragraph: what is purged and when)

**Interfaces:**
- Produces: `func Run(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger, every time.Duration)` (ticker loop, runs once at start, modelled on `upload.RunJanitor`) and `func Once(ctx context.Context, pool *pgxpool.Pool) (map[string]int64, error)` returning deleted counts per table (logged at Info when any > 0).

Delete rules (the `grace` is 24 h unless stated; tests pin each):

| Table | Delete when |
|---|---|
| `sessions` | `expires_at < now() - grace` |
| `share_sessions`, `request_sessions` | `expires_at < now() - grace` |
| `share_otps`, `request_otps` | `expires_at < now() - grace` |
| `mail_outbox` | `sent_at IS NULL AND attempts >= <outbox max attempts constant> AND created_at < now() - 30 days` (reuse the constant `mail/outbox.go` gives up at; export it if needed) |
| `vendor_share_views` | its share no longer exists or its share's `expires_at < now() - grace` (check the actual share expiry column name) |

- [ ] **Step 1: Write failing test** `TestOnceDeletesOnlyExpired`: for every table insert one row expired beyond grace and one live row (unexpired, or for outbox: a dead row younger than 30 days and a row still retrying with attempts below the cap); run `Once`; assert exactly the expired rows are gone and the counts map reports 1 per table.
- [ ] **Step 2: Run** `go test ./internal/purge -v` — Expected: FAIL (package missing).
- [ ] **Step 3: Implement** one `DELETE` per table; start `go purge.Run(ctx, pool, log, time.Hour)` in `main.go`.
- [ ] **Step 4: Run** `go test ./internal/purge ./cmd/... -v` — Expected: PASS.
- [ ] **Step 5: Commit** `feat: hourly purge of expired sessions, codes and dead mail`.

### Task 4: Vendor domain block on share list and vendor audit accuracy

**Files:**
- Modify: `internal/httpapi/vendor_shares_handlers.go` (`listVendorShares` ~11), `internal/httpapi/recipient_download.go` (audit ~71), `internal/httpapi/preview_handlers.go` (audit ~191), `internal/upload/tus.go` (~179 `recipient_not_allowed`)
- Test: `internal/httpapi/vendor_shares_test.go`, `internal/upload/vendor_test.go`

**Interfaces:**
- Consumes: `rules.Rules.DomainAllowed(email string) bool`; `auth.UserFrom(ctx)` for the vendor email; `audit.Event`.

- [ ] **Step 1: Write failing tests**
  - `TestVendorShareListDomainBlocked`: vendor has a share; set a site rule that blocks the vendor's email domain; `GET /api/vendor/shares` returns 403 with the same error code `VendorAccess` uses for `ErrDomainBlocked`.
  - `TestVendorDownloadAuditActor` / `TestVendorViewAuditActor`: after a vendor downloads/views, the audit row has `actor_type='vendor'` and `actor_id` = the vendor's user id; a one-time recipient's row is still `actor_type='recipient'`.
  - `TestVendorUploadRecipientNotAllowedAudited`: vendor tus upload with metadata `recipient` not allowed → 403 as today **and** one audit row with `result='denied'` (or the codebase's existing denied result value) and detail reason `recipient_not_allowed`.
- [ ] **Step 2: Run** the three tests — Expected: FAIL.
- [ ] **Step 3: Implement**: in the list handler, check `rl.DomainAllowed(email)` before querying; in both audit sites set `ActorType:"vendor", ActorID: *a.Recipient.VendorID` when `VendorID != nil`; append an audit event before `forbid` in tus.go.
- [ ] **Step 4: Run** `go test ./internal/httpapi ./internal/upload` — Expected: PASS. Check the audit page's actor filter (web `admin/Audit`) already offers `vendor`; if not, add it with i18n keys in both `en.json` and `zh-TW.json`.
- [ ] **Step 5: Commit** `fix: block vendor share list by domain; audit vendors as vendors`.

### Task 5: External login — audit internal errors, validate directory emails

**Files:**
- Modify: `internal/httpapi/oidc_handlers.go` (~108-124), `internal/httpapi/ldap_handlers.go` (~67-81), `internal/ldapauth/ldapauth.go` (~176-178, ~235), `internal/oidcauth/oidcauth.go` (~142-146)
- Test: `internal/httpapi/oidc_test.go` (`TestOIDCCallbackInternalErrors` ~241), `internal/httpapi/ldap_test.go` (`TestLDAPLoginInternalError` ~208), `internal/ldapauth/ldapauth_test.go` (`TestAuthenticateNoEmail` ~163), `internal/oidcauth/oidcauth_test.go`

**Interfaces:**
- Consumes: `mail.ValidAddress(s string) (string, bool)` (`internal/mail/mail.go:45`). If importing `mail` from `ldapauth`/`oidcauth` creates a cycle, validate in the handlers instead before `UpsertExternal`.

- [ ] **Step 1: Write failing tests**
  - Extend `TestOIDCCallbackInternalErrors` and `TestLDAPLoginInternalError`: when `UpsertExternal` or session creation fails, a `login.fail` audit row exists with stage `db` (OIDC still redirects to `?oidc_error=unavailable`; LDAP still answers 500).
  - `TestAuthenticateInvalidEmail` (ldapauth): directory returns mail `bob`, then `a@b\r\nBcc:x` → `ErrNoEmail` (no account created). Mixed-case `Bob@Example.COM` is accepted and normalised the way `ValidAddress` normalises.
  - OIDC: an `email` claim of `not-an-email@` → treated as no email (`ErrNoEmail`).
- [ ] **Step 2: Run** the tests — Expected: FAIL.
- [ ] **Step 3: Implement**: route both DB-error paths through the existing `fail(...)` closures (stage `"db"`); run the chosen email through `mail.ValidAddress` and treat `!ok` as no email.
- [ ] **Step 4: Run** `go test ./internal/httpapi ./internal/ldapauth ./internal/oidcauth` — Expected: PASS.
- [ ] **Step 5: Commit** `fix: audit external-login internal errors; validate directory emails`.

### Task 6: Resource limits — mark-slot wait timeout, app memory limit, scan network

**Files:**
- Modify: `internal/httpapi/recipient_download.go` (`markSlots` ~204, `buildMarked` ~243), `docker-compose.yml`, `docs/admin-manual.md`
- Test: `internal/httpapi/recipient_download_test.go` (`TestMarkBuildSlots` ~587)

**Interfaces:**
- Produces: package var `markWait = 2 * time.Minute` (var so tests can shorten it). On timeout the download answers 503 with code `busy` and a `Retry-After: 30` header.

- [ ] **Step 1: Write failing test** `TestMarkSlotWaitTimesOut`: fill both slots, set `markWait` to 50 ms, request a marked download; assert 503, code `busy`, `Retry-After: 30`, and no audit row claiming a completed download.
- [ ] **Step 2: Run** — Expected: FAIL (request blocks).
- [ ] **Step 3: Implement** the timed wait. In `docker-compose.yml`:
  - `app`: `mem_limit: 2g`, `memswap_limit: 2g`, `pids_limit: 512`. Before settling on 2g, check the marked-download and tus paths stream rather than buffer whole files (grep for `io.ReadAll` / `bytes.Buffer` on file content); if something buffers up to `SX_MARK_MAX_BYTES`, size the limit to cover two concurrent marks of that size plus 512 MiB and note the arithmetic in the admin manual.
  - New network `scan: {internal: true}`; `clamav` moves to `[scan, updates]` (off `backend`); `worker` joins `[backend, scan]`. First confirm with grep that only the worker process dials `SX_CLAMD_ADDR`; if the app also dials it, put `app` on `scan` as well.
  - Admin manual: one short section listing the container limits and the new network.
- [ ] **Step 4: Run** `go test ./internal/httpapi -run 'Mark' -v` and `docker compose config -q` — Expected: PASS / no output.
- [ ] **Step 5: Commit** `fix: bound mark-slot waits; app memory limit; isolate clamav network`.
