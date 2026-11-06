# Phase 7.2 User Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Admins manage every account in the UI. They invite local staff and admins, disable and enable accounts, change roles, reset TOTP (vendors included), force TOTP site-wide for local staff, and browse and revoke every share and upload request, viewing their files with an admin watermark.

**Architecture:**
- A new package `internal/account` holds the admin-side account operations and the staff invitation and activation flow.
- The invitation token mechanics move out of `internal/vendor` into `internal/auth`, so vendors and staff share them.
- Forced TOTP is a new `site_rules.force_totp` column, enforced at login: the user gets a not-yet-MFA session that can only enrol TOTP.
- Admin browsing adds `Admin*` methods to the share and intake services, and an admin-only preview route family whose watermark names the admin.

**Tech Stack:** Go 1.26, pgx/v5, goose; React 19 + TS, vitest, react-i18next, `qrcode` (already a dependency).

**Spec:** `docs/superpowers/specs/2026-11-07-phase7-admin-design.md` (§4.4, §5 使用者／全站分享, §9 session 何時失效／管理員開啟員工檔案, §8 item 2)

## Global Constraints

- Every change goes through the PR workflow: CI jobs `test` (-race), `lint` (golangci, goimports `-local github.com/tntrock/secure-exchange`), `coverage` (Go ≥ 90 % via `scripts/covergate.sh`; web vitest thresholds) must be green.
- **Third-party and module imports:** put them in separate import groups. Check locally with `~/go/bin/goimports -local github.com/tntrock/secure-exchange -l ./internal`. The host has no cgo, so run `-race` only in CI or in a `golang:1.26` container.
- **Holding a tx:** never call a pool-based helper (`rules.Get`, `Users.ByID`, …) while holding a tx. Use the tx (for rules, `GetTx`).
- **Spec wording on forced TOTP:** "全站強制 TOTP … 只套用於本機員工與管理員（廠商本來就強制）"; "開啟後，尚未設定 TOTP 的本機帳號下次登入時必須先完成設定才能使用".
- **Spec wording on the last admin:** "停用、降級最後一位啟用中的本機管理員時拒絕"; "外部來源的管理員不算".
- **Spec wording on roles:** "只有本機帳號可以手動改角色".
- **Disable and demote take effect immediately:** sessions of a disabled account are deleted (spec §9). `requireRole` already re-reads the account on every request.
- **Spec wording on admin viewing:** "只能線上檢視，一律加浮水印（浮水印內容是管理員身分），不提供下載"; "每次開啟寫稽核".
- **Passwords:** at least 12 runes and at most 256 bytes (the existing vendor rule, moved to `auth`).
- **Invitations:** valid 7 days and single use. A newer invitation voids older ones. A reinvite also drops the pending TOTP secret.
- **i18n:** every new UI string goes into both `en` and `zh-TW` (key parity is enforced by `keys.test.ts`).
- **Manuals:** update `docs/admin-manual.md` and `docs/user-manual.md` in Traditional Chinese, replacing the SQL workarounds in §5 and §6 with UI steps.
- **Commits** end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

**Rulings made in this plan (not in the spec):**
- **Disabled owners:** a disabled owner's shares and upload requests stop serving. External recipients and uploaders get `gone`. This closes the parked phase-2 follow-up "disabled owner's shares still serve" (spec §4.4 "停用").
- **Vendor TOTP reset:** it clears the vendor's password and TOTP and mails a fresh invitation in the same transaction. This matches today's manual SQL procedure, and the vendor is back in status `invited`.
- **Local staff TOTP reset:** it clears TOTP only; the password stays. If force-TOTP is on, the next login enrols again.
- **Who counts as the last admin:** a "usable local admin" is `role='admin' AND auth_source='local' AND NOT disabled AND password_hash IS NOT NULL`. An invited admin who never activated does not count.
- **Staff activation path:** staff activation uses `/activate/:token` and `/api/activate/{token}`, outside the external-IP gate. The vendor `/api/invite/` stays gated, and each endpoint refuses the other role's tokens.
- **Admin watermark:** the trace code is the literal `ADMIN`. Admin views create no `download_traces` row.

## Review Focus

1. **Two admins disable or demote each other at the same moment** while only two usable local admins exist. Exactly one request must succeed and the other must get `409 last_admin`. Covered in Task 2.
2. **Admin resets TOTP while the user holds a session** (fully logged in, or halfway at the code step). Every session must die, and the old authenticator code must no longer log in. Covered in Task 2 and Task 3.
3. **Forced-TOTP user reloads the login page or abandons enrolment.** The next attempt must show the same QR secret (pending secret reused), never lock them out. The enrol endpoints must refuse fully-MFA sessions and accounts that already have TOTP. Covered in Task 3.
4. **A staff invite token is posted to the vendor endpoint, or the reverse.** It must answer `410 gone` and change nothing. Covered in Task 3.
5. **The owner is disabled while a recipient or uploader is in the middle of a session.** The next request on that session must be refused, not just the landing page. Covered in Task 4.

---

### Task 1: Schema, shared invitation helpers, password rule

**Files:**
- Create: `internal/db/migrations/0008_accounts.sql`
- Create: `internal/auth/invite.go`, `internal/auth/invite_test.go`
- Modify: `internal/auth/users.go` (columns, `TouchLogin`, `ValidPassword`), `internal/auth/password.go`
- Modify: `internal/vendor/vendor.go` (use the auth helpers; drop `hashToken`, `minPassword`, `maxPassword`)
- Modify: `internal/rules/rules.go` (`ForceTOTP`), `internal/rules/*_test.go`

**Interfaces:**
- Produces:
  - `auth.CreateInvite(ctx, tx pgx.Tx, userID uuid.UUID) (token string, expires time.Time, err error)`: inserts into `account_invites`, 7-day expiry.
  - `auth.InviteUser(ctx, q Querier, token string) (uuid.UUID, error)`: the user behind an unused, unexpired invitation that is the newest for that user. Otherwise it returns `auth.ErrInviteGone`.
  - `auth.ConsumeInvite(ctx, tx pgx.Tx, token string) error`: returns `ErrInviteGone` when it is already used.
  - `auth.ValidPassword(pw string) string`: returns `""`, `"too_short"` or `"invalid"`.
  - `(*auth.Users).TouchLogin(ctx, id) error`: sets `last_login_at = now()`.
  - `auth.User.LastLoginAt *time.Time`.
  - `rules.Rules.ForceTOTP bool` with JSON `force_totp`.
  - `auth.Querier` is the minimal interface satisfied by both pool and tx (`QueryRow`). Reuse it if `auth` already has one.

- [ ] **Step 1: Write the migration.**
  - `ALTER TABLE vendor_invites RENAME TO account_invites;` and rename its index to `account_invites_user`.
  - `ALTER TABLE users ADD COLUMN last_login_at timestamptz;`
  - `ALTER TABLE site_rules ADD COLUMN force_totp bool NOT NULL DEFAULT false;`
  - Write a full Down that reverses all of it.

- [ ] **Step 2: Write the failing tests in `internal/auth/invite_test.go`.**
  - `TestInviteNewestOnly`: create two invites for one user. `InviteUser(first)` gives `ErrInviteGone` and `InviteUser(second)` gives the id.
  - `TestInviteExpiredAndConsumed`: force `expires_at` into the past and get `ErrInviteGone`. After `ConsumeInvite`, `InviteUser` gives `ErrInviteGone`, and a second `ConsumeInvite` gives `ErrInviteGone`.
  - `TestValidPassword`: 11 runes gives `"too_short"`, 12 CJK runes gives `""`, and 257 bytes gives `"invalid"`.
  - `TestTouchLogin`: `LastLoginAt` is nil, then non-nil after the call.
  - Rules test: `ForceTOTP` round-trips through `Update`/`Get`, and `Update` returns `before.ForceTOTP == false`.

- [ ] **Step 3: Run the tests and confirm they fail.**
  Run `go test ./internal/auth/ ./internal/rules/`. Expected: FAIL (undefined: CreateInvite, ForceTOTP …).

- [ ] **Step 4: Implement the helpers and wire them in.**
  - Implement the helpers, add `last_login_at` to `userCols`/`scanUser`, and add `force_totp` to rules `cols`/scan/`Update`.
  - Rewrite `vendor.invite`, `vendor.validInvite` and `vendor.Activate` on the auth helpers; vendor behaviour is unchanged.
  - Make `vendor.validInvite` also require `role='vendor'`, which it already gets via `get`'s `WHERE u.role = 'vendor'`. Map `ErrNotFound` there to `ErrInviteGone`.

- [ ] **Step 5: Run the tests and confirm they pass.**
  Run `go test ./internal/...`. Expected: PASS, with every existing vendor test unchanged.

- [ ] **Step 6: Commit.** Message: `feat(auth): shared account invitations, last login, force_totp rule`

---

### Task 2: `internal/account` service

**Files:**
- Create: `internal/account/account.go`, `internal/account/account_test.go`
- Modify: `internal/mail/templates.go` (`StaffInvitation`), `internal/mail/mail_test.go`

**Interfaces:**
- Consumes: the Task 1 helpers; `auth.Users`, `auth.Sessions`, `mail.Outbox`, `rules.Service`.
- Produces:

```go
type Account struct {
    ID uuid.UUID; Email, DisplayName, Role, AuthSource, Status string // status: invited|active|disabled (vendors: vendor.Status values)
    TOTPEnabled bool; LastLoginAt, CreatedAt *time.Time
}
type CreateInput struct{ Email, DisplayName, Role string } // role: staff|admin
var ErrNotFound, ErrEmailTaken, ErrState, ErrLastAdmin, ErrInviteGone, ErrBadCode, ErrTOTPRequired, ErrExternal error
type ValidationError struct{ Field, Code string }
func New(pool *pgxpool.Pool, users *auth.Users, sessions *auth.Sessions, outbox *mail.Outbox, rules *rules.Service, baseURL string) *Service
func (s *Service) List(ctx) ([]Account, error)                                   // all accounts, newest first
func (s *Service) Create(ctx, by *auth.User, in CreateInput) (*Account, error)   // local, no password, mails invite
func (s *Service) Reinvite(ctx, by *auth.User, id uuid.UUID) error               // staff/admin in status invited only
func (s *Service) SetDisabled(ctx, id uuid.UUID, disabled bool) error            // any role; disable revokes sessions
func (s *Service) SetRole(ctx, id uuid.UUID, role string) error                  // local staff<->admin only
func (s *Service) ResetTOTP(ctx, by *auth.User, id uuid.UUID) error
func (s *Service) InviteInfo(ctx, token string) (email string, totpRequired bool, otpauthURL string, err error)
func (s *Service) Activate(ctx, token, password, code string) (uuid.UUID, error)
```

- **Status for non-vendors:** `disabled` if disabled, else `invited` if `password_hash IS NULL`, else `active`.
- **Status for vendors:** the same derivation as `vendor.scanVendor`. Extract it into an exported `vendor.StatusOf(approval string, disabled bool, expires time.Time, enrolled bool) string` and call it from both places.
- **Email validation:** reuse the vendor package's email validation. Move it to `auth.ValidEmail` if it is unexported.

- [ ] **Step 1: Write the failing tests in `internal/account/account_test.go`.**
  - `TestCreateInvitesLocalStaff`:
    - The account has status `invited`, `auth_source` `local`, and one outbox message to the email containing `/activate/`.
    - A duplicate email (case-insensitive, including an existing vendor's) gives `ErrEmailTaken`.
    - Role `vendor` gives `*ValidationError{Field:"role"}`.
  - `TestActivateWithoutForcedTOTP`:
    - `InviteInfo` gives `totpRequired=false` and an empty URL.
    - `Activate(token,"correct horse battery","")` succeeds; the user then has a password and logs in with `TOTPEnabled=false`.
    - Reusing the token gives `ErrInviteGone`.
  - `TestActivateWithForcedTOTP`:
    - Turn rule `ForceTOTP` on. `InviteInfo` gives `totpRequired=true` and a URL, and a second `InviteInfo` gives the same URL.
    - `Activate` with code `""` gives `ErrTOTPRequired`, and with a wrong code gives `ErrBadCode`. Neither changes anything.
    - A valid code (computed from the secret in the URL) gives `TOTPEnabled=true`.
  - `TestActivateRefusesVendorToken`: a vendor invitation token gives `ErrInviteGone` from both `InviteInfo` and `Activate`.
  - `TestReinviteVoidsOldLink`:
    - After `Reinvite`, the old token gives `ErrInviteGone` and the new one works.
    - Reinviting an active account gives `ErrState`.
  - `TestLastAdminGuard`:
    - With one usable local admin, `SetDisabled(admin,true)` and `SetRole(admin,"staff")` give `ErrLastAdmin`.
    - An invited admin with no password does not count.
    - With a second usable admin, both calls succeed.
  - `TestLastAdminGuardConcurrent`:
    - Set up two usable admins, A and B. In parallel, run `SetDisabled(A)` and `SetDisabled(B)`.
    - Exactly one returns nil and the other returns `ErrLastAdmin`. Afterwards one usable admin remains.
  - `TestSetDisabledRevokesSessions`: after disable, `Sessions.Lookup` fails for that user's token. After enable, the account is `active` again.
  - `TestSetRoleRules`:
    - A vendor target gives `ErrState`. A non-local account (insert one with `auth_source='ldap'`) gives `ErrExternal`.
    - A role outside staff/admin gives `ValidationError{Field:"role"}`.
  - `TestResetTOTPLocal`:
    - Start from a staff user with TOTP and a session. After reset, `TOTPEnabled=false`, `totp_secret_sealed` is NULL, `totp_last_step` is 0, the session is gone, and the password still verifies.
    - A user without TOTP gives `ErrState`.
  - `TestResetTOTPVendor`:
    - An active vendor ends with status `invited`, `password_hash` NULL, sessions gone, and one new outbox invite.
    - The old vendor invite token is not valid; the new one activates through `vendor.Service.Activate`.
  - `TestResetTOTPExternal`: an `ldap` account gives `ErrExternal`.

- [ ] **Step 2: Run the tests and confirm they fail.**
  Run `go test ./internal/account/`. Expected: FAIL (package does not compile).

- [ ] **Step 3: Implement the service.**
  - **Last-admin guard:** inside the tx, `SELECT id FROM users WHERE role='admin' AND auth_source='local' AND NOT disabled AND password_hash IS NOT NULL ORDER BY id FOR UPDATE`. If the target is in that set and the set has exactly one row, return `ErrLastAdmin`; otherwise update.
    - Lock the target row first only when it is not an admin.
    - The ordered `FOR UPDATE` serialises concurrent admin changes.
  - **Disable:** in the same tx, `DELETE FROM sessions WHERE user_id=$1`.
  - **Vendor TOTP reset:** in one tx:
    - clear `password_hash`, `totp_enabled`, `totp_secret_sealed`, `totp_last_step`;
    - delete the sessions;
    - `auth.CreateInvite`, then enqueue `mail.VendorInvitation` with `baseURL+"/invite/"+token`.
  - **Staff invite mail:** `mail.StaffInvitation(url, inviterName string, expires time.Time) (subject, body string)`, bilingual like `VendorInvitation`. The url is `baseURL+"/activate/"+token`.
  - **Activate:** mirror `vendor.Activate`:
    - check the code against the sealed secret captured before the check;
    - the conditional `UPDATE … WHERE password_hash IS NULL AND (NOT $force OR totp_secret_sealed = $sealed)`;
    - `ConsumeInvite` in the same tx;
    - read `ForceTOTP` via `rules.GetTx` inside the tx, or via `rules.Get` before the tx begins, never `Get` while the tx is open.

- [ ] **Step 4: Run the tests and confirm they pass.**
  Run `go test ./internal/account/ ./internal/mail/ ./internal/vendor/`. Expected: PASS.

- [ ] **Step 5: Commit.** Message: `feat(account): admin account management and staff invitations`

---

### Task 3: HTTP for users, activation, forced TOTP at login

**Files:**
- Create: `internal/httpapi/users_handlers.go`, `internal/httpapi/users_test.go`
- Modify: `internal/httpapi/server.go` (`Deps.Accounts *account.Service`, routes), `internal/httpapi/auth_handlers.go`, `internal/httpapi/rules_handlers.go` (`force_totp` in GET/PUT)
- Modify: `internal/audit/audit.go`, `cmd/secure-exchange/main.go` (wire `account.New` into `Deps.Accounts`)

**Interfaces:**
- Consumes: Task 2's `account.Service`.
- Produces: the HTTP surface for Tasks 5 and 6.
  - `GET /api/admin/users` returns an array of `{id,email,display_name,role,auth_source,status,totp_enabled,last_login_at,created_at}`.
  - `POST /api/admin/users {email,display_name,role}` returns 201 with the account.
  - `POST /api/admin/users/{id}/disable` and `POST /api/admin/users/{id}/enable` return 204.
  - `PATCH /api/admin/users/{id} {role}` returns 204.
  - `POST /api/admin/users/{id}/reset-totp` returns 204.
  - `POST /api/admin/users/{id}/reinvite` returns 204.
  - `GET /api/activate/{token}` returns `{email,totp_required,otpauth_url}`.
  - `POST /api/activate/{token} {password,code}` returns 204.
  - `POST /api/auth/login` now returns `{mfa_required, totp_setup_required}`.
  - `POST /api/auth/totp/setup` returns `{otpauth_url}`.
  - `POST /api/auth/totp/enroll {code}` returns `{mfa_required:false}`.
- **Admin routes:** all `/api/admin/users*` routes use `requireAdmin`. The activate routes use `perIP` and are not under `/api/invite/`.
- **Error mapping** for `accountErr`:

| Error | Status | Body |
|---|---|---|
| ValidationError | 422 | `{error:"validation",field,code}` |
| ErrNotFound | 404 | `not_found` |
| ErrEmailTaken | 409 | `email_taken` |
| ErrState | 409 | `wrong_state` |
| ErrLastAdmin | 409 | `last_admin` |
| ErrExternal | 409 | `external_account` |
| ErrInviteGone | 410 | `gone` |
| ErrBadCode | 401 | `invalid_code` |
| ErrTOTPRequired | 400 | `totp_required` |

- **Audit actions** (new, `TargetType:"user"`):
  - `user.create`
  - `user.disable`
  - `user.enable`
  - `user.role` (detail `{from,to}`)
  - `user.totp_reset`
  - `user.reinvite`
  - `user.activate` (actor = the new user; `result:"fail"` on a bad code, like vendor activate)
  - Each is written only on success, apart from the activate fail case.

- [ ] **Step 1: Write the failing tests in `internal/httpapi/users_test.go`.**
  - `TestAdminUsersRequireAdmin`: as staff, every `/api/admin/users*` route gives 403; without a session it gives 401.
  - `TestAdminCreateAndActivateStaff`:
    - The admin POSTs a user and gets 201, with an outbox link `/activate/<token>`.
    - `GET /api/activate/<token>` gives 200 with `totp_required:false`. POST with a 12-character password gives 204.
    - The user logs in, gets `{mfa_required:false,totp_setup_required:false}`, and `/api/me` gives 200.
    - The audit log has `user.create` then `user.activate`.
  - `TestActivateNotIPGated`: set the rule `external_ip_allow=["10.0.0.0/8"]` with the request from `203.0.113.5`. `GET /api/activate/<token>` gives 200, while `GET /api/invite/<token>` gives 403 `ip_denied`.
  - `TestCrossInviteTokens`: a staff token on `POST /api/invite/{t}` gives 410, and a vendor token on `POST /api/activate/{t}` gives 410. Neither account changes.
  - `TestForcedTOTPLogin`:
    - With the rule `force_totp` on, a staff user without TOTP logs in and gets `{mfa_required:false,totp_setup_required:true}`.
    - `/api/me` gives 401. Two calls to `POST /api/auth/totp/setup` return the same `otpauth_url`.
    - Enrol with a wrong code: 401 `invalid_code`. Enrol with a valid code: 200, then `/api/me` gives 200.
    - The audit log has `auth.totp.enable` and `auth.login.ok`, and `last_login_at` is set.
  - `TestForcedTOTPNotForVendorsOrEnrolled`:
    - A vendor (already enrolled) gets `mfa_required:true,totp_setup_required:false`.
    - A staff user with TOTP gets `mfa_required:true`. `POST /api/auth/totp/setup` with that half-session gives 401.
    - A fully logged-in session on `/api/auth/totp/setup` gives 401.
  - `TestForcedTOTPOff`: with the rule off, a staff user without TOTP logs straight in, and `totp_setup_required` is false.
  - `TestResetTOTPKillsSessions`:
    - A staff user with TOTP holds a full session S1 and a half (pre-code) session S2. The admin's reset gives 204.
    - S1 on `/api/me` gives 401, and S2 on `POST /api/auth/totp` gives 401.
    - The old code no longer logs in; the login answers `mfa_required:false`.
  - `TestAdminUserActionsAudit`:
    - Disable gives 204 plus a `user.disable` audit. Disabling the last admin gives 409 `last_admin`, with no audit row.
    - PATCH role on a vendor gives 409 `wrong_state`.
  - `TestRulesForceTOTPRoundTrip`: `PUT /api/admin/rules` with `force_totp:true` returns it, and `GET /api/rules` shows it.
  - `TestLoginTouchesLastLogin`: a password-only login sets `last_login_at`; a TOTP login sets it only after the code step.

- [ ] **Step 2: Run the tests and confirm they fail.**
  Run `go test ./internal/httpapi/ -run 'Admin|Activate|CrossInvite|ForcedTOTP|ResetTOTP|ForceTOTP|LastLogin'`. Expected: FAIL.

- [ ] **Step 3: Implement the handlers and login changes.**
  - **Login:** `setup := !u.TOTPEnabled && u.Role != "vendor" && u.AuthSource == "local" && rules.ForceTOTP`. Create the session with `mfaPassed = !u.TOTPEnabled && !setup`. Only for a fully logged-in result: `TouchLogin` plus `auth.login.ok`.
  - **Code step:** `totp` (the existing code step) also calls `TouchLogin`.
  - **`totpSetupPending` and `totpEnroll`:**
    - Require `session ok && !se.MFAPassed`, an `Active` user, `!u.TOTPEnabled`, a non-vendor and a local account; otherwise 401 `unauthorized`.
    - Setup reuses `PendingTOTP` and falls back to `BeginTOTP`.
    - Enroll runs `EnableTOTP`, then `MarkMFA`, `TouchLogin`, and audits `auth.totp.enable` and `auth.login.ok`.
    - Both use `accountLimit` keyed `"user:"+id`.

- [ ] **Step 4: Run the tests and confirm they pass.**
  Run `go test ./internal/...`. Expected: PASS.

- [ ] **Step 5: Commit.** Message: `feat(httpapi): user admin API, staff activation, forced TOTP enrolment`

---

### Task 4: Admin browsing of shares and requests; admin file view; disabled owners

**Files:**
- Modify: `internal/share/share.go`, `internal/share/access.go` (`OwnerDisabled`, `Admin*`), `internal/share/*_test.go`
- Modify: `internal/intake/intake.go`, `internal/intake/access.go` (same), `internal/intake/*_test.go`
- Create: `internal/httpapi/admin_browse_handlers.go`, `internal/httpapi/admin_browse_test.go`
- Modify: `internal/httpapi/preview_handlers.go` (admin route family, admin mark), `internal/httpapi/files_handlers.go` (owner-agnostic file lookup)

**Interfaces:**
- Produces:
  - `share.Share.OwnerDisabled bool` (from `u.disabled` in `shareCols`); `intake.Request.OwnerDisabled bool` likewise.
  - **Share admin methods:**
    - `(*share.Service).AdminList(ctx, q string, offset int) ([]share.Share, error)`: 100 per page, newest first. `q` matches the owner email or the share message, case-insensitive substring.
    - `AdminGet(ctx, id) (*share.Share, error)`.
    - `AdminRevoke(ctx, id) error`.
  - **Intake admin methods:** `(*intake.Service).AdminList(ctx, q string, offset int)`, `AdminGet(ctx, id)`, `AdminRevoke(ctx, id)`, with the same semantics.
  - **Admin HTTP routes:** all use `requireAdmin`.
    - `GET /api/admin/shares?q=&offset=` returns an array of `shareBase` plus `owner_email`, `file_count`, `recipient_count`.
    - `GET /api/admin/shares/{id}` returns `shareDetail` plus `owner_email`.
    - `POST /api/admin/shares/{id}/revoke` returns 204.
    - `GET /api/admin/requests?q=&offset=`, `GET /api/admin/requests/{id}` (the `requestDetail` shape) and `POST /api/admin/requests/{id}/revoke`.
    - `GET /api/admin/files/{id}/preview`, `…/preview/pages/{n}`, `…/preview/video.m3u8` and `…/preview/segments/{seg}`: any live, scan-clean file (staff-owned, vendor-uploaded or request-uploaded). There is no content/download route.
- **Implementation ruling:** keep the owner `Get`/`Revoke` signatures. Implement the owner and admin variants on shared private helpers that take a WHERE fragment, as `list` already does.

- [ ] **Step 1: Write the failing tests.**
  - `share`:
    - `TestDisabledOwnerShareGone`: disable the owner. `Landing` gives `ErrGone`, and `Authorize` on a pre-existing recipient session gives `ErrGone`.
    - Re-enabling serves again.
    - `VendorAccess` also gives `ErrGone`.
  - `intake`: `TestDisabledOwnerRequestGone`, the same for `Landing`, `Authorize` and `CheckUpload`.
  - `share`: `TestAdminListGetRevoke`:
    - Two owners' shares both appear, and `q` filters by owner email.
    - `AdminGet` of another owner's share works. `AdminRevoke` sets `revoked_at` and deletes the share's recipient sessions.
    - An unknown id gives `ErrNotFound`.
  - `intake`: `TestAdminListGetRevoke`, likewise.
  - `httpapi` in `admin_browse_test.go`:
    - `TestAdminBrowseRequiresAdmin`: staff on every `/api/admin/shares*`, `/api/admin/requests*` and `/api/admin/files*` route gets 403.
    - `TestAdminRevokeShareAudited`:
      - The admin revokes staff B's share and gets 204.
      - The audit has `share.revoke` with `ActorID` = the admin and detail `{"owner_id": B, "admin": true}`.
      - B's `GET /api/shares/{id}` shows `revoked_at`.
    - `TestAdminViewWatermarked`: use the existing fake preview fixtures from `preview_test.go`.
      - On an image file owned by staff B, the admin calls `GET /api/admin/files/{id}/preview` and then `/pages/0`.
      - The JPEG differs from the owner's unwatermarked `/api/files/{id}/preview/pages/0`.
      - Exactly one `file.view` audit row exists with the admin as actor, `target_id` = the file and detail `{"admin": true}`.
      - A second `GET …/preview` adds a second row; page fetches add none.
    - `TestAdminViewRefusesDeletedOrUnscanned`: a soft-deleted file and a `scan_status='infected'` file both give 404.
    - `TestAdminNoDownloadRoute`: `GET /api/admin/files/{id}/content` gives 404 `not_found`.

- [ ] **Step 2: Run the tests and confirm they fail.**
  Run `go test ./internal/share/ ./internal/intake/ ./internal/httpapi/ -run 'Disabled|Admin'`. Expected: FAIL.

- [ ] **Step 3: Implement.**
  - **Disabled owners:** `check` (share and intake) returns `ErrGone` when `OwnerDisabled`.
  - **Admin view context:** the admin preview wrap puts the admin into the context via a private key, `adminViewer`.
  - **Admin mark:** `mark` returns `preview.Mark{Email: admin.Email, IP: ip, At: now, Code: "ADMIN"}`, draw=true, when `a == nil` and an admin viewer is present. It does this before the owner path.
  - **Audit:** only the admin `…/preview` status route records `file.view`.
  - **File lookup:** `ownCleanFile` and the new admin lookup share one query helper that takes an optional owner id.

- [ ] **Step 4: Run the tests and confirm they pass.**
  Run `go test ./internal/...`. Expected: PASS.

- [ ] **Step 5: Commit.** Message: `feat: admin browsing of shares and requests, watermarked admin view; disabled owners stop serving`

---

### Task 5: Web: users page, activation, forced-TOTP login, rules toggle

**Files:**
- Create: `web/src/pages/admin/Users.tsx`, `web/src/pages/admin/Users.test.tsx`
- Modify: `web/src/pages/Invite.tsx` (prop `kind: "vendor" | "staff"`), `web/src/pages/Invite.test.tsx`
- Modify: `web/src/pages/Login.tsx`, `web/src/pages/Login.test.tsx`
- Modify: `web/src/pages/admin/Rules.tsx`, `web/src/pages/admin/Rules.test.tsx`
- Modify: `web/src/main.tsx`, `web/src/components/Shell.tsx`, `web/src/api.ts`, `web/src/i18n/*`

**Interfaces:**
- Consumes: Task 3's HTTP surface.
- **API client** (`api.ts`):
  - `adminUsers()`, `adminCreateUser(email, display_name, role)`, `adminUserAction(id, "disable"|"enable"|"reset-totp"|"reinvite")`, `adminSetRole(id, role)`.
  - `activateInfo(token)`, `activate(token, password, code)`.
  - `totpSetupPending()`, `totpEnroll(code)`.
  - `login` returns `{mfa_required, totp_setup_required}`.
- **Routes:** `/admin/users` (admin) and `/activate/:token` (public, `<Invite kind="staff" />`). The Shell admin nav gets "Users".

- [ ] **Step 1: Write the failing tests.**
  - `Users.test.tsx`:
    - The table renders the columns email, name, role, source, status, TOTP, last login.
    - The create form posts `{email,display_name,role}` and the new row appears.
    - "Reset TOTP" asks `window.confirm` and calls the action only on confirm.
    - The role select appears only for `auth_source==="local"` and non-vendor rows.
    - "Reinvite" appears only when the status is `invited`.
    - A 409 `last_admin` shows the `users.error.lastAdmin` text.
  - `Invite.test.tsx` (staff):
    - With `totp_required:false`, no QR is shown and the submit sends code `""`.
    - With `true`, the QR is shown.
    - A 400 `totp_required` reloads the info and shows the QR.
    - The vendor kind is unchanged: the existing tests still pass.
  - `Login.test.tsx`: when login answers `totp_setup_required:true`, the page shows the QR from `totpSetupPending`. A wrong code shows `login.invalidCode`, and a right code navigates to `/files`.
  - `Rules.test.tsx`: the `force_totp` checkbox loads and saves.

- [ ] **Step 2: Run the tests and confirm they fail.**
  Run `cd web && npx vitest run`. Expected: FAIL in the new tests.

- [ ] **Step 3: Implement.**
  - Reuse the `qrcode` rendering exactly as `TotpSetup.tsx` does.
  - Error keys:
    - `users.error.lastAdmin`: 「不能停用或降級最後一位本機管理員」
    - `users.error.external`: 「外部登入來源的帳號不能在這裡修改」
    - `users.error.emailTaken`
  - Rules page help text for force-TOTP: 「只套用於本機員工與管理員；廠商本來就必須使用雙因素驗證。開啟後，尚未設定的人下次登入時必須先完成設定。」

- [ ] **Step 4: Run the tests and confirm they pass.**
  Run `cd web && npx vitest run && npx tsc --noEmit`. Expected: PASS, with coverage thresholds met.

- [ ] **Step 5: Commit.** Message: `feat(web): users admin page, staff activation, forced TOTP enrolment`

---

### Task 6: Web: all-shares browsing

**Files:**
- Create: `web/src/pages/admin/AllShares.tsx`, `web/src/pages/admin/AllShares.test.tsx`
- Modify: `web/src/pages/ShareDetail.tsx`, `web/src/pages/RequestDetail.tsx` (prop `admin?: boolean`), their tests
- Modify: `web/src/main.tsx`, `Shell.tsx`, `api.ts`, `i18n/*`

**Interfaces:**
- Consumes: Task 4's HTTP surface.
- **Routes:**
  - `/admin/shares` (a tab switch between shares and requests, a search box `q`, and "more" paging by `offset`, 100 per page).
  - `/admin/shares/:id` gives `<ShareDetail admin />`, and `/admin/requests/:id` gives `<RequestDetail admin />`.
- **Admin mode** in `ShareDetail` and `RequestDetail`:
  - Load from `/api/admin/...` and show the owner email.
  - Hide owner-only actions: add or revoke recipients, copy link.
  - Keep "Revoke", which uses the admin endpoint.
  - The file "View" button opens `<Viewer base={"/api/admin/files/"+fid+"/preview"} />`.
  - Show no download button.
- **Nav:** the Shell admin nav gets "All shares".

- [ ] **Step 1: Write the failing tests.**
  - `AllShares.test.tsx`: the list renders the owner email. Typing `q` and submitting refetches with `?q=`. "More" requests `offset=100`. The requests tab lists requests.
  - `ShareDetail.test.tsx` (admin):
    - It fetches `/api/admin/shares/{id}`. There is no add-recipient form.
    - Revoke posts to `/api/admin/shares/{id}/revoke` after `confirm`.
    - View opens the Viewer with the admin base. There is no download link.
  - `RequestDetail.test.tsx` (admin): the same pattern.

- [ ] **Step 2: Run the tests and confirm they fail.**
  Run `cd web && npx vitest run`. Expected: FAIL.

- [ ] **Step 3: Implement.**

- [ ] **Step 4: Run the tests and confirm they pass.**
  Run `cd web && npx vitest run && npx tsc --noEmit`. Expected: PASS.

- [ ] **Step 5: Commit.** Message: `feat(web): admin all-shares and upload-request browsing`

---

### Task 7: Manuals and README

**Files:**
- Modify: `docs/admin-manual.md`:
  - §5: replace 「員工帳號（目前版本的限制）」 and 「員工遺失雙因素驗證裝置」 with the UI flow. Add the new subsections 「使用者管理」, 「全站強制雙因素驗證」 and 「最後一位管理員」.
  - §6: replace 「廠商遺失驗證器裝置」 with the reset-TOTP button.
  - §7: add the force-TOTP row.
  - Add a new section 「全站分享瀏覽」 that covers watermarked view only, the audit row, and the effect of a disabled owner.
- Modify: `docs/user-manual.md`: 「啟用帳號」 (the invitation link) and 「首次登入需設定雙因素驗證」.
- Modify: `README.md` and `README.en.md` feature lists only where they claim no user management.

- [ ] **Step 1: Edit the manuals and READMEs.** Every SQL block for staff or vendor TOTP is gone. Check with `grep -n "totp_enabled = false" docs/`, which should print nothing.
- [ ] **Step 2: Commit.** Message: `docs: user management, forced TOTP, admin share browsing`
