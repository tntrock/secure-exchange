# Phase 6: Vendor Accounts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Long-term external partners get vendor accounts that sign in with a password plus mandatory TOTP. Staff can share files to them, they see a "shared with me" list, and they can upload directly to staff who have dealt with them.

**Architecture:**
- **Accounts.** A vendor is a `users` row with `role = 'vendor'`. Phase 6 adds an organisation, a creator, an expiry date and an approval state to `users`, and a `vendor_invites` table.
- **`internal/vendor`** owns account lifecycle (create, approve, invite, activate, disable, expiry) and the creation policy `SX_VENDOR_CREATION`.
- **Shares to vendors** reuse the one-time-share machinery. A vendor recipient is a `share_recipients` row with `vendor_id` set. The vendor's logged-in session (not an email code) produces the same `share.Access`, so the phase 3–4 download, preview, watermark and trace handlers serve vendors unchanged under `/api/vendor/shares/{id}/files/{fid}/…`.
- **Direct uploads** reuse the tus handler with a third caller kind (vendor). They land in the chosen staff member's space with `vendor_id` set and go through the phase 5 scan exactly like request-link uploads.
- **Role enforcement.** `requireUser` becomes staff/admin only, `requireVendor` is vendor only, and `requireAccount` (any role) is used for `/api/me` and logout.

**Tech Stack:**
- Go: pgx/v5, goose, `pquerna/otp` (already used by `internal/auth/totp.go`).
- React 19, vitest, react-i18next, tus-js-client, `qrcode` (all already installed).

**Spec:** `docs/superpowers/specs/2026-10-24-secure-exchange-design.md`. Relevant sections: §3 (roles), §4.2, §5.2, §5.3 (vendor direct upload), §5.4 (watermark identity), §5.10 (vendor accounts), §5.8 (audit), §6, §11 phase 6.

## Global Constraints

**From the spec:**
- §3/§4.2: vendor accounts sign in with a password and **mandatory TOTP**.
- §5.10: staff create vendor accounts subject to a site-wide setting with three options: staff create freely, an admin must approve, or only admins create. Creation sends an invitation email, and the vendor sets a password and TOTP at first sign-in. A vendor account has an expiry date and can be disabled.
- §5.10: one vendor account is one person. Accounts may be grouped under a vendor organisation.
- §5.10: any staff member may share to any *active* vendor account.
- §5.10: a vendor uploading directly may only pick staff who have shared to them or who created their account. Vendors never see the full staff list.
- §5.2: a share can contain both email recipients and vendors. Vendors skip the email-code flow and see shared files in a "shared with me" list. View mode, watermark, expiry and IP rules are the same as for one-time shares.
- §5.4: the watermark identity for a vendor is the vendor account's email.
- §5.3: vendor uploads are external uploads, so they are ClamAV-scanned with the phase 5 gating and notifications.

**Project rules:**
- No new Go module dependencies. No new npm dependencies.
- Every UI string exists in both `web/src/i18n/en.json` and `web/src/i18n/zh-TW.json`. `keys.test.ts` enforces this.
- CI gates are test, lint and coverage. Go coverage is computed with `scripts/covergate.sh` on the profile merged with the tools tests, and must stay ≥ 90%; the last run was 91.36%. Web vitest thresholds must stay green. New code needs behavioural tests, not filler.
- Lint locally with:
  `MSYS_NO_PATHCONV=1 docker run --rm -v "$PWD:/app" -w /app golangci/golangci-lint:v2.15.0 golangci-lint run --build-tags tools ./...`
- DB tests use `testdb.New(t)`, which gives each test its own schema. It needs `SX_TEST_DATABASE_URL='postgres://sx:sx@localhost:55432/sx?sslmode=disable'`.
- CI runs with `-race`, which needs cgo, and the host has none. Check new concurrent test code in a container:
  `MSYS_NO_PATHCONV=1 docker run --rm -v "$PWD:/src" -w /src --network host -e SX_TEST_DATABASE_URL=… golang:1.26 go test -race ./internal/<pkg>/`
- Audit every security event with `s.record` (httpapi) or `audit.Log.Append`.
- Tokens: invitation links carry 32 random bytes in base64url. Only the SHA-256 is stored; there is no sealed copy, so `sealedCols` needs no change.

## Review Focus

1. **Role confusion.** A vendor session calling any staff endpoint (files, shares, requests, uploads, admin) gets 403. A staff session calling any `/api/vendor/…` endpoint gets 403. Test: Task 1 `TestRoleGates`, table-driven over every route in `server.go`.
2. **A vendor is disabled, expires or is rejected mid-session.** The next request is 401, and disabling revokes all of that vendor's sessions. Tests: Task 1 `TestVendorExpiredSessionRejected`, Task 2 `TestDisableRevokesSessions`.
3. **IDOR across shares.** Vendor A cannot open share S or its files if A is not a recipient of S. A revoked vendor recipient, or a revoked or expired share, is refused. Test: Task 3 `TestVendorShareIsolation`.
4. **An upload targets a staff member outside the allowed list** (an arbitrary staff UUID, an admin who never shared, a disabled staff member). The response is 403 and no upload row is created. Test: Task 4 `TestVendorUploadTargetNotAllowed`.
5. **Invitation token misuse.** Using a token twice, after its 7-day expiry, after a newer invitation replaced it, or for a rejected or disabled account returns 410. Activation also fails on a wrong TOTP code, and nothing changes. Test: Task 2 `TestInviteTokenLifecycle`.

---

### Task 1: Schema, config and role enforcement

**Files:**
- Create: `internal/db/migrations/0006_vendors.sql`
- Modify: `internal/auth/users.go`: new `User` fields; `userCols`
- Modify: `internal/config/config.go`: `VendorCreation`
- Modify: `internal/httpapi/middleware.go`: `requireUser` becomes staff/admin; add `requireAccount` and `requireVendor`
- Modify: `internal/httpapi/server.go`: `/api/me`, `/api/me/totp/*` and `/api/auth/logout` use `requireAccount`
- Modify: `internal/httpapi/auth_handlers.go`: login rejects a vendor that is expired, not approved or has no TOTP; `/api/me` adds `org` and `expires_at`
- Test: `internal/httpapi/roles_test.go`, `internal/config/config_test.go`, `internal/auth/users_test.go`

**Interfaces:**
- Produces:
  - `auth.User` gains `ExpiresAt *time.Time`, `Approval string` (`pending|approved|rejected`), `OrgID *uuid.UUID` and `CreatedBy *uuid.UUID`.
  - `func (u *User) Active(now time.Time) bool`: true when the user is not disabled, `Approval == "approved"`, and has no `ExpiresAt` or `now` is before it. For role `vendor`, it also requires `PasswordHash != ""` and `TOTPEnabled`.
  - `config.Config.VendorCreation string`, from `SX_VENDOR_CREATION`, one of `staff`, `approval` or `admin`, default `approval`. It is web-only; the worker ignores it.
  - Middleware, each built on the MFA-passed session lookup that `requireUser` uses today:
    - `requireAccount(next) http.Handler`: any role that is `Active`.
    - `requireUser(next)`: `Active`, and role is `staff` or `admin`. A vendor gets **403** `forbidden`.
    - `requireVendor(next)`: `Active`, and role is `vendor`. Staff and admins get **403** `forbidden`.
    - When the user is not `Active`, all three return 401 `unauthorized`.
    - `requireAdmin` keeps wrapping `requireUser`.
  - Login: password OK but `!u.Active(now)` → the same 401 `invalid_credentials` as a wrong password. Audit `auth.login.fail` with detail `stage: "inactive"`.

- [ ] **Step 1: Write migration `0006_vendors.sql`**

```sql
-- +goose Up
CREATE TABLE vendor_orgs (id uuid PRIMARY KEY, name text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE UNIQUE INDEX vendor_orgs_name ON vendor_orgs (lower(name));
ALTER TABLE users ADD COLUMN vendor_org_id uuid REFERENCES vendor_orgs, ADD COLUMN created_by uuid REFERENCES users,
  ADD COLUMN expires_at timestamptz,
  ADD COLUMN approval text NOT NULL DEFAULT 'approved' CHECK (approval IN ('pending','approved','rejected'));
CREATE TABLE vendor_invites (
  token_hash bytea PRIMARY KEY, user_id uuid NOT NULL REFERENCES users ON DELETE CASCADE,
  expires_at timestamptz NOT NULL, used_at timestamptz, created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX vendor_invites_user ON vendor_invites (user_id);
ALTER TABLE share_recipients ADD COLUMN vendor_id uuid REFERENCES users;
CREATE UNIQUE INDEX share_recipients_vendor ON share_recipients (share_id, vendor_id) WHERE vendor_id IS NOT NULL;
CREATE INDEX share_recipients_by_vendor ON share_recipients (vendor_id) WHERE vendor_id IS NOT NULL;
ALTER TABLE uploads ADD COLUMN vendor_id uuid REFERENCES users;
ALTER TABLE files ADD COLUMN vendor_id uuid REFERENCES users;
CREATE TABLE vendor_share_views (
  session_hash bytea NOT NULL, share_id uuid NOT NULL REFERENCES shares ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (session_hash, share_id));
-- phase-5 follow-ups: lookups by request / uploader
CREATE INDEX uploads_request ON uploads (request_id) WHERE request_id IS NOT NULL;
CREATE INDEX request_otps_uploader ON request_otps (uploader_id);
CREATE INDEX request_sessions_uploader ON request_sessions (uploader_id);

-- +goose Down
DROP INDEX request_sessions_uploader, request_otps_uploader, uploads_request;
DROP TABLE vendor_share_views;
ALTER TABLE files DROP COLUMN vendor_id;
ALTER TABLE uploads DROP COLUMN vendor_id;
ALTER TABLE share_recipients DROP COLUMN vendor_id;
DROP TABLE vendor_invites;
ALTER TABLE users DROP COLUMN approval, DROP COLUMN expires_at, DROP COLUMN created_by, DROP COLUMN vendor_org_id;
DROP TABLE vendor_orgs;
```

- [ ] **Step 2: Write the failing tests**
- **`TestRoleGates`** in `roles_test.go`:
  - Create one staff, one admin and one vendor. The vendor is active: password set, TOTP enabled, approved, expiry +30 days. Log each in through `/api/auth/login` and `/api/auth/totp`, using the TOTP test helper the auth tests already use.
  - Table: every `requireUser`/`requireAdmin` route registered in `server.go` (files, shares, requests, `/api/uploads/`, `/api/admin/trace`).
    - The vendor gets 403 on each.
    - Staff gets 403 on `/api/admin/trace`.
    - `/api/me` returns 200 for all three, with the correct `role`.
  - Task 1 has no vendor routes yet. Tasks 2–4 each add their `/api/vendor/…` routes to this table, expecting 403 for staff.
- **`TestVendorExpiredSessionRejected`**: the vendor logs in, then `UPDATE users SET expires_at = now() - interval '1 second'` → the next `/api/me` is 401.
- **`TestLoginRejectsInactiveVendor`**: all three of these get 401 `invalid_credentials`, and the audit detail is `stage: inactive`:
  - a vendor with `approval = 'pending'` and a valid password;
  - an expired vendor;
  - a vendor with a password but TOTP not enabled.
- **`TestUserActive`**: table-driven over the `Active` rules.
- **Config**: `SX_VENDOR_CREATION=bogus` → error. The default is `approval`.

- [ ] **Step 3: Run the tests and confirm they fail**

Run: `go test ./internal/httpapi/ ./internal/auth/ ./internal/config/ -run 'Role|Vendor|Active|Config'`
Expected: FAIL.

- [ ] **Step 4: Implement as in Interfaces.**
  - Keep `requireUser`'s callers unchanged: the role check happens inside it.
  - Look at the existing login and TOTP tests (`auth_test.go`). Staff without TOTP must still log in with `mfa_required: false`.

- [ ] **Step 5: Run `go test ./...` with the DB env set, then lint.**

Expected: PASS, and lint reports 0 issues.

- [ ] **Step 6: Commit**

```bash
git add internal/db/migrations/0006_vendors.sql internal/auth internal/config internal/httpapi
git commit -m "feat(auth): vendor schema and role-gated middleware"
```

---

### Task 2: Vendor account lifecycle

**Files:**
- Create: `internal/vendor/vendor.go`: service
- Create: `internal/httpapi/vendors_handlers.go`: staff/admin vendor management, invitation landing and activation
- Modify: `internal/httpapi/server.go`: `Deps.Vendors *vendor.Service`, routes
- Modify: `cmd/secure-exchange/main.go`: wiring
- Modify: `internal/mail/templates.go`: `VendorInvitation`, `VendorApprovalNeeded`
- Modify: `internal/audit/audit.go`: actions
- Test: `internal/vendor/vendor_test.go`, `internal/httpapi/vendors_test.go`

**Interfaces:**

```go
package vendor

var (
	ErrNotFound, ErrForbidden, ErrEmailTaken, ErrInviteGone, ErrBadCode error
)
type ValidationError struct{ Field, Code string } // codes: required, invalid, out_of_range, too_short

type Vendor struct {
	ID                 uuid.UUID
	Email, DisplayName string
	Org                string     // "" when none
	Status             string     // pending | rejected | invited | active | disabled | expired
	ExpiresAt          time.Time
	CreatedByID        *uuid.UUID
	CreatedByName      string
	CreatedAt          time.Time
}
type CreateInput struct {
	Email, DisplayName, Org string
	ExpiresAt               time.Time
}

func NewService(pool *pgxpool.Pool, users *auth.Users, sessions *auth.Sessions, outbox *mail.Outbox, baseURL, mode string) *Service
func (s *Service) Create(ctx context.Context, by *auth.User, in CreateInput) (*Vendor, error)
func (s *Service) List(ctx context.Context, activeOnly bool) ([]Vendor, error) // newest first; activeOnly = Status "active"
func (s *Service) Approve(ctx context.Context, by *auth.User, id uuid.UUID) error  // admin; pending → approved + invitation mail
func (s *Service) Reject(ctx context.Context, by *auth.User, id uuid.UUID) error   // admin; pending → rejected
func (s *Service) SetDisabled(ctx context.Context, by *auth.User, id uuid.UUID, disabled bool) error // creator or admin; disabling revokes sessions
func (s *Service) SetExpiry(ctx context.Context, by *auth.User, id uuid.UUID, at time.Time) error   // creator or admin
func (s *Service) Reinvite(ctx context.Context, by *auth.User, id uuid.UUID) error  // creator or admin; status invited only; voids older invitations
func (s *Service) InviteInfo(ctx context.Context, token string) (email, otpauthURL string, err error) // generates a fresh pending TOTP secret
func (s *Service) Activate(ctx context.Context, token, password, code string) (uuid.UUID, error)
```

**Status** is derived and never stored:
- `rejected` or `pending`, from `approval`;
- otherwise `disabled`, when disabled;
- otherwise `expired`, when `expires_at` is at or before now;
- otherwise `invited`, when the password is empty or TOTP is off;
- otherwise `active`.

**Rules:**
- **Create.** `role = 'vendor'`, `created_by` = the creating user, no password.
  - The email must be unique across all users; a duplicate returns `ErrEmailTaken`.
  - Fields:
    - `email` must pass `mail.ValidAddress`;
    - `display_name` is 1–100 runes;
    - `org` is optional, at most 100 runes, and is found or created case-insensitively in `vendor_orgs`;
    - `expires_at` must fall between now + 1 day and now + 1095 days.
  - **Policy** (`mode`):
    - `admin`: a non-admin gets `ErrForbidden`.
    - `approval`: a staff-created vendor gets `approval = 'pending'`, and every active admin is mailed `VendorApprovalNeeded`. An admin-created vendor is `approved`.
    - `staff`: always `approved`.
  - An `approved` vendor gets an invitation right away, in the same transaction: a `vendor_invites` row valid for 7 days, and a `VendorInvitation` email to `baseURL + "/invite/" + token`.
- **Permissions.** Creator-or-admin checks return `ErrForbidden`. A vendor ID that doesn't exist, or isn't a vendor, returns `ErrNotFound`.
- **`InviteInfo`.** Valid only when the token is not used, not expired, and the newest for its user, and the user's status is `invited`. Otherwise `ErrInviteGone`. Uses `users.BeginTOTP`.
- **`Activate`.** Same validity checks.
  - Password: at least 12 runes and at most 256 bytes. A short one returns `&ValidationError{"password","too_short"}`.
  - Then `users.EnableTOTP(code)`; a wrong code returns `ErrBadCode` and nothing changes.
  - In one transaction: set `password_hash`, `totp_enabled`, and the invitation's `used_at`.
  - Ordering: `EnableTOTP` writes its own row today. Check the code before the transaction with `CheckTOTP`. Inside the transaction set `totp_enabled = true` directly, guarded by `AND NOT totp_enabled`, so that a failure leaves nothing half-done.

**Audit actions:**
- `vendor.create`
- `vendor.approve`
- `vendor.reject`
- `vendor.disable`
- `vendor.enable`
- `vendor.expiry`
- `vendor.reinvite`
- `vendor.activate`

The actor is the user; for `vendor.activate` it is actor type `vendor` with the vendor id. The target is `user` with the vendor id.

**Routes:**
- `GET /api/vendors?active=1` (`requireUser`): JSON objects `{id, email, display_name, org, status, expires_at, created_by_name, created_at, can_manage}`. `can_manage` is true when the caller is the creator or an admin. Any staff member may list all vendors: they need the active list to share, and the spec lets any staff member share to any active vendor.
- `POST /api/vendors` (`requireUser`) returns 201 with the object. Errors:
  - 422 `{"error":"validation",field,code}`;
  - 409 `email_taken`;
  - 403 `forbidden` in admin mode.
- `POST /api/vendors/{id}/approve` and `/reject` (`requireAdmin`) return 204.
- `POST /api/vendors/{id}/disable`, `/enable` and `/reinvite`, and `PATCH /api/vendors/{id}` with `{expires_at}` (`requireUser`, creator or admin), return 204.
- `GET /api/invite/{token}` returns `{email, otpauth_url}`. `POST /api/invite/{token}` with `{password, code}` returns 204. Both are wrapped in `recipIP`, the padded per-IP limiter. A gone token returns 410 `gone`; a bad code returns 401 `invalid_code`.

- [ ] **Step 1: Write the failing tests**

`vendor_test.go`:
- **`TestCreatePolicy`**: in each of the three modes, a staff creator and an admin creator. Check the resulting status (`pending`, `invited` or `ErrForbidden`) and the mail rows: the invitation to the vendor, or the approval notice to the admins.
- **`TestCreateValidation`**: each field rule; a duplicate email (including a staff user's email) returns `ErrEmailTaken`.
- **`TestOrgFindOrCreate`**: `"ACME"` and `"acme"` share one org row.
- **`TestApproveRejectAdminOnly`**: staff calling `Approve` gets `ErrForbidden`. Approve moves the vendor to `invited` and sends the invitation; Reject moves it to `rejected`.
- **`TestManagePermissions`**: a staff member who is not the creator gets `ErrForbidden` on disable, expiry and reinvite. The creator and an admin succeed.
- **`TestDisableRevokesSessions`**: with a vendor session row present, `SetDisabled(true)` leaves no sessions for that user. `SetDisabled(false)` makes the vendor `active` again.
- **`TestInviteTokenLifecycle`**:
  - `InviteInfo` works.
  - `Activate` with an 11-rune password returns a `too_short` validation error.
  - A wrong code returns `ErrBadCode`, and both `password_hash` and `totp_enabled` stay unchanged.
  - A valid code (from the `otpauth` secret through `totp.GenerateCode`) works, and the status becomes `active`.
  - Reusing the same token returns `ErrInviteGone`.
  - `Reinvite` on another invited vendor voids its first token (`ErrInviteGone`), and the new one works.
  - An expired invitation (moved back with SQL) returns `ErrInviteGone`.

`vendors_test.go`: HTTP status and JSON mapping for each route. Covers 422, 409, the 403 for a non-creator, `can_manage`, and the invitation GET/POST including 410 and 401. Add the new routes to `TestRoleGates`.

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./internal/vendor/ ./internal/httpapi/ -run 'Vendor|Invite|Create|Approve|Manage|Disable|Org|Role'`
Expected: FAIL.

- [ ] **Step 3: Implement as in Interfaces, and wire up `main.go`.**

- [ ] **Step 4: Run `go test ./...` and lint.** Expected: PASS, 0 issues.

- [ ] **Step 5: Commit**

```bash
git add internal/vendor internal/httpapi internal/mail internal/audit cmd/secure-exchange/main.go
git commit -m "feat(vendor): vendor account creation, approval, invitation and activation"
```

---

### Task 3: Sharing to vendors

**Files:**
- Modify: `internal/share/share.go`: `CreateInput.VendorIDs`, `AddRecipients` with vendors, `Recipient.VendorID`
- Modify: `internal/share/access.go`: `RequestCode`/`VerifyCode` ignore vendor rows; `VendorAccess`, `VendorShares`
- Create: `internal/httpapi/vendor_shares_handlers.go`
- Modify: `internal/httpapi/server.go`, `preview_handlers.go` (vendor prefix), `shares_handlers.go` (create/add take `vendor_ids`; recipient JSON gains `vendor`)
- Modify: `internal/mail/templates.go`: `VendorShared`
- Test: `internal/share/vendor_test.go`, `internal/httpapi/vendor_shares_test.go`

**Interfaces:**
- **Consumes:** `auth.User.Active`, `requireVendor`, and the session token cookie (`s.session(r)`) for the session hash.
- **Produces:**

```go
type CreateInput struct { /* existing fields */ VendorIDs []uuid.UUID }
type Recipient struct { /* existing fields */ VendorID *uuid.UUID }

func (s *Service) AddRecipients(ctx context.Context, owner *auth.User, shareID uuid.UUID, emails []string, vendorIDs []uuid.UUID) ([]Recipient, error)
// VendorShares lists live shares (not revoked/expired) where vendorID is a non-revoked recipient, newest first.
func (s *Service) VendorShares(ctx context.Context, vendorID uuid.UUID) ([]Share, error)
// VendorAccess is Authorize for a signed-in vendor: same share checks (revoked/expired → ErrGone, IP → ErrIPDenied),
// recipient row must exist with vendor_id = vendorID and not be revoked (else ErrNotFound).
// The first call per (sessionHash, share) counts a view under max_views (ErrViewLimit when exhausted),
// sets first_opened_at (first-open mail to the owner, as VerifyCode does) and last_access_at.
func (s *Service) VendorAccess(ctx context.Context, vendorID, shareID uuid.UUID, sessionHash []byte, ip netip.Addr) (*Access, error)
```

- **Recipients.**
  - `Create` and `AddRecipients`: there must be at least one recipient in total, counting emails plus vendors. The 50 cap covers both. An empty list returns the validation error `recipients/required`.
  - Every vendor ID must be an `Active` vendor, otherwise `invalid("vendor_ids","not_found")`.
  - The recipient row stores the vendor's email and `vendor_id`.
  - If an email entry equals a vendor's address, keep the vendor row only, with no duplicate key error.
  - Vendors get a `VendorShared` email: sender, message, expiry, and the link `baseURL + "/vendor/shares"`. It contains no share token.
- **Email codes.** `RequestCode` and `VerifyCode` match only `vendor_id IS NULL` rows, so a vendor can never be reached with an email code.
- **Vendor routes** (all `requireVendor`):
  - `GET /api/vendor/shares` returns `[{id, owner_name, message, expires_at, file_count, allow_download, watermark}]`.
  - `GET /api/vendor/shares/{id}` calls `VendorAccess` and returns the same body as the recipient file list, built with the existing `recipientFiles(ctx, a)`.
  - `GET /api/vendor/shares/{id}/files/{fid}/content` is the existing `recipientDownload`.
  - The four preview routes go under the `"/api/vendor/shares/{id}/files/{fid}"` prefix, added to the `previewRoutes` map with a `vendorShare` wrapper. HEAD gets 405, as for recipients.
  - The `requireVendorShare(next)` middleware:
    - takes the session hash from the `sx_session` cookie (hashed the way `auth.Sessions` hashes it; reuse or export that helper);
    - calls `VendorAccess`;
    - maps errors with `recipientErr`;
    - stores the access under `accessKey{}`, so the existing handlers work unchanged.
- **Staff JSON.**
  - `POST /api/shares` and `POST /api/shares/{id}/recipients` accept `vendor_ids`.
  - In the share detail, recipient objects gain `vendor: true|false`.
- **Audit.** Vendor download and view events reuse the existing handlers, so they record actor type `recipient` with the recipient id. Nothing new is needed.

- [ ] **Step 1: Write the failing tests**

`vendor_test.go` (share package):
- **`TestCreateWithVendors`**:
  - vendors only → OK, and a `VendorShared` mail is queued;
  - an inactive or unknown vendor → `vendor_ids/not_found`;
  - an email that matches a vendor → a single vendor row;
  - no recipients at all → `recipients/required`.
- **`TestRequestCodeIgnoresVendorRows`**: `RequestCode` with the vendor's email → `sent=false`, and no OTP row.
- **`TestVendorAccessCountsViewOncePerSession`**: `max_views: 2`.
  - The same session twice → `view_count` 1.
  - A second session → 2.
  - A third session → `ErrViewLimit`.
  - `first_opened_at` is set, and exactly one first-open mail is queued.
- **`TestVendorShareIsolation`**:
  - vendor B (not a recipient) → `ErrNotFound`;
  - a revoked recipient → `ErrNotFound`;
  - a revoked share → `ErrGone`;
  - an IP outside the allow list → `ErrIPDenied`.
- **`TestVendorSharesList`**: only the vendor's live shares, newest first.

`vendor_shares_test.go` (HTTP, through a real vendor login):
- list → open share → download a plain file (200, the bytes match) → preview page;
- another vendor gets 404 on the same share's `files/{fid}/content`;
- staff calling `/api/vendor/shares` gets 403 (add these routes to `TestRoleGates`);
- after the share is revoked → 410.

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./internal/share/ ./internal/httpapi/ -run 'Vendor|RequestCodeIgnores|Role'`
Expected: FAIL.

- [ ] **Step 3: Implement.**

- [ ] **Step 4: Run `go test ./...` and lint.** Expected: PASS, 0 issues.

- [ ] **Step 5: Commit**

```bash
git add internal/share internal/httpapi internal/mail
git commit -m "feat(share): share to vendor accounts with signed-in access"
```

---

### Task 4: Vendor direct uploads

**Files:**
- Modify: `internal/upload/tus.go`: vendor caller
- Modify: `internal/scan/worker.go`: uploader email and link for vendor uploads
- Create: `internal/vendor/recipients.go`: `UploadTargets`
- Modify: `internal/httpapi/vendor_shares_handlers.go` (or a new `vendor_uploads_handlers.go`), `server.go`, `files_handlers.go`
- Test: `internal/upload/vendor_test.go`, `internal/scan/worker_test.go`, `internal/httpapi/vendor_uploads_test.go`

**Interfaces:**
- **Produces:**

```go
// UploadTargets lists staff/admin users the vendor may upload to: the creator of the vendor account plus the
// owner of every share that has (or had) this vendor as a recipient; disabled users excluded; ordered by name.
func UploadTargets(ctx context.Context, q Querier, vendorID uuid.UUID) ([]Target, error)
type Target struct{ ID uuid.UUID; Name, Email string }
func CanUploadTo(ctx context.Context, q Querier, vendorID, staffID uuid.UUID) (bool, error)
```

`Querier` is the same `Exec`/`QueryRow` interface as `intake.Querier`; declare it in `vendor`.

- **tus.** `caller()` gains a third kind: `auth.UserFrom(ctx)` with `Role == "vendor"`.
  - **Create:**
    - Reads the Upload-Metadata key `recipient` (a staff UUID).
    - `CanUploadTo` false, or a malformed UUID, → 403 with the plain-text body `recipient_not_allowed`.
    - Otherwise the upload row gets `owner_id = recipient` and `vendor_id = vendor`.
  - **load/delete** for a vendor match `vendor_id = $vendor`. For staff, add `AND vendor_id IS NULL` to the existing conditions. Uploader matching is unchanged.
  - **finish** inserts `files.vendor_id`, sets `scan_status = 'pending'` and creates the `scan_jobs` row, as for request uploads. The audit actor is type `vendor` with the vendor id.
- **Routes:**
  - `"/api/vendor/uploads/"`, mounted as `perIPUpload(requireVendor(s.Uploads.ServeHTTP))`. Only POST is rate-limited, as for the request mount.
  - `GET /api/vendor/recipients` returns `[{id, name, email}]`.
  - `GET /api/vendor/uploads` returns the vendor's finished files: `[{id, name, size, recipient_name, created_at}]`, newest first.
- **Staff `/api/files`** items gain `vendor_email` (null unless `vendor_id` is set).
- **Scan worker.**
  - The uploader email is `COALESCE(request_uploaders.email, vendor users.email)`, via LEFT JOINs.
  - The link is the request page when `request_id` is set, otherwise `BaseURL + "/files"`.
  - The admin copy of the infected notice still carries no link.

- [ ] **Step 1: Write the failing tests**
- **`TestVendorUploadCreatesPendingFile`** (upload): the vendor uploads to a staff member who shared to them. The file has `owner_id` = that staff member, `vendor_id` set, status `pending`, a scan job, and an audit actor of type `vendor`.
- **`TestVendorUploadTargetNotAllowed`**: each of these → 403 `recipient_not_allowed`, and the `uploads` row count is unchanged:
  - an arbitrary staff UUID;
  - an admin who never shared;
  - a disabled staff member who did share;
  - a missing `recipient` metadata key.
- **`TestVendorUploadIsolation`**:
  - vendor B gets 404 on HEAD or PATCH of vendor A's upload;
  - the target staff member gets 404 on HEAD of the vendor upload via `/api/uploads/{id}`.
- **`TestUploadTargets`**: creator plus share owners, deduplicated; a disabled user is excluded; another vendor's targets are not leaked.
- **Scan worker, `TestScanVendorUploadNotifies`**: a clean vendor file → the owner's mail mentions the vendor's email, and the link ends in `/files`.
- **HTTP, `vendor_uploads_test.go`**: `/api/vendor/recipients` and `/api/vendor/uploads` return the shapes above. Staff get 403 (add to `TestRoleGates`). `/api/files` shows `vendor_email`.

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./internal/upload/ ./internal/scan/ ./internal/vendor/ ./internal/httpapi/ -run 'Vendor|UploadTargets|Role'`
Expected: FAIL.

- [ ] **Step 3: Implement.**

- [ ] **Step 4: Run `go test ./...`, lint, and `-race` for `upload`/`scan` in the container.** Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/upload internal/scan internal/vendor internal/httpapi
git commit -m "feat(upload): vendor direct uploads to permitted staff"
```

---

### Task 5: Web, staff side

**Files:**
- Create: `web/src/pages/Vendors.tsx`: list, create form, manage actions, admin approvals
- Modify: `web/src/components/ShareDialog.tsx`: vendor picker
- Modify: `web/src/pages/ShareDetail.tsx`: vendor badge on recipients; add vendors
- Modify: `web/src/pages/Files.tsx`: source column
- Modify: `web/src/components/Shell.tsx`, `web/src/main.tsx`, `web/src/api.ts`, `web/src/i18n/en.json`, `web/src/i18n/zh-TW.json`
- Test: `Vendors.test.tsx`, plus updates to `ShareDialog.test.tsx`, `ShareDetail.test.tsx`, `Files.test.tsx` and `Shell.test.tsx`

**Interfaces:**
- **Consumes:** the JSON shapes from Tasks 2–4.
- **Produces:**
  - `api.ts`: type `VendorInfo` and methods `vendors(activeOnly?)`, `createVendor`, `approveVendor`, `rejectVendor`, `disableVendor`, `enableVendor`, `reinviteVendor`, `setVendorExpiry`. `createShare` and `addRecipients` gain `vendor_ids`. `FileInfo` gains `vendor_email`.
- **Behaviour:**
  - **Vendors page** (`/vendors`, staff and admin):
    - A create form with email, display name, organisation (free text, with a `<datalist>` of existing org names taken from the list), and an expiry date. The date input has `min` = tomorrow, `max` = today + 1095, and defaults to +365.
    - A table grouped by organisation, showing name, email, status badge, expiry, and created by.
    - Rows with `can_manage` get Disable/Enable, Reinvite (only when invited) and "Change expiry" (an inline date input).
    - Admins also get a "Pending approval" section with Approve and Reject; Reject asks for confirmation.
    - Errors map from `email_taken`, `forbidden` and the validation codes to i18n messages.
  - **ShareDialog**: a "Vendors" multi-select (a checkbox list with a filter input) of `vendors(true)`, shown as "Name <email> · Org". The dialog accepts zero emails when at least one vendor is chosen.
  - **ShareDetail**: vendor recipients show a badge. "Add recipients" also offers the vendor picker.
  - **Files**: a source line under the name: the vendor's email for vendor uploads, or a link to the request for request uploads.
  - **Shell**: a "Vendors" nav link for staff and admin.

- [ ] **Step 1: Write the failing tests**
- **`Vendors.test.tsx`**:
  - `creates a vendor with org and expiry`
  - `shows approve/reject only to admins`
  - `manage actions only when can_manage`
  - `email_taken shows message`
- **`ShareDialog.test.tsx`**:
  - `can share to vendors only`: `createShare` receives `vendor_ids` and `emails: []`
  - `filters vendor list`
- **`ShareDetail.test.tsx`**: `vendor recipient shows badge`.
- **`Files.test.tsx`**: `vendor upload shows source`.

- [ ] **Step 2: Run the tests and confirm they fail.** Run `cd web && npx vitest run`; expect the new tests to fail.

- [ ] **Step 3: Implement, including i18n in both languages.**

- [ ] **Step 4: Verify.** Run `cd web && npx vitest run --coverage && npx tsc -b`; expect PASS with the thresholds met.

- [ ] **Step 5: Commit**

```bash
git add web
git commit -m "feat(web): vendor management and sharing to vendors"
```

---

### Task 6: Web, vendor side and docs

**Files:**
- Create:
  - `web/src/pages/vendor/VendorShares.tsx`: "Shared with me" list
  - `web/src/pages/vendor/VendorShare.tsx`: one share's files
  - `web/src/pages/vendor/VendorUpload.tsx`
  - `web/src/pages/Invite.tsx`: activation
- Modify:
  - `web/src/main.tsx`: role-aware routes
  - `web/src/components/Shell.tsx`: vendor nav
  - `web/src/pages/Login.tsx`: redirect by role
  - `web/src/components/Uploader.tsx`: a `metadata` prop
  - `web/src/api.ts`, i18n files
  - `README.md`, `README.zh-TW.md`: a "Vendor accounts" section and `SX_VENDOR_CREATION`
  - `.env.example`
- Test: `vendor/*.test.tsx`, `Invite.test.tsx`, and updates to `Login.test.tsx`, `Uploader.test.tsx` and `main` routing tests if any exist

**Interfaces:**
- **Consumes:**
  - `/api/me` `role`;
  - `/api/vendor/shares`, `/api/vendor/shares/{id}` and its files, `/api/vendor/recipients`, `/api/vendor/uploads`;
  - tus at `/api/vendor/uploads/` with metadata `recipient`;
  - `/api/invite/{token}`.
- **Produces:**
  - `Uploader` gets the prop `metadata?: Record<string,string>`, merged into the tus metadata.
  - `Private` becomes role-aware:
    - `Private roles={["staff","admin"]}` for the staff pages;
    - `Private roles={["vendor"]}` for `/vendor/*`;
    - a wrong role redirects to that role's home (`/files` or `/vendor/shares`).
    - Login after success → `/vendor/shares` for vendors, `/files` otherwise.
- **Behaviour:**
  - **`/vendor/shares`**: a list with owner, message, expiry, file count, and a link to each share.
  - **`/vendor/shares/:id`**:
    - The same file list, view and download behaviour as `recipient/Access.tsx`'s files step, using `Viewer` with `base` = `/api/vendor/shares/${id}/files/${fid}/preview`.
    - Download link `/api/vendor/shares/${id}/files/${fid}/content`.
    - The same `mark_pending` note.
    - Errors 410/403/404 → the existing recipient messages, reusing the `recipient.*` keys where the text fits.
    - Extract shared bits into a component only if that is clearly smaller than duplicating them.
  - **`/vendor/upload`**:
    - A recipient `<select>` from `/api/vendor/recipients`. When the list is empty, explain that someone must share with you first.
    - An `Uploader` with `endpoint="/api/vendor/uploads/"` and `metadata={{recipient}}`, disabled until a recipient is chosen.
    - Below it, "Your uploads" from `/api/vendor/uploads`, refreshed `onDone`.
    - A 403 `recipient_not_allowed` shows a message.
  - **`/invite/:token`**:
    - Loads `/api/invite/{token}` and shows the email plus a QR code (`QRCode.toDataURL`, as `TotpSetup.tsx` does).
    - Fields: password and confirmation (minimum 12, both must match, checked client-side), and the 6-digit TOTP code.
    - Submit POSTs, then shows success with a link to `/login`.
    - 410 → "This invitation is no longer valid". 401 → invalid code. 422 `too_short` → message.
  - **Shell**: vendor nav is "Shared with me" and "Upload", with no Files/Shares/Requests/Vendors.

- [ ] **Step 1: Write the failing tests**
- `VendorShares` lists shares.
- `VendorShare` downloads and views via the vendor paths.
- `VendorUpload`:
  - `uploader disabled until recipient chosen`
  - `passes recipient metadata`
  - `empty recipients explains`
- `Invite`:
  - `activates with password and code`
  - `password mismatch blocks submit`
  - `410 shows invalid invitation`
- `Login`: `vendor goes to /vendor/shares`.
- Routing: `vendor visiting /files is redirected`.

- [ ] **Step 2: Run the tests and confirm they fail.** Run `cd web && npx vitest run`; expect the new tests to fail.

- [ ] **Step 3: Implement, including i18n in both languages, the README sections (en + zh-TW) and `.env.example`.**

- [ ] **Step 4: Verify.** Run `cd web && npx vitest run --coverage && npx tsc -b`; expect PASS. Also run `go test ./...`, since `webui` embeds the build.

- [ ] **Step 5: Commit**

```bash
git add web README.md README.zh-TW.md .env.example
git commit -m "feat(web): vendor portal, invitation activation, docs"
```
