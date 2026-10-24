# 階段 2：一次性分享 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 員工把自己的檔案分享給一組 email 收件人。系統寄出邀請信；收件人點連結、輸入自己的 email、收驗證碼、通過後在瀏覽器看到分享內容，並在允許下載時下載。寄件者可設定期限、檢視次數上限、IP 限制，可隨時撤銷整個分享或單一收件人，可事後加收件人，並在收件人第一次開啟與下載時收到通知。

**Architecture:** 新增 `internal/mail`（SMTP 寄送 + PostgreSQL outbox，內容以主金鑰封裝）與 `internal/share`（分享、收件人、驗證碼、收件人 session 的資料與規則）。HTTP 仍集中在 `internal/httpapi`：員工端 `/api/shares/...`（`requireUser`），收件人端 `/api/s/...`（`requireRecipient`）。下載沿用階段 1 的解密串流核心，抽成共用函式。

**Tech Stack:** 沿用階段 1（Go 1.27、pgx/v5、React + TS）。新增：stdlib `net/smtp`、`net/mail`；開發／CI 用 `axllent/mailpit:v1.27` 當 SMTP 測試伺服器。

**Spec:** `docs/superpowers/specs/2026-10-24-secure-exchange-design.md`（§4 第 1 點、§5.1、§5.8、§5.9、§6）

## Global Constraints

- 一次性分享**只用「收件人名單 + Email 驗證碼」**。沒有免驗證連結、沒有共用密碼、沒有網域白名單。
- 驗證碼：6 位數字（`crypto/rand`）、有效 10 分鐘、只能使用一次、每組碼最多嘗試 5 次；資料庫只存 `SHA-256(otpID || code)`。
- 不在名單內的 email 與在名單內的回應**完全相同**：`200 {"sent":true}`。
- 分享連結：`{SX_BASE_URL}/s/{token}`，token 為 32 bytes 隨機值 base64url；資料庫只存 SHA-256。
- 收件人 session：cookie `sx_share`，`HttpOnly; Secure; SameSite=Strict; Path=/`；32 bytes 隨機值，DB 只存 SHA-256；**只綁定一個分享的一位收件人**；有效 1 小時（絕對時間）。
- 每次收件人請求都重新檢查：分享未撤銷、收件人未撤銷、未過期、來源 IP 符合分享的 IP 限制。session 有效也不例外。
- 檢視次數上限 = 該分享**成功通過驗證碼的次數**上限；以單一條件式 UPDATE 計數，不可超過。
- 分享期限：必填，`1 小時 ≤ expires_at - now ≤ SX_SHARE_MAX_DAYS`（預設 30 天）；UI 預設 7 天。
- 每個分享最多 50 位收件人、100 個檔案；檔案必須是建立者自己的、未刪除的。
- 所有寄出的郵件都經 `mail_outbox`；郵件內容以 `Keyring.Seal(body, aad "mail:"+id)` 封裝後才寫入資料庫，主金鑰輪替要涵蓋它。
- 郵件為純文字、zh-TW 在前 en 在後的雙語內容；收件人 email、主旨不得含 CR/LF（防 header injection）；寄件者附言最多 2000 字元，只當內文。
- 與階段 1 相同：介面字串一律經 i18n（`zh-TW`、`en`）；不引入 Redis／訊息佇列；稽核紀錄只增不改；寫稽核時用 `context.WithoutCancel`。
- 「僅能線上檢視」的分享在階段 2 **不提供內容**（檢視器是階段 3）：收件人端列出檔案並顯示「線上檢視將在後續版本提供」，下載按鈕不出現、下載 API 回 403。「無法預覽的檔案設為僅線上檢視時擋下」也屬階段 3。
- 浮水印開關在階段 2 只儲存與顯示，實際套用是階段 3／4。

## Review Focus

1. **收件人 email 大小寫與空白**（`" Bob@X.com "` vs `bob@x.com`）→ 一律 trim 後以小寫比對；名單內重複的 email 合併為一筆（Task 3 `TestRecipientEmailNormalized`）。
2. **session 仍有效，但分享在途中被撤銷、過期、或收件人換了 IP** → 下一個請求就被拒（Task 4 `TestAccessRecheckedEveryRequest`）。
3. **同一組驗證碼同時送出兩次** → 只有一次成功（Task 4 `TestOTPSingleUseConcurrent`）。
4. **擁有者在分享後刪除檔案** → 收件人列表標示不可用、下載 404，同分享其他檔案照常（Task 6 `TestDeletedFileUnavailable`）。
5. **檢視次數上限被並行驗證撞到** → 成功次數絕不超過上限（Task 4 `TestMaxViewsConcurrent`）。

---

## File Structure

```
internal/db/migrations/0002_shares.sql   分享、收件人、驗證碼、收件人 session、下載通知、mail outbox
internal/config/config.go                 + SMTP 與分享設定
internal/mail/mail.go                     Message、Sender 介面、SMTP 實作
internal/mail/outbox.go                   Enqueue、背景 worker（封裝內容、重試）
internal/mail/templates.go                邀請、驗證碼、通知信的雙語文字
internal/share/share.go                   分享 CRUD 與驗證規則
internal/share/access.go                  驗證碼、收件人 session、每次請求的存取檢查
internal/sxcrypto/rotate.go               + mail_outbox.body_sealed
internal/httpapi/download.go              從 files_handlers 抽出的解密下載核心
internal/httpapi/shares_handlers.go       員工端分享 API
internal/httpapi/recipient_handlers.go    收件人端 API 與 requireRecipient
web/src/pages/Shares.tsx                  我的分享列表
web/src/pages/ShareDetail.tsx             分享詳情（收件人、撤銷、新增收件人）
web/src/components/ShareDialog.tsx        從檔案列表建立分享
web/src/pages/recipient/Access.tsx        /s/:token 收件人流程
docker-compose.dev.yml, .github/workflows/ci.yml, .env.example, README*  mailpit、SMTP 設定
```

---

### Task 1: 設定與 schema

**Files:**
- Modify: `internal/config/config.go`, `internal/config/config_test.go`
- Create: `internal/db/migrations/0002_shares.sql`
- Test: `internal/db/db_test.go`（加 case）

**Interfaces:**
- Produces（`Config` 新欄位）：`SMTP SMTPConfig{Host string; Port int (預設 587); Username, Password string; From string; TLS string ("starttls"|"tls"|"none", 預設 "starttls")}`、`ShareMaxDays int`（`SX_SHARE_MAX_DAYS`，預設 30，範圍 1..365）。`SX_SMTP_HOST`、`SX_SMTP_FROM` 為必填；`SX_SMTP_FROM` 必須能被 `net/mail.ParseAddress` 解析。
- Schema（後續 task 只讀不改）：

```sql
CREATE TABLE shares (
  id uuid PRIMARY KEY, owner_id uuid NOT NULL REFERENCES users,
  token_hash bytea NOT NULL UNIQUE, message text NOT NULL DEFAULT '',
  allow_download boolean NOT NULL, watermark boolean NOT NULL,
  expires_at timestamptz NOT NULL, max_views int CHECK (max_views > 0), view_count int NOT NULL DEFAULT 0,
  ip_allow cidr[] NOT NULL DEFAULT '{}', revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX shares_owner ON shares (owner_id, created_at DESC);
CREATE TABLE share_files (
  share_id uuid NOT NULL REFERENCES shares ON DELETE CASCADE,
  file_id uuid NOT NULL REFERENCES files, PRIMARY KEY (share_id, file_id));
CREATE TABLE share_recipients (
  id uuid PRIMARY KEY, share_id uuid NOT NULL REFERENCES shares ON DELETE CASCADE,
  email text NOT NULL, revoked_at timestamptz, first_opened_at timestamptz, last_access_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now());
CREATE UNIQUE INDEX share_recipients_email ON share_recipients (share_id, lower(email));
CREATE TABLE share_otps (
  id uuid PRIMARY KEY, recipient_id uuid NOT NULL REFERENCES share_recipients ON DELETE CASCADE,
  code_hash bytea NOT NULL, attempts int NOT NULL DEFAULT 0, used_at timestamptz,
  expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE share_sessions (
  token_hash bytea PRIMARY KEY, recipient_id uuid NOT NULL REFERENCES share_recipients ON DELETE CASCADE,
  ip text NOT NULL, user_agent text NOT NULL,
  expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE share_downloads (
  recipient_id uuid NOT NULL REFERENCES share_recipients ON DELETE CASCADE,
  file_id uuid NOT NULL REFERENCES files, first_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (recipient_id, file_id));
CREATE TABLE mail_outbox (
  id uuid PRIMARY KEY, to_addr text NOT NULL, body_sealed bytea NOT NULL,
  attempts int NOT NULL DEFAULT 0, next_attempt_at timestamptz NOT NULL DEFAULT now(),
  sent_at timestamptz, last_error text NOT NULL DEFAULT '', created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX mail_outbox_due ON mail_outbox (next_attempt_at) WHERE sent_at IS NULL;
```

（主旨與內文一起封裝在 `body_sealed`；`to_addr` 明文存放，因為 worker 要用、且它本身就是分享名單的一部分。）

- [ ] **Step 1: 寫失敗測試** `TestLoadSMTPDefaults`（只給必填 → Port 587、TLS starttls、ShareMaxDays 30）、`TestLoadSMTPRequired`（缺 `SX_SMTP_HOST` / `SX_SMTP_FROM` → error 含變數名）、`TestLoadSMTPFromInvalid`（`"not an address"` → error）、`TestLoadShareMaxDaysRange`（0、366 → error）、`TestLoadSMTPTLSValues`（`"bogus"` → error）；`TestMigration0002Applies`（testdb 後 `SELECT count(*) FROM shares` = 0）。所有提供完整 env 的既有測試（`internal/config/config_test.go`、`cmd/secure-exchange/main_test.go`）都要補上 `SX_SMTP_HOST`、`SX_SMTP_FROM`；`.env.example` 在 Task 9 才更新，但 `scripts/smoke.sh` 若用到 config 也要同步。
- [ ] **Step 2:** `go test ./internal/config/ ./internal/db/...` → FAIL
- [ ] **Step 3: 實作**
- [ ] **Step 4:** PASS
- [ ] **Step 5: Commit** `feat: SMTP and share config, share schema`

---

### Task 2: 郵件寄送與 outbox

**Files:**
- Create: `internal/mail/mail.go`, `internal/mail/outbox.go`, `internal/mail/templates.go`
- Modify: `internal/sxcrypto/rotate.go`（sealed 欄位清單加 `mail_outbox.body_sealed`，aad 前綴 `"mail:"`），`cmd/secure-exchange/main.go`（啟動 worker）、`docker-compose.dev.yml`（加 mailpit）
- Test: `internal/mail/mail_test.go`, `internal/sxcrypto/rotate_test.go`（加 case）

**Interfaces:**
- Produces:
  - `type Message struct { To, Subject, Body string }`
  - `type Sender interface { Send(ctx context.Context, m Message) error }`（兩個實作：SMTP 與測試用 `Recorder`）
  - `NewSMTP(cfg config.SMTPConfig) *SMTP`：`starttls` 用 `smtp.Dial` + `StartTLS`；`tls` 用 `tls.Dial`；`none` 只允許在 `Host` 為 `localhost`/`127.0.0.1`/`mailpit` 時使用（否則 `Send` 回 error），給開發用。有 Username 時用 `smtp.PlainAuth`。送出的 header：`From`、`To`、`Subject`（RFC 2047 `mime.QEncoding.Encode("utf-8", s)`）、`Date`、`Message-ID`、`MIME-Version: 1.0`、`Content-Type: text/plain; charset=utf-8`、`Content-Transfer-Encoding: 8bit`。
  - `ValidAddress(s string) (string, bool)`：trim、小寫、`net/mail.ParseAddress` 可解析、只有位址本身（不含顯示名稱）、不含 CR/LF、長度 ≤ 254。Task 3 用它正規化收件人。
  - `type Recorder struct{ mu; Sent []Message }`，`Send` 只記錄。
  - `type Outbox struct{ pool; keys *sxcrypto.Keyring; sender Sender }`；`NewOutbox(pool, keys, sender) *Outbox`
  - `(*Outbox) Enqueue(ctx context.Context, q Querier, m Message) error`：`type Querier interface{ Exec(ctx, sql string, args ...any) (pgconn.CommandTag, error) }`，讓呼叫者能在自己的 transaction 內寫入（`pgx.Tx` 與 `*pgxpool.Pool` 都符合）。拒絕 To／Subject 含 CR/LF。
  - `(*Outbox) Run(ctx context.Context)`：每 5 秒（並在 `Enqueue` 後以 channel 喚醒）取 `sent_at IS NULL AND next_attempt_at <= now()` 的 20 筆，`FOR UPDATE SKIP LOCKED`，解封、寄出、成功設 `sent_at`；失敗 `attempts+1`、`last_error`（截 500 字元）、`next_attempt_at = now() + 2^attempts 分鐘`（上限 6 小時）；`attempts` 達 10 後不再重試。寄出成功 7 天後刪除該列（`// ponytail: 寄送紀錄只留 7 天`）。
  - 未匯出 `(*Outbox) runOnce(ctx) (sent int, err error)` 供測試。
  - `templates.go`：`Invitation(shareURL, senderName, message string, expires time.Time) (subject, body string)`、`OTPCode(code string) (subject, body string)`、`NotifyFirstOpen(recipient, shareURL string) (subject, body string)`、`NotifyDownload(recipient, fileName, shareURL string) (subject, body string)`。主旨格式 `"[secure-exchange] <zh> / <en>"`；內文 zh-TW 段落、`----`、en 段落。驗證碼信內文寫明「10 分鐘內有效／valid for 10 minutes」，不含分享連結。
- `docker-compose.dev.yml` 加 `mailpit`（`axllent/mailpit:v1.27`，SMTP host port 51025 → 1025，Web/API host port 58025 → 8025）。
- [ ] **Step 1: 寫失敗測試**
  - `TestValidAddress`：`" Bob@Example.COM "` → `"bob@example.com", true`；`"Bob <bob@x.com>"`、`"a@b.com\r\nBcc: x@y.com"`、`"x"`、255 字元位址 → false。
  - `TestOutboxSealsBody`：Enqueue 一封內文含 `"CODE-123456"` 的信 → `mail_outbox.body_sealed` 不含該字串；`runOnce` 後 `Recorder.Sent[0].Body` 含它，`sent_at` 非空。
  - `TestOutboxRetryBackoff`：sender 回 error → `attempts=1`、`next_attempt_at` 約 now+2 分鐘、`last_error` 非空；再 `runOnce` 不會重寄（還沒到時間）。
  - `TestOutboxRejectsHeaderInjection`：To 或 Subject 含 `\n` → error，資料表無列。
  - `TestSMTPAgainstMailpit`（`SX_TEST_SMTP_ADDR` 未設時 skip，例如 `localhost:51025`）：`NewSMTP(TLS:"none")` 寄一封中文主旨的信 → 透過 `http://localhost:58025/api/v1/messages` 查到該主旨（解碼後相同）。
  - `rotate_test.go` 加：`mail_outbox` 列以 key1 封裝 → `RotateAll` 後以只有 key2 的 keyring 能解封。
- [ ] **Step 2:** FAIL
- [ ] **Step 3: 實作**（`main.go`：`serve` 時 `go outbox.Run(ctx)`）
- [ ] **Step 4:** `docker compose -f docker-compose.dev.yml up -d` 後 `SX_TEST_SMTP_ADDR=localhost:51025 go test ./internal/mail/ ./internal/sxcrypto/` → PASS
- [ ] **Step 5: Commit** `feat: SMTP sender and sealed mail outbox`

---

### Task 3: 分享資料與規則

**Files:**
- Create: `internal/share/share.go`
- Test: `internal/share/share_test.go`

**Interfaces:**
- Consumes: `mail.ValidAddress`、`mail.Outbox.Enqueue`、`mail.Invitation`
- Produces:
  - `type Share struct { ID, OwnerID uuid.UUID; OwnerName, OwnerEmail string; FileCount, RecipientCount int; Message string; AllowDownload, Watermark bool; ExpiresAt time.Time; MaxViews *int; ViewCount int; IPAllow []netip.Prefix; RevokedAt *time.Time; CreatedAt time.Time; Files []ShareFile; Recipients []Recipient }`
  - `type ShareFile struct { ID uuid.UUID; Name string; Size int64; Deleted bool }`
  - `type Recipient struct { ID uuid.UUID; Email string; RevokedAt, FirstOpenedAt, LastAccessAt *time.Time }`
  - `type CreateInput struct { FileIDs []uuid.UUID; Emails []string; AllowDownload, Watermark bool; ExpiresAt time.Time; MaxViews *int; IPAllow []string; Message string }`
  - `type Service struct{ pool; outbox *mail.Outbox; baseURL string; maxDays int; now func() time.Time }`；`NewService(pool, outbox, baseURL string, maxDays int) *Service`
  - `(*Service) Create(ctx, owner *auth.User, in CreateInput) (*Share, error)`：在一個 transaction 內驗證並寫入 shares／share_files／share_recipients，並為每位收件人 `Enqueue` 邀請信（連結 `baseURL + "/s/" + token`，寄件者名稱用 `DisplayName`，空白則用 email）。
  - 驗證錯誤：`type ValidationError struct{ Field, Code string }`（實作 `error`），Code 取值：`required`、`too_many`、`invalid`、`not_found`（檔案不屬於 owner 或已刪除）、`out_of_range`（期限）。
  - 規則：email 經 `ValidAddress` 正規化後去重，1..50 位；檔案 1..100 個；`ExpiresAt` 介於 now+1h 與 now+maxDays；`MaxViews` 為 nil 或 1..10000；`IPAllow` 每項可被 `netip.ParsePrefix` 或 `netip.ParseAddr`（單一位址轉 /32 或 /128）解析，最多 20 項；`Message` 最多 2000 字元（rune）。
  - `OwnerName` = 擁有者 `display_name`，空白時用 email；`OwnerEmail` 供通知信使用。
  - `(*Service) List(ctx, ownerID uuid.UUID) ([]Share, error)`（不填 Files/Recipients，只填 `FileCount`、`RecipientCount`）、`Get(ctx, ownerID, id uuid.UUID) (*Share, error)`（非 owner → `ErrNotFound`）。
  - `(*Service) Revoke(ctx, ownerID, id) error`、`RevokeRecipient(ctx, ownerID, shareID, recipientID) error`（同時刪除該收件人的 share_sessions）、`AddRecipients(ctx, owner *auth.User, shareID uuid.UUID, emails []string) ([]Recipient, error)`（已存在者略過；已撤銷的分享 → `ErrRevoked`；總數仍受 50 上限）。撤銷分享時刪除其所有 share_sessions。
  - `ErrNotFound`、`ErrRevoked` sentinel。
- [ ] **Step 1: 寫失敗測試**
  - `TestCreateShareSendsInvitations`：2 位收件人 → 2 筆 share_recipients、2 筆 outbox（解封後內文含 `/s/` 連結，且兩封連結相同）。
  - `TestRecipientEmailNormalized`：`[" Bob@X.com ", "bob@x.com", "carol@y.org"]` → 2 位，email 為小寫。
  - `TestCreateShareValidation`：表格式 case，各自回 `ValidationError` 對應 Field/Code：空收件人、51 位、無效 email、別人的檔案、已刪除檔案、期限 30 分鐘後、期限 31 天後、MaxViews 0、IP `"300.1.1.1"`、Message 2001 字。
  - `TestShareTokenStoredHashed`：DB 中 `token_hash` 不等於邀請信中的 token，且等於 `sha256(token)`。
  - `TestRevokeShareDropsSessions`、`TestRevokeRecipientDropsSessions`（直接插入 share_sessions 後撤銷 → 列被刪）。
  - `TestAddRecipientsSkipsExisting` 與 `TestAddRecipientsToRevokedShare`（→ ErrRevoked）。
  - `TestGetOtherOwner404`。
- [ ] **Step 2:** FAIL
- [ ] **Step 3: 實作**
- [ ] **Step 4:** PASS
- [ ] **Step 5: Commit** `feat: share model, validation and invitations`

---

### Task 4: 驗證碼、收件人 session、存取檢查

**Files:**
- Create: `internal/share/access.go`
- Test: `internal/share/access_test.go`

**Interfaces:**
- Consumes: Task 3 的 Service 與資料表、`mail.OTPCode`、`mail.NotifyFirstOpen`
- Produces:
  - `type Access struct { Share *Share; Recipient Recipient }`
  - `(*Service) Landing(ctx, token string, ip netip.Addr) (*Share, error)`：依 token 找分享，檢查未撤銷、未過期、IP 允許；回傳的 Share 只保證 `ExpiresAt`、`Message`、`OwnerName` 可用。失敗回 `ErrNotFound`（token 不存在）、`ErrGone`（撤銷或過期）、`ErrIPDenied`。
  - `(*Service) RequestCode(ctx, token, email string, ip netip.Addr) error`：先做與 Landing 相同的檢查；email 正規化後若是未撤銷的收件人 → 產生碼，插入 share_otps（同一收件人先前未使用的碼全部作廢：設 `used_at`），`Enqueue` 驗證碼信；不在名單內則什麼都不做。兩種情況都回 nil。
  - `(*Service) VerifyCode(ctx, token, email, code string, ip netip.Addr, ua string) (sessionToken string, a *Access, err error)`：在一個 transaction 內：鎖定該收件人最新未使用、未過期的 otp 列（`FOR UPDATE`）；`attempts >= 5` → `ErrBadCode`；比對失敗 → `attempts+1` 後 `ErrBadCode`；成功 → 設 `used_at`，`UPDATE shares SET view_count = view_count+1 WHERE id=$1 AND (max_views IS NULL OR view_count < max_views)`，0 列 → `ErrViewLimit`；建立 share_sessions（1 小時）；若 `first_opened_at` 為空則設定並 `Enqueue` 首次開啟通知給擁有者；更新 `last_access_at`。不在名單內的 email、沒有有效碼 → 一律 `ErrBadCode`。
  - `(*Service) Authorize(ctx, sessionToken string, ip netip.Addr) (*Access, error)`：依 session token 雜湊找 session → 收件人 → 分享；每次都檢查 session 未過期、收件人未撤銷、分享未撤銷、未過期、IP 允許；回傳的 Access.Share 含 Files（標示 Deleted）。失敗回 `ErrUnauthorized`（session 無效）、`ErrGone`、`ErrIPDenied`。成功時更新 `last_access_at`（最多每分鐘一次）。
  - `(*Service) RecordDownload(ctx, a *Access, fileID uuid.UUID) error`：`INSERT INTO share_downloads ... ON CONFLICT DO NOTHING`，真的插入時 `Enqueue` 下載通知給擁有者（每位收件人每個檔案只通知一次）。
  - `ipAllowed(list []netip.Prefix, ip netip.Addr) bool`：空清單 = 全部允許；IPv4-mapped IPv6 先 `Unmap()`。
  - sentinel：`ErrGone`、`ErrIPDenied`、`ErrBadCode`、`ErrViewLimit`、`ErrUnauthorized`。
- [ ] **Step 1: 寫失敗測試**
  - `TestRequestCodeUniform`：名單內 email → outbox 多一封驗證碼信；名單外 → 無新信；兩者回傳皆 nil。
  - `TestVerifyCodeFlow`：取出驗證碼信中的 6 位數 → VerifyCode 成功、回 session token；`share_otps.code_hash` 不含明文碼；第二次用同一碼 → ErrBadCode。
  - `TestOTPAttemptsLimit`：錯 5 次後，正確的碼也 → ErrBadCode。
  - `TestOTPExpired`：把 `expires_at` 改成過去 → ErrBadCode。
  - `TestOTPSingleUseConcurrent`：10 個 goroutine 同時用同一正確碼驗證 → 恰好 1 個成功。
  - `TestMaxViewsConcurrent`：`max_views=3`，5 位收件人各自拿碼後並行驗證 → 恰好 3 個成功、其餘 ErrViewLimit，`view_count=3`。
  - `TestNewCodeInvalidatesOld`：要兩次碼 → 第一組碼 → ErrBadCode。
  - `TestAccessRecheckedEveryRequest`：取得 session 後分別 (a) 撤銷分享 → ErrGone、(b) 撤銷該收件人 → ErrUnauthorized（RevokeRecipient 已刪除其 session）、(c) `expires_at` 改成過去 → ErrGone、(d) 分享 `ip_allow={10.0.0.0/8}` 而請求 IP 是 192.0.2.1 → ErrIPDenied。
  - `TestFirstOpenNotifiesOnce`：同一收件人驗證兩次 → 只有 1 封首次開啟通知寄給擁有者。
  - `TestRecordDownloadNotifiesOnce`：同檔案兩次 → 1 封；另一檔案 → 再 1 封。
  - `TestIPAllowed`：空清單允許；`::ffff:10.1.2.3` 符合 `10.0.0.0/8`。
- [ ] **Step 2:** FAIL
- [ ] **Step 3: 實作**
- [ ] **Step 4:** PASS
- [ ] **Step 5: Commit** `feat: share OTP verification, recipient sessions, access checks`

---

### Task 5: 員工端分享 API

**Files:**
- Create: `internal/httpapi/shares_handlers.go`, `internal/httpapi/download.go`
- Modify: `internal/httpapi/server.go`（Deps 加 `Shares *share.Service`、路由）、`internal/httpapi/files_handlers.go`（下載改用共用核心）、`internal/audit/audit.go`（新 action 常數）、`cmd/secure-exchange/main.go`（組裝 Outbox、share.Service）
- Test: `internal/httpapi/shares_test.go`

**Interfaces:**
- Consumes: Task 3 Service、`requireUser`、`s.record`
- Produces:
  - `download.go`：`(s *server) serveFile(w, r, f *fileRow, actor audit.Event) `：沿用 `downloadFile` 目前的邏輯（UnwrapDEK、OpenPlain 使用 DB size、ETag、Content-Disposition、`Cache-Control: private, no-store`、statusWriter、200/206 才寫稽核 `file.download`，detail 含 status/range）。`actor` 提供 ActorType/ActorID 與額外 detail（例如 share_id）。`downloadFile` 改為呼叫它，既有測試必須照常通過。
  - Audit 常數：`ActShareCreate = "share.create"`、`ActShareRevoke = "share.revoke"`、`ActShareRecipientAdd = "share.recipient.add"`、`ActShareRecipientRevoke = "share.recipient.revoke"`、`ActShareOTPRequest = "share.otp.request"`、`ActShareOTPVerify = "share.otp.verify"`。
  - API（JSON，皆 `requireUser`）：
    - `POST /api/shares` body `{file_ids:[uuid], emails:[string], allow_download:bool, watermark:bool, expires_at:RFC3339, max_views:int|null, ip_allow:[string], message:string}` → 201 分享詳情；ValidationError → 422 `{"error":"validation","field":..., "code":...}`。body 上限 64 KiB。
    - `GET /api/shares` → `[{id, created_at, expires_at, revoked:bool, expired:bool, file_count, recipient_count, view_count, max_views}]`
    - `GET /api/shares/{id}` → `{id, message, allow_download, watermark, expires_at, max_views, view_count, ip_allow:[string], revoked, expired, created_at, files:[{id,name,size,deleted}], recipients:[{id,email,revoked,first_opened_at,last_access_at}]}`（時間 RFC3339 或 null）
    - `POST /api/shares/{id}/revoke` → 204；`POST /api/shares/{id}/recipients` body `{emails:[string]}` → 200 新增的收件人陣列；`POST /api/shares/{id}/recipients/{rid}/revoke` → 204。
    - 非 owner 或不存在 → 404；對已撤銷分享加收件人 → 409 `{"error":"revoked"}`。
  - 每個變更動作寫稽核（ActorType `user`，Target `share`），建立時 detail 含 `recipient_count`、`file_count`（不寫 email 清單）。
- [ ] **Step 1: 寫失敗測試**
  - `TestCreateShareAPI`：建立 → 201，GET 詳情欄位正確，稽核一筆 `share.create`。
  - `TestCreateShareValidationAPI`：別人的檔案 → 422 `{"error":"validation","field":"file_ids","code":"not_found"}`。
  - `TestShareOwnerOnly`：B 使用者 GET/revoke A 的分享 → 404。
  - `TestRevokeAndRecipientAPI`：撤銷收件人 → 204，詳情中該收件人 `revoked=true`；撤銷分享 → 204；之後加收件人 → 409。
  - `TestOwnerDownloadStillWorks`：既有 `TestDownloadRanges` 等全部照常通過（重構後回歸）。
- [ ] **Step 2:** FAIL
- [ ] **Step 3: 實作**
- [ ] **Step 4:** `go test ./internal/httpapi/` → PASS
- [ ] **Step 5: Commit** `feat: staff share API`

---

### Task 6: 收件人端 API

**Files:**
- Create: `internal/httpapi/recipient_handlers.go`
- Modify: `internal/httpapi/server.go`（路由、`requireRecipient`）
- Test: `internal/httpapi/recipient_test.go`

**Interfaces:**
- Consumes: Task 4（Landing、RequestCode、VerifyCode、Authorize、RecordDownload）、Task 5 的 `serveFile`
- Produces（皆無需員工登入）：
  - `GET /api/s/{token}` → 200 `{owner_name, message, expires_at}`；ErrNotFound → 404；ErrGone → 410 `{"error":"gone"}`；ErrIPDenied → 403 `{"error":"ip_denied"}`。
  - `POST /api/s/{token}/code` body `{email}` → 一律 200 `{"sent":true}`（分享無效時回對應的 404/410/403，因為這與 email 無關）。限流：每 IP 10 次/分（`rate.Every(6s)`, burst 10）、每 `(token, email 小寫)` 3 次/10 分（`rate.Every(200s)`, burst 3）→ 429。稽核 `share.otp.request`（ActorType `recipient`，ActorID 為截斷的 email，Result `ok`／`ignored`）。
  - `POST /api/s/{token}/verify` body `{email, code}` → 200 並設 `sx_share` cookie（Global Constraints 的屬性、`Max-Age=3600`）；ErrBadCode → 401 `{"error":"invalid_code"}`；ErrViewLimit → 403 `{"error":"view_limit"}`。限流：每 IP 10 次/分。稽核 `share.otp.verify` 成功／失敗。
  - `requireRecipient(next)`：讀 `sx_share` → `Authorize`；ErrUnauthorized → 401 `{"error":"unauthorized"}`、ErrGone → 410、ErrIPDenied → 403；成功時把 `*share.Access` 放進 context，並確認 URL 中的 `{token}` 屬於同一分享（不符 → 401）。
  - `GET /api/s/{token}/files`（requireRecipient）→ `{message, expires_at, allow_download, watermark, files:[{id,name,size,available}]}`，`available = !deleted`。
  - `GET /api/s/{token}/files/{fid}/content`（requireRecipient）：`fid` 不在分享內或已刪除 → 404；`allow_download=false` → 403 `{"error":"view_only"}`；否則 `serveFile`，稽核 actor 為 `recipient`、detail 含 `share_id`；回應 200/206 時呼叫 `RecordDownload`。
  - `POST /api/s/{token}/logout` → 刪除 session，204，清除 cookie。
  - 所有收件人端 email、User-Agent 寫入稽核前截斷（沿用 `Truncate`／`UserAgent`）。
- [ ] **Step 1: 寫失敗測試**（`httptest.NewTLSServer` + cookie jar + Origin header，Recorder 當 sender，直接呼叫 outbox `runOnce` 取得信件內容）
  - `TestRecipientHappyPath`：建立分享（允許下載）→ 從邀請信取 token → GET landing → POST code → 從驗證碼信取碼 → verify → GET files → 下載檔案內容 SHA-256 正確 → 擁有者收到首次開啟與下載兩封通知。
  - `TestRecipientUnknownEmailUniform`：名單外 email 的 code 回應與名單內完全相同（狀態與 body）。
  - `TestRecipientViewOnlyNoDownload`：`allow_download=false` → content 403 `view_only`。
  - `TestDeletedFileUnavailable`：擁有者刪除其中一個檔案 → files 中該檔 `available=false`、content 404；另一檔照常下載。
  - `TestRecipientCannotUseOtherShare`：分享 A 的 session cookie 打分享 B 的 `/files` → 401。
  - `TestRecipientRevokedMidSession`：verify 後擁有者撤銷 → files 410。
  - `TestRecipientCodeRateLimit`：同 email 第 4 次 code → 429。
  - `TestRecipientCookieAttributes`：HttpOnly、Secure、SameSite=Strict、Max-Age=3600。
- [ ] **Step 2:** FAIL
- [ ] **Step 3: 實作**
- [ ] **Step 4:** PASS
- [ ] **Step 5: Commit** `feat: recipient share API`

---

### Task 7: 員工端介面

**Files:**
- Create: `web/src/components/ShareDialog.tsx`, `web/src/pages/Shares.tsx`, `web/src/pages/ShareDetail.tsx`
- Modify: `web/src/pages/Files.tsx`（勾選檔案 → 「建立分享」）、`web/src/main.tsx`（路由 `/shares`、`/shares/:id`，Shell 導覽加「我的分享」）、`web/src/api.ts`、`web/src/i18n/{zh-TW,en}.json`
- Test: `web/src/components/ShareDialog.test.tsx`, `web/src/pages/ShareDetail.test.tsx`

**Interfaces:**
- Consumes: Task 5 API。
- 行為：
  - Files 頁每列加 checkbox；有勾選時顯示「建立分享」按鈕，開啟 `ShareDialog`。
  - `ShareDialog` 欄位：收件人（多行文字，一行一個或以逗號分隔）、允許下載（checkbox，預設關）、浮水印（checkbox，預設開）、有效期限（`<input type="datetime-local">`，預設 now+7 天）、檢視次數上限（選填 number）、IP 限制（選填多行）、附言（textarea，maxLength 2000）。送出 → 成功導到 `/shares/:id`；422 時在對應欄位顯示錯誤（以 `field`+`code` 對應 i18n key `share.error.<field>.<code>`，找不到 key 時用 `share.error.generic`）。
  - 「僅線上檢視」被選時顯示提示：`share.viewOnlyNote`（「線上檢視將在後續版本提供，目前收件人只能看到檔案清單」）。
  - `Shares`：表格列出建立時間、到期、狀態（有效／已過期／已撤銷）、檔案數、收件人數、檢視次數（`view_count / max_views` 或 `view_count`）。
  - `ShareDetail`：基本設定、檔案清單（已刪除者標示）、收件人清單（email、首次開啟、最後存取、狀態、「撤銷」按鈕）、「新增收件人」表單、「撤銷整個分享」按鈕（confirm）。分享連結**不顯示**（只寄給收件人；員工端沒有拿到連結的途徑，避免被當成免驗證連結轉傳）。
- [ ] **Step 1: 寫失敗測試** `ShareDialog.test.tsx`：mock fetch，填兩位收件人、送出 → 請求 body 的 `emails` 為 2 項、`expires_at` 為 ISO 字串、`allow_download=false`、`watermark=true`；422 `{"field":"emails","code":"invalid"}` → 畫面顯示 `share.error.emails.invalid` 的文字。`ShareDetail.test.tsx`：渲染一個含已撤銷收件人的詳情 → 該列不顯示撤銷按鈕；點另一位的撤銷 → 呼叫正確 URL。
- [ ] **Step 2:** `cd web && npx vitest run` → FAIL
- [ ] **Step 3: 實作**（所有字串進 i18n，兩語言 key 一致）
- [ ] **Step 4:** `npx vitest run && npm run build` → PASS
- [ ] **Step 5: Commit** `feat: share creation and management UI`

---

### Task 8: 收件人介面

**Files:**
- Create: `web/src/pages/recipient/Access.tsx`
- Modify: `web/src/main.tsx`（`/s/:token` 路由，**不經過** `Private`，不呼叫 `/api/me`）、`web/src/api.ts`、i18n JSON
- Test: `web/src/pages/recipient/Access.test.tsx`

**Interfaces:**
- Consumes: Task 6 API。
- 行為（單一頁面三個狀態，右上角 `LangSwitch`）：
  1. 載入 landing：顯示寄件者名稱、附言、到期時間；404／410／403 顯示對應訊息（`recipient.error.notFound`／`gone`／`ipDenied`）。
  2. 「輸入您的 email」→ 送出後一律顯示「若您在名單中，將收到驗證碼」（`recipient.codeSent`），並顯示驗證碼輸入框（`inputMode="numeric"`、`autocomplete="one-time-code"`、maxLength 6）；429 顯示 `recipient.error.rateLimited`。
  3. 驗證成功 → 檔案清單：名稱、大小、狀態。`allow_download` 時每列顯示下載連結（`<a href download>`）；否則顯示 `share.viewOnlyNote`。不可用的檔案標示 `recipient.fileUnavailable`。401 `invalid_code` → `recipient.error.invalidCode`；403 `view_limit` → `recipient.error.viewLimit`。重新整理頁面時先嘗試 `GET /api/s/{token}/files`，200 就直接進狀態 3。
  - 「離開」按鈕呼叫 logout。
- [ ] **Step 1: 寫失敗測試**：mock fetch 依序回 landing、code、verify、files（allow_download=true、一個不可用檔案）→ 畫面出現下載連結且 href 為 `/api/s/<token>/files/<id>/content`、不可用檔案沒有連結；另一 case verify 回 401 → 顯示 invalidCode 文字。
- [ ] **Step 2:** FAIL
- [ ] **Step 3: 實作**
- [ ] **Step 4:** `npx vitest run && npm run build` → PASS
- [ ] **Step 5: Commit** `feat: recipient access UI`

---

### Task 9: 部署設定、文件、端對端測試

**Files:**
- Modify: `.env.example`（SMTP 與 `SX_SHARE_MAX_DAYS`）、`docker-compose.yml`（若需要傳入新變數）、`.github/workflows/ci.yml`（`docker run -d -p 51025:1025 -p 58025:8025 axllent/mailpit:v1.27` 並等就緒、設 `SX_TEST_SMTP_ADDR`）、`README.md`、`README.zh-TW.md`（SMTP 設定、一次性分享使用說明、驗證碼流程、目前「僅線上檢視」尚無內容的限制）、`scripts/smoke.sh`（加分享流程：建立分享 → 從 mailpit API 取邀請與驗證碼 → 驗證 → 下載比對 SHA-256）
- Create: `internal/httpapi/share_integration_test.go`
- Test: 上述

**Interfaces:**
- `share_integration_test.go`：以真實 `upload.NewHandler`、`share.Service`、`mail.Outbox`（Recorder sender）組 `httpapi.NewServer`，跑：員工登入 → tus 上傳 → 建立分享（2 位收件人、允許下載、max_views 2）→ 收件人 1 取碼驗證下載 → 收件人 2 取碼驗證 → 第三次驗證（收件人 1 重新取碼）→ 403 view_limit → 擁有者撤銷 → 收件人 2 的 session 打 files → 410 → 稽核 `Verify()==0` 且含 share.create、share.otp.verify、file.download（actor recipient）、share.revoke。
- 冒煙測試在 compose 環境中要能收信：`docker-compose.yml` 不含 mailpit（正式環境用真的 SMTP）；smoke.sh 以 `-f docker-compose.yml -f docker-compose.smoke.yml` 疊加一個只含 mailpit 的 override（新增 `docker-compose.smoke.yml`），app 的 `SX_SMTP_HOST=mailpit`、`SX_SMTP_TLS=none`。
- [ ] **Step 1: 寫失敗測試** `share_integration_test.go`。
- [ ] **Step 2:** FAIL（若前面 task 正確，它應直接通過；以暫時改壞一個期望值確認它能失敗，再還原）
- [ ] **Step 3:** 更新 `.env.example`、compose override、CI、README 兩語言、smoke.sh。
- [ ] **Step 4:** `go test ./... -count=1`、`cd web && npx vitest run && npm run build`、`bash scripts/smoke.sh` 全部通過。
- [ ] **Step 5: Commit** `chore: SMTP deployment config, share docs, e2e test`

---

## 不在本階段

- 線上檢視、浮水印實際套用、「無法預覽 + 僅線上檢視」的擋下（階段 3）
- 下載檔追蹤標記與溯源（階段 4）
- 上傳請求連結、掃毒（階段 5）
- 廠商帳號（階段 6）
- 管理員強制規則（網域封鎖、預設 IP、最長期限改由管理介面設定）、通知偏好設定（階段 7）
