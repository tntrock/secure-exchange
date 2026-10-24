# 階段 1：基礎 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 可部署的骨架：員工以本機帳號（可選 TOTP）登入，以可續傳方式上傳數百 GB 檔案，檔案以分塊信封加密存放於本機或 S3，可列出、下載（支援 Range）、刪除，所有動作寫入雜湊鏈稽核紀錄，以 `docker compose up -d` 啟動。

**Architecture:** 單一 Go 執行檔（stdlib `net/http` ServeMux）內嵌 React 前端；PostgreSQL 存中繼資料；檔案切成 1 MiB 區塊各自以 AES-256-GCM 加密，每檔一把 DEK，DEK 由主金鑰包裝。上傳使用自行實作的 tus 1.0 core + creation + termination（不用 tusd，因為需要強制區塊對齊與 session 驗證）。

**Tech Stack:** Go ≥ 1.26、pgx/v5、pressly/goose/v3、minio-go/v7、golang.org/x/crypto/argon2、pquerna/otp、golang.org/x/time/rate、google/uuid；React 18 + TypeScript + Vite、react-router、react-i18next、tus-js-client、qrcode；PostgreSQL 17；Caddy 2。

**Spec:** `docs/superpowers/specs/2026-10-24-secure-exchange-design.md`

## Global Constraints

- Go module：`github.com/tntrock/secure-exchange`；Go ≥ 1.26（需要 `http.CrossOriginProtection`，1.25 起）。
- 所有設定由 `SX_` 前綴環境變數提供；缺少必填值或主金鑰格式錯誤時拒絕啟動。
- 檔案（含暫存）寫入磁碟前一律加密；明文不得落地。
- 區塊大小 `ChunkSize = 1 << 20`（1 MiB）；密文區塊 = 明文 + 16 bytes tag。
- 密碼雜湊：argon2id，參數 `time=3, memory=64*1024 KiB, threads=4, keyLen=32, saltLen=16`。
- 分享／session token ≥ 128 bit 隨機值，資料庫只存 SHA-256。
- Session cookie：`sx_session`，`HttpOnly; Secure; SameSite=Strict; Path=/`。
- 稽核紀錄只增不改，雜湊鏈。
- 介面字串一律經 i18n（`zh-TW`、`en`），不可寫死。
- 不引入 Redis / 訊息佇列；背景工作用 goroutine 或 PostgreSQL。
- 測試資料庫：環境變數 `SX_TEST_DATABASE_URL`；未設定時 DB 測試 `t.Skip`，CI 中必設。

## Review Focus

1. **上傳在 PATCH 中途斷線後續傳** → 最終檔案與原檔逐位元相同、SHA-256 相同（Task 9 `TestTusResumeAfterPartialPatch`）。
2. **Range 請求跨區塊邊界、只要最後一個 byte、超出檔案大小** → 回傳正確位元組；超出範圍回 416（Task 10 `TestDownloadRanges`）。
3. **檔名含中文、`../`、引號、控制字元** → 只當中繼資料存，不影響路徑；下載標頭用 RFC 5987 `filename*=UTF-8''…`（Task 10 `TestDownloadFilenameHeader`）。
4. **多個請求同時寫稽核紀錄** → 雜湊鏈仍可驗證（Task 6 `TestAuditConcurrentAppends`）。
5. **登入：不存在的 email、錯誤密碼、連續嘗試** → 回應一致不透露帳號存在；超過頻率回 429（Task 8 `TestLoginUniformFailure`、`TestLoginRateLimited`）。

---

## File Structure

```
cmd/secure-exchange/main.go          進入點：serve / rotate-keys 子命令
internal/config/config.go            環境變數解析
internal/db/db.go                    pgxpool 連線 + goose migration
internal/db/migrations/*.sql         schema
internal/db/testdb/testdb.go         測試用：每個測試建立獨立 schema
internal/sxcrypto/keyring.go         主金鑰環、DEK 包裝、小值封裝
internal/sxcrypto/chunk.go           區塊加解密、PlainFile (ReadSeeker)
internal/blob/blob.go                Store 介面 + Local
internal/blob/s3.go                  S3 實作
internal/audit/audit.go              雜湊鏈寫入、驗證、查詢
internal/auth/password.go            argon2id
internal/auth/totp.go                TOTP
internal/auth/users.go               使用者資料存取 + 首位管理員
internal/auth/sessions.go            session 建立、查詢、撤銷
internal/httpapi/server.go           路由組裝
internal/httpapi/middleware.go       client IP、安全標頭、CSRF、session、頻率限制
internal/httpapi/auth_handlers.go    登入／登出／TOTP API
internal/httpapi/files_handlers.go   檔案列表／下載／刪除
internal/upload/tus.go               tus 處理器
internal/upload/janitor.go           清理過期未完成上傳
internal/webui/webui.go              go:embed web/dist
web/                                 React 前端
Dockerfile, docker-compose.yml, Caddyfile, .env.example
.github/workflows/ci.yml
README.md, README.zh-TW.md, LICENSE (AGPL-3.0)
```

---

### Task 1: 專案骨架與設定

**Files:**
- Create: `go.mod`, `cmd/secure-exchange/main.go`, `internal/config/config.go`, `.gitignore`, `.gitattributes`（`* text=auto eol=lf`）
- Test: `internal/config/config_test.go`

**Interfaces:**
- Produces: `config.Load(getenv func(string) string) (*Config, error)`；`Config` 欄位：`Listen string`（預設 `:8080`）、`BaseURL string`（必填）、`DatabaseURL string`（必填）、`MasterKeys string`（必填）、`ActiveKeyID int`（必填）、`Storage string`（`local`|`s3`，預設 `local`）、`StorageDir string`（預設 `/data/blobs`）、`StagingDir string`（預設 `/data/staging`）、`S3 S3Config{Endpoint, Bucket, AccessKey, SecretKey, Region string; UseSSL bool}`、`TrustedProxies []netip.Prefix`（逗號分隔 CIDR）、`MaxFileSize int64`（預設 `500 << 30`）、`SessionTTL time.Duration`（預設 `12h`）、`InitAdminEmail, InitAdminPassword string`。

- [ ] **Step 0: 安裝 Go**（環境沒有 Go）：`winget install GoLang.Go`，開新 shell 後 `go version` 顯示 ≥ go1.26。
- [ ] **Step 1: 寫失敗測試** `TestLoadDefaults`（只給必填值 → 預設值如上）、`TestLoadMissingRequired`（缺 `SX_DATABASE_URL` → error 訊息含 `SX_DATABASE_URL`）、`TestLoadTrustedProxies`（`"10.0.0.0/8, 192.168.1.1/32"` → 兩個 prefix；`"bad"` → error）、`TestLoadS3RequiresBucket`（`SX_STORAGE=s3` 缺 `SX_S3_BUCKET` → error）。
- [ ] **Step 2:** `go test ./internal/config/` → FAIL（未定義）。
- [ ] **Step 3: 實作** `config.Load`。環境變數名 = `SX_` + 欄位大寫蛇形（`SX_MASTER_KEYS`、`SX_S3_USE_SSL`…）。`main.go`：`serve` 子命令（預設）讀設定、啟動 `http.Server`，只掛 `GET /healthz` → 200 `ok`；SIGTERM 時 `Shutdown`。
- [ ] **Step 4:** `go test ./... && go vet ./...` → PASS。
- [ ] **Step 5: Commit** `feat: project skeleton and config`

---

### Task 2: 資料庫與 migration

**Files:**
- Create: `internal/db/db.go`, `internal/db/migrations/0001_init.sql`, `internal/db/testdb/testdb.go`, `docker-compose.dev.yml`（僅 postgres:17，port 5432，供本機測試）
- Test: `internal/db/db_test.go`

**Interfaces:**
- Produces: `db.Open(ctx, url string) (*pgxpool.Pool, error)`（連線並執行 goose migration，migration 以 `embed.FS` 內嵌）；`testdb.New(t *testing.T) *pgxpool.Pool`（建立隨機名稱 schema、`search_path` 指向它、跑 migration、`t.Cleanup` 刪除；`SX_TEST_DATABASE_URL` 未設時 `t.Skip`）。

Schema（`0001_init.sql`，後續 task 只讀不改；需要新欄位就新增 migration）：

```sql
CREATE TABLE users (
  id uuid PRIMARY KEY, email text NOT NULL, display_name text NOT NULL DEFAULT '',
  role text NOT NULL CHECK (role IN ('admin','staff','vendor')),
  auth_source text NOT NULL DEFAULT 'local' CHECK (auth_source IN ('local','ldap','oidc')),
  password_hash text, totp_secret_sealed bytea, totp_enabled boolean NOT NULL DEFAULT false,
  totp_last_step bigint NOT NULL DEFAULT 0,
  disabled boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now());
CREATE UNIQUE INDEX users_email_lower ON users (lower(email));
CREATE TABLE sessions (
  token_hash bytea PRIMARY KEY, user_id uuid NOT NULL REFERENCES users ON DELETE CASCADE,
  mfa_passed boolean NOT NULL, ip text NOT NULL, user_agent text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL);
CREATE TABLE files (
  id uuid PRIMARY KEY, owner_id uuid NOT NULL REFERENCES users,
  name text NOT NULL, content_type text NOT NULL, size bigint NOT NULL, sha256 bytea NOT NULL,
  wrapped_dek bytea NOT NULL, key_id int NOT NULL, storage_key text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), deleted_at timestamptz);
CREATE TABLE uploads (
  id uuid PRIMARY KEY, owner_id uuid NOT NULL REFERENCES users,
  name text NOT NULL, content_type text NOT NULL, size bigint NOT NULL, "offset" bigint NOT NULL DEFAULT 0,
  wrapped_dek bytea NOT NULL, key_id int NOT NULL, hash_state bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE audit_log (
  id bigserial PRIMARY KEY, at timestamptz NOT NULL, actor_type text NOT NULL, actor_id text NOT NULL,
  ip text NOT NULL, user_agent text NOT NULL, action text NOT NULL,
  target_type text NOT NULL, target_id text NOT NULL, result text NOT NULL,
  detail jsonb NOT NULL DEFAULT '{}', prev_hash bytea NOT NULL, hash bytea NOT NULL);
CREATE RULE audit_no_update AS ON UPDATE TO audit_log DO INSTEAD NOTHING;
CREATE RULE audit_no_delete AS ON DELETE TO audit_log DO INSTEAD NOTHING;
```

- [ ] **Step 1: 寫失敗測試** `TestMigrationsApply`：`testdb.New(t)` 後 `SELECT count(*) FROM users` = 0；`TestAuditLogImmutable`：插入一筆 audit_log 後 `UPDATE`／`DELETE`，再查該筆內容不變。
- [ ] **Step 2:** `docker compose -f docker-compose.dev.yml up -d`；`SX_TEST_DATABASE_URL=postgres://sx:sx@localhost:5432/sx?sslmode=disable go test ./internal/db/...` → FAIL。
- [ ] **Step 3: 實作** `db.Open`、`testdb.New`、migration。
- [ ] **Step 4:** 同上命令 → PASS。
- [ ] **Step 5: Commit** `feat: database and migrations`

---

### Task 3: 金鑰環與小值封裝

**Files:**
- Create: `internal/sxcrypto/keyring.go`
- Test: `internal/sxcrypto/keyring_test.go`

**Interfaces:**
- Produces:
  - `ParseKeyring(spec string, activeID int) (*Keyring, error)`：`spec` 格式 `"1:<base64 32 bytes>,2:<base64>"`；ID 重複、長度非 32、`activeID` 不存在 → error。
  - `(*Keyring) ActiveID() int`
  - `(*Keyring) NewDEK() (dek, wrapped []byte, keyID int, err error)`：32 bytes 隨機 DEK，以 active 主金鑰 AES-256-GCM 包裝（`wrapped = nonce(12) || ciphertext`）。
  - `(*Keyring) UnwrapDEK(wrapped []byte, keyID int) ([]byte, error)`
  - `(*Keyring) Seal(plain, aad []byte) ([]byte, error)` / `(*Keyring) Open(sealed, aad []byte) ([]byte, error)`：給 TOTP secret 等小值；`sealed = keyID(uint32 BE) || nonce || ct`。

- [ ] **Step 1: 寫失敗測試** `TestKeyringRoundTrip`（NewDEK → UnwrapDEK 相同）、`TestKeyringRejectsBadSpec`（`""`、`"1:short"`、`"1:k,1:k"`、activeID=9 → error）、`TestUnwrapWithOldKey`（keyring A 只有 key1 包裝 → keyring B 有 key1,key2 active=2 仍能 Unwrap）、`TestSealAADMismatch`（不同 aad Open → error）、`TestUnwrapTampered`（翻轉一 byte → error）。
- [ ] **Step 2:** `go test ./internal/sxcrypto/` → FAIL
- [ ] **Step 3: 實作**（`crypto/aes` + `crypto/cipher` GCM，`crypto/rand`）。
- [ ] **Step 4:** PASS
- [ ] **Step 5: Commit** `feat: master keyring and envelope key wrapping`

---

### Task 4: 分塊加密與可 Seek 的解密讀取

**Files:**
- Create: `internal/sxcrypto/chunk.go`
- Test: `internal/sxcrypto/chunk_test.go`

**Interfaces:**
- Produces:
  - `const ChunkSize = 1 << 20`；`const SealedChunkSize = ChunkSize + 16`
  - `ChunkCount(size int64) int64`：`size==0` → 1（空檔也有一個空的 last 區塊，防截斷）；否則 `ceil(size/ChunkSize)`。
  - `SealChunk(dek []byte, fileID uuid.UUID, index uint64, last bool, plain []byte) []byte`
  - `OpenChunk(dek []byte, fileID uuid.UUID, index uint64, last bool, sealed []byte) ([]byte, error)`
  - nonce = 4 bytes 0 + index(uint64 BE)；AAD = `fileID[16] || index(uint64 BE) || last(1 byte)`。每檔 DEK 唯一，所以 nonce 可決定性。
  - `type RangeOpener func(ctx context.Context, off, length int64) (io.ReadCloser, error)`（讀密文）
  - `OpenPlain(ctx context.Context, open RangeOpener, dek []byte, fileID uuid.UUID, size int64) io.ReadSeekCloser`：Seek 只記位置，Read 時按需打開「目前區塊起」的密文範圍，逐區塊解密並丟棄區塊內前置位元組。讓 `http.ServeContent` 直接處理 Range。

- [ ] **Step 1: 寫失敗測試**
  - `TestChunkRoundTrip`：index 0..2 各自 seal/open 相同。
  - `TestChunkSwapDetected`：用 index 1 的密文以 index 2 打開 → error；`last` 旗標不符 → error；不同 fileID → error。
  - `TestOpenPlainSeek`：準備 `2.5*ChunkSize` 隨機明文、全部 seal 進 `bytes.Reader` 做 opener；對位移 `{0, ChunkSize-1, ChunkSize, 2*ChunkSize+7, size-1}` Seek 後讀 100 bytes（不足就讀到尾）→ 與明文切片相同。
  - `TestOpenPlainTruncated`：密文少掉最後一個區塊 → Read 回 error（不能靜默 EOF）。
  - `TestEmptyFile`：size 0 → 一個區塊，讀出 0 bytes、無 error。
- [ ] **Step 2:** FAIL
- [ ] **Step 3: 實作**
- [ ] **Step 4:** PASS
- [ ] **Step 5: Commit** `feat: chunked AEAD file encryption with seekable reader`

---

### Task 5: Blob 儲存（本機、S3）

**Files:**
- Create: `internal/blob/blob.go`, `internal/blob/s3.go`
- Test: `internal/blob/blob_test.go`

**Interfaces:**
- Produces:
  - `type Store interface { Put(ctx context.Context, key string, r io.Reader, size int64) error; OpenRange(ctx context.Context, key string, off, length int64) (io.ReadCloser, error); Delete(ctx context.Context, key string) error }`（兩個實作，介面有其必要）
  - `NewLocal(dir string) (*Local, error)`：Put 先寫 `key.tmp` 再 rename；key 只允許 `[a-f0-9-]`，否則 error。
  - `NewS3(cfg config.S3Config) (*S3, error)`：minio-go `PutObject`（size 已知，SDK 自動 multipart）、`GetObject` 搭配 `SetRange`。
  - `New(cfg *config.Config) (Store, error)` 依 `cfg.Storage` 選擇。
- [ ] **Step 1: 寫失敗測試** `testStore(t, s Store)` 共用：Put 3 MiB → OpenRange(1, 10) 與原資料相同；OpenRange 超出 → error；Delete 後 OpenRange → error；Put 不合法 key `"../x"` → error。`TestLocal` 用 `t.TempDir()`；`TestS3` 在 `SX_TEST_S3_ENDPOINT` 未設時 skip（`docker-compose.dev.yml` 加 `minio` 服務供本機跑）。
- [ ] **Step 2:** FAIL
- [ ] **Step 3: 實作**
- [ ] **Step 4:** PASS（含 MinIO）
- [ ] **Step 5: Commit** `feat: local and S3 blob stores`

---

### Task 6: 稽核紀錄雜湊鏈

**Files:**
- Create: `internal/audit/audit.go`
- Test: `internal/audit/audit_test.go`

**Interfaces:**
- Produces:
  - `type Event struct { ActorType, ActorID, IP, UserAgent, Action, TargetType, TargetID, Result string; Detail map[string]any }`
  - `type Log struct{ pool *pgxpool.Pool }`；`New(pool) *Log`
  - `(*Log) Append(ctx context.Context, e Event) error`：在交易內 `pg_advisory_xact_lock(7461)` → 讀最後一筆 `hash`（無則 32 bytes 0）→ `hash = SHA256(prev_hash || canonical)`，`canonical` = 依欄位固定順序的 JSON（`at` 用 RFC3339Nano UTC、`detail` 以 `json.Marshal` 輸出，map key 已排序）→ insert。
  - `(*Log) Verify(ctx context.Context) (badID int64, err error)`：依 id 順序重算，第一筆不符回其 id；全部正確回 0。
  - `(*Log) List(ctx context.Context, f Filter) ([]Entry, error)`；`Filter{ActorID, Action string; Since, Until time.Time; Limit int}`。
  - Action 常數（後續 task 使用）：`ActLoginOK = "auth.login.ok"`、`ActLoginFail = "auth.login.fail"`、`ActLogout = "auth.logout"`、`ActTOTPEnable = "auth.totp.enable"`、`ActUpload = "file.upload"`、`ActDownload = "file.download"`、`ActDelete = "file.delete"`、`ActKeyRotate = "crypto.rotate"`。
- [ ] **Step 1: 寫失敗測試** `TestAuditChainVerifies`（append 3 筆 → Verify = 0）、`TestAuditDetectsTamper`（`DROP RULE audit_no_update ON audit_log` 後直接改第 2 筆 `result` → Verify = 第 2 筆 id）、`TestAuditConcurrentAppends`（50 個 goroutine 同時 Append → Verify = 0，筆數 50）。
- [ ] **Step 2:** FAIL
- [ ] **Step 3: 實作**
- [ ] **Step 4:** PASS
- [ ] **Step 5: Commit** `feat: hash-chained audit log`

---

### Task 7: 使用者、密碼、TOTP、首位管理員

**Files:**
- Create: `internal/auth/password.go`, `internal/auth/totp.go`, `internal/auth/users.go`
- Test: `internal/auth/auth_test.go`

**Interfaces:**
- Consumes: `sxcrypto.Keyring.Seal/Open`（aad = `"totp:" + userID`）
- Produces:
  - `HashPassword(pw string) (string, error)`（PHC 格式 `$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>`）；`VerifyPassword(encoded, pw string) bool`（`subtle.ConstantTimeCompare`）。
  - 密碼規則：長度 ≥ 12，否則 `ErrWeakPassword`。
  - `type User struct { ID uuid.UUID; Email, DisplayName, Role, AuthSource string; PasswordHash string; TOTPEnabled, Disabled bool }`
  - `type Users struct{ pool; keys *sxcrypto.Keyring }`；`NewUsers(pool, keys) *Users`
  - `(*Users) Create(ctx, email, displayName, role, password string) (*User, error)`；email 重複（不分大小寫）→ `ErrEmailTaken`。
  - `(*Users) ByEmail(ctx, email) (*User, error)`、`ByID(ctx, id)`；找不到 → `ErrNotFound`。
  - `(*Users) BeginTOTP(ctx, id) (otpauthURL string, err error)`：產生 secret（issuer `secure-exchange`），sealed 存入 `totp_secret_sealed`，`totp_enabled` 維持 false。
  - `(*Users) EnableTOTP(ctx, id, code string) error`：驗證成功才設 true；失敗 `ErrBadCode`。
  - `(*Users) CheckTOTP(ctx, id, code string) bool`（允許 ±1 個 30 秒時間窗；成功時以 `UPDATE … WHERE totp_last_step < $step` 記錄時間步，同一時間步的碼不得重複使用）。
  - `WithUser(ctx, *User) context.Context` / `UserFrom(ctx) *User`：放在 auth 套件，讓 httpapi 與 upload 都能使用而不互相 import。
  - `(*Users) EnsureInitialAdmin(ctx, email, password string) error`：`users` 為空且兩值皆非空時建立 admin；否則不動作。
- [ ] **Step 1: 寫失敗測試** `TestPasswordHashVerify`、`TestWeakPassword`（11 字元 → ErrWeakPassword）、`TestEmailCaseInsensitiveUnique`（`A@x.com` 後 `a@X.com` → ErrEmailTaken）、`TestTOTPFlow`（BeginTOTP → 從 URL 取 secret → `totp.GenerateCode` → EnableTOTP 成功；錯碼 → ErrBadCode；DB 中 `totp_secret_sealed` 不含 secret 明文）、`TestTOTPNoReplay`（同一碼 CheckTOTP 第二次 → false）、`TestEnsureInitialAdminOnlyWhenEmpty`（呼叫兩次只建立一位；已有使用者時不建立）。
- [ ] **Step 2:** FAIL
- [ ] **Step 3: 實作**
- [ ] **Step 4:** PASS
- [ ] **Step 5: Commit** `feat: users, argon2id passwords, TOTP`

---

### Task 8: Session、登入 API、中介層

**Files:**
- Create: `internal/auth/sessions.go`, `internal/httpapi/server.go`, `internal/httpapi/middleware.go`, `internal/httpapi/auth_handlers.go`
- Modify: `cmd/secure-exchange/main.go`（組裝 pool、keyring、users、audit、server；啟動時 `EnsureInitialAdmin`）
- Test: `internal/auth/sessions_test.go`, `internal/httpapi/auth_test.go`

**Interfaces:**
- Produces:
  - `type Sessions struct{...}`；`(*Sessions) Create(ctx, userID uuid.UUID, mfaPassed bool, ip, ua string, ttl time.Duration) (token string, err error)`（32 bytes 隨機，base64url）；`Lookup(ctx, token) (*Session, error)`（過期 → `ErrNotFound`）；`MarkMFA(ctx, token)`；`Revoke(ctx, token)`；`RevokeAllForUser(ctx, userID)`。
  - `ClientIP(r *http.Request, trusted []netip.Prefix) string`：RemoteAddr 在 trusted 內才採 `X-Forwarded-For` 由右往左第一個非 trusted 位址。
  - 中介層：`securityHeaders`（`Content-Security-Policy: default-src 'self'; img-src 'self' blob: data:; frame-ancestors 'none'`、`X-Content-Type-Options: nosniff`、`Referrer-Policy: no-referrer`、`Strict-Transport-Security: max-age=31536000`）；`http.NewCrossOriginProtection()` 包住整個 mux；`requireUser`（需 session 且 `mfa_passed`、使用者未停用，否則 401；以 `auth.WithUser` 放進 context）；`rateLimit(key func(*http.Request) string, r rate.Limit, burst int)`（in-memory map，`// ponytail: 單機記憶體限流，多實例部署時改存 PostgreSQL`）。
  - API（JSON）：
    - `POST /api/auth/login {email,password}` → 200 `{"mfa_required":bool}` 並設 cookie；任何失敗（無此帳號、錯密碼、停用）一律 401 `{"error":"invalid_credentials"}`，無此帳號時仍跑一次 `VerifyPassword` 對假雜湊以等化時間。限流：每 IP 10 次/分、每 email 5 次/分 → 429。
    - `POST /api/auth/totp {code}` → 200 並 MarkMFA；需有 mfa 未通過的 session；錯碼 401；限流同上。
    - `POST /api/auth/logout` → 204。
    - `GET /api/me` → `{id,email,display_name,role,totp_enabled}`。
    - `POST /api/me/totp/setup` → `{otpauth_url}`；`POST /api/me/totp/enable {code}` → 204。
  - 每次登入成功／失敗、登出、啟用 TOTP 寫入 audit。
- [ ] **Step 1: 寫失敗測試**（`httptest.Server`）
  - `TestLoginSuccessNoTOTP`：200、`mfa_required=false`、cookie 屬性 HttpOnly/Secure/SameSite=Strict；`GET /api/me` 200。
  - `TestLoginWithTOTP`：login → `mfa_required=true`；此時 `/api/me` 401；`/api/auth/totp` 正確碼後 200。
  - `TestLoginUniformFailure`：不存在 email 與錯密碼的回應狀態與 body 完全相同。
  - `TestLoginRateLimited`：同 email 第 6 次 → 429。
  - `TestCrossOriginPostRejected`：`Origin: https://evil.example`、`Sec-Fetch-Site: cross-site` 的 POST → 403。
  - `TestClientIP`：未信任來源忽略 XFF；信任來源取正確位址。
  - `TestAuditOnLogin`：成功與失敗各產生一筆對應 action。
- [ ] **Step 2:** FAIL
- [ ] **Step 3: 實作**
- [ ] **Step 4:** PASS
- [ ] **Step 5: Commit** `feat: sessions, login API, security middleware`

---

### Task 9: tus 可續傳上傳

**Files:**
- Create: `internal/upload/tus.go`, `internal/upload/janitor.go`
- Modify: `internal/httpapi/server.go`（掛在 `/api/uploads/`，需 `requireUser`）
- Test: `internal/upload/tus_test.go`

**Interfaces:**
- Consumes: `Keyring.NewDEK/UnwrapDEK`、`SealChunk`、`blob.Store.Put`、`audit.Log.Append`、`auth.UserFrom`
- Produces: `NewHandler(pool, keys, store blob.Store, audit *audit.Log, stagingDir string, maxSize int64) http.Handler`；`RunJanitor(ctx, pool, stagingDir string, maxAge time.Duration)`（每 10 分鐘刪除 `updated_at` 超過 maxAge=24h 的 uploads 列與暫存檔）。

協定行為（tus 1.0.0：core + creation + termination）：
- `OPTIONS` → `Tus-Version: 1.0.0`、`Tus-Extension: creation,termination`、`Tus-Max-Size`。
- `POST /api/uploads/`：需 `Upload-Length`（不支援 deferred length）；超過 maxSize → 413；`Upload-Metadata` 取 `filename`、`filetype`（base64）；建立 uploads 列（新 DEK、`hash_state` = 空 `sha256.New()` 的 `MarshalBinary`）、空暫存檔 `stagingDir/<id>`；201 + `Location`。
- `HEAD /api/uploads/{id}` → `Upload-Offset`、`Upload-Length`；非擁有者 → 404。
- `PATCH /api/uploads/{id}`：`Content-Type: application/offset+octet-stream`；`Upload-Offset` 必須等於目前 offset（否則 409）且是 `ChunkSize` 的倍數。以 `io.ReadFull` 逐 `ChunkSize` 讀取：完整區塊（或抵達 `size` 的最終區塊）→ 更新 sha256、`SealChunk`、附加到暫存檔；讀到不完整且未達 `size` 的尾段 → **丟棄**。每個區塊寫入後 fsync 並更新 `offset` 與 `hash_state`（同一交易）。回 204 + 新 `Upload-Offset`。
- 若暫存檔長度大於 offset 對應的密文長度（上次在寫檔與更新 DB 之間當機），PATCH 開始前先 truncate。
- 抵達 `size` 時：`blob.Put(storage_key=file id, 暫存檔)` → 插入 files 列（同 id、sha256 = 最終雜湊）→ 刪 uploads 列與暫存檔 → audit `file.upload` → 回應標頭 `X-SX-File-ID`。
- `DELETE /api/uploads/{id}` → 204，刪列與暫存檔。
- 前端要把 tus-js-client `chunkSize` 設為 `64 * ChunkSize`（這是對齊要求，寫在 Task 12）。

- [ ] **Step 1: 寫失敗測試**
  - `TestTusFullUpload`：3.5 MiB 隨機資料一次 PATCH → files 列存在，sha256 正確；以 `OpenPlain` 讀回相同。
  - `TestTusResumeAfterPartialPatch`：第一次 PATCH 只送 2.5 MiB 後關閉 body → HEAD offset = 2 MiB；從 2 MiB 續傳剩餘 → 最終讀回逐位元相同。
  - `TestTusRejectsMisalignedOffset`：offset 不等於目前值 → 409；offset 非 ChunkSize 倍數 → 409。
  - `TestTusTooLarge`：`Upload-Length` > maxSize → 413。
  - `TestTusOtherUserCannotAccess`：B 使用者 HEAD/PATCH A 的上傳 → 404。
  - `TestStagingIsEncrypted`：上傳一段已知明文（重複 `"PLAINTEXT"`）中途暫停 → 暫存檔不含該字串。
  - `TestJanitorRemovesStale`：將 `updated_at` 改為 25 小時前 → RunJanitor 一輪後列與檔皆刪除。
- [ ] **Step 2:** FAIL
- [ ] **Step 3: 實作**
- [ ] **Step 4:** PASS
- [ ] **Step 5: Commit** `feat: resumable chunk-aligned tus uploads with encrypted staging`

---

### Task 10: 檔案 API

**Files:**
- Create: `internal/httpapi/files_handlers.go`
- Test: `internal/httpapi/files_test.go`

**Interfaces:**
- Consumes: `OpenPlain`、`blob.Store.OpenRange`、`Keyring.UnwrapDEK`、`audit`
- Produces（皆需 `requireUser`，只能存取自己的檔案，其他人的一律 404）：
  - `GET /api/files` → `[{id,name,content_type,size,sha256(hex),created_at}]`，不含已刪除，依 `created_at` desc。
  - `GET /api/files/{id}/content` → `http.ServeContent`（支援 Range、`If-Range`）；`Content-Disposition: attachment; filename="<ASCII 備援>"; filename*=UTF-8''<percent-encoded>`；`Content-Type` 一律 `application/octet-stream`（避免瀏覽器把上傳的 HTML 當頁面渲染）；只在完整下載或第一個 Range 起點為 0 時寫 audit `file.download`。
  - `DELETE /api/files/{id}` → 204；設 `deleted_at`、`blob.Delete`、audit `file.delete`。
- [ ] **Step 1: 寫失敗測試**
  - `TestListOwnFilesOnly`。
  - `TestDownloadRanges`：5 MiB 檔；`bytes=0-0`、`bytes=1048575-1048576`（跨區塊）、`bytes=-1`（最後 1 byte）、`bytes=4194304-`、`bytes=99999999-` → 前四者 206 內容正確，最後 416。
  - `TestDownloadFilenameHeader`：檔名 `報價單 "v2"/../\x01.pdf` → 標頭可被 `mime.ParseMediaType` 解析、`filename*` 解碼後等於原檔名去除控制字元、無路徑字元影響。
  - `TestDeleteThenGone`：刪除後 GET content 404、列表不出現、blob 已刪。
  - `TestOtherUserFile404`。
- [ ] **Step 2:** FAIL
- [ ] **Step 3: 實作**
- [ ] **Step 4:** PASS
- [ ] **Step 5: Commit** `feat: file list, ranged download, delete`

---

### Task 11: 主金鑰輪替命令

**Files:**
- Modify: `cmd/secure-exchange/main.go`（`rotate-keys` 子命令）
- Create: `internal/sxcrypto/rotate.go`
- Test: `internal/sxcrypto/rotate_test.go`

**Interfaces:**
- Produces: `RotateAll(ctx, pool, keys *Keyring) (n int, err error)`：把 `files`、`uploads` 中 `key_id != active` 的 `wrapped_dek` 解包後以 active 重新包裝；`users.totp_secret_sealed` 一併重封。每 500 列一個交易；完成寫 audit `crypto.rotate`（detail 含筆數）。檔案內容不需重新加密。
- 操作文件（README）：在 `SX_MASTER_KEYS` 新增 key → 設 `SX_ACTIVE_KEY_ID` 為新 ID → 重啟 → `docker compose exec app secure-exchange rotate-keys` → 確認後可移除舊 key。
- [ ] **Step 1: 寫失敗測試** `TestRotateRewrapsAndStillDecrypts`：以 key1 上傳檔案並啟用 TOTP → 新 keyring(1,2 active=2) RotateAll → 所有列 `key_id=2`；以只含 key2 的 keyring 仍可 `OpenPlain` 讀回、`CheckTOTP` 成功。
- [ ] **Step 2:** FAIL
- [ ] **Step 3: 實作**
- [ ] **Step 4:** PASS
- [ ] **Step 5: Commit** `feat: master key rotation command`

---

### Task 12: 前端（登入、TOTP、上傳、檔案列表）並內嵌

**Files:**
- Create: `web/`（`npm create vite@latest web -- --template react-ts`）、`web/src/i18n/{index.ts,zh-TW.json,en.json}`、`web/src/api.ts`、`web/src/pages/{Login.tsx,TotpSetup.tsx,Files.tsx}`、`web/src/components/Uploader.tsx`、`internal/webui/webui.go`
- Modify: `internal/httpapi/server.go`（非 `/api/` 路徑交給 webui；找不到的路徑回 `index.html` 以支援前端路由）
- Test: `web/src/components/Uploader.test.tsx`（vitest + @testing-library/react）、`internal/webui/webui_test.go`

**Interfaces:**
- Consumes: Task 8、9、10 的 API。
- Produces: `webui.Handler() http.Handler`（`//go:embed all:dist`，`web/dist` 由 `npm run build` 產生；`go build` 前需先 build 前端；為讓 `go test` 在沒 build 時仍可編譯，repo 內保留 `internal/webui/dist/.gitkeep`，vite `outDir` 設為 `../internal/webui/dist`）。
- 頁面：`/login`（email、密碼，必要時第二步輸入 TOTP）；`/files`（列表：名稱、大小、時間、SHA-256 前 12 碼；下載、刪除；拖放上傳與進度條，可暫停／繼續）；`/settings/totp`（顯示 QR code、輸入驗證碼啟用）。右上角語言切換（`zh-TW` 預設，依 `navigator.language` 選初值，存 localStorage）。
- `Uploader` 使用 tus-js-client：`endpoint: "/api/uploads/"`、`chunkSize: 64 * 1024 * 1024`、`retryDelays: [0, 1000, 3000, 5000, 10000]`、`metadata: {filename, filetype}`、`storeFingerprintForResuming: true`（重新整理頁面後可續傳）。
- [ ] **Step 1: 寫失敗測試** `Uploader.test.tsx`：mock `tus.Upload`，斷言建構參數 `chunkSize === 67108864` 且 metadata 含檔名；`webui_test.go`：`GET /files` 回 200 且 `Content-Type` 為 text/html（SPA fallback）、`GET /api/unknown` 不被 webui 接走（404 JSON）。
- [ ] **Step 2:** `cd web && npx vitest run` → FAIL
- [ ] **Step 3: 實作**（所有字串放 i18n JSON，兩語言 key 完全一致）
- [ ] **Step 4:** `npx vitest run && npm run build && go test ./internal/webui/` → PASS；另加 `web/src/i18n/keys.test.ts` 斷言 `zh-TW.json` 與 `en.json` key 集合相同。
- [ ] **Step 5: Commit** `feat: web UI for login, TOTP, upload and files`

---

### Task 13: 容器化、部署文件、CI

**Files:**
- Create: `Dockerfile`（multi-stage：node 建前端 → golang 建執行檔 → `gcr.io/distroless/static-debian12:nonroot`）、`docker-compose.yml`（`app`、`postgres:17`、`caddy:2`；volumes `pgdata`、`sxdata`、`caddydata`）、`Caddyfile`（`{$SX_DOMAIN} { reverse_proxy app:8080 }`）、`.env.example`、`LICENSE`（AGPL-3.0 全文）、`README.md`、`README.zh-TW.md`、`.github/workflows/ci.yml`
- Test: CI 本身，加上一次手動冒煙測試

**Interfaces:**
- `.env.example` 列出所有 `SX_` 變數與說明，並附產生主金鑰的指令：`openssl rand -base64 32`。
- compose 中 `app` 設 `SX_TRUSTED_PROXIES` 為 compose 網段，`SX_BASE_URL=https://${SX_DOMAIN}`；Caddy 自動申請憑證；`app` 不對外開 port。
- README（兩語言）：功能概述、快速部署（`cp .env.example .env` → 填值 → `docker compose up -d`）、備份（`pg_dump` + `sxdata` volume + **主金鑰，遺失即無法解密**）、主金鑰輪替步驟、開發環境（`docker-compose.dev.yml`、`SX_TEST_DATABASE_URL`）。
- CI（push 與 PR）：services postgres:17 + minio；`go vet ./...`、`go test -race ./...`（設 `SX_TEST_DATABASE_URL`、`SX_TEST_S3_ENDPOINT`）、`cd web && npm ci && npx vitest run && npm run build`、`docker build .`。
- [ ] **Step 1:** 寫 Dockerfile、compose、Caddyfile、.env.example。
- [ ] **Step 2: 冒煙測試**：本機以 `SX_DOMAIN=localhost` 啟動 `docker compose up -d --build` → `curl -k https://localhost/healthz` = `ok`；瀏覽器以 `.env` 的初始管理員登入、上傳一個 > 200 MiB 檔案、中途重新整理頁面後續傳完成、下載後 `sha256sum` 與原檔相同。
- [ ] **Step 3:** 寫 README 兩語言、LICENSE、CI。
- [ ] **Step 4:** push 分支、開 PR，CI 全綠。
- [ ] **Step 5: Commit** `chore: docker deployment, docs, CI`

---

## 後續階段（各自另寫計畫）

2 一次性分享 → 3 線上檢視 → 4 下載標記與溯源 → 5 收件與掃毒 → 6 廠商帳號 → 7 強制規則、管理介面、LDAP/OIDC、稽核 CSV／syslog → 8 多語系補完、端對端測試、v1.0。
