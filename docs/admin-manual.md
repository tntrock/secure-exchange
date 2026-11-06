# 安全檔案交換：管理員手冊

本手冊給負責部署與維運安全檔案交換系統的管理員。日常操作（上傳、分享、上傳請求、廠商）請見[使用者手冊](user-manual.md)。

## 目錄

1. [系統架構](#1-系統架構)
2. [系統需求](#2-系統需求)
3. [安裝部署](#3-安裝部署)
4. [設定參考](#4-設定參考)
5. [帳號與權限](#5-帳號與權限)
6. [廠商帳號管理](#6-廠商帳號管理)
7. [溯源查詢（追查外流）](#7-溯源查詢追查外流)
8. [病毒掃描（ClamAV）](#8-病毒掃描clamav)
9. [線上預覽 worker](#9-線上預覽-worker)
10. [稽核紀錄](#10-稽核紀錄)
11. [電子郵件](#11-電子郵件)
12. [備份與還原](#12-備份與還原)
13. [主金鑰輪替](#13-主金鑰輪替)
14. [升級](#14-升級)
15. [監控與疑難排解](#15-監控與疑難排解)
16. [安全建議清單](#16-安全建議清單)

---

## 1. 系統架構

系統以 Docker Compose 執行，包含下列服務：

| 服務 | 用途 | 網路 |
|---|---|---|
| `caddy` | 對外的 HTTPS 入口，自動申請與更新 TLS 憑證 | `sx`（可連外） |
| `app` | 主程式：網頁介面、API、登入、分享、上傳、寄信 | `sx`、`backend` |
| `worker` | 線上預覽轉檔、病毒掃描等背景工作 | 只有 `backend`（**無法連外**） |
| `clamav` | 病毒掃描引擎 clamd | `backend`、`updates`（只為更新病毒碼而連外） |
| `postgres` | 資料庫（中繼資料、稽核紀錄） | `backend` |

資料存放：

| Volume | 內容 |
|---|---|
| `pgdata` | PostgreSQL 資料 |
| `sxdata` | 加密後的檔案與上傳中的暫存檔（使用 S3 時檔案改存 S3） |
| `caddydata` | TLS 憑證 |
| `clamdb` | 病毒碼資料庫 |

**加密方式**：每個檔案有自己的資料金鑰（AES-256-GCM），資料金鑰再以主金鑰（`SX_MASTER_KEYS`）包裝。預覽頁面與影片片段同樣加密後才儲存。**主金鑰遺失，所有檔案都無法解密。**

## 2. 系統需求

- 一台 Linux 主機，安裝 Docker 與 Docker Compose。
- 一個指向該主機的網域名稱，並開放 80 與 443 埠（Caddy 自動申請憑證需要）。
- 可用的 SMTP 寄信服務（**必填**，邀請信與驗證碼都靠它）。
- 記憶體：worker 上限 6 GB、clamav 上限 4 GB，加上 app、資料庫與系統本身，**建議 16 GB 以上**。
- CPU：建議 4 核以上（影片轉檔吃 CPU）。
- 磁碟：依檔案總量而定。加密後的大小約等於原檔，另外需預留預覽產物的空間。

## 3. 安裝部署

### 3.1 準備設定檔

```sh
git clone https://github.com/tntrock/secure-exchange.git
cd secure-exchange
cp .env.example .env
```

編輯 `.env`，至少填好下列項目：

| 項目 | 說明 |
|---|---|
| `SX_DOMAIN` | 對外網域，例如 `files.example.com` |
| `POSTGRES_PASSWORD` | 資料庫密碼，只能用英數字。可用 `openssl rand -hex 24` 產生 |
| `SX_MASTER_KEYS` | 主金鑰，格式 `1:<金鑰>`。以 `openssl rand -base64 32` 產生 |
| `SX_ACTIVE_KEY_ID` | 目前使用的金鑰編號，初次安裝填 `1` |
| `SX_INIT_ADMIN_EMAIL` | 第一位管理員的 email |
| `SX_INIT_ADMIN_PASSWORD` | 第一位管理員的密碼，請使用長密碼 |
| `SX_SMTP_HOST`、`SX_SMTP_FROM` | 寄信伺服器與寄件人（見[電子郵件](#11-電子郵件)） |

> **立刻把 `.env` 備份到伺服器以外的安全地方**（例如密碼管理器或離線媒體）。主金鑰只存在這個檔案裡。

### 3.2 啟動

```sh
docker compose up -d
```

第一次啟動會建置映像檔，並由 ClamAV 下載病毒碼（數分鐘）。完成後開啟 `https://<SX_DOMAIN>`。

### 3.3 首次登入

1. 以 `SX_INIT_ADMIN_EMAIL` 與 `SX_INIT_ADMIN_PASSWORD` 登入。管理員帳號只在資料庫中**沒有任何使用者**時建立一次。
2. 立刻到「我的檔案」→「雙因素驗證設定」為管理員帳號啟用雙因素驗證。
3. 帳號建立後，可從 `.env` 移除 `SX_INIT_ADMIN_PASSWORD`（之後不再使用），重新執行 `docker compose up -d`。

### 3.4 本機試用

`SX_DOMAIN=localhost` 時 Caddy 使用本機 CA，瀏覽器會出現憑證警告，`curl` 需加 `-k`。專案附的 `scripts/smoke.sh` 會在一個用完即丟的環境自動跑一次完整的端對端測試（上傳、續傳、分享、線上檢視、溯源、上傳請求與病毒掃描），可用來驗證主機環境。它需要 Docker，且在已有 `.env` 時會拒絕執行。

## 4. 設定參考

所有設定都是 `.env` 中的環境變數，修改後執行 `docker compose up -d` 生效。完整說明也寫在 `.env.example` 中。

### 部署與基本

| 變數 | 預設 | 說明 |
|---|---|---|
| `SX_DOMAIN` | （必填） | 對外網域 |
| `POSTGRES_PASSWORD` | （必填） | 內建資料庫密碼 |
| `SX_HTTP_PORT`／`SX_HTTPS_PORT` | 80／443 | 主機對外埠 |
| `SX_MASTER_KEYS` | （必填） | 主金鑰清單，`id:金鑰` 以逗號分隔 |
| `SX_ACTIVE_KEY_ID` | （必填） | 新資料使用哪一把金鑰 |
| `SX_INIT_ADMIN_EMAIL`／`SX_INIT_ADMIN_PASSWORD` | — | 第一位管理員 |
| `SX_MAX_FILE_SIZE` | 500 GiB | 單一檔案上傳上限（位元組） |
| `SX_SESSION_TTL` | `12h` | 登入狀態有效時間 |
| `SX_TRUSTED_PROXIES` | （compose 自動設定） | 信任哪些反向代理的 `X-Forwarded-For` |

### 儲存

| 變數 | 預設 | 說明 |
|---|---|---|
| `SX_STORAGE` | `local` | `local`（存在 `sxdata` volume）或 `s3` |
| `SX_S3_ENDPOINT`、`SX_S3_BUCKET`、`SX_S3_ACCESS_KEY`、`SX_S3_SECRET_KEY`、`SX_S3_REGION`、`SX_S3_USE_SSL` | — | S3 相容儲存設定 |

使用 S3 且 S3 位於 compose 之外時，worker 也必須能連到 S3。請建立 `docker-compose.override.yml`，讓 worker 多接一個網路，並在防火牆上限制該網路只能連到 S3 端點：

```yaml
services:
  worker:
    networks: [backend, s3]
networks:
  s3: {}
```

### 分享

| 變數 | 預設 | 說明 |
|---|---|---|
| `SX_SHARE_MAX_DAYS` | `30` | 分享與上傳請求的最長有效天數 |

### 線上預覽

| 變數 | 預設 | 說明 |
|---|---|---|
| `SX_PREVIEW_MAX_BYTES` | 1 GiB | 文件與圖片可預覽的大小上限 |
| `SX_PREVIEW_MAX_PAGES` | `500` | 文件最多轉幾頁 |
| `SX_PREVIEW_MAX_VIDEO_BYTES` | 1.5 GiB | 影片可預覽的大小上限 |
| `SX_PREVIEW_MAX_VIDEO_SECONDS` | `7200` | 影片可預覽的長度上限（秒） |
| `SX_RENDER_DPI` | `110` | 文件頁面解析度 |

調高上限時請一併調整 worker 的 `/work` tmpfs 與 `mem_limit`，見[線上預覽 worker](#9-線上預覽-worker)。

### 下載追蹤標記

| 變數 | 預設 | 說明 |
|---|---|---|
| `SX_MARK_MAX_BYTES` | 256 MiB | 在記憶體中加標記（PDF 中繼資料、圖片）的檔案上限，也是溯源查詢上傳檔案的分析上限 |
| `SX_MARK_MAX_PIXELS` | 50,000,000 | 可加標記的圖片像素上限 |
| `SX_UNMARKABLE_POLICY` | `warn` | `warn`：無法完整加標記的檔案照樣送出；`block`：拒絕這類下載，也不允許建立「允許下載 + 浮水印」且含這類檔案的分享 |

### 病毒掃描

| 變數 | 預設 | 說明 |
|---|---|---|
| `SX_CLAMD_ADDR` | （compose 自動設定） | clamd 位址 |
| `SX_SCAN_MAX_BYTES` | 1 GiB | 超過此大小的外部上傳**不掃描直接放行**（標示「未掃描」） |

### 廠商帳號

| 變數 | 預設 | 說明 |
|---|---|---|
| `SX_VENDOR_CREATION` | `approval` | 誰能建立廠商帳號，見[廠商帳號管理](#6-廠商帳號管理) |

### 電子郵件

見[電子郵件](#11-電子郵件)。

## 5. 帳號與權限

### 角色

| 角色 | 能做什麼 |
|---|---|
| 管理員（admin） | 員工的所有功能，加上：溯源查詢、核准／拒絕廠商申請、管理所有廠商帳號、收到病毒感染通知 |
| 員工（staff） | 上傳檔案、建立分享、建立上傳請求、建立廠商（依政策）、管理自己建立的廠商 |
| 廠商（vendor） | 只能看「與我分享」並上傳給允許的員工；看不到任何員工端頁面 |
| 外部收件人／上傳者 | 沒有帳號，以 email 驗證碼取得單次、限時的存取 |

系統在**每一個請求**都會重新檢查帳號狀態：帳號被停用或過期後，下一個請求就會被拒絕，不必等登入逾時。

### 員工帳號（目前版本的限制）

目前版本**只有第一位管理員**（由 `SX_INIT_ADMIN_*` 建立），尚未提供新增員工帳號的介面。員工帳號管理、LDAP 與 OIDC 單一登入會在第七階段（管理後台）加入。

### 員工遺失雙因素驗證裝置

目前沒有介面可重設，請在資料庫中關閉該帳號的雙因素驗證，讓使用者以密碼登入後重新設定：

```sh
docker compose exec postgres psql -U sx -d sx -c \
  "UPDATE users SET totp_enabled = false, totp_secret_sealed = NULL WHERE lower(email) = lower('user@example.com') AND role <> 'vendor';"
```

執行前請先確認對方身分（例如當面或電話確認），並自行記錄這次操作。

## 6. 廠商帳號管理

### 建立政策

`SX_VENDOR_CREATION` 決定誰能建立廠商帳號：

| 值 | 行為 |
|---|---|
| `staff` | 任何員工建立後立即寄出邀請。 |
| `approval`（預設） | 員工建立的廠商進入「待核准」，所有管理員會收到通知信；管理員建立的直接寄出邀請。 |
| `admin` | 只有管理員能建立，員工會看到「您沒有執行此操作的權限」。 |

### 核准與拒絕

管理員在「廠商」頁上方的「待核准」區塊可以：

- **核准**：寄出邀請信，狀態變為「已邀請」。
- **拒絕**：狀態變為「已拒絕」。

> 注意：被拒絕的廠商 email 目前**無法再用來建立新帳號**（email 在系統中必須唯一）。拒絕前請確認。

### 邀請與啟用

- 邀請連結 7 天內有效、只能用一次。廠商開啟後設定密碼（至少 12 字元）並綁定驗證器 App，雙因素驗證是強制的。
- 「重新邀請」會寄出新連結並讓舊連結失效，只適用於「已邀請」狀態。

### 停用、到期與延長

- **停用**：立即結束該廠商所有登入中的連線。**啟用**可恢復。
- **到期日**：建立時設定（明天到三年內），到期後無法登入。用「變更到期日」延長，已過期的帳號也可以延長。
- 建立者與管理員可以管理廠商；其他員工只能把檔案分享給「有效」的廠商。

### 廠商遺失驗證器裝置

目前沒有介面可重設。請在資料庫中清除該廠商的密碼與雙因素驗證，並結束其連線，讓狀態回到「已邀請」，再到「廠商」頁按「重新邀請」：

```sh
docker compose exec postgres psql -U sx -d sx <<'SQL'
BEGIN;
UPDATE users SET password_hash = NULL, totp_enabled = false, totp_secret_sealed = NULL
  WHERE lower(email) = lower('vendor@example.com') AND role = 'vendor';
DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE lower(email) = lower('vendor@example.com') AND role = 'vendor');
COMMIT;
SQL
```

執行前請先確認對方身分。

### 廠商能看到與做到什麼

- 只看得到分享給自己、尚未過期或撤銷的內容。分享的檢視次數、IP 限制、浮水印規則與一次性分享相同，浮水印上顯示廠商的 email。
- 只能上傳給**曾分享給他的員工**或**建立他帳號的員工**，看不到完整的員工名單。廠商上傳的檔案一律經病毒掃描。

## 7. 溯源查詢（追查外流）

收件人（含廠商）每次下載都會產生一組追蹤碼（`SX-` 加 10 個字元），並記錄收件人、IP 與時間；依檔案類型，追蹤碼會嵌入檔案：

| 檔案類型 | 浮水印開啟 | 浮水印關閉 |
|---|---|---|
| PDF | 重新產生為帶可見與不可見浮水印的 PDF，追蹤碼另寫入中繼資料與隱藏文字層 | 追蹤碼寫入 PDF 中繼資料 |
| Office（doc/docx/xls/xlsx/ppt/pptx/odt/ods/odp/rtf） | 轉為帶浮水印的 PDF | docx/xlsx/pptx 與 odt/ods/odp 寫入文件屬性；doc/xls/ppt/rtf 不嵌入 |
| JPEG／PNG | 可見加不可見浮水印 | 只加不可見浮水印 |
| 其他（影片、壓縮檔等） | 只記錄下載者與檔案指紋 | 同左 |

### 查詢方式

管理員登入後點上方「溯源查詢」，可用三種方式查：

1. **追蹤碼**：從可見浮水印或檔案上讀到的 `SX-…`。
2. **SHA-256**：外流檔案的指紋，可查出原始檔與所有下載紀錄。
3. **上傳可疑檔案**：系統只在記憶體中分析、不會儲存，會讀取中繼資料、隱藏文字層與不可見浮水印。超過 `SX_MARK_MAX_BYTES` 的檔案只比對 SHA-256。

結果列出來源（下載／線上檢視／原始上傳）、找到的方式、追蹤碼、檔案、擁有者、下載者、IP 與時間。查不到時顯示「無法判定」。

**截圖或翻拍**不帶嵌入標記，請從畫面上的可見浮水印讀出追蹤碼，再以「追蹤碼」方式查詢。

每次查詢本身也會記錄在稽核紀錄（`trace.lookup`）。

## 8. 病毒掃描（ClamAV）

所有**外部**上傳都會掃描：上傳請求的上傳者，以及廠商的直接上傳。員工自己上傳的檔案不掃描。

### 運作方式

- 檔案上傳完成後狀態為「掃描中」，worker 只在記憶體中解密，再串流給 clamd。clamd 把串流暫存在記憶體的 `/tmp` tmpfs，明文不會落地。
- 結果：
  - **未發現病毒**：檔案放行，收件的員工收到通知信。
  - **已感染**：檔案隔離，無法下載、預覽或分享。收件的員工與**所有管理員**都會收到通知信。
  - **掃描失敗**：連續 5 次無法掃描就封鎖，並通知收件的員工。
  - **未掃描**：檔案大於 `SX_SCAN_MAX_BYTES`，不掃描直接放行，並在通知信與畫面上警告。這是目前已知的例外，日後會提供改為封鎖的選項。
- clamd 暫時無法連線時，掃描會延後重試，不會消耗失敗次數。

### 維運注意事項

- **首次啟動**需要數分鐘下載病毒碼。這段期間的上傳會停在「掃描中」，clamd 就緒後自動處理。
- 病毒碼由 clamav 容器自動更新（透過可連外的 `updates` 網路）。
- clamd 約使用 1.5 至 3 GB 記憶體（上限 `mem_limit: 4g`）。
- 「未發現病毒」代表在 ClamAV 的掃描時間、大小與壓縮檔層數限制內沒有發現病毒，不等於證明檔案安全。
- 要調高掃描上限，下列各項都要調到不小於新值：`SX_SCAN_MAX_BYTES`、`clamd.conf` 的 `StreamMaxLength` 與 `MaxFileSize`、`docker-compose.yml` 中 clamav 的 `/tmp` tmpfs 大小。ClamAV 本身的硬上限約 4000 MiB。

查看掃描狀態：

```sh
docker compose logs --tail=100 clamav
docker compose exec postgres psql -U sx -d sx -c \
  "SELECT scan_status, count(*) FROM files WHERE deleted_at IS NULL GROUP BY scan_status;"
```

## 9. 線上預覽 worker

worker 會用 LibreOffice、poppler 與 FFmpeg 處理不受信任的檔案，因此被嚴格隔離：

- 沒有對外網路，只能連到資料庫與內部服務。
- 根檔案系統唯讀；解密後的檔案只放在 `/work` 的 tmpfs（4 GiB），每個工作結束就刪除。
- 不使用 swap（`memswap_limit` 等於 `mem_limit`），解密資料不會被換出到磁碟。`/work` 不是 tmpfs 時 worker 會拒絕啟動。
- 記憶體 6 GiB（含 4 GiB tmpfs）、2 顆 CPU、512 個 process，移除所有 capabilities，以非 root 使用者執行，每個外部程式都有逾時。

**容量規則**：必須維持「最大預覽輸入 + 產出 ≤ `/work` 大小（4 GiB）< `mem_limit`（6 GiB）」。調高預覽上限時，請一併調高 `docker-compose.yml` 中 worker 的 tmpfs 大小與 `mem_limit`。把 `/work` 寫滿的工作會被標為「檔案過大無法預覽」。

影片浮水印使用的 TTF 字型可用 `SX_FONT_FILE` 指定（預設 DejaVu Sans）。

## 10. 稽核紀錄

所有安全相關事件都寫入資料庫的 `audit_log` 表。這張表**只能新增、不能修改或刪除**（資料庫規則擋下），每筆紀錄還包含前一筆的雜湊值，形成雜湊鏈，任何竄改都會讓鏈斷掉。

目前版本沒有稽核紀錄的瀏覽介面（第七階段加入），請以 SQL 查詢：

```sh
# 最近 50 筆
docker compose exec postgres psql -U sx -d sx -c \
  "SELECT at, actor_type, actor_id, ip, action, target_type, target_id, result, detail FROM audit_log ORDER BY id DESC LIMIT 50;"

# 某段期間的登入失敗
docker compose exec postgres psql -U sx -d sx -c \
  "SELECT at, ip, detail FROM audit_log WHERE action = 'auth.login.fail' AND at > now() - interval '1 day' ORDER BY at;"
```

常見的事件類型：

| 類別 | 事件 |
|---|---|
| 登入 | `auth.login.ok`、`auth.login.fail`、`auth.logout`、`auth.totp.enable` |
| 檔案 | `file.upload`、`file.download`、`file.view`、`file.delete`、`file.scan` |
| 分享 | `share.create`、`share.revoke`、`share.recipient.add`、`share.recipient.revoke`、`share.otp.request`、`share.otp.verify` |
| 上傳請求 | `request.create`、`request.revoke`、`request.otp.request`、`request.otp.verify` |
| 廠商 | `vendor.create`、`vendor.approve`、`vendor.reject`、`vendor.disable`、`vendor.enable`、`vendor.expiry`、`vendor.reinvite`、`vendor.activate` |
| 溯源 | `trace.lookup` |

`actor_type` 表示操作者類型：`user`（員工、管理員）、`vendor`、`recipient`（分享收件人，廠商檢視分享時也記為此類）、`uploader`（上傳請求的上傳者）、`system`（系統自動作業，例如病毒掃描）。

## 11. 電子郵件

邀請信、驗證碼與通知都靠 SMTP 寄出，**沒設定 `SX_SMTP_HOST` 與 `SX_SMTP_FROM` 時系統不會啟動**。

```sh
SX_SMTP_HOST=smtp.example.com
SX_SMTP_PORT=587
SX_SMTP_USERNAME=apikey-or-user
SX_SMTP_PASSWORD=secret
SX_SMTP_FROM="Secure Exchange <noreply@example.com>"
SX_SMTP_TLS=starttls        # starttls（預設）、tls（通常為 465 埠）或 none
```

`SX_SMTP_TLS=none` 只允許 `localhost`、`127.0.0.1` 與 `mailpit`，僅供本機測試。

寄信採佇列方式：寄送失敗會自動重試，最多 10 次。檢查寄不出去的信：

```sh
docker compose logs app | grep "mail send failed"
docker compose exec postgres psql -U sx -d sx -c \
  "SELECT id, to_addr, attempts, next_attempt_at FROM mail_outbox WHERE sent_at IS NULL ORDER BY id DESC LIMIT 20;"
```

信件內容在資料庫中是加密存放的。建議為寄件網域設定 SPF、DKIM 與 DMARC，以免邀請信被當成垃圾郵件。

## 12. 備份與還原

### 備份

下列三項**必須一起備份**，缺一不可：

1. **資料庫**：
   ```sh
   docker compose exec -T postgres pg_dump -U sx sx > sx.sql
   ```
2. **檔案資料**（`sxdata` volume，或你的 S3 bucket）：
   ```sh
   docker run --rm --volumes-from "$(docker compose ps -aq app)" -v "$PWD:/backup" \
     debian:bookworm-slim tar -C /data -czf /backup/sxdata.tgz .
   ```
3. **`.env` 檔**：其中的 `SX_MASTER_KEYS` 是主金鑰。**主金鑰遺失，所有檔案永遠無法解密。** 請另存在伺服器之外的安全地方。

建議每天備份，並定期在另一台主機實際演練還原。

### 還原

還原時必須使用**與備份時相同的 `SX_MASTER_KEYS` 與 `SX_ACTIVE_KEY_ID`**。

1. 把備份的 `.env` 放回 `docker-compose.yml` 旁。
2. 建立容器與空的 volume，只啟動資料庫並匯入：
   ```sh
   docker compose create
   docker compose up -d postgres
   docker compose exec -T postgres psql -U sx -d sx -v ON_ERROR_STOP=1 < sx.sql
   ```
3. 還原檔案資料：
   ```sh
   docker run --rm --volumes-from "$(docker compose ps -aq app)" -v "$PWD:/backup" \
     debian:bookworm-slim tar -C /data -xzf /backup/sxdata.tgz
   ```
4. 選用：用同樣方式（把 `app` 換成 `caddy`）還原 `caddydata`，保留 TLS 憑證；不還原的話 Caddy 會重新申請。
5. `docker compose up -d`。

## 13. 主金鑰輪替

定期或懷疑金鑰外洩時，換成新的主金鑰：

1. 產生新金鑰：`openssl rand -base64 32`。
2. 在 `SX_MASTER_KEYS` 加入新金鑰，與舊金鑰並列（`1:<舊>,2:<新>`），並設 `SX_ACTIVE_KEY_ID=2`。
3. **先**讓所有 app 與 worker 改用新金鑰：`docker compose up -d`。
4. 在 app 容器內執行輪替，重複執行直到回報 `rotated 0 values`：
   ```sh
   docker compose exec app /secure-exchange rotate-keys
   ```
5. 確認下載正常後，才從 `SX_MASTER_KEYS` 移除舊金鑰並重啟。移除前請保留舊金鑰的備份。

## 14. 升級

```sh
cd secure-exchange
docker compose exec -T postgres pg_dump -U sx sx > before-upgrade.sql   # 先備份
git pull
docker compose up -d --build
```

資料庫結構會在 app 啟動時自動升級（多個實例同時啟動時有鎖保護）。升級後請檢查：

```sh
docker compose ps
docker compose logs --tail=50 app worker
curl -fsS https://<SX_DOMAIN>/healthz     # 應回傳 ok
```

升級前請閱讀版本說明，留意新增或變更的環境變數（與 `.env.example` 比對）。

## 15. 監控與疑難排解

### 健康檢查

- `https://<SX_DOMAIN>/healthz` 回傳 `ok` 表示 app 正常。
- `docker compose ps` 查看各服務狀態；`docker compose logs -f <服務>` 查看即時記錄。

### 常見問題

| 症狀 | 可能原因與處理 |
|---|---|
| 系統無法啟動，記錄提到 SMTP | 未設定 `SX_SMTP_HOST` 或 `SX_SMTP_FROM`。 |
| 沒有人能登入，記錄出現 `nobody can log in` | 首次啟動時沒有設定 `SX_INIT_ADMIN_EMAIL`／`SX_INIT_ADMIN_PASSWORD`。設定後重啟即可建立管理員。 |
| 無法取得 TLS 憑證 | 網域未指向本主機，或 80/443 埠被防火牆擋住。 |
| 收件人收不到邀請信或驗證碼 | 見[電子郵件](#11-電子郵件)檢查佇列；確認 SPF／DKIM；請收件人查看垃圾郵件。 |
| 外部上傳一直「掃描中」 | clamav 還在下載病毒碼，或 clamav 容器記憶體不足。查看 `docker compose logs clamav`。 |
| 預覽一直「處理中」 | 查看 `docker compose logs worker`；確認 worker 在執行且有足夠記憶體。 |
| 預覽顯示「檔案過大無法預覽」 | 超過預覽上限或寫滿 `/work`，見[線上預覽 worker](#9-線上預覽-worker)。 |
| 下載出現「檔案準備中，請稍後再試」 | 加浮水印的版本需要預覽完成，等預覽完成即可。 |
| worker 拒絕啟動，提到 tmpfs | `/work` 不是 tmpfs。請使用專案附的 `docker-compose.yml`。 |
| 檔案無法解密 | `SX_MASTER_KEYS` 與備份時不同，或移除了仍在使用的舊金鑰。 |
| 使用者被「嘗試次數過多」擋下 | 登入與驗證碼有每 IP 速率限制，稍等幾分鐘即會解除。 |

## 16. 安全建議清單

- [ ] `.env`（含主金鑰）已另存於伺服器以外的安全位置。
- [ ] 管理員帳號已啟用雙因素驗證。
- [ ] 首次啟動後已移除 `SX_INIT_ADMIN_PASSWORD`。
- [ ] 每日備份資料庫與檔案資料，並演練過還原。
- [ ] 寄件網域已設定 SPF、DKIM、DMARC。
- [ ] 主機只開放 80 與 443 埠，作業系統與 Docker 保持更新。
- [ ] 依公司政策決定 `SX_VENDOR_CREATION`（預設需管理員核准）。
- [ ] 若公司要求所有外流檔案都必須可追蹤，將 `SX_UNMARKABLE_POLICY` 設為 `block`。
- [ ] 定期以 `git pull` 與 `docker compose up -d --build` 更新，以取得安全修正。
- [ ] 發現安全問題請依 [SECURITY.md](../SECURITY.md) 私下回報。
