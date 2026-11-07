# 安全檔案交換：管理員手冊

本手冊給負責部署與維運安全檔案交換系統的管理員。日常操作（上傳、分享、上傳請求、廠商）請見[使用者手冊](user-manual.md)。

## 目錄

1. [系統架構](#1-系統架構)
2. [系統需求](#2-系統需求)
3. [安裝部署](#3-安裝部署)
4. [設定參考](#4-設定參考)
5. [帳號與權限](#5-帳號與權限)
    - [單一登入帳號（OIDC / Entra ID）](#單一登入帳號oidc--entra-id)
6. [廠商帳號管理](#6-廠商帳號管理)
7. [強制規則](#7-強制規則)
8. [溯源查詢（追查外流）](#8-溯源查詢追查外流)
9. [病毒掃描（ClamAV）](#9-病毒掃描clamav)
10. [線上預覽 worker](#10-線上預覽-worker)
11. [稽核紀錄](#11-稽核紀錄)
    - [11.1 轉送到 SIEM（syslog）](#111-轉送到-siemsyslog)
12. [電子郵件](#12-電子郵件)
13. [備份與還原](#13-備份與還原)
14. [主金鑰輪替](#14-主金鑰輪替)
15. [升級](#15-升級)
16. [監控與疑難排解](#16-監控與疑難排解)
17. [安全建議清單](#17-安全建議清單)

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
| `SX_SMTP_HOST`、`SX_SMTP_FROM` | 寄信伺服器與寄件人（見[電子郵件](#12-電子郵件)） |

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
| `SX_MAX_FILE_SIZE` | 500 GiB | 單一檔案上傳的硬上限（位元組）；[強制規則](#7-強制規則)中的「單檔大小上限」只能比它更低 |
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
| `SX_SHARE_MAX_DAYS` | `30` | 分享最長期限的**初始值**：只在第一次啟動、建立規則時寫入，之後請到管理頁的「規則」修改，見[強制規則](#7-強制規則) |

### 線上預覽

| 變數 | 預設 | 說明 |
|---|---|---|
| `SX_PREVIEW_MAX_BYTES` | 1 GiB | 文件與圖片可預覽的大小上限 |
| `SX_PREVIEW_MAX_PAGES` | `500` | 文件最多轉幾頁 |
| `SX_PREVIEW_MAX_VIDEO_BYTES` | 1.5 GiB | 影片可預覽的大小上限 |
| `SX_PREVIEW_MAX_VIDEO_SECONDS` | `7200` | 影片可預覽的長度上限（秒） |
| `SX_RENDER_DPI` | `110` | 文件頁面解析度 |

調高上限時請一併調整 worker 的 `/work` tmpfs 與 `mem_limit`，見[線上預覽 worker](#10-線上預覽-worker)。

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

### 稽核轉送

`SX_SYSLOG_ADDR`、`SX_SYSLOG_TRANSPORT`、`SX_SYSLOG_CA` 見[轉送到 SIEM](#111-轉送到-siemsyslog)。

### 網域登入（LDAP/AD）

`SX_LDAP_*` 見[網域帳號（LDAP/AD）](#網域帳號ldapad)。

### 單一登入（OIDC）

`SX_OIDC_*` 見[單一登入帳號（OIDC / Entra ID）](#單一登入帳號oidc--entra-id)。

### 電子郵件

見[電子郵件](#12-電子郵件)。

## 5. 帳號與權限

### 角色

| 角色 | 能做什麼 |
|---|---|
| 管理員（admin） | 員工的所有功能，加上：使用者管理、全站分享瀏覽、溯源查詢、核准／拒絕廠商申請、管理所有廠商帳號、收到病毒感染通知 |
| 員工（staff） | 上傳檔案、建立分享、建立上傳請求、建立廠商（依政策）、管理自己建立的廠商 |
| 廠商（vendor） | 只能看「與我分享」並上傳給允許的員工；看不到任何員工端頁面 |
| 外部收件人／上傳者 | 沒有帳號，以 email 驗證碼取得單次、限時的存取 |

系統在**每一個請求**都會重新檢查帳號狀態：帳號被停用或過期後，下一個請求就會被拒絕，不必等登入逾時。

### 使用者管理

登入後點選上方的「使用者」（只有管理員看得到）。頁面列出所有帳號（含廠商）：email、顯示名稱、角色、來源、狀態、TOTP、上次登入時間。

**新增員工或管理員**：按「新增員工帳號」，輸入電子郵件、顯示名稱並選擇角色（員工或管理員），按「建立並邀請」，系統會寄出邀請信。對方開啟 `/activate/<token>` 連結（7 天內有效、只能用一次，重新邀請後舊連結失效），設定密碼（至少 12 字元）即可啟用；若已開啟[全站強制雙因素驗證](#全站強制雙因素驗證)，啟用時還要綁定驗證器 App。員工啟用連結**不受**「允許外部使用者連線的網路」限制；廠商邀請連結仍受限制。

**各列的操作**：

| 操作 | 說明 |
|---|---|
| 停用／啟用 | 停用會立即結束該帳號所有登入中的連線，該帳號建立的分享與上傳請求也立即失效（見[全站分享瀏覽](#全站分享瀏覽)）。啟用可恢復。 |
| 變更角色 | 員工與管理員互轉，僅限本機帳號。 |
| 重設 TOTP | 見下方「員工遺失雙因素驗證裝置」與[廠商遺失驗證器裝置](#廠商遺失驗證器裝置)。 |
| 重新邀請 | 僅適用於狀態為「已邀請」的員工，寄出新連結並讓舊連結失效。 |

初始管理員仍由 `SX_INIT_ADMIN_*` 環境變數在第一次啟動時建立。LDAP 網域登入見[網域帳號（LDAP/AD）](#網域帳號ldapad)；OIDC 單一登入見[單一登入帳號（OIDC / Entra ID）](#單一登入帳號oidc--entra-id)。外部登入來源（LDAP、OIDC）的帳號仍可在這裡停用與啟用；但角色與雙因素驗證由外部來源決定，不能在這裡變更角色或重設 TOTP。

### 員工遺失雙因素驗證裝置

先確認對方身分（例如當面或電話確認），再到「使用者」頁按該員工的「重設 TOTP」。系統會清除雙因素驗證、保留密碼，並結束其所有連線。對方以密碼登入後重新設定；若已開啟全站強制雙因素驗證，登入後會被要求立即設定。操作會寫入稽核紀錄 `user.totp_reset`。

### 全站強制雙因素驗證

「規則」頁的「全站強制雙因素驗證（TOTP）」開啟後，沒有設定雙因素驗證的**本機員工與管理員**在密碼登入後，必須先完成驗證器綁定才能使用其他功能。廠商本來就一律要求雙因素驗證，不受此開關影響；LDAP／OIDC 帳號也不適用。

### 最後一位管理員

為避免鎖死系統，停用或降級**最後一位可用的本機管理員**會被拒絕並顯示錯誤。外部（LDAP／OIDC）管理員與從未啟用的管理員不計入。

### 全站分享瀏覽

點選上方的「所有分享」（只有管理員看得到），可瀏覽全站每一個分享與上傳請求，以擁有者 email 或訊息搜尋，並可撤銷。

- 管理員只能**線上檢視**檔案，一律加上浮水印（顯示管理員自己的身分，追蹤碼為 `ADMIN`），不提供下載。
- 每次開啟檔案都會寫入稽核紀錄 `file.view`。
- 擁有者帳號被停用後，其所有分享與上傳請求立即失效：收件人與上傳者看到的是已過期或不存在，包括已經開啟中的連線。

### 網域帳號（LDAP/AD）

讓員工以公司網域帳號登入。登入頁會多出「網域帳號」表單（只有設定了 `SX_LDAP_URL` 才會出現）。

LDAP／OIDC 的設定**只能寫在 `.env`**，管理介面中沒有對應的設定頁。

**設定**（寫在 `.env`，修改後 `docker compose up -d`；以下僅列重點，完整清單見 `.env.example`）：

| 變數 | 預設 | 說明 |
|---|---|---|
| `SX_LDAP_URL` | 空（關閉） | `ldaps://host:636` 或 `ldap://host:389`。`ldap://` 一律先以 StartTLS 加密才會綁定，無法設定明文登入。 |
| `SX_LDAP_BIND_DN`、`SX_LDAP_BIND_PASSWORD`、`SX_LDAP_BASE_DN` | 無 | 設定 URL 後必填：用來查詢使用者的服務帳號與搜尋起點。服務帳號只需唯讀權限。 |
| `SX_LDAP_CA` | 系統根憑證 | 驗證網域伺服器用的根憑證檔路徑，見下方「憑證」。 |
| `SX_LDAP_USER_FILTER` | `(&(objectClass=user)(\|(sAMAccountName={username})(userPrincipalName={username})))` | 必須含 `{username}`，會代入（已跳脫的）登入輸入。 |
| `SX_LDAP_ID_ATTR`、`SX_LDAP_EMAIL_ATTR`、`SX_LDAP_NAME_ATTR` | `objectGUID`、`mail`、`displayName` | 帳號唯一識別、email、顯示名稱的屬性。email 為空時改用 `userPrincipalName`；兩者皆空則無法登入。 |
| `SX_LDAP_ADMIN_GROUP` | 空 | 管理員群組的 DN；留空表示沒有人會因 LDAP 成為管理員。 |
| `SX_LDAP_TLS_INSECURE` | `false` | 略過憑證驗證，**不建議**，見下方「憑證」。 |

AD 範例：

```
SX_LDAP_URL=ldaps://dc01.corp.example:636
SX_LDAP_CA=/etc/secure-exchange/certs/ad-root.cer
SX_LDAP_BIND_DN=CN=svc-sx,OU=Service,DC=corp,DC=example
SX_LDAP_BIND_PASSWORD=<服務帳號密碼>
SX_LDAP_BASE_DN=DC=corp,DC=example
SX_LDAP_ADMIN_GROUP=CN=SX-Admins,OU=Groups,DC=corp,DC=example
```

**運作方式**

- 使用者在登入頁輸入網域帳號（`sAMAccountName` 或 UPN）與密碼；系統先以服務帳號找到使用者，再以該使用者的密碼綁定驗證。
- 帳號在**第一次登入時自動建立**為員工；之後每次登入都會更新 email 與顯示名稱。
- 網域帳號**不會與本機帳號合併**：即使 email 相同，也是兩個獨立的帳號，網域登入永遠不會進到本機帳號。兩個網域帳號的 email 相同時，第二個會被擋下（`email_conflict`），請在 AD 修正 email。若是**舊網域帳號仍占用該 email**（AD 帳號被刪除後重建、或 email 轉給別人），在 AD 修正無效，請見下方疑難排解的兩種處理。
- **管理員**：屬於 `SX_LDAP_ADMIN_GROUP` 的人為管理員，其他人為員工，每次登入都重新判斷。AD 會計入巢狀群組；其他 LDAP 伺服器只看使用者的 `memberOf` 是否直接包含該群組。判斷管理員時若網域伺服器忙碌或不可用，該次登入會失敗（503），不會被降級。
- **每 15 分鐘重新檢查**每個登入中的連線：帳號在 AD 已刪除或停用時，該使用者所有連線立即結束。
- **網域伺服器無法連線時**，重新檢查會結束該連線，所有網域使用者都會被登出、也無法登入，直到伺服器恢復。因此請**務必保留至少一位本機管理員**（`SX_INIT_ADMIN_*` 建立的帳號），否則 AD 故障時無人能管理系統。
- 網域帳號**沒有 TOTP**，不適用[全站強制雙因素驗證](#全站強制雙因素驗證)；請使用 AD／公司的多因素驗證。使用者自行啟用 TOTP 會被拒絕。
- 網域帳號的**角色由管理員群組決定**，不能在「使用者」頁變更角色或重設 TOTP。管理員仍可在本機**停用**網域帳號（停用後即使 AD 密碼正確也無法登入）。外部管理員不計入[最後一位管理員](#最後一位管理員)的檢查。
- 在 AD 停用的帳號，登入時通常顯示為帳號或密碼錯誤（AD 直接拒絕綁定）。

#### 登入失敗與帳號鎖定

網域登入失敗會**直接計入 AD 的帳號鎖定次數**。系統內針對使用者名稱的限流可以被不同寫法繞過（例如 `DOMAIN\u` 與 `u@upn` 視為不同名稱），因此對網際網路開放的站台，請依賴 IP 限流／反向代理的限流，並在 AD 設定帳號鎖定原則。

#### email 被舊網域帳號占用（`email_conflict`）

AD 帳號刪除後重建（`objectGUID` 改變、email 相同），或 email 轉給另一個人時，系統內舊的網域帳號仍占用該 email，每次登入都會得到 409 `email_conflict`；在 AD 修正無效。先到「稽核紀錄」頁找該次 `auth.login.fail`（stage 為 `email_conflict`），「詳細資料」中的 `external_id` 就是新帳號的 objectGUID（十六進位）。以下 SQL 用 `docker compose exec postgres psql -U sx -d sx -c "…"` 執行，`<email>` 換成該 email：

- **同一個人**（復職、帳號重建）：把舊帳號改綁到新的 objectGUID，檔案與分享都保留。

  ```sh
  docker compose exec postgres psql -U sx -d sx -c \
    "UPDATE users SET external_id='<新的 external_id>' WHERE auth_source='ldap' AND lower(email)=lower('<email>');"
  ```

- **該 email 現在屬於另一個人**：釋出 email 並讓舊帳號維持停用，新的人下次登入會建立全新帳號。

  ```sh
  docker compose exec postgres psql -U sx -d sx -c \
    "UPDATE users SET email = email || '.retired-' || left(id::text, 8), disabled = true WHERE auth_source='ldap' AND lower(email)=lower('<email>');"
  ```

#### 憑證

建議的作法：

1. 在 Windows 匯出 AD 的根 CA 憑證：開啟 MMC，加入「憑證」嵌入式管理單元，找到根 CA 憑證，右鍵「所有工作」→「匯出」；格式選「Base-64 編碼 X.509 (.CER)」或「DER 編碼二進位 X.509 (.CER)」皆可。或在 CA 伺服器執行 `certutil -ca.cert ad-root.cer`。
2. 把檔案複製到專案的 `./certs` 目錄（`docker-compose.yml` 會以唯讀方式掛載到容器的 `/etc/secure-exchange/certs`）。
3. 在 `.env` 設定 `SX_LDAP_CA=/etc/secure-exchange/certs/ad-root.cer`，再 `docker compose up -d`。

若網域控制站使用**自簽憑證**，可直接把該憑證當作 `SX_LDAP_CA` 使用，作法相同。可放多張憑證（PEM 合併檔）。

`SX_LDAP_TLS_INSECURE=true` 會**完全略過憑證驗證**（連線仍加密，但不驗證對方身分）。風險：網路路徑上的任何人都能冒充網域控制站，取得使用者輸入的網域密碼。請優先使用 `SX_LDAP_CA`，此開關只作為暫時措施；啟用期間每次啟動都會在記錄中出現 WARN。

登入失敗的稽核紀錄若帶有 `reason: certificate`，代表 CA 設定錯誤或缺少（而不是網域控制站當機）。

#### 疑難排解

| 症狀 | 處理 |
|---|---|
| 登入顯示「網域伺服器暫時無法連線…」，稽核 `auth.login.fail` 的 stage 為 `ldap_unavailable` | 網域伺服器連不上、逾時（10 秒），或憑證驗證失敗。detail 含 `reason: certificate` 者請檢查 `SX_LDAP_CA` 與 `./certs`；否則檢查網路、埠與服務帳號密碼。 |
| 登入顯示 email 已被另一個網域帳號使用（`email_conflict`） | 兩個 AD 帳號的 email（或 UPN）相同，請在 AD 修正；若是 AD 帳號重建或 email 轉讓，見上方「email 被舊網域帳號占用」的兩種 SQL 處理。 |
| stage 為 `ldap_no_email` | 該帳號的 `SX_LDAP_EMAIL_ATTR` 與 `userPrincipalName` 都是空的。 |
| stage 為 `ldap_disabled` | AD 帳號已停用。stage 為 `disabled` 則是管理員在本機停用。 |
| 使用者突然被登出，稽核 `auth.session.end` 的 reason 為 `ldap_unavailable`／`ldap_gone`／`ldap_error` | 分別是網域伺服器無法連線、帳號在 AD 已刪除或停用、更新帳號資料失敗。關閉 LDAP 時，既有網域連線也會結束。 |

### 單一登入帳號（OIDC / Entra ID）

讓員工以公司的單一登入（Microsoft Entra ID 或其他 OpenID Connect 身分提供者）登入。登入頁會多出「以 Microsoft 登入」按鈕（只有設定了 `SX_OIDC_ISSUER` 才會出現）。採用 Authorization Code + PKCE，並驗證 `state`、`nonce`、ID token 簽章、`iss` 與 `aud`。設定**只能寫在 `.env`**。

**設定**（修改後 `docker compose up -d`；完整清單見 `.env.example`）：

| 變數 | 預設 | 說明 |
|---|---|---|
| `SX_OIDC_ISSUER` | 空（關閉） | 發行者網址，必須是 `https://`。Entra 為 `https://login.microsoftonline.com/<tenant-id>/v2.0`，**必須用你的租用戶 ID**；`common`、`organizations` 與權杖中的 `iss` 不相符，無法使用。 |
| `SX_OIDC_CLIENT_ID`、`SX_OIDC_CLIENT_SECRET` | 無 | 設定發行者後必填：應用程式（用戶端）識別碼與用戶端密碼的「值」。 |
| `SX_OIDC_SCOPES` | `openid profile email` | 以空白分隔；缺少 `openid` 時會自動補上。 |
| `SX_OIDC_ADMIN_CLAIM` | `groups` | 決定管理員的權杖宣告名稱。Entra 建議改為 `roles`。 |
| `SX_OIDC_ADMIN_VALUE` | 空 | 使其成為管理員的值；留空表示沒有人會因單一登入成為管理員。 |
| `SX_OIDC_BUTTON_TEXT` | 空 | 登入按鈕文字，設定後原樣顯示；留空則顯示內建的「以 Microsoft 登入」。 |
| `SX_OIDC_CA` | 系統根憑證 | 內部身分提供者（如 Keycloak）的根憑證檔（PEM 或 DER），作法同 LDAP 的「憑證」：放進 `./certs`，路徑寫 `/etc/secure-exchange/certs/<檔名>`。 |

**重新導向 URI**：沒有獨立的變數，固定是 `SX_BASE_URL` + `/api/auth/oidc/callback`，例如 `https://files.corp.example/api/auth/oidc/callback`。請在身分提供者**完整一字不差**地註冊這個網址。

**啟動時不連線**：系統啟動時只檢查設定，不會連到身分提供者；第一次有人登入時才做探索並快取，失敗則下次登入再試。因此身分提供者故障不會讓系統無法啟動，本機管理員也仍可登入；恢復後不需重啟。

#### Entra ID 設定步驟

1. Entra 系統管理中心 →「應用程式註冊」→「新增註冊」。
2. 「重新導向 URI」選平台「Web」，填入上述回呼網址（`<SX_BASE_URL>/api/auth/oidc/callback`）。
3. 記下「應用程式（用戶端）識別碼」（`SX_OIDC_CLIENT_ID`）與「目錄（租用戶）識別碼」，組成 `SX_OIDC_ISSUER=https://login.microsoftonline.com/<租用戶識別碼>/v2.0`。
4. 「憑證與祕密」→ 新增用戶端密碼，複製「值」（只顯示一次）作為 `SX_OIDC_CLIENT_SECRET`，並**記下到期日**。密碼到期後，所有單一登入都會失敗（`oidc_unavailable`，伺服器記錄為 ERROR），請在到期前換新並更新 `.env`。
5. 設定管理員對應（見下），`docker compose up -d`。

#### 管理員對應

**建議使用 App Role（`roles`）：**

1. 在應用程式註冊的「應用程式角色」建立角色，值例如 `SecureExchange.Admin`（允許的成員類型：使用者／群組）。
2. 在「企業應用程式」→ 該應用程式 →「使用者和群組」，把要當管理員的人指派到該角色。
3. `.env` 設定 `SX_OIDC_ADMIN_CLAIM=roles`、`SX_OIDC_ADMIN_VALUE=SecureExchange.Admin`。

宣告若是字串，須與設定值完全相同；若是陣列，任一元素相同即可（區分大小寫）。

**為什麼不建議用 `groups`**（雖然它是預設值）：

- Entra 權杖的群組宣告裝的是群組的**物件識別碼**（GUID），不是名稱，`SX_OIDC_ADMIN_VALUE` 必須填 GUID。
- 使用者所屬群組超過 200 個時，Entra 不會把群組放進權杖（overage），改以 `_claim_names` 指向 Graph。系統不會去呼叫 Graph，該使用者會**成為員工而非管理員**，且該次登入的稽核 `auth.login.ok` 詳細資料帶有 `groups_overage: true`。管理員被降級時請先查這個欄位。使用 App Role 沒有此限制。

#### 其他身分提供者

- **Google Workspace**：權杖沒有群組宣告，所以 `SX_OIDC_ADMIN_VALUE` 留空，單一登入的使用者都是員工；需要管理員時，請另外建立本機管理員帳號。
- **Keycloak**：`SX_OIDC_ISSUER=https://kc.corp.example/realms/<realm>`；若使用內部 CA，設定 `SX_OIDC_CA`。管理員對應請在 Keycloak 讓權杖帶出角色或群組宣告，再設定 `SX_OIDC_ADMIN_CLAIM`／`SX_OIDC_ADMIN_VALUE`。

#### 帳號行為

- 帳號在**第一次登入時自動建立**為員工；之後每次登入都會更新 email 與顯示名稱。email 取 `email`，沒有則 `preferred_username`，再沒有則 `upn`；三者都空則無法登入。`email_verified` 不是必要條件。
- 單一登入帳號**不會與本機或網域帳號合併**：即使 email 相同，也是獨立的帳號（唯一識別為 `iss` + `sub`），單一登入永遠不會進到本機或網域帳號，本機密碼登入仍進本機帳號。
- **角色每次登入重新判斷**；不能在「使用者」頁變更角色或重設 TOTP。外部管理員不計入[最後一位管理員](#最後一位管理員)的檢查，請保留至少一位本機管理員。
- 管理員可在本機**停用**帳號；被停用的帳號無法登入（稽核 stage 為 `disabled`）。
- 登入狀態最長為 `SX_SESSION_TTL`（預設 12 小時，絕對時間、不會延長）。系統**不會定期向身分提供者重新檢查**，因此在 Entra 停用使用者後，要等其登入狀態到期才生效；要立即中斷，請同時在「使用者」頁停用該帳號。
- 單一登入帳號**沒有 TOTP**，不適用[全站強制雙因素驗證](#全站強制雙因素驗證)；多因素驗證由 Entra 的條件式存取負責。
- 在本系統登出只結束本系統的登入狀態，**不會**登出 Microsoft（身分提供者）。
- 移除 `SX_OIDC_ISSUER`（關閉單一登入）後，既有的單一登入連線在下一次請求就會結束（稽核 `auth.session.end` 的 reason 為 `oidc_disabled`）。

#### 疑難排解

登入失敗時，使用者會被帶回 `/login?oidc_error=<代碼>`；到「稽核紀錄」頁找 `auth.login.fail`，詳細資料的 `source` 為 `oidc`，`stage` 如下：

| stage | 頁面代碼 | 說明與處理 |
|---|---|---|
| `oidc_denied` | `denied` | 身分提供者回傳錯誤（例如使用者按了取消、或未被指派存取權）。詳細資料的 `idp_error` 是對方的錯誤代碼（最多 64 字元）。 |
| `oidc_state` | `invalid` | `state` 與瀏覽器 cookie 不符或 cookie 遺失（逾時 10 分鐘、跨瀏覽器、或疑似偽造的登入請求）。請使用者從登入頁重新按按鈕。 |
| `oidc_token` | `invalid` | 權杖被拒：授權碼無效或已用過、ID token 簽章／`iss`／`aud`／到期驗證失敗，或 `nonce` 不符。多半是 `SX_OIDC_ISSUER` 或 `SX_OIDC_CLIENT_ID` 設定錯誤（例如用了 `common`）。 |
| `oidc_no_email` | `invalid` | 權杖中 `email`、`preferred_username`、`upn` 都沒有值。請在身分提供者補上 email。 |
| `oidc_unavailable` | `unavailable` | 連不上身分提供者（探索、金鑰或權杖端點逾時 10 秒／5xx），或**用戶端被拒絕**（`invalid_client`，通常是用戶端密碼到期或填錯，伺服器記錄為 ERROR）。檢查網路、`SX_OIDC_CLIENT_SECRET` 到期日，內部 CA 則檢查 `SX_OIDC_CA`。本機登入不受影響。 |
| `email_conflict` | `email_conflict` | 已有另一個單一登入帳號占用同一個 email，見下。 |
| `disabled` | `invalid` | 管理員在本機停用了該帳號。 |

#### email 被舊單一登入帳號占用（`email_conflict`）

在 Entra 刪除使用者後重建（`sub` 改變、email 相同），或 email 轉給別人時，系統內舊的單一登入帳號仍占用該 email，每次登入都會被擋下。到「稽核紀錄」頁找 stage 為 `email_conflict` 的 `auth.login.fail`，詳細資料中的 `external_id` 是新帳號的識別，格式為 `iss` + 一個空白 + `sub`（例如 `https://login.microsoftonline.com/<tenant-id>/v2.0 <sub>`）。以下 SQL 用 `docker compose exec postgres psql -U sx -d sx -c "…"` 執行，`<email>` 換成該 email：

- **同一個人**（復職、帳號重建）：把舊帳號改綁到新的 `external_id`，檔案與分享都保留。

  ```sh
  docker compose exec postgres psql -U sx -d sx -c \
    "UPDATE users SET external_id='<新的 external_id，含 iss 與空白>' WHERE auth_source='oidc' AND lower(email)=lower('<email>');"
  ```

- **該 email 現在屬於另一個人**：釋出 email 並讓舊帳號維持停用，新的人下次登入會建立全新帳號。

  ```sh
  docker compose exec postgres psql -U sx -d sx -c \
    "UPDATE users SET email = email || '.retired-' || left(id::text, 8), disabled = true WHERE auth_source='oidc' AND lower(email)=lower('<email>');"
  ```

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

先確認對方身分，再到「使用者」頁按該廠商的「重設 TOTP」。系統會清除該廠商的密碼與雙因素驗證、結束其所有連線，並**自動寄出新的邀請信**；廠商開啟連結後重新設定密碼與驗證器 App。

### 廠商能看到與做到什麼

- 只看得到分享給自己、尚未過期或撤銷的內容。分享的檢視次數、IP 限制、浮水印規則與一次性分享相同，浮水印上顯示廠商的 email。
- 只能上傳給**曾分享給他的員工**或**建立他帳號的員工**，看不到完整的員工名單。廠商上傳的檔案一律經病毒掃描。

## 7. 強制規則

管理員可以在網頁介面訂定全站規則，強制套用在所有員工與外部使用者身上。登入後點選上方的「規則」（只有管理員看得到），共有 14 項設定，分成五組：安全性、分享、收件人、外部上傳、儲存空間。按「儲存」後立即生效：系統在每一個請求都會重新讀取規則，不必重啟服務。儲存後頁面會顯示「受影響的分享：N」。

### 設定一覽

**安全性**

| 設定 | 說明 |
|---|---|
| 全站強制雙因素驗證（TOTP） | 只套用於本機員工與管理員，見「全站強制雙因素驗證」。 |

**分享**

| 設定 | 說明 |
|---|---|
| 一律加浮水印 | 所有分享都必須加浮水印，員工建立分享時此選項被鎖定。 |
| 禁止下載（僅能檢視） | 所有分享都只能線上檢視，員工建立分享時「允許下載」被鎖定。 |
| 分享最長期限（天） | 1 至 365 天。同時是上傳請求的最長期限。 |
| 分享預設期限（天） | 建立分享時預設的期限，須介於 1 天與最長期限之間。 |
| 單一分享大小上限（MiB） | 一個分享內所有檔案的總大小；`0` 表示不限。 |

**收件人**

| 設定 | 說明 |
|---|---|
| 封鎖的 Email 網域 | 每行一個網域。 |
| 允許的 Email 網域 | 每行一個網域；留空表示全部允許，有填寫時只有這些網域可以。 |
| 允許外部使用者連線的網路 | CIDR（也可只填單一 IP），每行一個；留空表示不限制。 |

**外部上傳**

| 設定 | 說明 |
|---|---|
| 允許的上傳副檔名 | 每行一個（可寫 `pdf` 或 `.pdf`，不分大小寫）；留空表示全部允許。 |
| 外部上傳大小上限（MiB） | 外部上傳者與廠商上傳的單檔上限；`0` 表示不限。 |

**儲存空間**

| 設定 | 說明 |
|---|---|
| 單檔大小上限（MiB） | `0` 表示只受 `SX_MAX_FILE_SIZE` 限制；填寫的值不能超過 `SX_MAX_FILE_SIZE`。 |
| 每位使用者儲存配額（MiB） | `0` 表示不限。 |
| 保存天數 | `0` 表示不自動清除，見下方「自動清除」。 |

欄位上限：網域各最多 200 個、副檔名最多 200 個、網路最多 100 個。網域與副檔名會自動轉成小寫並去除重複；副檔名只能包含英文字母與數字。格式有誤時，頁面會在該欄位旁顯示錯誤，整份規則不會儲存。

### 對員工分享選項的影響

規則鎖定的選項在建立分享對話框中會變灰，並標示「由管理員設定」；即使繞過介面直接呼叫 API，伺服器也會拒絕（「管理員已禁止下載」「管理員要求必須加浮水印」）。

### 對既有分享：以較嚴格者為準

「禁止下載」「一律加浮水印」與網域規則在**每一次檢視與下載**時都會重新檢查，所以收緊規則後，**已經建立的分享**（一次性分享與分享給廠商的分享）也立即受到限制，不必逐一撤銷：

- 禁止下載後，既有分享即使設定為允許下載，收件人也只能線上檢視。無法線上預覽的檔案因此無法存取，收件人會看到「此檔案目前無法存取（管理員已禁止下載）」；新建立的「僅線上檢視」分享若含有這類檔案，會被拒絕。
- 一律加浮水印後，既有分享的檢視與下載都會加上浮水印。
- 網域規則：封鎖的網域**優先於**允許清單；清單中的網域也涵蓋其子網域（封鎖 `example.com` 同時封鎖 `mail.example.com`）。規則同樣適用於廠商帳號的 email（建立廠商、分享給廠商、廠商存取分享時）。收件人 email 被規則擋下時，仍會收到驗證碼（可證明身分），但驗證後會被拒絕並看到「您的 Email 網域不允許存取此分享」。
- 員工下載**自己的檔案**不受這些規則影響。

分享期限上限、預設期限與各種大小上限只在**建立**時檢查，不會回頭影響既有分享。

### 外部 IP 清單

「允許外部使用者連線的網路」只限制**外部使用者**：分享收件人、上傳請求的上傳者、廠商（包含廠商登入與邀請啟用頁面）。員工與管理員不受影響。清單留空代表不限制。來源 IP 取決於 `SX_TRUSTED_PROXIES`（見[設定參考](#4-設定參考)），反向代理設定錯誤時可能把所有人都判成同一個 IP。被擋下的外部使用者會看到「您目前的網路位置不允許存取此分享」。請先確認自己的網路不會被誤擋再儲存；管理員本身不受此清單限制，不會因此被鎖在外面。

### 外部上傳限制

「允許的上傳副檔名」與「外部上傳大小上限」套用在上傳請求的上傳者與廠商上傳。若上傳請求本身也有自己的副檔名或大小限制，兩者取**較嚴格者**。被擋下時上傳者會看到「不允許此檔案類型」或「檔案過大」。

### 儲存配額

配額以每位員工計算，**包含外部人員上傳給他的檔案**（上傳請求與廠商上傳）；已刪除（軟刪除）的檔案不計入。超過時員工上傳會顯示「儲存空間已滿」，外部人員上傳給該員工時則顯示「收件人的儲存空間已滿」。

### 自動清除（保存天數）

保存天數大於 0 時，系統每小時掃描一次，刪除符合下列條件的檔案：

- 檔案曾放入分享，或是透過上傳請求收到的；
- 且**所有**引用它的分享與上傳請求都已結束（過期或撤銷）超過 N 天。

從未分享過的檔案，以及廠商直接上傳、從未被分享過的檔案，**不會**被清除。清除會寫入稽核紀錄 `file.retention_delete`（`actor_type` 為 `system`）。清除後無法復原，調低保存天數前請先確認備份。

### 收緊規則的通知信

收緊「禁止下載」「一律加浮水印」或網域規則時，每位受影響分享的擁有者會收到**一封**摘要信，列出受影響的分享。管理員儲存後，規則頁會顯示受影響的分享數量。

### 稽核與環境變數

- 每次儲存都會寫入稽核紀錄 `rules.update`，`detail` 內含修改前與修改後的完整規則。
- `SX_SHARE_MAX_DAYS` 現在**只用來設定第一次啟動時的初始值**，之後以規則頁為準，修改環境變數不會有作用。若啟動時發現它與資料庫中的值不同，會記一筆警告 log。
- `SX_MAX_FILE_SIZE` 仍是硬上限，規則頁的「單檔大小上限」只能更低。

## 8. 溯源查詢（追查外流）

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

## 9. 病毒掃描（ClamAV）

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

## 10. 線上預覽 worker

worker 會用 LibreOffice、poppler 與 FFmpeg 處理不受信任的檔案，因此被嚴格隔離：

- 沒有對外網路，只能連到資料庫與內部服務。
- 根檔案系統唯讀；解密後的檔案只放在 `/work` 的 tmpfs（4 GiB），每個工作結束就刪除。
- 不使用 swap（`memswap_limit` 等於 `mem_limit`），解密資料不會被換出到磁碟。`/work` 不是 tmpfs 時 worker 會拒絕啟動。
- 記憶體 6 GiB（含 4 GiB tmpfs）、2 顆 CPU、512 個 process，移除所有 capabilities，以非 root 使用者執行，每個外部程式都有逾時。

**容量規則**：必須維持「最大預覽輸入 + 產出 ≤ `/work` 大小（4 GiB）< `mem_limit`（6 GiB）」。調高預覽上限時，請一併調高 `docker-compose.yml` 中 worker 的 tmpfs 大小與 `mem_limit`。把 `/work` 寫滿的工作會被標為「檔案過大無法預覽」。

影片浮水印使用的 TTF 字型可用 `SX_FONT_FILE` 指定（預設 DejaVu Sans）。

## 11. 稽核紀錄

所有安全相關事件都寫入資料庫的 `audit_log` 表。這張表**只能新增、不能修改或刪除**（資料庫規則擋下），每筆紀錄還包含前一筆的雜湊值，形成雜湊鏈，任何竄改都會讓鏈斷掉。

### 在網頁上查詢

管理員登入後，點上方導覽的「稽核紀錄」（`/admin/audit`）。可用下列條件篩選，按「篩選」後分頁瀏覽：

- **起始時間**、**結束時間**：查詢的時間範圍。
- **操作者**：輸入 email 或使用者 id。
- **動作**：以前綴比對，例如輸入 `share.` 列出所有分享相關事件，輸入 `auth.login.fail` 找登入失敗。
- **對象**：輸入對象 id。若輸入的是**分享 id**，結果也會一併列出該分享底下的檔案檢視與下載紀錄。

例如查「過去一天的登入失敗」：起始時間設為一天前，動作填 `auth.login.fail`。

### 匯出 CSV

按「匯出 CSV」會依目前的篩選條件下載。檔案為 UTF-8 並帶 BOM（Excel 可直接開啟中文），依 id 由小到大排列。為避免在試算表中被當成公式執行，開頭為 `=`、`+`、`-`、`@`、Tab 或換行字元（CR）的儲存格，內容前會加上一個 `'`；若要還原原始值，請去掉最前面的 `'`。

### 驗證雜湊鏈

按「驗證雜湊鏈」會重新計算整條鏈。結果會顯示已檢查的筆數；若有被竄改或遺失的紀錄，則顯示第一筆斷鏈的 id。

**匯出與驗證本身也會寫入稽核紀錄**（`audit.export`、`audit.verify`）。

常見的事件類型：

| 類別 | 事件 |
|---|---|
| 登入 | `auth.login.ok`、`auth.login.fail`、`auth.logout`、`auth.totp.enable` |
| 檔案 | `file.upload`、`file.download`、`file.view`、`file.delete`、`file.scan` |
| 分享 | `share.create`、`share.revoke`、`share.recipient.add`、`share.recipient.revoke`、`share.otp.request`、`share.otp.verify` |
| 上傳請求 | `request.create`、`request.revoke`、`request.otp.request`、`request.otp.verify` |
| 使用者 | `user.create`、`user.activate`、`user.disable`、`user.enable`、`user.role`、`user.totp_reset`、`user.reinvite` |
| 廠商 | `vendor.create`、`vendor.approve`、`vendor.reject`、`vendor.disable`、`vendor.enable`、`vendor.expiry`、`vendor.reinvite`、`vendor.activate` |
| 溯源與稽核 | `trace.lookup`、`audit.export`、`audit.verify` |
| 強制規則 | `rules.update`（含修改前後的規則）、`file.retention_delete`（自動清除，`actor_type` 為 `system`） |

`actor_type` 表示操作者類型：`user`（員工、管理員）、`vendor`、`recipient`（分享收件人，廠商檢視分享時也記為此類）、`uploader`（上傳請求的上傳者）、`system`（系統自動作業，例如病毒掃描）。

### 11.1 轉送到 SIEM（syslog）

可把稽核紀錄即時轉送到 Splunk、ELK 等 SIEM，作為資料庫以外的獨立備份。

| 變數 | 預設 | 說明 |
|---|---|---|
| `SX_SYSLOG_ADDR` | 空（關閉） | SIEM 位址，格式 `host:port`，例如 `siem.example.com:6514` |
| `SX_SYSLOG_TRANSPORT` | `tls` | `udp`、`tcp` 或 `tls` |
| `SX_SYSLOG_CA` | 空 | 僅 `tls` 使用：驗證 SIEM 憑證的 CA（PEM 檔路徑）；未設定則使用系統根憑證 |

設定後重新啟動即生效。

**格式**：RFC 5424 syslog。facility 為 13（log audit）；`result` 為 `ok` 的事件 severity 為 6（info），其他結果為 4（warning），因此 PRI 分別是 `<110>` 與 `<108>`。APP-NAME 為 `secure-exchange`，MSGID 為動作名稱（例如 `share.create`），訊息本文為該筆稽核紀錄的 JSON：`id`、`at`、`actor_type`、`actor_id`、`ip`、`user_agent`、`action`、`target_type`、`target_id`、`result`、`detail`、`prev_hash`、`hash`（雜湊為十六進位字串）。TCP 與 TLS 採用 octet-counting 分框（RFC 6587）；UDP 則每筆紀錄一個封包。

**SIEM 端設定**：Splunk 可建立 TCP（或 SSL）資料輸入並指定 sourcetype 為 `syslog`；ELK 可用 Logstash 的 `syslog` 或 `tcp` input 搭配 TLS，再以 `json` filter 解析本文。請確認輸入端接受 octet-counting 分框（RFC 6587）。若該 SIEM 只支援換行分框，請在前面放一個支援 octet-counting 的 syslog 收集器（例如 rsyslog 或 syslog-ng）。

**行為與限制**：

- 每 2 秒檢查一次，每批最多 500 筆；失敗時每 10 秒重試。進度記在資料庫，服務重啟或 SIEM 中斷後會從上次位置接續。有多個執行個體時，只有一個負責轉送。
- **第一次啟用時會從第 1 筆開始送出全部歷史紀錄**，筆數多時請先確認 SIEM 容量。
- 傳送為**至少一次**（at-least-once）：在送出與記錄進度之間當機，或 SIEM 在寫入途中中斷，極少數情況下可能重送或遺失最多一批（500 筆）。SIEM 端請以 `id` 去重。
- UDP 無法確認送達，可能靜默丟失；正式環境建議使用 `tls`。
- 使用 UDP 時，單筆稽核紀錄超過約 64 KB 就無法送出，轉送會卡在該筆並出現警示；有此疑慮請改用 TCP 或 `tls`。
- 轉送持續失敗超過 15 分鐘時，管理介面頂端會出現警示橫幅。

## 12. 電子郵件

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

## 13. 備份與還原

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

## 14. 主金鑰輪替

定期或懷疑金鑰外洩時，換成新的主金鑰：

1. 產生新金鑰：`openssl rand -base64 32`。
2. 在 `SX_MASTER_KEYS` 加入新金鑰，與舊金鑰並列（`1:<舊>,2:<新>`），並設 `SX_ACTIVE_KEY_ID=2`。
3. **先**讓所有 app 與 worker 改用新金鑰：`docker compose up -d`。
4. 在 app 容器內執行輪替，重複執行直到回報 `rotated 0 values`：
   ```sh
   docker compose exec app /secure-exchange rotate-keys
   ```
5. 確認下載正常後，才從 `SX_MASTER_KEYS` 移除舊金鑰並重啟。移除前請保留舊金鑰的備份。

## 15. 升級

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

> 升級到 7.3 時，遷移 0009 會為稽核紀錄建立索引：大型安裝首次啟動可能需要數分鐘，期間需寫入稽核的操作會等待。請以單一實例升級。

> 升級到 7.4 時，遷移 0010 會把 email 的唯一索引改為「每個來源各自唯一」（本機與網域帳號可各有相同 email，但永遠不合併），並在 sessions 加上 `checked_at` 欄位。需要新的設定請見[網域帳號（LDAP/AD）](#網域帳號ldapad)。

## 16. 監控與疑難排解

### 健康檢查

- `https://<SX_DOMAIN>/healthz` 回傳 `ok` 表示 app 正常。
- `docker compose ps` 查看各服務狀態；`docker compose logs -f <服務>` 查看即時記錄。

### 常見問題

| 症狀 | 可能原因與處理 |
|---|---|
| 系統無法啟動，記錄提到 SMTP | 未設定 `SX_SMTP_HOST` 或 `SX_SMTP_FROM`。 |
| 沒有人能登入，記錄出現 `nobody can log in` | 首次啟動時沒有設定 `SX_INIT_ADMIN_EMAIL`／`SX_INIT_ADMIN_PASSWORD`。設定後重啟即可建立管理員。 |
| 無法取得 TLS 憑證 | 網域未指向本主機，或 80/443 埠被防火牆擋住。 |
| 收件人收不到邀請信或驗證碼 | 見[電子郵件](#12-電子郵件)檢查佇列；確認 SPF／DKIM；請收件人查看垃圾郵件。 |
| 外部上傳一直「掃描中」 | clamav 還在下載病毒碼，或 clamav 容器記憶體不足。查看 `docker compose logs clamav`。 |
| 預覽一直「處理中」 | 查看 `docker compose logs worker`；確認 worker 在執行且有足夠記憶體。 |
| 預覽顯示「檔案過大無法預覽」 | 超過預覽上限或寫滿 `/work`，見[線上預覽 worker](#10-線上預覽-worker)。 |
| 下載出現「檔案準備中，請稍後再試」 | 加浮水印的版本需要預覽完成，等預覽完成即可。 |
| worker 拒絕啟動，提到 tmpfs | `/work` 不是 tmpfs。請使用專案附的 `docker-compose.yml`。 |
| 檔案無法解密 | `SX_MASTER_KEYS` 與備份時不同，或移除了仍在使用的舊金鑰。 |
| 使用者被「嘗試次數過多」擋下 | 登入與驗證碼有每 IP 速率限制，稍等幾分鐘即會解除。 |

## 17. 安全建議清單

- [ ] `.env`（含主金鑰）已另存於伺服器以外的安全位置。
- [ ] 管理員帳號已啟用雙因素驗證（或在規則頁開啟全站強制雙因素驗證）。
- [ ] 首次啟動後已移除 `SX_INIT_ADMIN_PASSWORD`。
- [ ] 每日備份資料庫與檔案資料，並演練過還原。
- [ ] 寄件網域已設定 SPF、DKIM、DMARC。
- [ ] 主機只開放 80 與 443 埠，作業系統與 Docker 保持更新。
- [ ] 依公司政策決定 `SX_VENDOR_CREATION`（預設需管理員核准）。
- [ ] 若公司要求所有外流檔案都必須可追蹤，將 `SX_UNMARKABLE_POLICY` 設為 `block`。
- [ ] 到「規則」頁依公司政策設定禁止下載／浮水印、分享期限、儲存配額與保存天數；若有固定的合作網段，可設定外部 IP 清單。
- [ ] 定期以 `git pull` 與 `docker compose up -d --build` 更新，以取得安全修正。
- [ ] 發現安全問題請依 [SECURITY.md](../SECURITY.md) 私下回報。
