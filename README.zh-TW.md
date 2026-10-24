# secure-exchange

[English](README.md) | 繁體中文

自架的安全檔案交換系統，開源（AGPL-3.0）。單一 Go 執行檔（內嵌網頁介面）、以 PostgreSQL 存放中繼資料、檔案內容存放於本機磁碟或 S3 相容儲存。

## 功能（第一至二階段）

- 支援超大檔案的可續傳上傳（tus）；檔案在寫入磁碟或 S3 之前一律先加密（AES-256-GCM，每個檔案一把金鑰，再由主金鑰包裝）。
- argon2id 密碼登入、可選的 TOTP 雙因素驗證、速率限制、雜湊鏈稽核紀錄。
- 網頁介面支援繁體中文與英文。
- `rotate-keys` 子命令，可將已存資料換到新的主金鑰。
- 一次性分享：將檔案分享給指定收件人，每位收件人以 email 一次性驗證碼驗證；支援期限、檢視次數、IP 限制、撤銷與通知。

## 快速部署

需要 Docker（含 Compose），以及指向本主機的網域名稱（開放 80/443 埠）。Caddy 會自動申請 TLS 憑證。

```sh
cp .env.example .env
# 編輯 .env：SX_DOMAIN、POSTGRES_PASSWORD、SX_MASTER_KEYS、初始管理員
openssl rand -base64 32      # 輸出值填入 SX_MASTER_KEYS=1:<金鑰>
docker compose up -d
```

開啟 `https://<SX_DOMAIN>`，以 `SX_INIT_ADMIN_EMAIL` / `SX_INIT_ADMIN_PASSWORD` 登入。本機試用可設 `SX_DOMAIN=localhost`（使用 Caddy 本機 CA，`curl` 請加 `-k`）。`scripts/smoke.sh` 會在用完即丟的環境做上傳／續傳／下載／分享的端對端檢查（需 Docker；已有 `.env` 時拒絕執行）。

所有設定皆為環境變數；每個 `SX_*` 設定都在 `.env.example` 中說明。

## 電子郵件（SMTP）

分享邀請、驗證碼與通知都以電子郵件寄出，因此 SMTP 設定為**必填**（未設定 `SX_SMTP_HOST` 與 `SX_SMTP_FROM` 時程式無法啟動）。一般郵件中繼的 `.env` 範例：

```sh
SX_SMTP_HOST=smtp.example.com
SX_SMTP_PORT=587
SX_SMTP_USERNAME=apikey-or-user
SX_SMTP_PASSWORD=secret
SX_SMTP_FROM="Secure Exchange <noreply@example.com>"
SX_SMTP_TLS=starttls        # starttls（預設）、tls（隱式 TLS，通常為 465 埠）或 none
```

`SX_SMTP_TLS=none` 會以未加密方式寄信，只接受 `localhost`、`127.0.0.1` 與 `mailpit`，僅供本機測試。`SX_SHARE_MAX_DAYS`（預設 30）為分享期限的上限天數。

## 一次性分享

1. 在「分享」頁選擇檔案、輸入收件人的 email（最多 50 位），設定是否允許下載、期限（1 小時至 `SX_SHARE_MAX_DAYS`，預設 7 天），並可選填檢視次數上限、IP 限制與簡短附言。
2. 每位收件人會收到邀請信，內含分享連結 `https://<SX_DOMAIN>/s/<token>`。沒有密碼，也沒有免驗證連結：連結必須搭配一次性驗證碼才能使用。
3. 收件人開啟連結、輸入自己的 email 後，會收到 6 位數驗證碼（10 分鐘有效、僅能使用一次、最多嘗試 5 次）。驗證通過後可在 1 小時內檢視檔案。不在名單內的 email 會得到完全相同的回應，無法藉此探測名單。
4. 檢視次數上限計算的是驗證碼成功驗證的次數。每次請求都會重新檢查 IP 限制與撤銷狀態。
5. 可隨時撤銷整個分享或單一收件人，已開啟的連線會立即失效。也可對既有分享追加收件人（對方會收到自己的邀請信）。
6. 收件人通過驗證、以及下載檔案時，你會收到通知信。每個步驟都記錄於稽核紀錄。

目前限制：設為「僅線上檢視」的分享只會列出檔案，尚無內容可看（線上檢視功能尚未提供），下載按鈕與下載 API 對其停用。

本機開發時，`docker-compose.dev.yml` 內含 mailpit（SMTP 在 `:51025`，網頁介面在 `http://localhost:58025`）；`scripts/smoke.sh` 會在一個用完即丟的環境跑完整流程。

## 備份

下列各項必須一起備份：

1. 資料庫：`docker compose exec -T postgres pg_dump -U sx sx > sx.sql`
2. `sxdata` volume（加密後的檔案與暫存），或你的 S3 bucket：
   `docker run --rm --volumes-from "$(docker compose ps -aq app)" -v "$PWD:/backup" debian:bookworm-slim tar -C /data -czf /backup/sxdata.tgz .`
3. **`.env` 檔。其中的 `SX_MASTER_KEYS` 存放主金鑰。主金鑰遺失，已儲存的檔案即無法解密。請在伺服器之外另存一份。**

## 還原

還原時必須使用與備份當時**相同的 `SX_MASTER_KEYS` 與 `SX_ACTIVE_KEY_ID`**，否則還原後的檔案無法解密。

1. 把備份的 `.env` 放回 `docker-compose.yml` 旁。
2. 建立容器與空的 volume，只啟動 PostgreSQL，再把備份匯入空的資料庫：
   ```sh
   docker compose create
   docker compose up -d postgres
   docker compose exec -T postgres psql -U sx -d sx -v ON_ERROR_STOP=1 < sx.sql
   ```
3. 還原 `sxdata` volume（或你的 S3 bucket）：
   `docker run --rm --volumes-from "$(docker compose ps -aq app)" -v "$PWD:/backup" debian:bookworm-slim tar -C /data -xzf /backup/sxdata.tgz`
4. 選用：以同樣方式（把 `app` 換成 `caddy`）還原 `caddydata` volume 以保留 TLS 憑證；否則 Caddy 會重新申請。
5. `docker compose up -d`。

## 主金鑰輪替

1. 產生新金鑰：`openssl rand -base64 32`。
2. 把新金鑰加到 `SX_MASTER_KEYS`，與舊金鑰並列（`1:<舊>,2:<新>`），並設 `SX_ACTIVE_KEY_ID=2`。
3. 在進行下一步**之前**，先把**所有**應用程式實例重啟到新的使用中金鑰（`docker compose up -d`），避免仍有實例以舊金鑰寫入。
4. 執行 `docker compose exec app /secure-exchange rotate-keys`。重複執行，直到回報 `rotated 0 values`。
5. 這時才從 `SX_MASTER_KEYS` 移除舊金鑰並重啟。確認下載仍正常之前，請保留舊金鑰備份。

## 開發環境

```sh
docker compose -f docker-compose.dev.yml up -d     # postgres :55432、minio :59000、mailpit :51025（介面 :58025）
export SX_TEST_DATABASE_URL='postgres://sx:sx@localhost:55432/sx?sslmode=disable'
export SX_TEST_S3_ENDPOINT=localhost:59000          # 選用；未設定時 S3 測試會跳過
(cd web && npm ci && npm run build)                 # Go 執行檔會內嵌 internal/webui/dist
go vet ./... && go test ./...
```

未設定 `SX_TEST_DATABASE_URL` 時，資料庫測試會跳過。CI 以 `-race` 執行全部測試。

## 授權

[AGPL-3.0](LICENSE)
