# secure-exchange

[English](README.md) | 繁體中文

自架的安全檔案交換系統，開源（AGPL-3.0）。單一 Go 執行檔（內嵌網頁介面）、以 PostgreSQL 存放中繼資料、檔案內容存放於本機磁碟或 S3 相容儲存。

## 功能（第一階段）

- 支援超大檔案的可續傳上傳（tus）；檔案在寫入磁碟或 S3 之前一律先加密（AES-256-GCM，每個檔案一把金鑰，再由主金鑰包裝）。
- argon2id 密碼登入、可選的 TOTP 雙因素驗證、速率限制、雜湊鏈稽核紀錄。
- 網頁介面支援繁體中文與英文。
- `rotate-keys` 子命令，可將已存資料換到新的主金鑰。

## 快速部署

需要 Docker（含 Compose），以及指向本主機的網域名稱（開放 80/443 埠）。Caddy 會自動申請 TLS 憑證。

```sh
cp .env.example .env
# 編輯 .env：SX_DOMAIN、POSTGRES_PASSWORD、SX_MASTER_KEYS、初始管理員
openssl rand -base64 32      # 輸出值填入 SX_MASTER_KEYS=1:<金鑰>
docker compose up -d
```

開啟 `https://<SX_DOMAIN>`，以 `SX_INIT_ADMIN_EMAIL` / `SX_INIT_ADMIN_PASSWORD` 登入。本機試用可設 `SX_DOMAIN=localhost`（使用 Caddy 本機 CA，`curl` 請加 `-k`）。`scripts/smoke.sh` 會對運作中的實例做上傳／續傳／下載的端對端檢查。

所有設定皆為環境變數；每個 `SX_*` 設定都在 `.env.example` 中說明。

## 備份

下列三項必須一起備份：

1. 資料庫：`docker compose exec postgres pg_dump -U sx sx > sx.sql`
2. `sxdata` volume（加密後的檔案與暫存），或你的 S3 bucket。
3. **`SX_MASTER_KEYS` 中的主金鑰。主金鑰遺失，已儲存的檔案即無法解密。請在伺服器之外另存一份。**

## 主金鑰輪替

1. 產生新金鑰：`openssl rand -base64 32`。
2. 把新金鑰加到 `SX_MASTER_KEYS`，與舊金鑰並列（`1:<舊>,2:<新>`），並設 `SX_ACTIVE_KEY_ID=2`。
3. 在進行下一步**之前**，先把**所有**應用程式實例重啟到新的使用中金鑰（`docker compose up -d`），避免仍有實例以舊金鑰寫入。
4. 執行 `docker compose exec app /secure-exchange rotate-keys`。重複執行，直到回報 `rotated 0 values`。
5. 這時才從 `SX_MASTER_KEYS` 移除舊金鑰並重啟。確認下載仍正常之前，請保留舊金鑰備份。

## 開發環境

```sh
docker compose -f docker-compose.dev.yml up -d     # postgres 在 :55432，minio 在 :59000
export SX_TEST_DATABASE_URL='postgres://sx:sx@localhost:55432/sx?sslmode=disable'
export SX_TEST_S3_ENDPOINT=localhost:59000          # 選用；未設定時 S3 測試會跳過
(cd web && npm ci && npm run build)                 # Go 執行檔會內嵌 internal/webui/dist
go vet ./... && go test ./...
```

未設定 `SX_TEST_DATABASE_URL` 時，資料庫測試會跳過。CI 以 `-race` 執行全部測試。

## 授權

[AGPL-3.0](LICENSE)
