# secure-exchange

[![CI](https://github.com/tntrock/secure-exchange/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/tntrock/secure-exchange/actions/workflows/ci.yml)
[![CodeQL](https://github.com/tntrock/secure-exchange/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/tntrock/secure-exchange/security/code-scanning)
[![codecov](https://codecov.io/gh/tntrock/secure-exchange/graph/badge.svg)](https://codecov.io/gh/tntrock/secure-exchange)
[![Go version](https://img.shields.io/github/go-mod/go-version/tntrock/secure-exchange?logo=go)](go.mod)
[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=white)](web/package.json)
[![License: AGPL-3.0](https://img.shields.io/github/license/tntrock/secure-exchange)](LICENSE)

[English](README.md) | 繁體中文

自架的安全檔案交換系統，開源（AGPL-3.0）。單一 Go 執行檔（內嵌網頁介面）、以 PostgreSQL 存放中繼資料、檔案內容存放於本機磁碟或 S3 相容儲存。

## 功能（第一至三階段）

- 支援超大檔案的可續傳上傳（tus）；檔案在寫入磁碟或 S3 之前一律先加密（AES-256-GCM，每個檔案一把金鑰，再由主金鑰包裝）。
- argon2id 密碼登入、可選的 TOTP 雙因素驗證、速率限制、雜湊鏈稽核紀錄。
- 網頁介面支援繁體中文與英文。
- `rotate-keys` 子命令，可將已存資料換到新的主金鑰。
- 一次性分享：將檔案分享給指定收件人，每位收件人以 email 一次性驗證碼驗證；支援期限、檢視次數、IP 限制、撤銷與通知。
- 線上檢視：文件、圖片與影片以伺服器端產生的頁面圖片與影片片段呈現，可依收件人加上浮水印；轉檔在隔離的 worker 容器中進行。

## 快速部署

需要 Docker（含 Compose），以及指向本主機的網域名稱（開放 80/443 埠）。Caddy 會自動申請 TLS 憑證。

```sh
cp .env.example .env
# 編輯 .env：SX_DOMAIN、POSTGRES_PASSWORD、SX_MASTER_KEYS、初始管理員
openssl rand -base64 32      # 輸出值填入 SX_MASTER_KEYS=1:<金鑰>
docker compose up -d
```

開啟 `https://<SX_DOMAIN>`，以 `SX_INIT_ADMIN_EMAIL` / `SX_INIT_ADMIN_PASSWORD` 登入。本機試用可設 `SX_DOMAIN=localhost`（使用 Caddy 本機 CA，`curl` 請加 `-k`）。`scripts/smoke.sh` 會在用完即丟的環境做上傳／續傳／下載／分享／線上檢視的端對端檢查（需 Docker；已有 `.env` 時拒絕執行）。

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
6. 每位收件人第一次開啟分享（通過驗證）、以及第一次下載每個檔案時，你會收到通知信；之後的開啟與下載不再寄信。每個步驟都記錄於稽核紀錄。

設為「僅線上檢視」的分享，收件人以線上檢視（見下節）觀看檔案；下載按鈕與下載 API 對其停用。

本機開發時，`docker-compose.dev.yml` 內含 mailpit（SMTP 在 `:51025`，網頁介面在 `http://localhost:58025`）；`scripts/smoke.sh` 會在一個用完即丟的環境跑完整流程。

## 線上檢視

檔案可直接在瀏覽器中檢視，不必下載。瀏覽器收到的只有伺服器端產生的圖片與影片片段；檢視功能從不送出原始檔、PDF 或 Office 檔。

- **支援格式：** 文件逐頁轉成圖片（PDF、Word／Excel／PowerPoint 與 OpenDocument、RTF、CSV、純文字、Markdown、JSON／XML／YAML、記錄檔與常見原始碼、HTML）；圖片（JPEG、PNG、GIF、WebP、BMP、TIFF）；影片（MP4、MOV、M4V、MKV、WebM、AVI）轉為 H.264／AAC、最高 720p，以 HLS 串流。其他檔案仍可用允許下載的分享傳送。
- **預覽上限**（環境變數，見 `.env.example`）：`SX_PREVIEW_MAX_BYTES`（文件與圖片，預設 1 GiB）、`SX_PREVIEW_MAX_PAGES`（500）、`SX_PREVIEW_MAX_VIDEO_BYTES`（1.5 GiB）、`SX_PREVIEW_MAX_VIDEO_SECONDS`（7200）、`SX_RENDER_DPI`（110）。超過上限的檔案視為無法預覽。**容量規則：** 解密後的輸入檔與所有產出都放在 worker 的 `/work` tmpfs，而 tmpfs 會計入容器記憶體上限，因此須維持「*最大預覽輸入 + 產出 ≤ `/work` 大小（4 GiB）< `mem_limit`（6 GiB）*」，且不使用 swap。調高上限時，請一併調高 `docker-compose.yml` 中的 tmpfs 大小與 `mem_limit`；仍把 `/work` 寫滿的工作會視為無法預覽。
- **僅線上檢視的分享**需要預覽已完成：預覽仍在產生時不能加入該檔案；無法預覽的檔案只能放在允許下載的分享。
- **浮水印：** 分享開啟「浮水印」後，收件人看到的每一頁、每一個影片片段都帶有平鋪、半透明的一行文字：追蹤碼、時間（UTC）、IP 與收件人 email。浮水印於每次請求時繪製，不會快取。檢視自己的檔案時不加浮水印。

預覽由獨立的 **worker** 容器產生（`docker compose up -d` 會一併啟動）。它要以 LibreOffice、poppler 與 FFmpeg 處理不受信任的檔案，因此有以下隔離：

- **無對外網路：** 只接內部網路 `backend`（與 PostgreSQL、app 相連），無法連上網際網路。
- **根檔案系統唯讀；** 解密後的檔案與中間檔只放在 `/work` 的 tmpfs（`SX_WORKER_TMP`，4 GiB），每個工作結束即刪除。產生的頁面與片段在儲存前一律加密。
- **不使用 swap：** `memswap_limit` 等於 `mem_limit`，tmpfs 上的解密資料不會被換出到磁碟。若 `/work` 不是 tmpfs，worker 會拒絕啟動（`SX_WORKER_ALLOW_NON_TMPFS=1` 可略過此檢查，僅限開發使用）。
- **資源上限：** 記憶體 6 GiB（含 4 GiB tmpfs）、2 顆 CPU、512 個 process；移除所有 capabilities、`no-new-privileges`、以 uid 65532 執行。每個外部程式都有逾時。

**外部 S3：** 使用 `SX_STORAGE=s3` 且 S3 位於 compose 之外時，worker 需要能連到它。以 `docker-compose.override.yml` 讓它多接一個網路：

```yaml
services:
  worker:
    networks: [backend, s3]
networks:
  s3: {}
```

這個網路會讓 worker 重新能對外連線，請在防火牆上限制為只能連到 S3 端點。

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
3. 在進行下一步**之前**，先把**所有** app 與 worker 實例重啟到新的使用中金鑰（`docker compose up -d`），避免仍有實例以舊金鑰寫入。
4. 執行 `docker compose exec app /secure-exchange rotate-keys`。此命令會載入完整設定（資料庫、金鑰、SMTP 等），因此請在已有 `.env` 設定的 app 容器內執行，而不是在主機上。重複執行，直到回報 `rotated 0 values`。
5. 這時才從 `SX_MASTER_KEYS` 移除舊金鑰並重啟。確認下載仍正常之前，請保留舊金鑰備份。

## 開發環境

```sh
docker compose -f docker-compose.dev.yml up -d     # postgres :55432、minio :59000、mailpit :51025（介面 :58025）
export SX_TEST_DATABASE_URL='postgres://sx:sx@localhost:55432/sx?sslmode=disable'
export SX_TEST_S3_ENDPOINT=localhost:59000          # 選用；未設定時 S3 測試會跳過
(cd web && npm ci && npm run build)                 # Go 執行檔會內嵌 internal/webui/dist
go vet ./... && go test ./...
docker run --rm -v "$PWD:/app" -w /app golangci/golangci-lint:v2.15.0 golangci-lint run --build-tags tools ./...
```

未設定 `SX_TEST_DATABASE_URL` 時，資料庫測試會跳過。CI 以 `-race` 執行全部測試。

`//go:build tools` 測試（LibreOffice、poppler、FFmpeg）在 worker-test 映像中執行；它加入開發用 compose 網路，以服務名稱連到 PostgreSQL 與 MinIO（原始碼掛載於 `/src`）：

```sh
docker compose -f docker-compose.dev.yml --profile tools run --rm worker-test
```

CI 以獨立的 `tools` job 執行這些測試。

## 安全性

請以私下方式回報弱點，詳見 [SECURITY.md](SECURITY.md)。

## 授權

[AGPL-3.0](LICENSE)
