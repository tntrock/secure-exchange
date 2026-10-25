# 階段 3：線上檢視與伺服器端浮水印 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 上傳的檔案在背景轉成「預覽素材」（PDF/Office/文字 → 逐頁圖片；圖片 → 正規化圖片；影片 → HLS 片段），以加密形式存放。員工可在瀏覽器檢視自己的檔案；收件人在「僅能線上檢視」或「允許下載」的分享中都能線上檢視，畫面上的浮水印（收件人 email、IP、時間、追蹤碼）在伺服器端直接畫進像素或燒進影片。原始檔不送到瀏覽器。無法預覽的檔案不能用「僅能線上檢視」分享。

**Architecture:** 新增 `secure-exchange worker` 子命令，跑在獨立容器（含 LibreOffice、poppler、FFmpeg、CJK 字型；唯讀根目錄、tmpfs 工作目錄、無對外網路、資源上限），從 PostgreSQL 工作佇列取件。轉檔產物以既有的分塊加密（每個產物一把 DEK）寫入 blob store。App 端（同一份程式碼，映像改為 debian-slim + FFmpeg）讀取無浮水印的底圖，每次請求即時畫上浮水印再送出；影片片段每次請求以 FFmpeg 透過 pipe 即時燒入。

**Tech Stack:** 沿用階段 1–2。新增：`golang.org/x/image`（webp/bmp/tiff 解碼、draw、opentype、gofont）；worker 映像中的 `libreoffice`（headless）、`poppler-utils`（pdftoppm）、`ffmpeg`、`fonts-noto-cjk`；前端 `hls.js`。

**Spec:** `docs/superpowers/specs/2026-10-24-secure-exchange-design.md`（§4 第 4、5 點、§5.4、§6 轉檔隔離、§6.1 預覽上限）

## Global Constraints

- **送到瀏覽器的只有伺服器端產生的圖片或轉碼後的影片片段**；原始檔、PDF、Office 檔不經由檢視 API 送出。
- **明文不得落地**：worker 解密後的原始檔與所有中間檔只能放在 tmpfs 工作目錄（`SX_WORKER_TMP`，容器內 `/work`，以 tmpfs 掛載）；每個工作有獨立子目錄，結束（含失敗、逾時、panic）一律刪除。產物寫入 blob store 前一律加密。
- 產物加密：每個產物（一頁圖片、一個影片片段）一把新 DEK，以 `sxcrypto.SealChunk` 分塊加密，AAD 的 fileID 用**產物自己的 id**；DEK 由主金鑰包裝，金鑰輪替要涵蓋 `preview_items.wrapped_dek`。
- 預覽上限（環境變數，之後階段 7 改由管理介面設定）：`SX_PREVIEW_MAX_BYTES`（文件與圖片，預設 2 GiB）、`SX_PREVIEW_MAX_PAGES`（預設 500）、`SX_PREVIEW_MAX_VIDEO_BYTES`（預設 20 GiB）、`SX_PREVIEW_MAX_VIDEO_SECONDS`（預設 7200）、`SX_RENDER_DPI`（預設 110）。超過上限 → 狀態 `too_large`，視為無法預覽。
- 每個外部程式都有逾時：LibreOffice 轉 PDF 180 秒、pdftoppm 整份 300 秒、FFmpeg 轉 HLS = `max(600, 3 × 影片秒數)` 秒。逾時殺掉整個 process group。外部程式以空白環境變數（只留 `PATH`、`HOME=<工作目錄>`）執行。
- 圖片產物：PNG，最長邊 ≤ 2000 px（文件頁以 DPI 決定，再縮到這個上限）；圖片檔正規化後最長邊 ≤ 4096 px。
- 影片產物：H.264 + AAC，高度 ≤ 720，HLS 片段 6 秒（`mpegts`）。
- **浮水印**：分享 `watermark=true` 時，收件人取得的每一張頁面圖、每一個影片片段都必須帶浮水印；內容一行：`<收件人 email> · <IP> · <YYYY-MM-DD HH:MM UTC> · <追蹤碼>`，半透明（alpha ≈ 0.18）、斜向 30°、平鋪整個畫面。`watermark=false` 時不畫、不產生追蹤碼。員工檢視自己的檔案不加浮水印。
- 追蹤碼：10 字元 Crockford base32（`crypto/rand`），每個 (收件人 session, 檔案) 一組，記錄於 `view_traces`（階段 4 的溯源會查它）。
- **快取只存無浮水印的底圖**（就是 blob store 裡的加密產物）；不快取帶浮水印的圖片或片段。
- 檢視 API 的回應：`Cache-Control: private, no-store`、`Content-Disposition: inline`、`X-Content-Type-Options: nosniff`；頁面圖一律輸出 JPEG（quality 85）。
- 「僅能線上檢視」分享中的檔案，預覽狀態必須是 `ready`；`pending` → 422 `preview_pending`；`failed`／`unsupported`／`too_large` → 422 `not_previewable`。「允許下載」的分享不受此限制（無法預覽的檔案仍可下載）。
- 與先前階段相同：介面字串一律經 i18n；稽核只增不改、寫稽核用 `context.WithoutCancel`；client 字串寫入 DB／稽核前截斷；in-process 鎖與限流為單機（ponytail 註解）。

## Review Focus

1. **惡意或損壞的文件**（LibreOffice 卡住、壓縮炸彈、上萬頁 PDF、假副檔名）→ 逾時被殺、頁數上限截斷為 `too_large`，worker 繼續處理下一件（Task 4 `TestRunKillsOnTimeout`、`TestPDFPageCap`、`TestMislabeledFile`）。
2. **工作目錄在失敗與 panic 後也被清掉**，且不在 tmpfs 以外寫任何明文（Task 4 `TestWorkDirRemovedOnFailure`）。
3. **收件人要求不存在的頁碼、不屬於分享的檔案、或沒有 session** → 404／401，不洩漏檔案是否存在（Task 7 `TestRecipientPageBounds`）。
4. **浮水印開關**：`true` 時每張頁面圖都和底圖不同且尺寸相同；`false` 時與底圖解碼後完全相同、不產生追蹤碼（Task 7 `TestRecipientWatermarkToggle`）。
5. **worker 在工作途中當機** → 租約到期後重新排入、最多嘗試 3 次後標記 `failed`（Task 2 `TestLeaseExpiryRequeues`）。

---

## File Structure

```
internal/db/migrations/0003_previews.sql   file_previews、preview_items、render_jobs、view_traces
internal/config/config.go                  + 預覽上限、worker 設定
internal/sxcrypto/rotate.go                DEK 表清單共用化 + preview_items
internal/preview/classify.go               依副檔名與內容判斷預覽類型
internal/preview/jobs.go                   工作佇列（enqueue、claim、租約、完成、失敗）、預覽狀態
internal/preview/items.go                  產物的加密寫入與解密讀取
internal/preview/sandbox.go                外部程式執行（逾時、process group、乾淨環境、工作目錄）
internal/preview/worker.go                 worker 迴圈與各類型 pipeline 調度
internal/preview/pipeline_doc.go           文件／文字 → PDF → 頁面圖
internal/preview/pipeline_image.go         圖片正規化
internal/preview/pipeline_video.go         影片 → HLS 片段
internal/preview/watermark.go              浮水印繪製、追蹤碼
internal/httpapi/preview_handlers.go       員工端與收件人端檢視 API
internal/httpapi/segment.go                影片片段即時燒入（FFmpeg pipe）
web/src/components/Viewer.tsx              頁面檢視器 + 影片播放器
Dockerfile                                 app 映像改 debian-slim + ffmpeg；新增 worker、worker-test stage
docker-compose.yml / docker-compose.dev.yml / .github/workflows/ci.yml / README*
```

---

### Task 1: 設定、schema、金鑰輪替涵蓋

**Files:**
- Modify: `internal/config/config.go`, `internal/config/config_test.go`, `internal/sxcrypto/rotate.go`, `internal/sxcrypto/rotate_test.go`
- Create: `internal/db/migrations/0003_previews.sql`
- Test: `internal/db/db_test.go`（加 case）

**Interfaces:**
- Produces（`Config` 新欄位）：`Preview PreviewConfig{MaxBytes int64 (2<<30); MaxPages int (500); MaxVideoBytes int64 (20<<30); MaxVideoSeconds int (7200); DPI int (110)}`、`WorkerTmp string`（`SX_WORKER_TMP`，預設 `/work`）。數值必須為正，否則 error。
- `rotate.go`：把 `[]string{"uploads", "files"}`（rotatePass 與 residual 兩處）改成一個共用的 `dekTables` 清單並加入 `preview_items`；residual 的訊息包含每張表的計數。
- Schema：

```sql
CREATE TABLE file_previews (
  file_id uuid PRIMARY KEY REFERENCES files ON DELETE CASCADE,
  kind text NOT NULL CHECK (kind IN ('pages','image','video','none')),
  status text NOT NULL CHECK (status IN ('pending','ready','failed','unsupported','too_large')),
  page_count int NOT NULL DEFAULT 0, width int NOT NULL DEFAULT 0, height int NOT NULL DEFAULT 0,
  duration_ms bigint NOT NULL DEFAULT 0, error text NOT NULL DEFAULT '',
  updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE preview_items (
  id uuid PRIMARY KEY, file_id uuid NOT NULL REFERENCES files ON DELETE CASCADE,
  kind text NOT NULL CHECK (kind IN ('page','image','segment')), idx int NOT NULL,
  storage_key text NOT NULL, size bigint NOT NULL, wrapped_dek bytea NOT NULL, key_id int NOT NULL,
  width int NOT NULL DEFAULT 0, height int NOT NULL DEFAULT 0, duration_ms bigint NOT NULL DEFAULT 0,
  UNIQUE (file_id, kind, idx));
CREATE TABLE render_jobs (
  id uuid PRIMARY KEY, file_id uuid NOT NULL UNIQUE REFERENCES files ON DELETE CASCADE,
  status text NOT NULL CHECK (status IN ('queued','running','done','failed')),
  attempts int NOT NULL DEFAULT 0, lease_until timestamptz, error text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX render_jobs_ready ON render_jobs (created_at) WHERE status = 'queued';
CREATE TABLE view_traces (
  code text PRIMARY KEY, file_id uuid NOT NULL REFERENCES files,
  share_id uuid REFERENCES shares, recipient_id uuid REFERENCES share_recipients,
  session_hash bytea, ip text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (session_hash, file_id));
```

- [ ] **Step 1: 寫失敗測試** `TestLoadPreviewDefaults`（只給必填 → 上述預設值、`WorkerTmp=/work`）、`TestLoadPreviewInvalid`（`SX_PREVIEW_MAX_PAGES=0`、`SX_RENDER_DPI=abc` → error 含變數名）、`TestMigration0003Applies`、`TestRotateCoversPreviewItems`（preview_items 列以 key1 包裝 → RotateAll 後 key_id=2 且以只含 key2 的 keyring 可解包）。
- [ ] **Step 2:** FAIL
- [ ] **Step 3: 實作**
- [ ] **Step 4:** `go test ./internal/config/ ./internal/db/... ./internal/sxcrypto/` → PASS
- [ ] **Step 5: Commit** `feat: preview config, schema, rotation coverage`

---

### Task 2: 類型判斷、預覽狀態與工作佇列

**Files:**
- Create: `internal/preview/classify.go`, `internal/preview/jobs.go`
- Modify: `internal/upload/tus.go`（finish 的 transaction 內呼叫 `preview.Enqueue`）、`cmd/secure-exchange/main.go`（`serve` 啟動時 `preview.Backfill`）
- Test: `internal/preview/classify_test.go`, `internal/preview/jobs_test.go`, `internal/upload/tus_test.go`（加 case）

**Interfaces:**
- Produces:
  - `type Kind string`：`KindPages = "pages"`、`KindImage = "image"`、`KindVideo = "video"`、`KindNone = "none"`
  - `Classify(name string, head []byte, size int64, cfg config.PreviewConfig) (Kind, Status)`：`head` 是檔案前 512 bytes（解密後）。規則：
    - pages：副檔名 `.pdf .doc .docx .odt .rtf .xls .xlsx .ods .csv .ppt .pptx .odp .txt .md .log .json .xml .yaml .yml .go .py .js .ts .java .c .cpp .h .cs .sh .sql .html .css`；`.pdf` 還要 `head` 以 `%PDF-` 開頭，不符 → `none/unsupported`。
    - image：`http.DetectContentType(head)` 為 `image/jpeg|png|gif|webp|bmp`，或副檔名 `.tif .tiff` 且 head 為 TIFF magic（`II*\0`／`MM\0*`）。
    - video：副檔名 `.mp4 .mov .m4v .mkv .webm .avi`。
    - 其他 → `none/unsupported`。
    - 大小：pages／image 超過 `MaxBytes` → `too_large`；video 超過 `MaxVideoBytes` → `too_large`；否則 `pending`。
  - `type Status string`：`pending ready failed unsupported too_large`
  - `Enqueue(ctx, q mail.Querier, fileID uuid.UUID, kind Kind, status Status) error`：寫 `file_previews`；`status=pending` 時另寫 `render_jobs(status queued)`。（重用 `mail.Querier` 型別或在 preview 定義同形的 interface；不要讓 preview import mail 只為了型別 — 在 preview 自己定義 `Querier`。）
  - `Backfill(ctx, pool, store, keys, cfg) (int, error)`：對沒有 `file_previews` 列、未刪除的檔案，讀取解密後前 512 bytes 分類並 Enqueue（階段 1–2 已上傳的檔案）。
  - `Claim(ctx, pool, lease time.Duration) (*Job, error)`：一個 transaction 內 `SELECT ... FOR UPDATE SKIP LOCKED`，對象為 `status='queued'` 或 `status='running' AND lease_until < now()`（租約過期）；設 `running`、`attempts+1`、`lease_until = now()+lease`；無工作回 `nil, nil`。`attempts` 已達 3 的過期工作直接標 `failed`（`file_previews.status=failed`, error `"too many attempts"`）不交出。
  - `type Job struct{ ID, FileID uuid.UUID; Attempts int }`
  - `Renew(ctx, pool, jobID, lease)`、`Complete(ctx, pool, jobID, fileID, r Result)`（一個 transaction：寫 `file_previews` 為 `ready`（含 page_count/width/height/duration_ms）、`render_jobs` 為 `done`）、`Fail(ctx, pool, jobID, fileID, status Status, msg string)`（`failed` 或 `too_large`；error 截 500 字元、去除 NUL、合法 UTF-8）。
  - `type Result struct{ Kind Kind; PageCount, Width, Height int; DurationMs int64 }`
  - `GetStatus(ctx, q, fileID) (*Preview, error)`；`type Preview struct{ Kind Kind; Status Status; PageCount, Width, Height int; DurationMs int64 }`；沒有列 → `ErrNoPreview`。
- `upload.finish`：在插入 files 列的同一個 transaction 中，從加密暫存檔讀回第 0 個區塊並以 `sxcrypto.OpenChunk` 解密（只在記憶體），取前 512 bytes 呼叫 `Classify` + `Enqueue`（上傳可能跨多次 PATCH 或伺服器重啟，所以不能依賴記憶體中保留的首段）。0-byte 檔案 → `none/unsupported`。
- [ ] **Step 1: 寫失敗測試**
  - `TestClassify`：表格式：`a.pdf`+`%PDF-1.7` → pages/pending；`a.pdf`+`MZ` → none/unsupported；`a.docx` → pages；`a.png`+PNG magic → image；`a.png`+文字內容 → none/unsupported（DetectContentType 不符）；`a.tiff`+`II*\0` → image；`a.mp4` → video；`a.zip` → none/unsupported；`a.pdf` 大小 `MaxBytes+1` → too_large；`a.mp4` 大小 `MaxVideoBytes+1` → too_large。
  - `TestEnqueueAndClaim`：Enqueue 2 件 → Claim 依 created_at 取第 1 件，attempts=1；第二次 Claim 取第 2 件；第三次 nil。
  - `TestClaimConcurrentNoDouble`：10 件、5 個 goroutine 並行 Claim 直到 nil → 每件恰被取一次。
  - `TestLeaseExpiryRequeues`：Claim 後把 lease_until 改成過去 → 再 Claim 取回同一件 attempts=2；再過期兩次後 → Claim 回 nil，該檔 `file_previews.status=failed`。
  - `TestCompleteAndFail`：Complete → GetStatus ready、page_count 正確；Fail too_large → status too_large。
  - `TestUploadEnqueuesPreview`（tus_test）：上傳 `%PDF-` 開頭的小檔 → file_previews pending + render_jobs queued；上傳 `.zip` → unsupported、無 job。
  - `TestBackfill`：直接插入一個沒有 preview 的 files 列（加密 blob）→ Backfill 回 1，之後再呼叫回 0。
- [ ] **Step 2:** FAIL
- [ ] **Step 3: 實作**
- [ ] **Step 4:** PASS
- [ ] **Step 5: Commit** `feat: preview classification and render job queue`

---

### Task 3: 預覽產物的加密存取

**Files:**
- Create: `internal/preview/items.go`
- Test: `internal/preview/items_test.go`

**Interfaces:**
- Consumes: `sxcrypto.Keyring.NewDEK/UnwrapDEK`、`SealChunk`、`OpenPlain`、`ChunkSize`、`blob.Store`
- Produces:
  - `type Item struct{ ID uuid.UUID; Kind string; Idx, Width, Height int; Size, DurationMs int64 }`
  - `PutItem(ctx, pool, store, keys, fileID uuid.UUID, kind string, idx int, r io.Reader, size int64, meta Item) (Item, error)`：新 DEK、id=uuid.New()、以 SealChunk 逐 1 MiB 串流加密（`io.Pipe` 接 `store.Put`，不整份放記憶體）、storage_key = `"pv-" + id`（**注意** blob key 只允許 `[a-f0-9-]`，所以用 `id.String()` 本身，不加前綴）、寫 preview_items 列。同 (file_id, kind, idx) 已存在 → 先刪舊列與舊 blob 再寫（重新轉檔時）。
  - `OpenItem(ctx, pool, store, keys, fileID uuid.UUID, kind string, idx int) (io.ReadSeekCloser, Item, error)`：找不到 → `ErrNoItem`。
  - `ListItems(ctx, pool, fileID, kind) ([]Item, error)`（依 idx 排序；影片播放清單用）。
  - `DeleteItems(ctx, pool, store, fileID) error`（刪列 + blob，best-effort 刪 blob 並記 log）。
  - files 被軟刪除時（`httpapi.deleteFile`）呼叫 `DeleteItems`。
- [ ] **Step 1: 寫失敗測試** `TestPutOpenItemRoundTrip`（2.5 MiB 隨機資料 → OpenItem 讀回相同、Seek 到中間讀取正確）、`TestItemBlobEncrypted`（以已知字串填滿的資料寫入 → 本機 blob 檔不含該字串）、`TestPutItemReplaces`（同 idx 寫兩次 → 只剩一列，舊 blob 已刪）、`TestDeleteItems`、`TestOpenItemMissing`（→ ErrNoItem）、`TestDeleteFileDeletesItems`（httpapi：DELETE /api/files/{id} 後 preview_items 無列）。
- [ ] **Step 2:** FAIL
- [ ] **Step 3: 實作**
- [ ] **Step 4:** PASS
- [ ] **Step 5: Commit** `feat: encrypted preview item storage`

---

### Task 4: worker、外部程式沙盒、文件與圖片 pipeline

**Files:**
- Create: `internal/preview/sandbox.go`, `internal/preview/worker.go`, `internal/preview/pipeline_doc.go`, `internal/preview/pipeline_image.go`
- Modify: `cmd/secure-exchange/main.go`（`worker` 子命令）
- Test: `internal/preview/sandbox_test.go`, `internal/preview/pipeline_image_test.go`, `internal/preview/tools_test.go`（`//go:build tools`，需要 soffice／pdftoppm，在 worker-test 容器跑，見 Task 10）

**Interfaces:**
- Produces:
  - `type Sandbox struct{ Root string }`；`(Sandbox) NewDir() (dir string, cleanup func(), err error)`：在 Root 下建 0700 子目錄；cleanup 以 `os.RemoveAll`，呼叫端 `defer`，panic 時也會執行。
  - `Run(ctx context.Context, dir string, timeout time.Duration, name string, args ...string) ([]byte, error)`：`exec.CommandContext`，`Dir=dir`，`Env=[]string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir}`，Unix 上 `SysProcAttr{Setpgid: true}` 並在逾時時殺整個 process group（`syscall.Kill(-pid, SIGKILL)`；Windows build 只殺單一行程 — 用 build tag 分檔 `sandbox_unix.go`／`sandbox_windows.go`）；回傳合併後 stdout+stderr 的最後 4 KiB；逾時回 `ErrTimeout`。
  - `type Worker struct{ Pool; Store; Keys; Cfg config.PreviewConfig; Sandbox; Lease time.Duration (5m) }`；`(*Worker) Run(ctx)`：迴圈 Claim → 依 kind 處理 → Complete／Fail；沒有工作時睡 2 秒；處理期間每 60 秒 Renew；單一工作 panic 被 recover → Fail(failed, "internal error")，迴圈繼續。
  - 處理流程：OpenPlain 解密原始檔 → 寫到 `dir/in<ext>`（tmpfs）→ 執行 pipeline → 以 PutItem 寫產物 → Complete。
  - `pipeline_doc.go`：非 `.pdf` 先 `soffice --headless --norestore --nolockcheck -env:UserInstallation=file://<dir>/profile --convert-to pdf --outdir <dir>/out <dir>/in.ext`（逾時 180s）；取得 PDF 後 `pdfinfo` 讀頁數 → 超過 `MaxPages` → Fail(too_large)；`pdftoppm -r <DPI> -png <pdf> <dir>/p`（逾時 300s）；每頁若最長邊 > 2000 px 則以 Go 縮小到 2000（不放大小頁）；依序 PutItem(kind "page", idx 從 0)；Result{KindPages, PageCount, 第一頁 Width/Height}。
  - `pipeline_image.go`：Go 解碼（`image/jpeg`、`image/png`、`image/gif` 第一格、`golang.org/x/image/webp|bmp|tiff`）；先用 `image.DecodeConfig` 檢查寬高，`width*height > 100_000_000` → Fail(too_large)（防解壓炸彈）；最長邊縮到 ≤ 4096（`x/image/draw.CatmullRom`）；編碼 PNG；PutItem(kind "image", idx 0)。
  - `main.go`：`worker` 子命令只需要 DB、blob、keyring、Preview 設定；**不需要** SMTP（`config.Load` 對 worker 放寬：新增 `config.LoadWorker(getenv)`，只檢查 worker 用得到的變數）。
- [ ] **Step 1: 寫失敗測試**
  - `TestRunKillsOnTimeout`：`Run(..., 200ms, "sleep", "10")`（Windows 上 skip 或改 `timeout` 命令）→ ErrTimeout，耗時 < 2s。
  - `TestRunCleanEnv`：`Run(..., "env")`（Unix）→ 輸出只含 PATH 與 HOME。
  - `TestWorkDirRemovedOnFailure`：pipeline 回 error 與 panic 兩種情況 → Root 下沒有殘留子目錄。
  - `TestImagePipeline`：5000×3000 PNG → 產物最長邊 4096、kind image、Result 寬高正確；GIF 取第一格；`TestImageBomb`：header 宣稱 30000×30000 → too_large，且未分配大圖（用 `DecodeConfig` 判斷）。
  - `TestMislabeledFile`：副檔名 `.png` 但內容是隨機 bytes → Fail(failed)，worker 繼續處理下一件。
  - `TestWorkerLoopProcessesJobs`（DB）：Enqueue 一張 PNG → 啟動 Worker.Run（ctx 限時）→ file_previews ready、preview_items 1 列。
  - tools build tag：`TestDocPipelineDocx`（用 Go 產生一個最小 docx？改為用 soffice 轉一個 `.txt` 含中文「測試文件」兩頁內容 → PageCount ≥ 1、頁面 PNG 非全白）、`TestPDFPageCap`（用 soffice 由 600 行換頁文字產生 >`MaxPages`（設 5）頁 PDF → too_large）、`TestSofficeTimeout`（逾時設 1ms → failed）。
- [ ] **Step 2:** `go test ./internal/preview/` → FAIL
- [ ] **Step 3: 實作**
- [ ] **Step 4:** `go test ./internal/preview/` PASS（tools 測試在 Task 10 的容器中跑；本 task 也可先 `docker build --target worker-test` 手動跑 — 若 Task 10 尚未建立該 stage，於報告中註明）
- [ ] **Step 5: Commit** `feat: preview worker with sandboxed document and image pipelines`

---

### Task 5: 影片 pipeline

**Files:**
- Create: `internal/preview/pipeline_video.go`
- Modify: `internal/preview/worker.go`（video 分派）
- Test: `internal/preview/tools_video_test.go`（`//go:build tools`）

**Interfaces:**
- Produces:
  - `ffprobe -v error -show_entries format=duration -of csv=p=0 <in>` 取秒數；`> MaxVideoSeconds` → Fail(too_large)；ffprobe 失敗 → Fail(failed)。
  - `ffmpeg -nostdin -i <in> -map 0:v:0 -map 0:a:0? -vf "scale=-2:'min(720,ih)'" -c:v libx264 -preset veryfast -crf 23 -pix_fmt yuv420p -c:a aac -b:a 128k -ac 2 -f hls -hls_time 6 -hls_playlist_type vod -hls_segment_type mpegts -hls_segment_filename <dir>/out/s%05d.ts <dir>/out/index.m3u8`（逾時 `max(600, 3×秒數)` 秒）。
  - 解析 `index.m3u8` 的 `#EXTINF:<秒>` 取得每段長度；每段 PutItem(kind "segment", idx, duration_ms)；Result{KindVideo, DurationMs, 寬高（ffprobe `stream=width,height`）}。
- [ ] **Step 1: 寫失敗測試**（tools tag）`TestVideoPipeline`：以 `ffmpeg -f lavfi -i testsrc=duration=14:size=1280x720:rate=25 -f lavfi -i sine=duration=14` 產生 14 秒 mp4 → 3 段（6+6+2，允許 ±0.5s）、高度 720；`TestVideoTooLong`：`MaxVideoSeconds=5` → too_large；`TestVideoCorrupt`：隨機 bytes 的 `.mp4` → failed。
- [ ] **Step 2:** FAIL
- [ ] **Step 3: 實作**
- [ ] **Step 4:** PASS（worker-test 容器）
- [ ] **Step 5: Commit** `feat: video to encrypted HLS segments`

---

### Task 6: 浮水印與追蹤碼

**Files:**
- Create: `internal/preview/watermark.go`
- Test: `internal/preview/watermark_test.go`

**Interfaces:**
- Produces:
  - `type Mark struct{ Email, IP string; At time.Time; Code string }`；`(Mark) Text() string` → `"<email> · <ip> · <2006-01-02 15:04 UTC> · <code>"`（email 先截 254 字元）。
  - `Apply(img image.Image, m Mark) *image.RGBA`：複製底圖；以 `golang.org/x/image/font/gofont/goregular` + `opentype` 繪製文字，字級 = `max(14, 影像寬度/45)` px；將文字畫在透明 tile 上，以 `x/image/draw` 的 `f64.Aff3` 旋轉 30°，在整張圖上以固定間距平鋪；文字顏色白色與深灰兩層（描邊效果）以便在亮暗背景都看得到，整體 alpha ≈ 0.18。
  - `EncodeJPEG(w io.Writer, img image.Image) error`（quality 85）。
  - `NewTraceCode() string`：10 字元 Crockford base32（字母表 `0123456789ABCDEFGHJKMNPQRSTVWXYZ`）。
  - `Trace(ctx, pool, fileID, shareID, recipientID uuid.UUID, sessionHash []byte, ip string) (code string, created bool, err error)`：`INSERT ... ON CONFLICT (session_hash, file_id) DO NOTHING RETURNING code`；已存在則查回舊碼（同一 session 同一檔案碼不變）。
- [ ] **Step 1: 寫失敗測試**
  - `TestApplyChangesPixelsKeepsSize`：800×1000 純白圖 → 結果尺寸相同，至少 2% 像素被改變，且沒有任何像素變成全黑（alpha 合理）。
  - `TestApplyCoversWholeImage`：把圖切 4×4 格，每格都有被改變的像素（平鋪到邊角）。
  - `TestMarkText`：固定時間 → 精確字串；300 字元 email 被截斷。
  - `TestTraceCodeAlphabet`：1000 次 → 長度 10、只含字母表字元、無重複。
  - `TestTraceStablePerSession`（DB）：同 (session, file) 兩次 → 相同碼、第二次 created=false；不同 session → 不同碼。
- [ ] **Step 2:** FAIL
- [ ] **Step 3: 實作**
- [ ] **Step 4:** PASS
- [ ] **Step 5: Commit** `feat: server-side watermark rendering and trace codes`

---

### Task 7: 檢視 API（員工端、收件人端、影片片段燒入）

**Files:**
- Create: `internal/httpapi/preview_handlers.go`, `internal/httpapi/segment.go`
- Modify: `internal/httpapi/server.go`（路由、Deps 加 `Preview config.PreviewConfig`）、`internal/audit/audit.go`（`ActFileView = "file.view"`）、`internal/share/access.go`（`Access` 新增欄位 `SessionHash []byte`，由 `Authorize` 填入，供 `Trace` 去重）
- Test: `internal/httpapi/preview_test.go`, `internal/httpapi/segment_tools_test.go`（`//go:build tools`）

**Interfaces:**
- 員工端（`requireUser`、只限自己的檔案、無浮水印）：
  - `GET /api/files/{id}/preview` → `{kind, status, page_count, width, height, duration_ms}`（無列 → `{"kind":"none","status":"unsupported"}`）
  - `GET /api/files/{id}/preview/pages/{n}` → JPEG（kind pages 時 n ∈ [0, page_count)；kind image 時只接受 n=0）
  - `GET /api/files/{id}/preview/video.m3u8` → 由 ListItems 動態產生 VOD 播放清單，片段 URL 為相對路徑 `segments/{n}.ts`
  - `GET /api/files/{id}/preview/segments/{n}.ts` → 解密後直接送出（`video/mp2t`）
- 收件人端（`requireRecipient`；檔案必須在分享中且未刪除；**allow_download 與否都可檢視**）：
  - `GET /api/s/{token}/files/{fid}/preview` → 同上格式
  - `GET /api/s/{token}/files/{fid}/preview/pages/{n}` → 解密底圖 → `share.Watermark` 為 true 時 `Trace` 取追蹤碼並 `Apply`（Mark：收件人 email、`ClientIP`、`time.Now().UTC()`、碼）→ JPEG
  - `GET /api/s/{token}/files/{fid}/preview/video.m3u8`、`.../segments/{n}.ts` → watermark 為 true 時以 `segment.go` 即時燒入；false 時直接送解密片段
  - 第一次為某 (session, 檔案) 產生追蹤碼時（`created=true`）寫稽核 `file.view`（ActorType recipient、detail `{share_id, trace_code}`）；watermark=false 時，每個 (session, 檔案) 第一次取得 page 0 或 segment 0 時寫一次 `file.view`（detail 無 trace_code）— 以 `view_traces` 同樣的去重表記錄（code 用 NewTraceCode 但不畫上去，欄位照填），讓去重邏輯只有一套。
  - 狀態不是 ready → 409 `{"error":"preview_not_ready","status":...}`；頁碼或片段越界 → 404。
- `segment.go`：`burnSegment(ctx, w io.Writer, src io.Reader, m preview.Mark) error`：`ffmpeg -nostdin -loglevel error -copyts -i pipe:0 -vf "drawtext=fontfile=<SX_FONT_FILE>:text='<escaped>':fontsize=h/22:fontcolor=white@0.22:x=(w-tw)/2:y=(h-th)/2,drawtext=...:y=h/5,drawtext=...:y=4*h/5" -c:v libx264 -preset ultrafast -crf 26 -c:a copy -muxdelay 0 -f mpegts pipe:1`；`<escaped>` 必須跳脫 `\`、`'`、`:`、`%`（寫成獨立函式 `drawtextEscape` 並測試）；逾時 30 秒；字型檔路徑由 `SX_FONT_FILE`（預設 `/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf`）提供，新增到 Config。`// ponytail: 每次請求都重新燒入，同時觀看人數多時需改為快取或預先轉檔`
- 所有檢視回應：`Cache-Control: private, no-store`、`Content-Disposition: inline`。
- [ ] **Step 1: 寫失敗測試**（以 Task 3 的 PutItem 直接放入一張 PNG 頁面與狀態 ready，不跑 worker）
  - `TestOwnerPreviewNoWatermark`：員工取 page 0 → JPEG 解碼後與底圖逐像素相近（JPEG 誤差內，平均差 < 3）。
  - `TestOwnerPreviewOtherUser404`。
  - `TestRecipientWatermarkToggle`：watermark=true 分享 → 與底圖平均差 > 3、尺寸相同、`view_traces` 1 列、稽核 1 筆 file.view 含 trace_code；同 session 再取 page 1 → view_traces 仍 1 列、稽核仍 1 筆。watermark=false 分享 → 與底圖相近、稽核 1 筆 file.view 無 trace_code。
  - `TestRecipientViewOnlyCanView`：allow_download=false 分享仍可取 page（下載 API 仍 403）。
  - `TestRecipientPageBounds`：n = page_count → 404；fid 不在分享 → 404；無 cookie → 401。
  - `TestPreviewNotReady`：status pending → 409。
  - `TestPlaylist`：3 段（6000/6000/2000 ms）→ m3u8 含 `#EXT-X-TARGETDURATION:6`、3 個 `#EXTINF`、`#EXT-X-ENDLIST`、片段 URL 為相對路徑。
  - `TestDrawtextEscape`：`a:b'c\d%e` → 正確跳脫。
  - tools tag：`TestBurnSegment`：用 ffmpeg 產生 6 秒 ts 片段 → burnSegment 輸出可被 ffprobe 解析、時長相近、首幀與原片段不同。
- [ ] **Step 2:** FAIL
- [ ] **Step 3: 實作**
- [ ] **Step 4:** PASS
- [ ] **Step 5: Commit** `feat: preview API with server-side watermarks`

---

### Task 8: 分享建立規則與預覽狀態顯示

**Files:**
- Modify: `internal/share/share.go`（Create 與 AddRecipients 不受影響；Create 驗證）、`internal/httpapi/files_handlers.go`（列表加 preview 欄位）、`web/src/pages/Files.tsx`、`web/src/components/ShareDialog.tsx`、i18n JSON
- Test: `internal/share/share_test.go`（加 case）、`internal/httpapi/files_test.go`（加 case）、`web/src/components/ShareDialog.test.tsx`（加 case）

**Interfaces:**
- `share.Create`：`AllowDownload=false` 時，所有檔案的 `file_previews.status` 必須為 `ready`；任一為 `pending`（或沒有 preview 列）→ `ValidationError{file_ids, preview_pending}`；任一為 `failed|unsupported|too_large` → `ValidationError{file_ids, not_previewable}`。`AllowDownload=true` 不檢查。
- `GET /api/files` 每筆加 `preview_status`（無列 → `"unsupported"`）與 `preview_kind`。
- Files 頁：每列顯示預覽狀態（處理中／可預覽／無法預覽／檔案過大／失敗），可預覽者顯示「檢視」按鈕（開啟 Task 9 的檢視器）；處理中每 5 秒重新整理一次列表（只在有 pending 時）。
- ShareDialog：422 `file_ids.preview_pending` 與 `file_ids.not_previewable` 顯示對應訊息（「部分檔案仍在處理預覽，請稍候」／「部分檔案無法線上預覽，請改為允許下載」）；勾選「僅線上檢視」時，若選取的檔案有非 ready 的，送出前就顯示提示（仍送出由伺服器判定）。
- 移除 `share.viewOnlyNote` 的「後續版本」說法：改為「收件人只能在瀏覽器中檢視」。
- [ ] **Step 1: 寫失敗測試** `TestCreateViewOnlyRequiresReadyPreview`（pending → preview_pending；unsupported → not_previewable；ready → OK；allow_download=true + unsupported → OK）、`TestListFilesPreviewStatus`、ShareDialog 的兩個 422 訊息。
- [ ] **Step 2:** FAIL
- [ ] **Step 3: 實作**
- [ ] **Step 4:** `go test ./internal/share/ ./internal/httpapi/ && cd web && npx vitest run` → PASS
- [ ] **Step 5: Commit** `feat: view-only shares require ready previews`

---

### Task 9: 檢視器介面

**Files:**
- Create: `web/src/components/Viewer.tsx`, `web/src/components/Viewer.test.tsx`
- Modify: `web/src/pages/Files.tsx`（檢視按鈕）、`web/src/pages/recipient/Access.tsx`（每個 ready 檔案顯示「檢視」，不論是否允許下載）、`web/src/api.ts`、i18n JSON、`web/package.json`（`hls.js` 釘選確切版本）

**Interfaces:**
- `Viewer({ base, onClose })`：`base` 為檢視 API 前綴（員工 `/api/files/{id}/preview`、收件人 `/api/s/{token}/files/{fid}/preview`）。先 GET `base` 取得 kind/status。
  - pages／image：直向捲動列出 `<img src={base + "/pages/" + n} loading="lazy" draggable={false}>`，頂端工具列：頁碼（目前／總數，捲動時更新）、上一頁／下一頁、縮放（50%–300%，以 CSS `transform: scale` 或寬度百分比）、關閉。鍵盤：←／→／PageUp／PageDown 翻頁、+／- 縮放、Esc 關閉。`onContextMenu` 阻止右鍵、`user-select: none`。
  - video：`hls.js`（`Hls.isSupported()`；Safari 走原生 `video.canPlayType('application/vnd.apple.mpegurl')`）載入 `base + "/video.m3u8"`，`<video controls controlsList="nodownload" disablePictureInPicture>`。
  - status 非 ready → 顯示對應訊息；409／401／410 → 顯示訊息（收件人 401 時呼叫 `onSessionEnded`）。
  - 全螢幕 overlay，`role="dialog" aria-modal="true"`，開啟時焦點移到關閉鈕。
- [ ] **Step 1: 寫失敗測試**：mock fetch 回 `{kind:"pages",status:"ready",page_count:3}` → 渲染 3 個 img、src 正確、`draggable=false`；按 → 鍵後頁碼顯示 2/3；`{kind:"video"}` → 有 `<video>`、hls.js 被以 m3u8 URL 呼叫（mock `hls.js`）；status pending → 顯示處理中訊息；Esc → onClose。
- [ ] **Step 2:** `npx vitest run` → FAIL
- [ ] **Step 3: 實作**
- [ ] **Step 4:** `npx vitest run && npm run build` → PASS
- [ ] **Step 5: Commit** `feat: page and video viewer`

---

### Task 10: 容器、worker 隔離、CI、文件、冒煙測試

**Files:**
- Modify: `Dockerfile`、`docker-compose.yml`、`docker-compose.dev.yml`、`.github/workflows/ci.yml`、`.env.example`、`README.md`、`README.zh-TW.md`、`scripts/smoke.sh`
- Test: CI、smoke

**Interfaces:**
- `Dockerfile` stages：
  - `app`（預設最終 stage）：`debian:bookworm-slim` + `ffmpeg` + `fonts-dejavu-core` + `ca-certificates`，nonroot uid 65532，`/data` 擁有者 65532，`ENTRYPOINT ["/secure-exchange"]`。
  - `worker`：`debian:bookworm-slim` + `libreoffice-writer libreoffice-calc libreoffice-impress`（`--no-install-recommends`）+ `poppler-utils` + `ffmpeg` + `fonts-noto-cjk fonts-dejavu-core`，nonroot 65532，`ENTRYPOINT ["/secure-exchange","worker"]`。
  - `worker-test`：基於 `worker` stage 的套件 + Go toolchain（複製 `golang:1.27-bookworm` 的 `/usr/local/go`），`WORKDIR /src`，用來跑 `go test -tags tools ./internal/preview/... ./internal/httpapi/...`。
- `docker-compose.yml`：新增 `worker` service（`build: {context: ., target: worker}`），`env_file: .env`、同樣的 DB URL；`read_only: true`；`tmpfs: ["/work:size=4g,mode=0700,uid=65532,gid=65532", "/tmp:size=64m"]`；`cap_drop: [ALL]`；`security_opt: ["no-new-privileges:true"]`；`mem_limit: 4g`、`cpus: 2`、`pids_limit: 512`；volumes `sxdata:/data`（blob 為 local 時需要）；**網路**：新增 `backend` 網路 `internal: true`（postgres、app、worker 加入），worker **只**接 `backend`（無對外網路）；app 同時接 `sx`（給 Caddy）與 `backend`；README 說明使用外部 S3 時要把 worker 另接一個可連到 S3 的網路。app 的 `build` 改 `target: app`。
- `docker-compose.dev.yml`：新增 `worker-test` service（`build: {context: ., target: worker-test}`、`profiles: [tools]`、`network_mode: host` 以連 dev postgres／minio，或改用 compose 網路 + 服務名；擇一並在 README 說明），指令 `go test -tags tools -count=1 ./internal/preview/... ./internal/httpapi/...`。
- CI：新增 job `tools`：`docker build --target worker-test -t sx-worker-test .`，再以 `docker run --network host -e SX_TEST_DATABASE_URL=... sx-worker-test` 跑 tools 測試（需要 postgres service 與 minio 同現有 job 的作法）。
- `.env.example`：新增 `SX_PREVIEW_MAX_BYTES`、`SX_PREVIEW_MAX_PAGES`、`SX_PREVIEW_MAX_VIDEO_BYTES`、`SX_PREVIEW_MAX_VIDEO_SECONDS`、`SX_RENDER_DPI`、`SX_WORKER_TMP`、`SX_FONT_FILE`（皆註解掉、附預設值說明）。
- README 兩語言：線上檢視與浮水印說明、支援的格式、預覽上限、worker 隔離方式（無對外網路、tmpfs、資源上限）、外部 S3 的網路調整、`docker compose run --rm worker-test`（dev）。
- `scripts/smoke.sh`：在既有流程後加：上傳一個 `.txt`（含中文兩段）→ 輪詢 `GET /api/files` 直到 `preview_status=ready`（最多 120 秒）→ 建立僅線上檢視、浮水印開啟的分享 → 收件人驗證 → 取 `preview/pages/0` → 確認 `Content-Type: image/jpeg` 且大小 > 1 KB；下載 API → 403。
- [ ] **Step 1:** 寫 Dockerfile stages、compose、override、CI。
- [ ] **Step 2:** `docker compose -f docker-compose.dev.yml --profile tools run --rm worker-test` → Task 4、5、7 的 tools 測試全部 PASS。
- [ ] **Step 3:** `bash scripts/smoke.sh` → PASS；`docker compose ... exec worker sh -c 'touch /x'` 失敗（唯讀）、`exec worker getent hosts example.com` 或 `wget` 連不到外網（擇一驗證無對外網路），結果寫進報告。
- [ ] **Step 4:** README 兩語言、.env.example。
- [ ] **Step 5: Commit** `chore: worker container isolation, tools tests in CI, viewer docs`

---

## 不在本階段

- 下載檔加浮水印與追蹤標記、外流溯源查詢介面（階段 4；本階段只先產生並記錄檢視追蹤碼）
- 圖片的不可見浮水印（階段 4）
- 收件與掃毒（階段 5）、廠商帳號（階段 6）
- 管理員調整預覽上限、強制浮水印（階段 7）
- 影片片段的觀看快取或預先燒入（目前每次請求即時燒入，已標 ponytail）
