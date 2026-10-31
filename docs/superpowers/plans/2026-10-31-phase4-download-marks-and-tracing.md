# 階段 4：下載追蹤標記與外流溯源 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 收件人在「允許下載」的分享中每下載一次，就產生一組唯一追蹤碼，並依檔案類型與浮水印設定把追蹤碼嵌進下載檔：可見浮水印、PDF 中繼資料與隱藏文字層、圖片不可見浮水印、Office 文件屬性。每次下載都記錄追蹤碼、分享、下載者、時間、IP 與下載檔的 SHA-256。管理員可以上傳疑似外流的檔案、輸入追蹤碼或輸入 SHA-256 來查出來源。

**Architecture:** 新增 `internal/mark` 套件，只用 Go 程式處理，不需要外部工具：
- 圖片不可見浮水印；
- 以預覽頁面圖產生 PDF 的串流寫入器；
- PDF 中繼資料寫入（pdfcpu）；
- OOXML／ODF 文件屬性寫入（以 zip raw copy 串流，不重新壓縮）；
- 從可疑檔案讀出追蹤碼。

收件人下載 handler 依 `mark.Decide` 選擇標記方式，邊產生邊計算 SHA-256 邊送出，送完再補記 SHA-256。「浮水印開」的 PDF 與 Office 改用階段 3 已產生、無浮水印的頁面底圖，逐頁畫上浮水印，組成只有圖片的 PDF。這樣 app 不必在 process 內解析不受信任的 PDF 版面，對方也拿不到可編輯的原檔。溯源 API 只開放給管理員。

**Tech Stack:** 沿用階段 1–3，新增 `github.com/pdfcpu/pdfcpu`（Apache-2.0，與 AGPL-3.0 相容），只用 `api.AddProperties` 與 `api.Properties`。其餘只用標準函式庫：`archive/zip`、`compress/zlib`、`image/jpeg`、`image/png`、`crypto/sha256`。

**Spec:** `docs/superpowers/specs/2026-10-24-secure-exchange-design.md`（§5.5、§5.6、§6「追蹤標記的成本」、§9 安全路徑測試）

## Global Constraints

- 只有分享的 `allow_download=true` 時才能下載，這是現有行為。員工下載自己的檔案不加標記，維持現狀。
- **每次 GET 下載都產生新的追蹤碼。** 例外是「無標記」的下載，每個 (收件人, 檔案) 只記一列，因為原檔支援 Range 續傳，每個 Range 請求都產生新碼沒有意義。HEAD 請求不產生任何列。
- 追蹤碼沿用 `preview.NewTraceCode()`：10 字元 Crockford base32。嵌入檔案時一律寫成 `SX-<code>`，萃取時用 regex `SX-([0-9A-HJKMNP-TV-Z]{10})`。
- 下載檔的標記方式（`mark.Method`）如下。「浮水印開／關」指分享的 `watermark` 設定。

  | 類型（依副檔名＋magic） | 浮水印開 | 浮水印關 |
  |---|---|---|
  | PDF（`.pdf`＋`%PDF-`） | `pdf_pages`：預覽頁面圖 → 每頁可見浮水印＋不可見浮水印 → PDF；Info 中繼資料與隱藏文字層都寫 `SX-<code>` | `pdf_meta`：原檔經 pdfcpu `AddProperties` 寫入 `{"sx_trace": "SX-<code>"}` |
  | Office 可轉頁面（`.doc .docx .odt .rtf .xls .xlsx .ods .ppt .pptx .odp`） | `pdf_pages`，輸出檔名改為 `<原檔名去副檔名>.pdf` | OOXML（`.docx .xlsx .pptx`）用 `ooxml_meta`，ODF（`.odt .ods .odp`）用 `odf_meta`；其他（`.doc .xls .ppt .rtf`）用 `none` |
  | 圖片（`image/jpeg`、`image/png`，依 `http.DetectContentType`） | `image_visible`：可見浮水印＋不可見浮水印，輸出格式與原檔相同 | `image_invisible`：只加不可見浮水印，輸出格式與原檔相同 |
  | 其他（含 gif/webp/tiff/bmp、影片、壓縮檔…） | `none` | `none` |

- **無法加標記與退回規則。** 遇到下列情況，就退回較弱的方式：
  - `pdf_pages` 需要預覽狀態為 `ready`：
    - 狀態 `pending` → 回 409 `mark_pending`，絕不送出原檔；
    - 狀態 `failed`、`unsupported` 或 `too_large` → 視為無法完整標記。
  - 超出上限：
    - `pdf_meta` 的檔案大小超過 `SX_MARK_MAX_BYTES`；
    - 圖片的大小超過 `SX_MARK_MAX_BYTES`，或像素數超過 `SX_MARK_MAX_PIXELS`。

  退回順序：
  - PDF：`pdf_pages` → `pdf_meta` → `none`；
  - OOXML／ODF：`pdf_pages` → `ooxml_meta`／`odf_meta` → `none`；
  - 圖片：`image_*` → `none`；
  - meta 寫入失敗（例如檔案損毀）也退回 `none`。
- **管理員政策 `SX_UNMARKABLE_POLICY`**：值為 `warn`（預設）或 `block`。只在分享的 `watermark=true` 時生效。
  - 「浮水印開時被退回」的定義：最後採用的方式不是表中「浮水印開」那一格。
  - `warn`：照退回結果送出。
  - `block`：下載回 403 `unmarkable`；建立分享時，若 `allow_download=true`、`watermark=true`，且任何檔案的 `Decide` 結果是被退回的，就回 422 `{"error":"unmarkable","file_ids":[…]}`。
  - 這個環境變數在階段 7 會改由管理介面設定，到時加上 ponytail 註解。
- **記憶體與串流：**
  - `pdf_pages` 和 `ooxml_meta`／`odf_meta` 必須逐頁或逐個 zip entry 串流，記憶體用量不隨檔案大小成長。
  - `pdf_meta` 與 `image_*` 會把整個檔案載入記憶體，所以受 `SX_MARK_MAX_BYTES` 限制，預設 `256 MiB`。
  - `SX_MARK_MAX_PIXELS` 預設 `50000000`。
  - 這兩個值都必須為正數。
- **有標記的下載：**
  - 不支援 Range（`Accept-Ranges: none`），也不設 `Content-Length`，回 200 並以串流送出；
  - `pdf_meta` 和 `image_*` 是先在記憶體產生完再送，所以可以設 `Content-Length`；
  - `Cache-Control: private, no-store`，`Content-Disposition` 用輸出檔名。
- **無標記的下載**維持現有 `serveFile` 的行為：支援 Range，`ETag` 用原檔的 SHA-256。
- 可見浮水印文字沿用 `preview.Mark{Email, IP, At: 下載時間, Code}` 與 `preview.Apply`。
- 稽核：
  - `file.download` 的 detail 加上 `trace_code` 和 `mark`（Method 名稱）；
  - 新增 `trace.lookup`，actor 為管理員，detail 記錄查詢方式與命中筆數，不記檔案內容；
  - 寫稽核一律用 `context.WithoutCancel`；
  - client 送來的字串寫入 DB 或稽核前先截斷。
- 溯源 API 只限 `role='admin'`：
  - 上傳檔案時，SHA-256 以串流方式算完整個檔案，大小不限；
  - 內容分析（讀中繼資料、文字層、不可見浮水印）只對前 `SX_MARK_MAX_BYTES` 做，且只在檔案不超過這個大小時進行；
  - 可疑檔案只放在記憶體，不寫入磁碟。
- 介面字串一律經 i18n（en、zh-TW）。

## Review Focus

1. **外流圖片被重新壓縮與縮放**（社群軟體轉存成 JPEG q70、縮成一半）時，仍要讀得出不可見浮水印的追蹤碼。圖片太小或被大幅裁切時，回「無法判定」，不能誤判成別人的追蹤碼（Task 2 `TestInvisibleSurvivesJPEGAndScale`、`TestInvisibleNoFalsePositive`）。
2. **收件人中途中斷有標記的下載**：該列的 `sha256` 維持 NULL，但用追蹤碼查詢仍查得到；之後重新下載會產生新的一列（Task 5 `TestMarkedDownloadAbortKeepsRow`）。
3. **浮水印開、預覽還在轉檔的 Office 或 PDF**：回 409 `mark_pending`，絕不退回送出可編輯的原檔（Task 5 `TestPendingPreviewNeverServesOriginal`）。
4. **損毀或惡意的 PDF、zip**，不論是分享中的檔案還是管理員上傳的可疑檔：不能 panic，也不能回 500；下載退回 `none`，溯源回空結果（Task 3 `TestPDFMetaCorruptInput`、Task 4 `TestZipMetaCorruptInput`、Task 6 `TestTraceGarbageUpload`）。
5. **非管理員呼叫溯源 API** → 403。收件人和員工都不能用追蹤碼反查他人的下載紀錄（Task 6 `TestTraceAdminOnly`）。

---

## File Structure

```
internal/db/migrations/0004_downloads.sql  download_traces
internal/config/config.go                  + MarkConfig
internal/mark/record.go                    download_traces 寫入、完成、查詢
internal/mark/invisible.go                 圖片不可見浮水印（嵌入／萃取）
internal/mark/pdfgen.go                    頁面圖 → PDF 串流寫入器（含隱藏文字層、Info）
internal/mark/pdfmeta.go                   PDF 中繼資料寫入與讀取（pdfcpu）
internal/mark/office.go                    OOXML／ODF 屬性寫入（zip raw copy）與讀取
internal/mark/decide.go                    選擇標記方式、退回規則
internal/mark/inspect.go                   從可疑檔案萃取追蹤碼（彙整各格式）
internal/httpapi/recipient_download.go     收件人下載：標記、串流雜湊、紀錄
internal/httpapi/trace_handlers.go         requireAdmin、POST /api/admin/trace
internal/httpapi/files_handlers.go         清單加 mark 欄位
internal/httpapi/shares_handlers.go        block 政策檢查
web/src/components/ShareDialog.tsx         無法加標記的警告
web/src/pages/admin/Trace.tsx              溯源頁
web/src/main.tsx / api.ts / i18n/*.json / README*
```

---

### Task 1: 設定、schema、下載紀錄

**Files:**
- Modify: `internal/config/config.go`, `internal/config/config_test.go`, `internal/audit/audit.go`
- Create: `internal/db/migrations/0004_downloads.sql`, `internal/mark/record.go`
- Test: `internal/mark/record_test.go`, `internal/db/db_test.go`（加 case）

**Interfaces:**
- Produces: `Config.Mark MarkConfig{MaxBytes int64 (256<<20); MaxPixels int (50_000_000); Policy string ("warn"|"block", 預設 "warn")}`。對應環境變數 `SX_MARK_MAX_BYTES`、`SX_MARK_MAX_PIXELS`、`SX_UNMARKABLE_POLICY`。非正數或未知政策 → error，訊息含變數名。
- Produces: `audit.ActTraceLookup = "trace.lookup"`
- Schema：

```sql
CREATE TABLE download_traces (
  code text PRIMARY KEY, file_id uuid NOT NULL REFERENCES files,
  share_id uuid NOT NULL REFERENCES shares, recipient_id uuid NOT NULL REFERENCES share_recipients,
  method text NOT NULL CHECK (method IN ('pdf_pages','pdf_meta','image_visible','image_invisible','ooxml_meta','odf_meta','none')),
  ip text NOT NULL, user_agent text NOT NULL, sha256 bytea, size bigint,
  created_at timestamptz NOT NULL DEFAULT now(), completed_at timestamptz);
CREATE UNIQUE INDEX download_traces_unmarked ON download_traces (recipient_id, file_id) WHERE method = 'none';
CREATE INDEX download_traces_sha ON download_traces (sha256) WHERE sha256 IS NOT NULL;
CREATE INDEX files_sha ON files (sha256);
```

- Produces（`internal/mark/record.go`）：
  - `type Method string`，七個常數 `PDFPages="pdf_pages"`、`PDFMeta`、`ImageVisible`、`ImageInvisible`、`OOXMLMeta`、`ODFMeta`、`None`。
  - `type Download struct{ FileID, ShareID, RecipientID uuid.UUID; Method Method; IP, UserAgent string }`
  - `Start(ctx, q preview.Querier, d Download) (code string, err error)`：
    - 有標記：插入新列並回傳新碼；
    - `None`：`ON CONFLICT (recipient_id, file_id) WHERE method='none' DO NOTHING`，再取回既有的碼；
    - ip 截 64 字元，user agent 截 512 字元。
  - `Complete(ctx, q, code string, sum []byte, size int64) error`：設定 sha256、size、`completed_at=now()`。
  - `type Hit struct{ Source string; Via string; Code string; FileID uuid.UUID; FileName string; ShareID *uuid.UUID; OwnerEmail, RecipientEmail, IP string; At time.Time; Method string }`
    - `Source` 為 `"download"`、`"view"` 或 `"file"`。
    - `Via` 為 `"metadata"`、`"text_layer"`、`"invisible"`、`"sha256"` 或 `"code"`，由呼叫者填入。
  - `ByCode(ctx, q, code string) ([]Hit, error)`：查 `download_traces` 與 `view_traces`（階段 3），兩邊都 JOIN files、users（owner）、share_recipients，取得 email。
  - `BySHA(ctx, q, sum []byte) ([]Hit, error)`：
    - `download_traces.sha256 = sum` → Source `download`；
    - `files.sha256 = sum`（未刪除）→ 每個檔案一筆 Source `file`，另外列出該檔案所有 `method='none'` 的下載。
- [ ] **Step 1: 寫失敗測試**
  - `TestLoadMarkDefaults`：只給必填變數時，得到上述預設值。
  - `TestLoadMarkInvalid`：`SX_MARK_MAX_BYTES=0` 或 `SX_UNMARKABLE_POLICY=deny` → error。
  - `TestMigration0004Applies`。
  - `TestStartMarkedAlwaysNew`：同一對 (收件人, 檔案) 呼叫 `Start` 兩次，方式為 `PDFMeta` → 得到兩組不同的碼。
  - `TestStartUnmarkedReuses`：方式為 `None` 時兩次 → 同一組碼，且只有一列。
  - `TestByCodeFindsDownloadAndView`：
    - 下載碼 → 1 筆 Source=download，RecipientEmail、IP 正確，`completed_at` 未設也查得到；
    - `view_traces` 的碼 → 1 筆 Source=view；
    - 不存在的碼 → 0 筆。
  - `TestBySHA`：
    - 用 `Complete` 寫入的 sum 查 → 1 筆 download；
    - 用原檔 sha 查 → 1 筆 file 加上該檔案的 none 下載；
    - 已刪除的檔案不出現。
- [ ] **Step 2:** 跑測試，預期 FAIL。
- [ ] **Step 3: 實作**
- [ ] **Step 4:** 執行 `go test ./internal/config/ ./internal/db/... ./internal/mark/` → PASS
- [ ] **Step 5: Commit** `feat: download trace schema, config, records`

---

### Task 2: 圖片不可見浮水印

**Files:**
- Create: `internal/mark/invisible.go`
- Test: `internal/mark/invisible_test.go`

**Interfaces:**
- Produces:
  - `EmbedInvisible(img image.Image, code string) *image.RGBA`
  - `ExtractInvisible(img image.Image) (code string, ok bool)`
- 演算法（這是 spec 說的「基本、可靠的頻域方法」，實作者照這個做，不要另外發明）：
  - **Payload：** 追蹤碼 10 字元 × 5 bit = 50 bit，加上 CRC-14（多項式 `0x2805`，初值 0），共 64 bit。
  - **格點：** 把影像的亮度 Y（BT.601）分成固定的 `24 × 24` 格，與解析度無關（格寬 = W/24，格高 = H/24，取整數邊界）。576 格中，第 k 格承載 bit `perm[k] mod 64`。`perm` 是以固定種子 `0x5345` 產生的 `[0,576)` 洗牌，用 `math/rand/v2` 的 PCG(0x5345, 0)，所以每個 bit 重複 9 次。
  - **嵌入：** 每格計算基底 `B(x,y)=cos(π(2x+1)/(2cw))·cos(π(2y+1)/(2ch))`（DCT 的 (1,1) 基底）上的係數 `c = Σ Y·B / Σ B²`。用 QIM 量化：步長 `Δ = 16`，bit 0 對應格點 `Δ·n`，bit 1 對應 `Δ·n + Δ/2`，取最近的格點 `c'`。然後在 Y 加上 `(c'-c)·B`，並把同一個差量等量加到 R、G、B，最後 clamp 到 0–255。
  - **萃取：** 用同樣的格點與基底算出 `c`，判斷它比較靠近哪一組格點，給該 bit 投一票，每票以 `|距離差|` 加權。64 bit 取多數決後驗 CRC，不符 → `ok=false`。最小尺寸：任一邊 < 192 px 時，`EmbedInvisible` 原樣回傳，`ExtractInvisible` 回 `ok=false`。
  - 若測試門檻過不了，只能調整 `Δ`（範圍 12–24），並同步更新這裡的數字。
- [ ] **Step 1: 寫失敗測試**（測試圖要有雜訊與漸層，用固定種子產生 1600×1200 的合成「照片」。不要用純色圖，純色圖太好過）
  - `TestInvisibleRoundTrip`：嵌入後直接萃取 → 得到同一個碼。
  - `TestInvisibleSurvivesJPEGAndScale`：嵌入 → JPEG q70 → 解碼 → 以 `draw.BiLinear` 縮成 800×600 → 再 JPEG q80 → 萃取 → 得到同一個碼。
  - `TestInvisibleQuality`：嵌入前後的 PSNR ≥ 38 dB。
  - `TestInvisibleNoFalsePositive`：未嵌入的 20 張不同種子合成圖，以及嵌入後再裁掉左側 30% 的圖 → 全部 `ok=false`。
  - `TestInvisibleTooSmall`：100×100 → 原樣回傳，萃取 `ok=false`。
- [ ] **Step 2:** 跑測試，預期 FAIL。
- [ ] **Step 3: 實作**
- [ ] **Step 4:** 執行 `go test ./internal/mark/ -run Invisible` → PASS
- [ ] **Step 5: Commit** `feat: frequency-domain invisible image watermark`

---

### Task 3: PDF：頁面圖 → PDF、中繼資料

**Files:**
- Create: `internal/mark/pdfgen.go`, `internal/mark/pdfmeta.go`
- Modify: `go.mod`, `go.sum`（`go get github.com/pdfcpu/pdfcpu@latest`，確認 `api.AddProperties(rs io.ReadSeeker, w io.Writer, map[string]string, *model.Configuration)` 與 `api.Properties(rs, conf)` 存在）
- Test: `internal/mark/pdf_test.go`

**Interfaces:**
- Produces:
  - `WritePagesPDF(w io.Writer, n int, page func(i int) (image.Image, error), code string) error`
    - 自己寫 PDF 1.4，只用標準函式庫，逐頁寫出。每頁做法：
      - `page(i)` 取得已畫好可見浮水印的圖；
      - 加上 `EmbedInvisible`，以 JPEG q85 編碼，寫成 `/DCTDecode` XObject；
      - 頁面大小：以 110 DPI 換算，`寬pt = px·72/110`；
      - 頁面 content stream 不壓縮，內容如下：
        - 畫圖：`q W 0 0 H 0 0 cm /Im0 Do Q`；
        - 隱藏文字層：`BT 3 Tr /F1 8 Tf 10 10 Td (SX-<code>) Tj ET`；
      - `/F1` 是 Helvetica 標準字型。
    - 結尾依序寫 Info `<< /Producer (secure-exchange) /Keywords (SX-<code>) /sx_trace (SX-<code>) >>`、Pages、Catalog、xref、trailer。
    - 只在記憶體保留各物件的位移，不保留頁面內容。
  - `AddPDFMeta(r io.ReadSeeker, w io.Writer, code string) error`：呼叫 pdfcpu `AddProperties` 寫入 `{"sx_trace": "SX-<code>"}`，用 `model.NewDefaultConfiguration()`，並以 `recover()` 把 panic 轉成 error。
  - `PDFCodes(data []byte) (meta, text []string)`：
    - `meta`：pdfcpu `Properties` 的 `sx_trace`，加上對整份檔案原始 bytes 跑 regex（Info 未壓縮的情況）；
    - `text`：在每段 `stream…endstream` 內，用 `zlib` 嘗試解壓縮（失敗就用原文）後跑 regex，每段解壓縮最多 16 MiB；
    - 結果去重，pdfcpu 的錯誤或 panic 都吞掉；
    - `meta` 以外的命中都算 `text`。
- [ ] **Step 1: 寫失敗測試**
  - `TestWritePagesPDF`：3 頁 400×300 的圖，碼為 `ABCDEFGH12`。
    - 輸出以 `%PDF-1.4` 開頭，pdfcpu `api.PageCount` 為 3；
    - `PDFCodes` 的 meta 與 text 都含 `ABCDEFGH12`；
    - 用 pdfcpu 抽出第一頁的圖解碼後，`ExtractInvisible` 得到同一個碼（若 400×300 太小，改用 1200×900）。
  - `TestAddPDFMeta`：用 `WritePagesPDF` 產生的 PDF（或測試裡內嵌的最小 PDF）跑 `AddPDFMeta` → `PDFCodes(out).meta` 含碼，pdfcpu 驗證通過。
  - `TestPDFMetaCorruptInput`：輸入 `%PDF-1.7\n垃圾` 或截斷一半的 PDF → `AddPDFMeta` 回 error 且不 panic；`PDFCodes` 回空，不 panic。
  - `TestPDFCodesCompressedText`：手工做一個 content stream 以 zlib 壓縮、內含 `(SX-ABCDEFGH12) Tj` 的 PDF → text 含碼。
- [ ] **Step 2:** 跑測試，預期 FAIL。
- [ ] **Step 3: 實作**
- [ ] **Step 4:** 執行 `go test ./internal/mark/ -run PDF` → PASS
- [ ] **Step 5: Commit** `feat: page-image PDF writer and PDF trace metadata`

---

### Task 4: Office 文件屬性

**Files:**
- Create: `internal/mark/office.go`
- Test: `internal/mark/office_test.go`

**Interfaces:**
- Produces:
  - `AddZipMeta(ra io.ReaderAt, size int64, w io.Writer, code string, odf bool) error`
    - 用 `zip.NewReader(ra, size)` 讀入；用 `zip.NewWriter(w)`，按原順序以 `OpenRaw`／`CreateRaw` 複製每個 entry，不解壓縮。所以 ODF 的 `mimetype` 仍是第一個 stored entry。
    - 唯一例外：OOXML 的 `docProps/core.xml`，或 ODF 的 `meta.xml`，限 1 MiB 以內，解壓縮後修改再以 Deflate 寫回：
      - OOXML：已有 `<cp:keywords>…</cp:keywords>` 就在內容後面加上 ` SX-<code>`；否則在 `</cp:coreProperties>` 前插入 `<cp:keywords>SX-<code></cp:keywords>`。
      - ODF：在 `</office:meta>` 前插入 `<meta:keyword>SX-<code></meta:keyword>`。
    - 找不到目標 entry 或結束標籤 → 回 `ErrNoProps`，呼叫者退回 `none`。
    - 用字串操作即可，不需要完整解析 XML。
  - `ZipCodes(data []byte) []string`：讀 `docProps/core.xml`、`docProps/custom.xml`、`meta.xml`（各限 1 MiB）後跑 regex。不是 zip 或讀取錯誤 → 回 nil。
  - `readerAt(rs io.ReadSeeker) io.ReaderAt`：用 mutex 包住 Seek+Read，給 `sxcrypto.OpenPlain` 的結果使用。
- [ ] **Step 1: 寫失敗測試**（以 `archive/zip` 在測試中組出最小的 docx 與 odt）
  - `TestAddZipMetaOOXML`：
    - core.xml 已有 keywords 時 → 原 keywords 保留並加上碼；
    - 沒有 keywords 時 → 插入；
    - 其他 entry 的 bytes（`OpenRaw` 讀出的值）與原本完全相同；
    - `ZipCodes` 找得到碼。
  - `TestAddZipMetaODF`：輸出的第一個 entry 是 `mimetype` 且為 Store；`ZipCodes` 找得到碼。
  - `TestAddZipMetaNoProps`：沒有 core.xml 的 zip → `ErrNoProps`。
  - `TestZipMetaCorruptInput`：輸入不是 zip，或 zip 被截斷 → `AddZipMeta` 回 error、`ZipCodes` 回 nil，都不 panic。
- [ ] **Step 2:** 跑測試，預期 FAIL。
- [ ] **Step 3: 實作**
- [ ] **Step 4:** 執行 `go test ./internal/mark/ -run Zip` → PASS
- [ ] **Step 5: Commit** `feat: OOXML/ODF trace properties via raw zip copy`

---

### Task 5: 選擇標記方式與收件人下載

**Files:**
- Create: `internal/mark/decide.go`, `internal/httpapi/recipient_download.go`（把 `recipientDownload` 從 `recipient_handlers.go` 移過來）
- Modify: `internal/httpapi/server.go`（`Deps.Mark config.MarkConfig`）、`cmd/secure-exchange/main.go`、`internal/httpapi/files_handlers.go`、`internal/httpapi/shares_handlers.go`、`internal/share/share.go`（若 block 檢查需要 `ErrUnmarkable` 與 `FileIDs`）
- Test: `internal/mark/decide_test.go`, `internal/httpapi/recipient_download_test.go`, `internal/httpapi/shares_test.go`（加 case）

**Interfaces:**
- Consumes: Task 1–4 的所有函式、`preview.GetStatus`、`preview.OpenItem`、`preview.Apply`、`preview.Mark`、`sxcrypto.OpenPlain`
- Produces:
  - `type Plan struct{ Method Method; OutName string; Degraded bool; Pending bool }`
  - `Decide(name string, head []byte, size int64, pixels int, p *preview.Preview, watermark bool, cfg config.MarkConfig) Plan`
    - 規則見 Global Constraints 的表與退回規則；
    - `p == nil` 視同 `unsupported`；
    - `pixels` 是圖片的寬×高，由呼叫者以 `image.DecodeConfig` 取得，非圖片時傳 0；
    - `Pending=true` 只在需要 `pdf_pages` 而預覽狀態為 `pending` 時出現；
    - `Degraded` 表示「浮水印開但被退回」。
  - 檔案清單 `GET /api/files` 的每個項目加上 `"mark": {"watermark": "<method>", "plain": "<method>", "degraded": bool}`，`degraded` 對應 watermark=true 的結果。`pixels` 在清單中傳 0，所以圖片的 degraded 只依 `MaxBytes` 判斷；ponytail 註解說明這點。
  - 建立分享：`Policy=="block" && allow_download && watermark` 時，若有任何檔案 `Decide(...).Degraded` → 422 `{"error":"unmarkable","file_ids":[...]}`。這裡的 `head` 由 handler 讀取解密後的前 512 bytes。
  - `recipientDownload` 的流程：
    1. 權限檢查不變，在 `!AllowDownload` 之後執行。
    2. 讀 head（512 bytes）與預覽狀態。若是圖片，讀出全部內容（≤ `MaxBytes`）並用 `DecodeConfig` 取得像素數。然後呼叫 `Decide`。
    3. `Pending` → 409 `mark_pending`。`Degraded && Policy=="block"` → 403 `unmarkable`。
    4. `None`：`mark.Start` 之後，用既有的 `serveFile`，audit detail 加 `trace_code`、`mark`；若狀態為 200 或 206 且整個檔案都已送出（200），就 `Complete` 寫入原檔 sha 與 size。
    5. 其他方式：HEAD → 只送 header（Content-Type、Content-Disposition），不建立紀錄。GET → `Start`，然後透過 `io.MultiWriter(w, sha256)` 產生並送出：
       - `pdf_pages`：`WritePagesPDF`，每頁用 `OpenItem(page or image, i)`，PNG 解碼後 `preview.Apply`；
       - `pdf_meta`：讀原檔進記憶體，`AddPDFMeta` 到 buffer；失敗就退回 `None` 流程（沒有任何 bytes 送出之前，才能這樣退回）；
       - `image_*`：解碼原檔，`image_visible` 先 `preview.Apply` 再 `EmbedInvisible`，然後以原格式編碼（JPEG q92，或 PNG）到 buffer；
       - `ooxml_meta`／`odf_meta`：`AddZipMeta(readerAt(OpenPlain(...)))` 直接寫進 MultiWriter；若在寫出任何 bytes 前就回 `ErrNoProps`，就退回 `None` 流程。
    6. 完整送完 → `Complete(code, sum, n)`，並寫 `file.download` 稽核（detail 含 `trace_code`、`mark`、`status`）。中途失敗 → 只記 log，不 `Complete`。
    7. 之後 `Shares.RecordDownload` 照舊呼叫。
- [ ] **Step 1: 寫失敗測試**
  - `TestDecide`：表格式測試，每一列至少涵蓋：
    - pdf＋ready＋wm → `pdf_pages`；
    - pdf＋pending＋wm → `Pending`；
    - pdf＋too_large＋wm → `pdf_meta`，`Degraded`；
    - pdf 超過 `MaxBytes`＋off → `none`；
    - docx＋ready＋wm → `pdf_pages`，`OutName` 為 `a.pdf`；
    - docx＋failed＋wm → `ooxml_meta`，`Degraded`；
    - docx＋off → `ooxml_meta`；
    - doc＋off → `none`；
    - odt＋off → `odf_meta`；
    - png＋wm → `image_visible`；
    - jpg＋off → `image_invisible`；
    - jpg 像素超過 `MaxPixels` → `none`（wm 時 `Degraded`）；
    - gif → `none`；
    - zip＋wm → `none`，`Degraded`；
    - zip＋off → `none`，不 `Degraded`。
  - `TestRecipientDownloadMarkedPDFPages`（測試用 DB＋假 store；預覽頁直接用 `PutItem` 放 2 張 PNG）：
    - GET 回 200，回應不含 `Accept-Ranges: bytes`，`PDFCodes` 的碼等於 DB 中的新碼；
    - 該列 `sha256` 等於回應 body 的 sha256；
    - 稽核含 `trace_code`；
    - 再 GET 一次 → 不同碼、兩列。
  - `TestRecipientDownloadPDFMeta`、`TestRecipientDownloadImage`、`TestRecipientDownloadOOXML`：各自用 `PDFCodes`、`ExtractInvisible`、`ZipCodes` 讀回碼，並和 DB 比對。
  - `TestRecipientDownloadUnmarkedRange`：zip 檔、Range `bytes=0-9` → 206，再 GET 整份 → 200，兩次都是同一組碼且只有一列，最後 `sha256` 等於原檔的 sha。
  - `TestPendingPreviewNeverServesOriginal`：docx＋wm＋預覽 pending → 409 `mark_pending`，body 不含原檔 bytes，沒有新增 download_traces 列。
  - `TestMarkedDownloadAbortKeepsRow`：有標記的下載中途讓 client 取消（context cancel，或用會在第 N byte 後回 error 的 writer）→ 該列存在、`sha256 IS NULL`，`ByCode` 查得到。
  - `TestUnmarkablePolicyBlock`：`Policy=block`、zip＋wm → 下載回 403 `unmarkable`；建立含此檔案的 allow_download＋wm 分享 → 422 且 `file_ids` 含該檔。`Policy=warn` → 兩者都成功。
  - `TestHeadCreatesNoTrace`：對有標記的檔案發 HEAD → 200，沒有新增任何列。
  - `TestListFilesMark`：清單項目的 `mark` 欄位符合 `Decide` 的結果。
  - `TestRecipientFilesMarkPending`：docx＋wm＋預覽 pending → 檔案清單中該檔 `mark_pending: true`；預覽 ready 或 wm 關 → false。
- [ ] **Step 2:** 跑測試，預期 FAIL。
- [ ] **Step 3: 實作**
- [ ] **Step 4:** 執行 `go test -race ./internal/mark/ ./internal/httpapi/ ./internal/share/` → PASS
- [ ] **Step 5: Commit** `feat: per-download trace marks for recipient downloads`

---

### Task 6: 外流溯源 API

**Files:**
- Create: `internal/mark/inspect.go`, `internal/httpapi/trace_handlers.go`
- Modify: `internal/httpapi/server.go`（路由）、`internal/httpapi/middleware.go`（`requireAdmin`）
- Test: `internal/mark/inspect_test.go`, `internal/httpapi/trace_test.go`

**Interfaces:**
- Produces:
  - `type Found struct{ Code, Via string }`
  - `Inspect(data []byte) []Found`
    - 依 magic 判斷格式：`%PDF-` → `PDFCodes`（meta 標為 `metadata`，text 標為 `text_layer`）；`PK\x03\x04` → `ZipCodes`（`metadata`）；能被 `image.Decode` 解碼（jpeg、png）→ `ExtractInvisible`（`invisible`）。
    - 結果依碼去重，保留 spec §5.6 順序中第一個命中的 `Via`。
  - `requireAdmin(next http.HandlerFunc) http.Handler`：建立在 `requireUser` 之上，`role != "admin"` → 403 `forbidden`。
  - `POST /api/admin/trace`，接受兩種輸入：
    - JSON `{"code": "..."}` 或 `{"sha256": "<64 hex>"}`：碼先去掉前綴 `SX-`、轉大寫、去空白，格式不符 → 400 `bad_code`；
    - multipart 欄位 `file`：用 `r.MultipartReader()` 串流讀取，同時寫入 sha256，並保留前 `MaxBytes+1` bytes；
      - 總長度 ≤ `MaxBytes` → 先 `Inspect`，再對每個碼 `ByCode`，最後 `BySHA`；
      - 超過 → 只做 `BySHA`，回應帶 `"analyzed": false`。
  - 回應：`{"hits": [Hit...], "analyzed": bool, "sha256": "<hex>"}`。`Hit` 序列化為 snake_case JSON，時間用 RFC3339。`hits` 依 Via 順序排列：`metadata`、`text_layer`、`invisible`、`sha256`。`hits` 為空就是「無法判定」，由前端顯示。
  - 稽核：`trace.lookup`，detail `{"by": "code"|"sha256"|"file", "hits": n}`，result `ok`。
  - 每個 IP 的速率限制沿用 `rateLimit`（與 login 相同的設定）。
- [ ] **Step 1: 寫失敗測試**
  - `TestInspect`：分別對 Task 3、4、2 產生的 PDF、docx、jpeg → 得到正確的碼與 Via。
  - `TestTraceByCode`：先做一次下載（直接呼叫 `mark.Start`）→ POST `{"code":"sx-<小寫碼>"}` → 1 筆 hit，email、IP 正確；稽核 `trace.lookup` 的 hits=1。
  - `TestTraceByUpload`：上傳 Task 5 產生的有標記 PDF → 命中 Via=`metadata`；上傳無標記下載的原檔 → Via=`sha256`、Source 為 `file` 與 `download`。
  - `TestTraceGarbageUpload`：上傳 1 KiB 隨機 bytes → 200、`hits` 為空、`analyzed` 為 true。
  - `TestTraceOversizeUpload`：`MaxBytes` 設 1 KiB，上傳 4 KiB → `analyzed` 為 false、`sha256` 正確。
  - `TestTraceAdminOnly`：staff 角色 → 403；未登入 → 401；收件人 cookie → 401。
- [ ] **Step 2:** 跑測試，預期 FAIL。
- [ ] **Step 3: 實作**
- [ ] **Step 4:** 執行 `go test -race ./internal/mark/ ./internal/httpapi/` → PASS
- [ ] **Step 5: Commit** `feat: admin leak-trace API`

---

### Task 7: 前端、文件

**Files:**
- Create: `web/src/pages/admin/Trace.tsx`, `web/src/pages/admin/Trace.test.tsx`
- Modify: `web/src/api.ts`, `web/src/main.tsx`, `web/src/components/ShareDialog.tsx`, `web/src/components/ShareDialog.test.tsx`, `web/src/i18n/en.json`, `web/src/i18n/zh-TW.json`, `web/src/pages/recipient/Access.tsx`, `README.md`, `README.zh-TW.md`, `docker-compose.yml`（env 範例）

**Interfaces:**
- Consumes: Task 5 的 `FileInfo.mark`、Task 6 的 `POST /api/admin/trace`
- Produces:
  - `api.ts`：
    - `FileInfo.mark: { watermark: MarkMethod; plain: MarkMethod; degraded: boolean }`；
    - `api.trace(input: { code: string } | { sha256: string } | File): Promise<TraceResult>`，File 以 `FormData` 送出；
    - `api.createShare` 的 422 `unmarkable` 錯誤要能取得 `file_ids`。
  - `ShareDialog`：勾選允許下載時，依所選檔案的 `mark` 顯示提示：
    - 浮水印開且 `degraded` → 警告 `share.markDegraded`，列出檔名，文案說明「這些檔案無法完整加上追蹤標記，只能靠下載紀錄追蹤」；
    - 方式為 `none` → 提示 `share.markNone`（只記錄下載者與檔案指紋）；
    - Office 浮水印開且為 `pdf_pages` → 提示 `share.officeAsPdf`（對方會拿到加浮水印的 PDF）；
    - 送出得到 422 `unmarkable` 時，顯示 `share.markBlocked` 並標出那些檔案。
  - 收件人 `Access`：Task 5 在 `recipientFiles` 的每個檔案加上 `"mark_pending": bool`，條件是 `watermark` 開、該檔需要 `pdf_pages`，且預覽狀態為 `pending`（只依副檔名與預覽狀態判斷，不讀檔）。onClick 本來就會重新載入檔案清單來檢查 session，若這時 `mark_pending` 為 true，就不跟隨連結，改顯示 `share.markPending`（檔案準備中，請稍後再試）。Task 5 的測試要加 `TestRecipientFilesMarkPending`。
  - `/admin/trace` 頁面，只在 `me.role === "admin"` 時於導覽列顯示 `nav.trace`：
    - 三種查詢方式：追蹤碼輸入、SHA-256 輸入、檔案上傳；
    - 結果表格欄位：來源、方式、追蹤碼、檔案、擁有者、下載者、IP、時間；
    - 沒有結果時顯示 `trace.undetermined`（「無法判定」）；
    - `analyzed=false` 時加註 `trace.notAnalyzed`。
  - README（中英）：
    - 「下載追蹤標記」一節：說明各類型的處理方式（照搬 Global Constraints 的表）、`SX_MARK_MAX_BYTES`／`SX_MARK_MAX_PIXELS`／`SX_UNMARKABLE_POLICY`；
    - 截圖類外流只能靠可見浮水印上的追蹤碼，以人工輸入查詢。
- [ ] **Step 1: 寫失敗測試**
  - `ShareDialog.test`：
    - zip 檔＋允許下載＋浮水印 → 出現 degraded 警告；
    - 關閉允許下載 → 警告消失；
    - docx＋浮水印 → 出現 officeAsPdf 提示；
    - 422 unmarkable → 出現 markBlocked。
  - `Trace.test`：
    - 輸入碼送出 → 呼叫 `/api/admin/trace` 時 body 為 `{"code":…}`，表格顯示 email；
    - 空結果 → 顯示「無法判定」；
    - 上傳檔案時用 FormData；
    - 非 admin 的導覽列不出現 trace 連結（`main.tsx` 的 Shell 依 `me.role` 決定）。
  - `keys.test`：en 與 zh-TW 的 key 集合一致（既有測試會自動涵蓋）。
- [ ] **Step 2:** 跑測試，預期 FAIL。
- [ ] **Step 3: 實作**
- [ ] **Step 4:** 在 `web/` 執行 `npx vitest run --coverage` → PASS，且達到門檻（statements/lines ≥ 90）。
- [ ] **Step 5: Commit** `feat: trace page, share mark warnings, docs`

---

## 完成條件

- `go test -race ./...`（需要 Docker 的測試資料庫）、`golangci-lint run --build-tags tools ./...`、`npx vitest run --coverage` 全部通過。
- CI 的 `coverage` 工作量到的 Go 覆蓋率仍 ≥ 90%（目前是 90.56%）。新的 `internal/mark` 套件要自己達到 90% 以上，不能拉低總數。
- 手動煙霧測試（app＋worker 容器）：
  1. 分享一個 PDF 與一個 docx，設允許下載＋浮水印；
  2. 收件人下載後，打開確認可見浮水印；
  3. 管理員把下載檔上傳到溯源頁，查到該收件人。

## 留到之後

- 管理員政策改由管理介面設定（階段 7）。
- 影片下載燒入浮水印：spec 的表沒有影片，所以歸在「其他」。
- PDF 浮水印開時保留向量與文字：目前輸出只有圖片，這是刻意的取捨，避免 app 在 process 內修改不受信任的 PDF 版面。
- 更強韌的不可見浮水印，例如抗裁切：spec 已說明不在 v1 範圍。
