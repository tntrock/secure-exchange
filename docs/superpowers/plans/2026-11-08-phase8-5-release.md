# Phase 8.5 映像發布與 v1.0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 推送 `v*` tag 就能自動建置、smoke 測試、推送 ghcr 映像並建立 GitHub Release；使用者用 `docker compose pull` 就能部署。

**Architecture:** 版本號只寫在 `VERSION`，Docker build arg 經 ldflags 寫進執行檔。`docker-compose.yml` 改為只引用 ghcr 映像（固定版本），本機建置移到新的 `docker-compose.build.yml` overlay；smoke、e2e、開發流程改用 overlay。新的 `release.yml` workflow 由 tag 觸發，另有 `workflow_dispatch` 演練模式（只 build + smoke，不推送、不發布），讓打 tag 前能先實測。

**Tech Stack:** Go、React/TS（i18n）、Docker、docker compose、GitHub Actions、`gh`。

**Spec:** `docs/superpowers/specs/2026-11-07-phase8-release-design.md` §6

## Global Constraints

- 映像：`ghcr.io/tntrock/secure-exchange`（Dockerfile `app` target）、`ghcr.io/tntrock/secure-exchange-worker`（`worker` target）；只建 `linux/amd64`。
- 標籤：`X.Y.Z`、`X.Y`、`latest`（v1.0.0 → `1.0.0`、`1.0`、`latest`）。
- `VERSION` 內容為 `1.0.0`（無 `v`、結尾換行）。
- tag 必須等於 `v` + `VERSION`，否則 release workflow 失敗。
- `docker-compose.yml` 中兩個映像標籤必須等於 `VERSION`（CI 檢查）。
- 第三方 action 一律釘 commit SHA 並註明版本（依 `e2e.yml` 慣例）。
- 映像以非 root 執行（`65532:65532`），不含 `.env`、金鑰、測試資料。
- 任一步失敗即停止：不推送、不發布。
- 一般 CI 與 e2e 繼續用本機 build，不依賴 ghcr。
- Release 附件：`docker-compose.yml`、`Caddyfile`、`clamd.conf`、`.env.example`，以及各自的 `.sha256`。
- 版本說明中英文各一段：功能清單、映像名稱、架設步驟連結。
- 中英文件結構一致；新增的 UI 字串 en/zh-TW 鍵值一致（`keys.test.ts`）。
- 覆蓋率門檻 90% 不變。

## Rulings（控制者決定）

- **版本號顯示位置**：啟動 log（app 與 worker）與管理員頁尾。版本只回給管理員：`GET /api/me` 在 role 為 admin 時多一個 `version` 欄位，其他角色不含，避免對外洩漏版本。
- **build overlay 檔名** `docker-compose.build.yml`（`docker-compose.dev.yml` 已是開發用資料庫，不混用）。
- **smoke 使用已建好的映像**：`scripts/smoke.sh` 預設加上 build overlay 並 `--build`；環境變數 `SMOKE_PREBUILT=1` 時不加 overlay、不 `--build`，直接用本機已有的 `ghcr.io/...:<VERSION>` 映像。release workflow 先 build 並打上最終標籤，再以 `SMOKE_PREBUILT=1` 跑 smoke，推送的就是測過的同一個映像。
- **演練模式**：`release.yml` 加 `workflow_dispatch`（無輸入），只執行到 smoke 為止；推送與 Release 步驟以 `if: startsWith(github.ref, 'refs/tags/v')` 限制。
- **ghcr 可見性**：第一次推送後套件可能預設為 private。發布後要用未登入的 `docker pull` 驗證；若是 private，由使用者在套件設定改成 public（這是帳號設定，Claude 不代為更改）。

## Review Focus

- tag 與 `VERSION` 不一致（例如 `v1.0.1` 但 VERSION 仍是 1.0.0）→ workflow 在任何 build 之前就失敗。
- `SMOKE_PREBUILT=1` 但本機沒有映像 → compose 會嘗試去 ghcr 拉取；release workflow 中必須確保先 build 再 smoke（`pull_policy` 不需調整，但 smoke 前要 `docker image inspect` 確認兩個映像存在）。
- 使用者只下載 Release 附件（沒有原始碼）也要能 `docker compose up -d`：`docker-compose.yml` 不可引用 repo 內其他檔案以外的路徑；確認它引用的 `Caddyfile`、`clamd.conf` 都在附件中。
- 頁尾版本只在管理員看到；非管理員 `/api/me` 不含 `version`。
- 未設 build arg 時（本機 `go build`、overlay build）版本顯示 `dev`，不會是空字串。

---

### Task 1: 版本號寫入執行檔並顯示

**Files:**
- Create: `VERSION`
- Modify: `Dockerfile`（build stage）、`cmd/secure-exchange/main.go`、`internal/httpapi/server.go`（Deps 加 `Version string`）、`internal/httpapi/auth_handlers.go`（`me`）、管理員頁尾所在元件（`web/src/components/Shell.tsx`）、`web/src/i18n/en.json`、`web/src/i18n/zh-TW.json`
- Test: `internal/httpapi/auth_test.go`（或 me 相關測試檔）、`web/src/components/Shell.test.tsx`

**Interfaces:**
- Produces: `main.version`（預設 `"dev"`，ldflags `-X main.version=...` 覆寫）；`Deps.Version`；`/api/me` 的 `version`（僅 admin）；Dockerfile `ARG VERSION=dev`。

- [ ] **Step 1: Go 失敗測試** `TestMeVersionAdminOnly`：`newEnv` 以 mod 設 `d.Version = "9.9.9"`；admin 登入 `/api/me` → `version == "9.9.9"`；staff 登入 → JSON 不含 `version` 鍵。
- [ ] **Step 2: 前端失敗測試**：Shell 以 admin 的 me（`version: "9.9.9"`）渲染時出現文字 `v9.9.9`；以 staff 渲染時沒有。
- [ ] **Step 3: 實作**：`VERSION` 寫 `1.0.0`；main.go `var version = "dev"`，app 與 worker 啟動 log 各加 `version` 欄位（沿用現有 slog 啟動訊息），並傳入 `Deps.Version`；`me` 在 `u.Role == "admin"` 時加 `"version"`；Dockerfile build stage 加 `ARG VERSION=dev` 並把 `-X main.version=${VERSION}` 加進現有 `-ldflags`；Shell 對 admin 在頁尾顯示 `v{{version}}`（i18n 鍵 `nav.version`：en `"v{{version}}"`、zh-TW `"v{{version}}"`）。
- [ ] **Step 4: 驗證**：`go test ./internal/httpapi -run Me`；`cd web && npx vitest run --coverage`（含 keys.test 與覆蓋率門檻）；`go build -ldflags "-X main.version=1.2.3" -o $TMP/sx ./cmd/secure-exchange && $TMP/sx 2>&1 | head -1` 含 `1.2.3`（版本 log 必須是 main 的第一個輸出，早於設定載入，所以缺設定時也看得到）；未帶 ldflags 時同指令顯示 `dev`。
- [ ] **Step 5: Commit** `feat: build version in binary, startup log and admin footer`

### Task 2: compose 改用 ghcr 映像，本機建置移到 overlay

**Files:**
- Modify: `docker-compose.yml`（app、worker：移除 `build:`，加 `image:`）、`scripts/smoke.sh`、`scripts/e2e.sh`、`.github/workflows/ci.yml`（docker 工作）
- Create: `docker-compose.build.yml`、`scripts/check-version.sh`、`scripts/check-image.sh`

**Interfaces:**
- Consumes: Task 1 的 `VERSION`、Dockerfile `ARG VERSION`。
- Produces: `docker-compose.build.yml`；`SMOKE_PREBUILT=1` 行為；`scripts/check-version.sh`（Task 3 的 workflow 也會呼叫，帶 tag 參數時另檢查 tag）。

- [ ] **Step 1: compose**：app `image: ghcr.io/tntrock/secure-exchange:1.0.0`，worker `image: ghcr.io/tntrock/secure-exchange-worker:1.0.0`。`docker-compose.build.yml` 對 app、worker 各給 `build: {context: ., target: app|worker, args: {VERSION: dev}}`（image 名沿用主檔，所以 build 出來的映像會帶同一個標籤）。
- [ ] **Step 2: smoke.sh / e2e.sh**：`dc()` 加入 `-f docker-compose.build.yml`；smoke.sh 在 `SMOKE_PREBUILT=1` 時不加 overlay、`up -d` 不帶 `--build`，並在 up 前用 `docker image inspect` 確認兩個映像存在，不存在就印出訊息並 exit 1。更新兩個腳本開頭的說明註解。
- [ ] **Step 3: `scripts/check-version.sh [tag]`**（POSIX sh）：讀 `VERSION`；檢查 `docker-compose.yml` 恰有兩行 `image: ghcr.io/tntrock/secure-exchange(-worker)?:<VERSION>`；給了 tag 時檢查 tag == `v<VERSION>`。不一致時印出期望值與實際值並 exit 1。手動驗證三種情況：一致 → 0；改壞 compose 標籤 → 1；`check-version.sh v9.9.9` → 1。
- [ ] **Step 4: CI**：`ci.yml` 的 docker 工作改為：`sh scripts/check-version.sh`；`docker build --target app -t sxapp .` 與 `--target worker -t sxworker .`；兩者 `docker inspect -f "{{.Config.User}}"` 必須等於 `65532:65532`；兩者 `docker export $(docker create IMG) | tar -t | grep -E "(^|/)\.env$|/testdata/|^src/"` 必須沒有輸出（用 `! grep -q` 讓找到時失敗）。把這段寫成 `scripts/check-image.sh IMG...` 供 Task 3 共用。
- [ ] **Step 5: 本機驗證**：`scripts/e2e.sh` 全過（overlay 生效）；`docker compose -f docker-compose.yml -f docker-compose.build.yml config` 顯示 build 區段；只用 `docker-compose.yml` 的 `config` 不含 build。
- [ ] **Step 6: Commit** `build: compose pulls ghcr images; local builds via docker-compose.build.yml`

### Task 3: release workflow 與版本說明

**Files:**
- Create: `.github/workflows/release.yml`、`docs/release-notes/v1.0.0.md`

**Interfaces:**
- Consumes: `scripts/check-version.sh <tag>`、`SMOKE_PREBUILT=1 scripts/smoke.sh`、Dockerfile `ARG VERSION`。

- [ ] **Step 1: workflow**：`on: push: tags: ['v*']` 與 `workflow_dispatch`。單一 job（`ubuntu-latest`，`permissions: contents: write, packages: write`），步驟依序：
  1. checkout（釘 SHA）。
  2. `V=$(cat VERSION)`；tag 觸發時 `sh scripts/check-version.sh "$GITHUB_REF_NAME"`，dispatch 時 `sh scripts/check-version.sh`。
  3. `docker build --build-arg VERSION=$V --target app` 與 `--target worker`，各打上 `:$V`、`:${V%.*}`、`:latest` 三個標籤（OCI label `org.opencontainers.image.source=https://github.com/tntrock/secure-exchange`、`org.opencontainers.image.version=$V`）。
  4. `sh scripts/check-image.sh` 檢查兩個映像（非 root、無 .env/testdata/原始碼）。
  5. `SMOKE_PREBUILT=1 scripts/smoke.sh`。
  6. 以下僅在 `startsWith(github.ref, 'refs/tags/v')`：`docker/login-action`（釘 SHA，`ghcr.io`、`github.actor`、`secrets.GITHUB_TOKEN`）→ `docker push --all-tags` 兩個映像 → 對四個附件各產生 `<file>.sha256`（`sha256sum <file> > <file>.sha256`）→ `gh release create "$GITHUB_REF_NAME" --title "$GITHUB_REF_NAME" --notes-file docs/release-notes/$GITHUB_REF_NAME.md` 附上 8 個檔案。
  - `concurrency: release`，不取消進行中的發布。
- [ ] **Step 2: `docs/release-notes/v1.0.0.md`**：中文段在前、英文段在後，各含功能清單（取 README 功能段）、兩個映像名稱與標籤、架設步驟連結（README「快速部署」與管理員手冊安裝章節的 GitHub 網址，中英各自指向自己語言的文件）、`sha256sum -c` 驗證附件的一行指令。
- [ ] **Step 3: 靜態檢查**：用 `actionlint`（若本機無，`docker run --rm -v "$PWD:/repo" -w /repo rhysd/actionlint:1.7.7`）檢查 `release.yml` 無錯誤。
- [ ] **Step 4: Commit** `ci: tag-triggered release workflow (build, smoke, push, GitHub Release)`

### Task 4: 部署與升級文件改為拉取映像

**Files:**
- Modify: `README.md`、`README.en.md`、`docs/admin-manual.md`、`docs/admin-manual.en.md`

- [ ] **Step 1: 快速部署**（README 與管理員手冊「3. 安裝部署」，中英同步）：兩種方式——(a) 從 Release 下載 `docker-compose.yml`、`Caddyfile`、`clamd.conf`、`.env.example` 並以 `sha256sum -c` 驗證；(b) `git clone` 後 checkout tag。接著編輯 `.env`、`docker compose pull`、`docker compose up -d`。註明 `docker pull` 指令在 v1.0.0 發布後才有效。
- [ ] **Step 2: 從原始碼建置**：一小節，指令 `docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build`；開發環境與 e2e 段落提到 overlay。
- [ ] **Step 3: 升級**（管理員手冊「15. 升級」中英）：備份 → 閱讀版本說明並比對 `.env.example` → 換成新版的 `docker-compose.yml`（或改映像標籤）→ `docker compose pull && docker compose up -d` → 健康檢查。移除 `git pull` 與 `--build` 的寫法（從原始碼建置者改看上一小節）。
- [ ] **Step 4: 驗證**：`go test ./internal/config`；`grep -c '^#'` 中英 README、管理員手冊各自相同；全文搜尋 `up -d --build` 只出現在「從原始碼建置」、開發與 e2e 段落。
- [ ] **Step 5: Commit** `docs: deploy and upgrade from published images`
