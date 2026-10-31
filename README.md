# secure-exchange

[![CI](https://github.com/tntrock/secure-exchange/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/tntrock/secure-exchange/actions/workflows/ci.yml)
[![CodeQL](https://github.com/tntrock/secure-exchange/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/tntrock/secure-exchange/security/code-scanning)
[![codecov](https://codecov.io/gh/tntrock/secure-exchange/graph/badge.svg)](https://codecov.io/gh/tntrock/secure-exchange)
[![Go version](https://img.shields.io/github/go-mod/go-version/tntrock/secure-exchange?logo=go)](go.mod)
[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=white)](web/package.json)
[![License: AGPL-3.0](https://img.shields.io/github/license/tntrock/secure-exchange)](LICENSE)

English | [繁體中文](README.zh-TW.md)

Self-hosted secure file exchange, open source (AGPL-3.0). One Go binary with the web UI embedded, PostgreSQL for metadata, and local disk or S3-compatible storage for file contents.

## Features (phase 1-4)

- Resumable uploads (tus) of very large files; files are encrypted (AES-256-GCM, per-file key wrapped by your master key) before anything touches disk or S3.
- Password login with argon2id, optional TOTP two-factor authentication, rate limiting, hash-chained audit log.
- Web UI in Traditional Chinese and English.
- `rotate-keys` subcommand to move stored data to a new master key.
- One-time shares: send files to named recipients, each verified by an emailed one-time code; expiry, view limit, IP restriction, revocation and notifications.
- Online viewer: documents, images and videos are shown as server-rendered pages and video segments, optionally watermarked per recipient; rendering happens in an isolated worker container.
- Download trace marks: every recipient download gets a tracking code and, where the file type allows, an embedded mark; administrators trace leaked files back to the recipient on the **Leak tracing** page.

## Quick deployment

Requires Docker with Compose and a DNS name pointing at the host (ports 80/443 open). Caddy obtains a TLS certificate automatically.

```sh
cp .env.example .env
# edit .env: SX_DOMAIN, POSTGRES_PASSWORD, SX_MASTER_KEYS, initial admin
openssl rand -base64 32      # use the output as the key in SX_MASTER_KEYS=1:<key>
docker compose up -d
```

Open `https://<SX_DOMAIN>` and sign in with `SX_INIT_ADMIN_EMAIL` / `SX_INIT_ADMIN_PASSWORD`. For a local trial use `SX_DOMAIN=localhost` (Caddy's local CA; use `curl -k`). `scripts/smoke.sh` runs an end-to-end upload, resume, download, share and online-viewer check on a throwaway stack (needs Docker; refuses to run if a `.env` exists).

Configuration is entirely through environment variables; every `SX_*` setting is documented in `.env.example`.

## Email (SMTP)

Share invitations, verification codes and notifications are sent by email, so SMTP settings are **required** (the app will not start without `SX_SMTP_HOST` and `SX_SMTP_FROM`). Example for a typical relay, in `.env`:

```sh
SX_SMTP_HOST=smtp.example.com
SX_SMTP_PORT=587
SX_SMTP_USERNAME=apikey-or-user
SX_SMTP_PASSWORD=secret
SX_SMTP_FROM="Secure Exchange <noreply@example.com>"
SX_SMTP_TLS=starttls        # starttls (default), tls (implicit TLS, usually port 465) or none
```

`SX_SMTP_TLS=none` sends mail unencrypted and is accepted only for `localhost`, `127.0.0.1` and `mailpit`; use it for local testing only. `SX_SHARE_MAX_DAYS` (default 30) caps how long a share may last.

## One-time shares

1. In **Shares**, pick files, enter the recipients' email addresses (up to 50), choose whether they may download, an expiry (1 hour up to `SX_SHARE_MAX_DAYS`, default 7 days), and optionally a view limit, IP restriction and a short message.
2. Each recipient gets an invitation email with the share link `https://<SX_DOMAIN>/s/<token>`. There is no password and no open link: the link only works together with a one-time code.
3. The recipient opens the link, enters their email address and receives a 6-digit code (valid 10 minutes, single use, 5 attempts). After entering it they see the files for one hour. Addresses not on the list get exactly the same response, so the list cannot be probed.
4. The view limit counts successful code verifications. IP restrictions and revocation are checked on every request.
5. Revoke a whole share, or a single recipient, at any time; open sessions end immediately. You can also add recipients to an existing share (they get their own invitation).
6. You are notified by email the first time each recipient opens the share (passes verification) and the first time they download each file; later opens and downloads are not mailed. Every step is recorded in the audit log.

For view-only shares the recipient sees the files in the online viewer (below); the download button and API are disabled.

For local development, `docker-compose.dev.yml` includes mailpit (SMTP on `:51025`, web UI on `http://localhost:58025`); `scripts/smoke.sh` runs the whole flow against a throwaway stack.

## Online viewer

Files can be viewed in the browser without downloading them. The browser only ever receives images and video segments the server rendered; the original file, PDF or Office document is never sent by the viewer.

- **Formats:** documents are rendered page by page (PDF, Word/Excel/PowerPoint and OpenDocument, RTF, CSV, plain text, Markdown, JSON/XML/YAML, logs and common source code, HTML); images (JPEG, PNG, GIF, WebP, BMP, TIFF); video (MP4, MOV, M4V, MKV, WebM, AVI) is transcoded to H.264/AAC, up to 720p, streamed as HLS. Other files can still be shared for download.
- **Limits** (environment variables, see `.env.example`): `SX_PREVIEW_MAX_BYTES` (documents/images, default 1 GiB), `SX_PREVIEW_MAX_PAGES` (500), `SX_PREVIEW_MAX_VIDEO_BYTES` (1.5 GiB), `SX_PREVIEW_MAX_VIDEO_SECONDS` (7200), `SX_RENDER_DPI` (110). Larger files are marked as not previewable. **Sizing rule:** the decrypted input and all rendered output share the worker's `/work` tmpfs, which counts against its memory limit, so keep *largest preview input + output ≤ `/work` size (4 GiB) < `mem_limit` (6 GiB)*, with swap disabled. Raise the tmpfs size and `mem_limit` in `docker-compose.yml` together with the limits; a job that still fills `/work` ends as not previewable.
- **View-only shares** require a ready preview: while it is still rendering, the share cannot include the file; files that cannot be previewed can only go in shares that allow download.
- **Watermark:** turn on *watermark* for a share and every page and video segment the recipient sees carries a tiled, semi-transparent line with a tracking code, the time (UTC), their IP and their email address. It is drawn per request and never cached. Your own previews have no watermark.

Previews are rendered by a separate **worker** container (`docker compose up -d` starts it). It runs LibreOffice, poppler and FFmpeg on untrusted files, so it is locked down:

- **No outbound network:** it is attached only to the internal `backend` network (with PostgreSQL and the app); it cannot reach the internet.
- **Read-only root filesystem;** decrypted files and intermediates live only on a tmpfs at `/work` (`SX_WORKER_TMP`, 4 GiB) and are deleted after each job. Rendered pages and segments are encrypted before they are stored.
- **No swap:** `memswap_limit` equals `mem_limit`, so decrypted pages on the tmpfs can never be swapped to disk. The worker refuses to start if `/work` is not a tmpfs (`SX_WORKER_ALLOW_NON_TMPFS=1` overrides this for development only).
- **Resource limits:** 6 GiB memory (including the 4 GiB tmpfs), 2 CPUs, 512 processes; all capabilities dropped, `no-new-privileges`, runs as uid 65532. Every external program has a timeout.

**External S3:** with `SX_STORAGE=s3` and an S3 endpoint outside the compose stack, the worker needs a route to it. Attach it to an additional network in a `docker-compose.override.yml`:

```yaml
services:
  worker:
    networks: [backend, s3]
networks:
  s3: {}
```

That network gives the worker outbound access again, so restrict it at your firewall to the S3 endpoint only.

## Download trace marks

Every download by a share recipient is recorded with a fresh 10-character tracking code (`SX-<code>`), the recipient, IP and time, and the file is marked so a leaked copy can be traced back. Your own downloads are not marked. Methods depend on the file type and on the share's *watermark* setting:

| Type | Watermark on | Watermark off |
|---|---|---|
| PDF | `pdf_pages`: preview pages re-assembled into a PDF with a visible and an invisible watermark; the code is also in the metadata and a hidden text layer | `pdf_meta`: original file with the code written into its metadata |
| Office that can be paged (`.doc .docx .odt .rtf .xls .xlsx .ods .ppt .pptx .odp`) | `pdf_pages`; the recipient receives a watermarked **PDF** (`<name>.pdf`) | `.docx .xlsx .pptx`: `ooxml_meta`; `.odt .ods .odp`: `odf_meta`; `.doc .xls .ppt .rtf`: `none` |
| JPEG / PNG images | `image_visible`: visible and invisible watermark, same format | `image_invisible`: invisible watermark only, same format |
| Everything else (GIF, WebP, TIFF, BMP, video, archives, ...) | `none` | `none` |

`none` records only who downloaded the file and its fingerprint (SHA-256); repeated downloads of the same file by the same recipient share one record and support Range requests. Marked downloads are streamed, so they do not support Range.

Marked images are re-encoded upright (a JPEG's EXIF orientation is applied) and carry no EXIF or ICC colour profile, so colours of wide-gamut photos may shift slightly. `pdf_meta` and image copies are built in memory, at most two at a time; further downloads wait for a free slot.

The method is chosen before the download starts: if a file cannot be marked as the table says, it falls back to a weaker method (`pdf_pages` -> `pdf_meta` -> `none`, images -> `none`), for example when a preview failed, the file is damaged, or it is over a limit. Once a marked download has started sending, there is no fallback: if a page fails midway through a `pdf_pages` download, that download is aborted and the recipient retries. While a preview is still rendering, the download answers 409 and is never replaced by the unmarked original; the UI asks the recipient to try again shortly. The share dialog warns you about files that will fall back.

| Variable | Default | Meaning |
|---|---|---|
| `SX_MARK_MAX_BYTES` | `268435456` (256 MiB) | Largest file the server marks in memory (`pdf_meta`, images) and the largest suspect file the trace page analyses. Must be positive. |
| `SX_MARK_MAX_PIXELS` | `50000000` | Largest image (width x height) that is marked. Must be positive. |
| `SX_UNMARKABLE_POLICY` | `warn` | `warn` delivers the weaker result; `block` refuses the download (403 `unmarkable`) and refuses to create a download share with a watermark that includes such files (422). Applies only to shares with the watermark on. |

**Tracing a leak.** Administrators open **Leak tracing** (`/admin/trace`) and look up a tracking code, a SHA-256, or upload the suspect file (analysed in memory only, never stored). The page reads the metadata, text layer and invisible watermark, and shows who downloaded it, for which file and share, from which IP and when; with no match it says "Undetermined". Screenshots and photos of the screen carry no embedded mark: read the tracking code from the visible watermark and look it up manually.

## ClamAV virus scanning

Files uploaded through upload request links by external users are scanned by ClamAV before the requester can download them. The `clamav` service starts with the stack and the worker feeds it each file (decrypted in memory only, never written to disk).

- The first start downloads the virus signatures, which takes several minutes. Files uploaded meanwhile stay `pending` and are scanned once clamd is ready.
- Infected files are quarantined and cannot be downloaded; the requester and all admins are emailed. A file that cannot be scanned after 5 attempts is blocked and the requester is told.
- Files over `SX_SCAN_MAX_BYTES` (default 1 GiB) are released unscanned, and the requester's email carries a warning.
- To raise the limit, raise all of these together to at least the new value: `SX_SCAN_MAX_BYTES`, `StreamMaxLength` and `MaxFileSize` in `clamd.conf`, and the `/tmp` tmpfs size of `clamav` in `docker-compose.yml` (clamd spools the stream there, in RAM).
- clamd needs about 1.5 to 3 GB of RAM (`mem_limit: 4g`). The `clamav` container is the only one that can reach the internet (the `updates` network, for signature updates).

## Backup

Back up all of these, together:

1. The database: `docker compose exec -T postgres pg_dump -U sx sx > sx.sql`
2. The `sxdata` volume (encrypted blobs and staging), or your S3 bucket:
   `docker run --rm --volumes-from "$(docker compose ps -aq app)" -v "$PWD:/backup" debian:bookworm-slim tar -C /data -czf /backup/sxdata.tgz .`
3. **The `.env` file. It holds the master key(s) in `SX_MASTER_KEYS`. If the key is lost, stored files cannot be decrypted. Keep a copy outside the server.**

## Restore

Restoring requires the **same `SX_MASTER_KEYS` and `SX_ACTIVE_KEY_ID`** as when the backup was taken; without them the restored files cannot be decrypted.

1. Put the backed-up `.env` next to `docker-compose.yml`.
2. Create the containers and empty volumes, start only PostgreSQL, and load the dump into the empty database:
   ```sh
   docker compose create
   docker compose up -d postgres
   docker compose exec -T postgres psql -U sx -d sx -v ON_ERROR_STOP=1 < sx.sql
   ```
3. Restore the `sxdata` volume (or your S3 bucket):
   `docker run --rm --volumes-from "$(docker compose ps -aq app)" -v "$PWD:/backup" debian:bookworm-slim tar -C /data -xzf /backup/sxdata.tgz`
4. Optional: restore the `caddydata` volume the same way (with `caddy` in place of `app`) to keep the TLS certificates; otherwise Caddy obtains new ones.
5. `docker compose up -d`.

## Master key rotation

1. Generate a new key: `openssl rand -base64 32`.
2. Add it to `SX_MASTER_KEYS` next to the old one (`1:<old>,2:<new>`) and set `SX_ACTIVE_KEY_ID=2`.
3. Restart **all** app and worker instances onto the new active key (`docker compose up -d`) **before** the next step, so nothing keeps writing under the old key.
4. Run `docker compose exec app /secure-exchange rotate-keys`. It loads the full configuration (database, keys, SMTP and the rest), so run it inside the app container, where the `.env` settings are present, not on the host. Re-run it until it reports `rotated 0 values`.
5. Only then remove the old key from `SX_MASTER_KEYS` and restart. Keep a backup of the old key until you have verified downloads still work.

## Development

```sh
docker compose -f docker-compose.dev.yml up -d     # postgres :55432, minio :59000, mailpit :51025 (web UI :58025)
export SX_TEST_DATABASE_URL='postgres://sx:sx@localhost:55432/sx?sslmode=disable'
export SX_TEST_S3_ENDPOINT=localhost:59000          # optional; S3 tests skip without it
(cd web && npm ci && npm run build)                 # the Go binary embeds internal/webui/dist
go vet ./... && go test ./...
docker run --rm -v "$PWD:/app" -w /app golangci/golangci-lint:v2.15.0 golangci-lint run --build-tags tools ./...
```

DB tests are skipped when `SX_TEST_DATABASE_URL` is unset. CI runs everything with `-race` and fails if Go (merged with the tools tests) or web statement coverage drops below 90% (`scripts/covergate.sh`, vitest thresholds).

The `//go:build tools` tests (LibreOffice, poppler, FFmpeg) run inside the worker-test image, which joins the dev compose network and reaches PostgreSQL and MinIO by service name (source mounted at `/src`):

```sh
docker compose -f docker-compose.dev.yml --profile tools run --rm worker-test
```

CI runs them in a separate `tools` job.

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

[AGPL-3.0](LICENSE)
