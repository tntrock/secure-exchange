# secure-exchange

[繁體中文](README.md)

[![CI](https://github.com/tntrock/secure-exchange/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/tntrock/secure-exchange/actions/workflows/ci.yml)
[![CodeQL](https://github.com/tntrock/secure-exchange/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/tntrock/secure-exchange/security/code-scanning)
[![codecov](https://codecov.io/gh/tntrock/secure-exchange/graph/badge.svg)](https://codecov.io/gh/tntrock/secure-exchange)
[![Go version](https://img.shields.io/github/go-mod/go-version/tntrock/secure-exchange?logo=go)](go.mod)
[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=white)](web/package.json)
[![License: AGPL-3.0](https://img.shields.io/github/license/tntrock/secure-exchange)](LICENSE)

Self-hosted secure file exchange, open source (AGPL-3.0). One Go binary with the web UI embedded, PostgreSQL for metadata, and local disk or S3-compatible storage for file contents.

## Features

- **Encrypted storage:** resumable uploads (tus) of very large files; files are encrypted (AES-256-GCM, per-file key wrapped by your master key) before anything touches disk or S3; the `rotate-keys` subcommand moves stored data to a new master key.
- **Sign-in:** local accounts (argon2id passwords), domain accounts (LDAP/AD) and single sign-on (OIDC, e.g. Entra ID); optional TOTP two-factor authentication; rate limiting.
- **One-time shares:** send files to named recipients, each verified by an emailed one-time code; expiry, view limit, IP restriction, revocation and notifications.
- **Online viewer:** documents, images and videos are shown as server-rendered pages and video segments, optionally watermarked per recipient; rendering happens in an isolated worker container.
- **Download trace marks and leak tracing:** every recipient download gets a tracking code and, where the file type allows, an embedded mark; administrators trace leaked files back to the recipient on the **Leak tracing** page.
- **Upload requests:** collect files from people without an account via a link; uploaders verify by email code.
- **Vendor accounts:** for long-term partners: password plus mandatory two-factor authentication, a "Shared with me" list, and direct uploads to staff.
- **Virus scanning:** every external upload is scanned by ClamAV; infected files are quarantined.
- **Enforcement rules:** on the **Rules** page administrators set download ban, forced watermark, email-domain and external-IP restrictions, expiry and size limits, storage quota and retention; changes apply immediately, including to existing shares.
- **Audit:** every change is written to a hash-chained audit log that can be verified, exported as CSV and forwarded to a SIEM via syslog; administrators can browse all shares.
- **Automatic cleanup:** files of ended shares are deleted after the retention period, and expired sessions, verification codes and unsent mail are purged hourly.
- **Interface:** the web UI is available in Traditional Chinese and English.

For usage instructions see the [user manual](docs/user-manual.en.md) and the [administrator manual](docs/admin-manual.en.md).

## Quick deployment

Requires Docker with Compose and a DNS name pointing at the host (ports 80/443 open). Caddy obtains a TLS certificate automatically. Images are pulled from `ghcr.io/tntrock/secure-exchange` (app and worker); no local build is needed.

**Option A: download the deployment files from the Release** (works once v1.0.0 is published)

```sh
mkdir secure-exchange && cd secure-exchange && mkdir certs
B=https://github.com/tntrock/secure-exchange/releases/download/v1.0.0
for f in docker-compose.yml .env.example Caddyfile clamd.conf; do
  curl -fsSLO $B/$f && curl -fsSLO $B/$f.sha256
done
sha256sum -c *.sha256
cp .env.example .env
```

**Option B: git clone and check out the version tag**

```sh
git clone https://github.com/tntrock/secure-exchange.git && cd secure-exchange
git checkout v1.0.0
mkdir -p certs
cp .env.example .env
```

`certs/` is mounted read-only into the containers (CA files for LDAP, OIDC and syslog); it may stay empty. Then:

```sh
# edit .env: SX_DOMAIN, POSTGRES_PASSWORD, SX_MASTER_KEYS, initial admin
openssl rand -base64 32      # use the output as the key in SX_MASTER_KEYS=1:<key>
docker compose pull
docker compose up -d
```

To build from source (development or local changes), use the overlay: `docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build`.

Open `https://<SX_DOMAIN>` and sign in with `SX_INIT_ADMIN_EMAIL` / `SX_INIT_ADMIN_PASSWORD`. For a local trial use `SX_DOMAIN=localhost` (Caddy's local CA; use `curl -k`). `scripts/smoke.sh` runs an end-to-end upload, resume, download, share and online-viewer check on a throwaway stack (needs Docker; refuses to run if a `.env` exists).

If the host's HTTPS port is not 443 (`SX_HTTPS_PORT`), set `SX_BASE_URL=https://<domain>:<port>` in `.env`; otherwise links in emails and the OIDC callback URL will lack the port.

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

- **No outbound network:** it is attached only to the internal `backend` network (with PostgreSQL and the app) and the internal `scan` network (with clamav); it cannot reach the internet.
- **Read-only root filesystem;** decrypted files and intermediates live only on a tmpfs at `/work` (`SX_WORKER_TMP`, 4 GiB) and are deleted after each job. Rendered pages and segments are encrypted before they are stored.
- **No swap:** `memswap_limit` equals `mem_limit`, so decrypted pages on the tmpfs can never be swapped to disk. The worker refuses to start if `/work` is not a tmpfs (`SX_WORKER_ALLOW_NON_TMPFS=1` overrides this for development only).
- **Resource limits:** 6 GiB memory (including the 4 GiB tmpfs), 2 CPUs, 512 processes; all capabilities dropped, `no-new-privileges`, runs as uid 65532. Every external program has a timeout.

**External S3:** with `SX_STORAGE=s3` and an S3 endpoint outside the compose stack, the worker needs a route to it. Attach it to an additional network in a `docker-compose.override.yml`:

```yaml
services:
  worker:
    networks: [backend, scan, s3]
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

## Upload requests

Upload requests let you collect files from people who have no account: you send them a link, they prove their email with a one-time code and upload straight into your file list.

**Creating a link.** Open **Requests** (`/requests`), fill in the form and press **Create request**:

- **Uploaders**: up to 50 email addresses (comma or newline separated). Only these people can sign in to the link.
- **Expires on**: end of that day; at most `SX_SHARE_MAX_DAYS` from now.
- **Max files** and **max total size (GB)**: limits for the whole request, shared by all uploaders.
- **Allowed extensions**: optional, for example `pdf, docx`. Empty means any type.
- **Message**: optional, shown to uploaders.

The detail page shows the link (copy it and send it to the uploaders yourself), the uploaders, and every uploaded file with its scan status. **Revoke request** ends the link immediately; files already uploaded stay in your file list.

**What uploaders see.** The link (`/r/<token>`) asks for their email, emails a 6-digit code, then shows the limits (allowed types, files left, space left) and a resumable uploader. Each uploader sees only their own files. Files that break a limit are refused before the upload starts, and again by the server.

**Scan states.** Files from upload requests are checked by ClamAV (see below) and show a badge on the detail page and in **My files**:

| Badge | Meaning for you |
|---|---|
| Scanning (`pending`) | Waiting for the scan. Download, preview and sharing are disabled; the page refreshes by itself. |
| No virus found | Scanned, nothing found. Works like any other file. |
| Infected | A signature matched (its name is shown). Quarantined: no download, preview or sharing. |
| Not scanned (`skipped`) | Larger than `SX_SCAN_MAX_BYTES`, released unscanned. Treat with caution. |
| Scan failed (`error`) | Could not be scanned after 5 attempts. Blocked like an infected file. |

Your own uploads are not scanned and show no badge.

## Vendor accounts

Vendor accounts are for outside people you work with often. Unlike a one-time share recipient, a vendor has a password and mandatory two-factor authentication (TOTP), and sees what is shared with them in a "Shared with me" list.

**Creating a vendor.** Open **Vendors** (`/vendors`), enter the email, display name, optional organisation and an expiry date, and press **Create and invite**. Who may create vendors is set by `SX_VENDOR_CREATION`:

| Value | Meaning |
|---|---|
| `staff` | Any staff member creates active vendor accounts directly. |
| `approval` (default) | Staff create a request; an administrator approves or rejects it on the same page. |
| `admin` | Only administrators create vendor accounts. |

**Invitation.** The vendor receives an email with a link (`/invite/<token>`, valid 7 days, single use). On that page they scan the QR code with an authenticator app, choose a password (at least 12 characters) and enter the 6-digit code. A newer invitation (**Reinvite**) replaces the old link. Accounts can be disabled (all their sessions end at once) and expire on the chosen date.

**Sharing.** In the share dialog, pick vendors in addition to or instead of email recipients. Any staff member may share to any active vendor. Vendors skip the email-code step; view mode, watermark, expiry, view limit and IP rules apply as for one-time shares, and the watermark names the vendor's email.

**What vendors see.** After login they land on **Shared with me** (`/vendor/shares`): each share with its owner, message, expiry and files, where they can view and download. **Upload** (`/vendor/upload`) lets them send files to staff who shared with them or who created their account; they never see the full staff list. Vendor uploads are scanned by ClamAV like upload request files and appear in the staff member's **My files** with the vendor's name.

## ClamAV virus scanning

Files uploaded by external users, through upload request links or directly by vendors, are scanned by ClamAV before the receiving staff member can download them. The `clamav` service starts with the stack and the worker feeds it each file (decrypted in memory only, never written to disk).

- The first start downloads the virus signatures, which takes several minutes. Files uploaded meanwhile stay `pending` and are scanned once clamd is ready.
- Infected files are quarantined and cannot be downloaded; the requester and all admins are emailed. A file that cannot be scanned after 5 attempts is blocked and the requester is told.
- Files over `SX_SCAN_MAX_BYTES` (default 1 GiB; ClamAV imposes a hard ceiling of about 4000 MiB) are released **unscanned**, with a warning badge and a warning in the requester's email. This is an accepted deviation from "every external upload is scanned"; an option to block such files instead is planned together with the admin rules.
- To raise the limit, raise all of these together to at least the new value: `SX_SCAN_MAX_BYTES`, `StreamMaxLength` and `MaxFileSize` in `clamd.conf`, and the `/tmp` tmpfs size of `clamav` in `docker-compose.yml` (clamd spools the stream there, in RAM).
- ClamAV's scan-time, size and archive limits stop a scan early and still report OK (`AlertExceedsMax` is `no`), so "No virus found" means no virus was found within ClamAV's limits, not that the file is proven clean.
- clamd needs about 1.5 to 3 GB of RAM (`mem_limit: 4g`). The worker has no internet access; `clamav` sits on its own `updates` network, which has egress for signature updates. (The `app` and `caddy` containers are on the `sx` network, which also has egress.)

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

### End-to-end tests

`e2e/` holds Playwright browser tests (Chromium only). `scripts/e2e.sh` builds from source (applying `docker-compose.build.yml`) and starts a throwaway compose stack (project `sxe2e`, HTTPS `:59443`, mailpit `:59025`, Dex for the OIDC test `:59556`), waits for it, runs the tests, and on exit (failure and Ctrl-C included) removes the stack, its volumes and its temporary `.env`:

```sh
(cd e2e && npm ci && npx playwright install chromium)   # once; on Linux use npx playwright install --with-deps chromium
scripts/e2e.sh                                          # all; arguments go to playwright, e.g. tests/auth.spec.ts
E2E_KEEP=1 scripts/e2e.sh tests/auth.spec.ts            # leave the stack up afterwards for debugging
scripts/e2e.sh tests/admin.spec.ts --no-deps               # admin only (without --no-deps the chromium project runs in full first)
```

Needs Docker, Node.js and `openssl`; refuses to run if a `.env` exists. ClamAV signatures are kept in `.e2e-clamav/`; the first run downloads a few hundred MB, and on Linux the directory ends up owned by uid 100 (the ClamAV container chowns it), so removing it needs sudo. Open the traces of failed tests with `cd e2e && npx playwright show-report` (or `npx playwright show-trace test-results/<test>/trace.zip`); all service logs are in `e2e/test-results/compose.log`. The test stack's Caddy trusts the `X-Forwarded-For` the tests send so that each test gets its own rate-limit budget (e2e only). OIDC sign-in is tested against Dex (`https://dex.localhost:59556/dex`, self-signed cert in the temporary `.e2e-dex/`). There is no LDAP end-to-end test (the Go tests cover it against a stub). CI runs it via `.github/workflows/e2e.yml` on every non-docs PR and push to main (not a required check yet); on failure `playwright-report` and `test-results` (incl. `compose.log`) are uploaded as artifacts for 7 days.

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

[AGPL-3.0](LICENSE)
