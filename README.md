# secure-exchange

English | [繁體中文](README.zh-TW.md)

Self-hosted secure file exchange, open source (AGPL-3.0). One Go binary with the web UI embedded, PostgreSQL for metadata, and local disk or S3-compatible storage for file contents.

## Features (phase 1-2)

- Resumable uploads (tus) of very large files; files are encrypted (AES-256-GCM, per-file key wrapped by your master key) before anything touches disk or S3.
- Password login with argon2id, optional TOTP two-factor authentication, rate limiting, hash-chained audit log.
- Web UI in Traditional Chinese and English.
- `rotate-keys` subcommand to move stored data to a new master key.
- One-time shares: send files to named recipients, each verified by an emailed one-time code; expiry, view limit, IP restriction, revocation and notifications.

## Quick deployment

Requires Docker with Compose and a DNS name pointing at the host (ports 80/443 open). Caddy obtains a TLS certificate automatically.

```sh
cp .env.example .env
# edit .env: SX_DOMAIN, POSTGRES_PASSWORD, SX_MASTER_KEYS, initial admin
openssl rand -base64 32      # use the output as the key in SX_MASTER_KEYS=1:<key>
docker compose up -d
```

Open `https://<SX_DOMAIN>` and sign in with `SX_INIT_ADMIN_EMAIL` / `SX_INIT_ADMIN_PASSWORD`. For a local trial use `SX_DOMAIN=localhost` (Caddy's local CA; use `curl -k`). `scripts/smoke.sh` runs an end-to-end upload, resume, download and share check on a throwaway stack (needs Docker; refuses to run if a `.env` exists).

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

Current limitation: shares set to view-only list the files but show no content ("online viewing" is not available yet), and the download button and API are disabled for them.

For local development, `docker-compose.dev.yml` includes mailpit (SMTP on `:51025`, web UI on `http://localhost:58025`); `scripts/smoke.sh` runs the whole flow against a throwaway stack.

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
3. Restart **all** app instances onto the new active key (`docker compose up -d`) **before** the next step, so nothing keeps writing under the old key.
4. Run `docker compose exec app /secure-exchange rotate-keys`. It loads the full configuration (database, keys, SMTP and the rest), so run it inside the app container, where the `.env` settings are present, not on the host. Re-run it until it reports `rotated 0 values`.
5. Only then remove the old key from `SX_MASTER_KEYS` and restart. Keep a backup of the old key until you have verified downloads still work.

## Development

```sh
docker compose -f docker-compose.dev.yml up -d     # postgres :55432, minio :59000, mailpit :51025 (web UI :58025)
export SX_TEST_DATABASE_URL='postgres://sx:sx@localhost:55432/sx?sslmode=disable'
export SX_TEST_S3_ENDPOINT=localhost:59000          # optional; S3 tests skip without it
(cd web && npm ci && npm run build)                 # the Go binary embeds internal/webui/dist
go vet ./... && go test ./...
```

DB tests are skipped when `SX_TEST_DATABASE_URL` is unset. CI runs everything with `-race`.

## License

[AGPL-3.0](LICENSE)
