# Secure Exchange: Administrator Manual

[繁體中文](admin-manual.md)

This manual is for administrators who deploy and operate the Secure Exchange system. For day-to-day tasks (uploading, sharing, upload requests, vendors), see the [User Manual](user-manual.en.md).

## Contents

1. [Architecture](#1-architecture)
2. [Requirements](#2-requirements)
3. [Installation](#3-installation)
4. [Configuration reference](#4-configuration-reference)
5. [Accounts and permissions](#5-accounts-and-permissions)
    - [Single sign-on accounts (OIDC / Entra ID)](#single-sign-on-accounts-oidc--entra-id)
6. [Vendor account management](#6-vendor-account-management)
7. [Mandatory rules](#7-mandatory-rules)
8. [Leak tracing (tracking down leaks)](#8-leak-tracing-tracking-down-leaks)
9. [Virus scanning (ClamAV)](#9-virus-scanning-clamav)
10. [Online preview worker](#10-online-preview-worker)
11. [Audit log](#11-audit-log)
    - [11.1 Forwarding to a SIEM (syslog)](#111-forwarding-to-a-siem-syslog)
12. [Email](#12-email)
13. [Backup and restore](#13-backup-and-restore)
14. [Master key rotation](#14-master-key-rotation)
15. [Upgrading](#15-upgrading)
16. [Monitoring and troubleshooting](#16-monitoring-and-troubleshooting)
17. [Security checklist](#17-security-checklist)

---

## 1. Architecture

The system runs on Docker Compose and consists of these services:

| Service | Purpose | Networks |
|---|---|---|
| `caddy` | Public HTTPS entry point; obtains and renews TLS certificates automatically | `sx` (internet access) |
| `app` | Main program: web UI, API, login, sharing, uploads, outgoing mail | `sx`, `backend` |
| `worker` | Background jobs such as preview conversion and virus scanning | `backend`, `scan` (**no internet access**) |
| `clamav` | Virus scanning engine clamd | `scan`, `updates` (internet access only to update signatures) |
| `postgres` | Database (metadata, audit log) | `backend` |

Data storage:

| Volume | Contents |
|---|---|
| `pgdata` | PostgreSQL data |
| `sxdata` | Encrypted files and in-progress upload staging files (with S3, files are stored in S3 instead) |
| `caddydata` | TLS certificates |
| `clamdb` | Virus signature database |

**Encryption**: every file has its own data key (AES-256-GCM), and the data key is wrapped by the master key (`SX_MASTER_KEYS`). Preview pages and video segments are also encrypted before they are stored. **If the master key is lost, no file can be decrypted.**

## 2. Requirements

- A Linux host with Docker and Docker Compose installed.
- A domain name pointing at the host, with ports 80 and 443 open (needed for Caddy to obtain certificates automatically).
- A working SMTP service (**required**: invitations and verification codes depend on it).
- Memory: the worker is capped at 6 GB and clamav at 4 GB; together with the app, the database and the OS, **16 GB or more is recommended**.
- CPU: 4 cores or more recommended (video conversion is CPU-intensive).
- Disk: depends on the total volume of files. The encrypted size is roughly the same as the original; reserve extra space for preview artifacts.

## 3. Installation

### 3.1 Prepare the configuration file

```sh
git clone https://github.com/tntrock/secure-exchange.git
cd secure-exchange
cp .env.example .env
```

Edit `.env` and fill in at least the following:

| Item | Description |
|---|---|
| `SX_DOMAIN` | Public domain, e.g. `files.example.com` |
| `POSTGRES_PASSWORD` | Database password, letters and digits only. Generate with `openssl rand -hex 24` |
| `SX_MASTER_KEYS` | Master key, in the form `1:<key>`. Generate with `openssl rand -base64 32` |
| `SX_ACTIVE_KEY_ID` | ID of the key currently in use; use `1` for a first install |
| `SX_INIT_ADMIN_EMAIL` | Email of the first administrator |
| `SX_INIT_ADMIN_PASSWORD` | Password of the first administrator; use a long password |
| `SX_SMTP_HOST`, `SX_SMTP_FROM` | Mail server and sender (see [Email](#12-email)) |

> **Back up `.env` right away to a safe place off the server** (for example a password manager or offline media). The master key exists only in this file.

### 3.2 Start

```sh
docker compose up -d
```

The first start builds the images and ClamAV downloads its virus signatures (a few minutes). When it finishes, open `https://<SX_DOMAIN>`.

### 3.3 First login

1. Log in with `SX_INIT_ADMIN_EMAIL` and `SX_INIT_ADMIN_PASSWORD`. The administrator account is created only once, when the database has **no users at all**.
2. Immediately go to "My files" → "Two-factor settings" and enable two-factor authentication for the administrator account.
3. After the account exists, you can remove `SX_INIT_ADMIN_PASSWORD` from `.env` (it is no longer used) and run `docker compose up -d` again.

### 3.4 Trying it locally

With `SX_DOMAIN=localhost`, Caddy uses a local CA, so the browser shows a certificate warning and `curl` needs `-k`. The bundled `scripts/smoke.sh` automatically runs a complete end-to-end test (upload, resume, sharing, online viewing, leak tracing, upload requests and virus scanning) in a throwaway environment, and can be used to validate the host environment. It needs Docker, and refuses to run if a `.env` already exists.

## 4. Configuration reference

All settings are environment variables in `.env`; after changing them, run `docker compose up -d` to apply. The full descriptions are also in `.env.example`.

### Deployment and basics

| Variable | Default | Description |
|---|---|---|
| `SX_DOMAIN` | (required) | Public domain |
| `POSTGRES_PASSWORD` | (required) | Password of the built-in database |
| `SX_HTTP_PORT`／`SX_HTTPS_PORT` | 80／443 | Host ports exposed to the outside |
| `SX_BASE_URL` | `https://${SX_DOMAIN}` (compose); can be overridden in `.env` | Public URL, used for links in emails and the OIDC callback. **Does not include `SX_HTTPS_PORT`**; see the note below |
| `SX_LISTEN` | `:8080` | Listen address inside the container (no change needed with compose; Caddy forwards to it) |
| `SX_DATABASE_URL` | Assembled automatically by compose | PostgreSQL connection URL; required when running the binary directly, while compose builds it from `POSTGRES_PASSWORD` |
| `SX_MASTER_KEYS` | (required) | List of master keys, `id:key` separated by commas |
| `SX_ACTIVE_KEY_ID` | (required) | Which key is used for new data |
| `SX_INIT_ADMIN_EMAIL`／`SX_INIT_ADMIN_PASSWORD` | — | The first administrator |
| `SX_MAX_FILE_SIZE` | 500 GiB | Hard limit for a single uploaded file (bytes); the "Maximum file size" in [Mandatory rules](#7-mandatory-rules) can only be lower than this |
| `SX_SESSION_TTL` | `12h` | How long a login session stays valid |
| `SX_TRUSTED_PROXIES` | (set automatically by compose) | Which reverse proxies' `X-Forwarded-For` is trusted |

**When the host HTTPS port is not 443**: by default compose sets `SX_BASE_URL` for the app and worker to `https://${SX_DOMAIN}`, without `SX_HTTPS_PORT`, so links in emails and the OIDC callback URL lack the port. Add `SX_BASE_URL=https://<domain>:<port>` (for example `https://files.example.com:8443`) to `.env`, and compose will use that value instead.

(When running the binary directly instead of through compose, set `SX_BASE_URL` in the environment.)

### Storage

| Variable | Default | Description |
|---|---|---|
| `SX_STORAGE` | `local` | `local` (stored in the `sxdata` volume) or `s3` |
| `SX_STORAGE_DIR` | `/data/blobs` | Directory for encrypted files when `local` (in compose, inside the `sxdata` volume) |
| `SX_STAGING_DIR` | `/data/staging` | Encrypted staging directory for uploads in progress |
| `SX_S3_ENDPOINT`, `SX_S3_BUCKET`, `SX_S3_ACCESS_KEY`, `SX_S3_SECRET_KEY`, `SX_S3_REGION`, `SX_S3_USE_SSL` | — | S3-compatible storage settings |

If you use S3 and the S3 service is outside compose, the worker must be able to reach S3 too. Create a `docker-compose.override.yml` that attaches the worker to one more network, and use the firewall to restrict that network to the S3 endpoint only:

```yaml
services:
  worker:
    networks: [backend, scan, s3]
networks:
  s3: {}
```

### Sharing

| Variable | Default | Description |
|---|---|---|
| `SX_SHARE_MAX_DAYS` | `30` | **Initial value** of the maximum share lifetime: written only on the first start, when the rules are created. Afterwards change it under "Rules" in the admin pages; see [Mandatory rules](#7-mandatory-rules) |

### Online preview

| Variable | Default | Description |
|---|---|---|
| `SX_PREVIEW_MAX_BYTES` | 1 GiB | Maximum size of documents and images that can be previewed |
| `SX_PREVIEW_MAX_PAGES` | `500` | Maximum number of pages converted per document |
| `SX_PREVIEW_MAX_VIDEO_BYTES` | 1.5 GiB | Maximum size of videos that can be previewed |
| `SX_PREVIEW_MAX_VIDEO_SECONDS` | `7200` | Maximum length of videos that can be previewed (seconds) |
| `SX_RENDER_DPI` | `110` | Resolution of rendered document pages |
| `SX_WORKER_TMP` | `/work` | Scratch directory where the worker holds decrypted plaintext; it must already exist and be a tmpfs (compose mounts `/work`) |
| `SX_WORKER_ALLOW_NON_TMPFS` | (unset) | When set to `1`, the worker allows a scratch directory that is not a tmpfs. **For development and testing only**: plaintext would reach disk, so do not set it in production |

When you raise the limits, also adjust the worker's `/work` tmpfs and `mem_limit`; see [Online preview worker](#10-online-preview-worker).

### Download tracking marks

| Variable | Default | Description |
|---|---|---|
| `SX_MARK_MAX_BYTES` | 256 MiB | Maximum size of files that are marked in memory (PDF metadata, images); also the analysis limit for files uploaded to leak tracing |
| `SX_MARK_MAX_PIXELS` | 50,000,000 | Maximum pixel count of images that can be marked |
| `SX_UNMARKABLE_POLICY` | `warn` | `warn`: files that cannot be fully marked are still delivered; `block`: such downloads are refused, and shares with "Allow download" + watermark that contain such files cannot be created |

### Virus scanning

| Variable | Default | Description |
|---|---|---|
| `SX_CLAMD_ADDR` | (set automatically by compose) | clamd address |
| `SX_SCAN_MAX_BYTES` | 1 GiB | External uploads larger than this are **let through without scanning** (marked "Not scanned (too large)") |

### Vendor accounts

| Variable | Default | Description |
|---|---|---|
| `SX_VENDOR_CREATION` | `approval` | Who can create vendor accounts; see [Vendor account management](#6-vendor-account-management) |

### Audit forwarding

For `SX_SYSLOG_ADDR`, `SX_SYSLOG_TRANSPORT` and `SX_SYSLOG_CA`, see [Forwarding to a SIEM](#111-forwarding-to-a-siem-syslog).

### Domain login (LDAP/AD)

For `SX_LDAP_*`, see [Domain accounts (LDAP/AD)](#domain-accounts-ldapad).

### Single sign-on (OIDC)

For `SX_OIDC_*`, see [Single sign-on accounts (OIDC / Entra ID)](#single-sign-on-accounts-oidc--entra-id).

### Email

See [Email](#12-email).

## 5. Accounts and permissions

### Roles

| Role | What they can do |
|---|---|
| Administrator (admin) | Everything staff can do, plus: user management, site-wide share browsing, leak tracing, approving/rejecting vendor requests, managing all vendor accounts, receiving virus-infection notifications |
| Staff | Upload files, create shares, create upload requests, create vendors (depending on policy), manage the vendors they created |
| Vendor | Can only see "Shared with me" and upload to permitted staff; cannot see any staff-side page |
| External recipient / uploader | Has no account; gets single-use, time-limited access with an email verification code |

The system re-checks the account status on **every request**: once an account is disabled or expired, its next request is rejected, without waiting for the session to time out.

### User management

After logging in, click "Users" at the top (visible to administrators only). The page lists all accounts (including vendors): email, display name, role, source, status, TOTP and last login time.

**Adding a staff member or administrator**: click "New staff account", enter the email and display name, choose a role (staff or administrator), and click "Create and invite"; the system sends an invitation email. The recipient opens the `/activate/<token>` link (valid for 7 days, single use; after a re-invite the old link stops working) and sets a password (at least 12 characters) to activate. If [site-wide mandatory two-factor authentication](#site-wide-mandatory-two-factor-authentication) is on, they must also bind an authenticator app during activation. Staff activation links are **not** subject to "Allowed networks for external users"; vendor invitation links still are.

**Actions on each row**:

| Action | Description |
|---|---|
| Disable / Enable | Disabling immediately ends all of that account's active sessions, and the shares and upload requests the account created stop working at once (see [Site-wide share browsing](#site-wide-share-browsing)). Enabling restores the account. |
| Change role | Switch between staff and administrator; local accounts only. |
| Reset TOTP | See "Staff member loses their two-factor device" below and [A vendor loses their authenticator device](#a-vendor-loses-their-authenticator-device). |
| Reinvite | Only for staff in the "Invited" status: sends a new link and invalidates the old one. |

The initial administrator is still created by the `SX_INIT_ADMIN_*` environment variables on first start. For LDAP domain login see [Domain accounts (LDAP/AD)](#domain-accounts-ldapad); for OIDC single sign-on see [Single sign-on accounts (OIDC / Entra ID)](#single-sign-on-accounts-oidc--entra-id). Accounts from external login sources (LDAP, OIDC) can still be disabled and enabled here; however their role and two-factor authentication are determined by the external source, so you cannot change the role or reset TOTP here.

### Staff member loses their two-factor device

First verify the person's identity (for example in person or by phone), then go to the "Users" page and click "Reset TOTP" on that staff member. The system clears the two-factor authentication, keeps the password, and ends all of their sessions. The person logs in with the password and sets it up again; if site-wide mandatory two-factor authentication is on, they are required to set it up immediately after logging in. The action is written to the audit log as `user.totp_reset`.

### Site-wide mandatory two-factor authentication

When "Require two-factor authentication for local staff and administrators" on the "Rules" page is turned on, **local staff and administrators** who have not set up two-factor authentication must finish binding an authenticator after the password login before they can use anything else. Vendors always require two-factor authentication and are not affected by this switch; LDAP/OIDC accounts are not covered either.

### The last administrator

To avoid locking yourself out, disabling or demoting the **last usable local administrator** is rejected with an error. External (LDAP/OIDC) administrators and administrators who never activated are not counted.

### Site-wide share browsing

Click "All shares" at the top (visible to administrators only) to browse every share and upload request on the site, search by owner email or message, and revoke them.

- Administrators can only **view files online**, always with a watermark (showing the administrator's own identity, with tracking code `ADMIN`); downloads are not offered.
- Every file opening is written to the audit log as `file.view`.
- When the owner's account is disabled, all of their shares and upload requests stop working immediately: recipients and uploaders see them as expired or nonexistent, including connections that are already open.

### Domain accounts (LDAP/AD)

Lets staff log in with their company domain account. The login page gets an extra "Domain account" form (shown only when `SX_LDAP_URL` is set).

LDAP/OIDC settings can be **set only in `.env`**; there is no corresponding settings page in the admin UI.

**Configuration** (in `.env`; run `docker compose up -d` after changes; only the key points are listed here, see `.env.example` for the full list):

| Variable | Default | Description |
|---|---|---|
| `SX_LDAP_URL` | empty (disabled) | `ldaps://host:636` or `ldap://host:389`. `ldap://` is always upgraded with StartTLS before binding; plaintext login cannot be configured. |
| `SX_LDAP_BIND_DN`, `SX_LDAP_BIND_PASSWORD`, `SX_LDAP_BASE_DN` | none | Required once the URL is set: the service account used to look up users, and the search base. The service account only needs read-only permission. |
| `SX_LDAP_CA` | system root certificates | Path of the root certificate file used to verify the domain server; see "Certificates" below. |
| `SX_LDAP_USER_FILTER` | `(&(objectClass=user)(\|(sAMAccountName={username})(userPrincipalName={username})))` | Must contain `{username}`, which is replaced with the (escaped) login input. |
| `SX_LDAP_ID_ATTR`, `SX_LDAP_EMAIL_ATTR`, `SX_LDAP_NAME_ATTR` | `objectGUID`, `mail`, `displayName` | Attributes for the unique account identifier, email and display name. When email is empty, `userPrincipalName` is used instead; if both are empty, login is impossible. |
| `SX_LDAP_ADMIN_GROUP` | empty | DN of the administrator group; empty means nobody becomes an administrator through LDAP. |
| `SX_LDAP_TLS_INSECURE` | `false` | Skips certificate verification; **not recommended**, see "Certificates" below. |

AD example:

```
SX_LDAP_URL=ldaps://dc01.corp.example:636
SX_LDAP_CA=/etc/secure-exchange/certs/ad-root.cer
SX_LDAP_BIND_DN=CN=svc-sx,OU=Service,DC=corp,DC=example
SX_LDAP_BIND_PASSWORD=<service account password>
SX_LDAP_BASE_DN=DC=corp,DC=example
SX_LDAP_ADMIN_GROUP=CN=SX-Admins,OU=Groups,DC=corp,DC=example
```

**How it works**

- Users enter their domain account (`sAMAccountName` or UPN) and password on the login page; the system first finds the user with the service account, then verifies by binding with that user's password.
- The account is **created automatically on first login** as staff; email and display name are updated on every later login.
- Domain accounts are **never merged with local accounts**: even with the same email they are two independent accounts, and domain login never lands in a local account. If two domain accounts have the same email, the second is blocked (`email_conflict`); fix the email in AD. If instead an **old domain account still holds that email** (the AD account was deleted and recreated, or the email was reassigned to someone else), fixing AD does not help; see the two remedies in troubleshooting below.
- **Administrators**: members of `SX_LDAP_ADMIN_GROUP` are administrators and everyone else is staff, re-evaluated on every login. AD counts nested groups; other LDAP servers only check whether the user's `memberOf` directly contains the group. If the domain server is busy or unavailable while deciding administrator status, that login fails (503) and the user is not demoted.
- **Every 15 minutes** each active session is re-checked: if the account was deleted or disabled in AD, all of that user's sessions end immediately.
- **When the domain server is unreachable**, the re-check ends the session, so all domain users are logged out and cannot log in until the server recovers. Therefore **always keep at least one local administrator** (the account created by `SX_INIT_ADMIN_*`); otherwise nobody can manage the system when AD is down.
- Domain accounts have **no TOTP** and are not covered by [site-wide mandatory two-factor authentication](#site-wide-mandatory-two-factor-authentication); use AD / company multi-factor authentication. Users who try to enable TOTP themselves are refused.
- The **role of a domain account is decided by the administrator group**; you cannot change the role or reset TOTP on the "Users" page. Administrators can still **disable** a domain account locally (a disabled account cannot log in even with the correct AD password). External administrators are not counted in the [last administrator](#the-last-administrator) check.
- An account disabled in AD usually shows up at login as a wrong account or password (AD rejects the bind outright).

#### Login failures and account lockout

Failed domain logins **count directly toward AD's account lockout**. The in-app per-username rate limit can be bypassed with different spellings (for example `DOMAIN\u` and `u@upn` are treated as different names), so for internet-facing sites rely on IP rate limiting / reverse-proxy rate limiting and set an account lockout policy in AD.

#### Email held by an old domain account (`email_conflict`)

When an AD account is deleted and recreated (`objectGUID` changes, same email), or an email is reassigned to someone else, the old domain account in the system still holds that email, and every login gets 409 `email_conflict`; fixing AD does not help. First go to the "Audit log" page and find that `auth.login.fail` (stage `email_conflict`); the `external_id` in its "Detail" is the new account's objectGUID (hexadecimal). Run the SQL below with `docker compose exec postgres psql -U sx -d sx -c "…"`, replacing `<email>` with that email:

- **The same person** (rehired, account recreated): rebind the old account to the new objectGUID; files and shares are kept.

  ```sh
  docker compose exec postgres psql -U sx -d sx -c \
    "UPDATE users SET external_id='<new external_id>' WHERE auth_source='ldap' AND lower(email)=lower('<email>');"
  ```

- **The email now belongs to a different person**: release the email and keep the old account disabled; the new person gets a brand-new account on their next login.

  ```sh
  docker compose exec postgres psql -U sx -d sx -c \
    "UPDATE users SET email = email || '.retired-' || left(id::text, 8), disabled = true WHERE auth_source='ldap' AND lower(email)=lower('<email>');"
  ```

#### Certificates

Recommended approach:

1. On Windows, export the AD root CA certificate: open MMC, add the "Certificates" snap-in, find the root CA certificate, right-click "All Tasks" → "Export"; choose either "Base-64 encoded X.509 (.CER)" or "DER encoded binary X.509 (.CER)". Or run `certutil -ca.cert ad-root.cer` on the CA server.
2. Copy the file into the project's `./certs` directory (`docker-compose.yml` mounts it read-only at `/etc/secure-exchange/certs` in the container).
3. Set `SX_LDAP_CA=/etc/secure-exchange/certs/ad-root.cer` in `.env`, then run `docker compose up -d`.

If the domain controller uses a **self-signed certificate**, you can use that certificate directly as `SX_LDAP_CA`, the same way. Multiple certificates (a merged PEM file) are allowed.

`SX_LDAP_TLS_INSECURE=true` **skips certificate verification entirely** (the connection is still encrypted, but the peer's identity is not verified). Risk: anyone on the network path can impersonate the domain controller and obtain the domain passwords users type. Prefer `SX_LDAP_CA`; use this switch only as a temporary measure. While it is enabled, a WARN appears in the log at every start.

If the audit record of a failed login carries `reason: certificate`, the CA is misconfigured or missing (rather than the domain controller being down).

#### Troubleshooting

| Symptom | What to do |
|---|---|
| Login shows "The domain server is temporarily unreachable…", and the audit `auth.login.fail` has stage `ldap_unavailable` | The domain server is unreachable, timed out (10 seconds), or certificate verification failed. If the detail contains `reason: certificate`, check `SX_LDAP_CA` and `./certs`; otherwise check the network, the port and the service account password. |
| Login shows that the email is already used by another domain account (`email_conflict`) | Two AD accounts have the same email (or UPN); fix it in AD. If an AD account was recreated or an email transferred, see the two SQL remedies in "Email held by an old domain account" above. |
| Stage is `ldap_no_email` | The account's `SX_LDAP_EMAIL_ATTR` and `userPrincipalName` are both empty. |
| Stage is `ldap_disabled` | The AD account is disabled. Stage `disabled` means an administrator disabled it locally. |
| A user is suddenly logged out, and the audit `auth.session.end` reason is `ldap_unavailable` / `ldap_gone` / `ldap_error` | Respectively: the domain server is unreachable, the account was deleted or disabled in AD, or refreshing the account data failed. When LDAP is turned off, existing domain sessions also end. |

### Single sign-on accounts (OIDC / Entra ID)

Lets staff log in with the company's single sign-on (Microsoft Entra ID or another OpenID Connect identity provider). The login page gets an extra "Sign in with Microsoft" button (shown only when `SX_OIDC_ISSUER` is set). It uses Authorization Code + PKCE and verifies `state`, `nonce`, the ID token signature, `iss` and `aud`. Settings **can be set only in `.env`**.

**Configuration** (run `docker compose up -d` after changes; see `.env.example` for the full list):

| Variable | Default | Description |
|---|---|---|
| `SX_OIDC_ISSUER` | empty (disabled) | Issuer URL; must be `https://`. For Entra it is `https://login.microsoftonline.com/<tenant-id>/v2.0`, and **you must use your own tenant ID**; `common` and `organizations` do not match the `iss` in the token and cannot be used. |
| `SX_OIDC_CLIENT_ID`, `SX_OIDC_CLIENT_SECRET` | none | Required once the issuer is set: the application (client) ID and the "Value" of the client secret. |
| `SX_OIDC_SCOPES` | `openid profile email` | Space-separated; `openid` is added automatically if missing. |
| `SX_OIDC_ADMIN_CLAIM` | `groups` | Name of the token claim that decides administrators. For Entra, `roles` is recommended. |
| `SX_OIDC_ADMIN_VALUE` | empty | The value that makes a user an administrator; empty means nobody becomes an administrator through single sign-on. |
| `SX_OIDC_BUTTON_TEXT` | empty | Login button text, shown as-is when set; when empty, the built-in "Sign in with Microsoft" is shown. |
| `SX_OIDC_CA` | system root certificates | Root certificate file (PEM or DER) of an internal identity provider (such as Keycloak); same approach as "Certificates" under LDAP: put it in `./certs` and write the path as `/etc/secure-exchange/certs/<filename>`. |

**Redirect URI**: there is no separate variable; it is always `SX_BASE_URL` + `/api/auth/oidc/callback`, for example `https://files.corp.example/api/auth/oidc/callback`. Register exactly this URL, character for character, at the identity provider.

**No connection at startup**: at startup the system only checks the configuration and does not contact the identity provider; discovery happens when someone first logs in and is then cached, and a failure is retried at the next login. So an identity provider outage does not stop the system from starting, local administrators can still log in, and no restart is needed after recovery.

#### Entra ID setup steps

1. In the Entra admin center go to "App registrations" → "New registration".
2. For "Redirect URI" choose the platform "Web" and enter the callback URL above (`<SX_BASE_URL>/api/auth/oidc/callback`).
3. Note the "Application (client) ID" (`SX_OIDC_CLIENT_ID`) and the "Directory (tenant) ID", and build `SX_OIDC_ISSUER=https://login.microsoftonline.com/<tenant ID>/v2.0`.
4. Under "Certificates & secrets" add a client secret and copy its "Value" (shown only once) as `SX_OIDC_CLIENT_SECRET`, and **note the expiry date**. After the secret expires all single sign-on fails (`oidc_unavailable`, logged by the server as ERROR); replace it before it expires and update `.env`.
5. Set up the administrator mapping (below), then run `docker compose up -d`.

#### Administrator mapping

**App Roles (`roles`) are recommended:**

1. Under "App roles" of the app registration, create a role with a value such as `SecureExchange.Admin` (allowed member types: Users/Groups).
2. Under "Enterprise applications" → that application → "Users and groups", assign the people who should be administrators to the role.
3. In `.env` set `SX_OIDC_ADMIN_CLAIM=roles` and `SX_OIDC_ADMIN_VALUE=SecureExchange.Admin`.

If the claim is a string, it must be exactly equal to the configured value; if it is an array, any element matching is enough (case-sensitive).

**Why `groups` is not recommended** (even though it is the default):

- The groups claim in an Entra token carries the groups' **object IDs** (GUIDs), not their names, so `SX_OIDC_ADMIN_VALUE` must be a GUID.
- When a user belongs to more than 200 groups, Entra does not put the groups in the token (overage) and instead points to Graph through `_claim_names`. The system does not call Graph, so that user **becomes staff rather than an administrator**, and the audit record `auth.login.ok` for that login carries `groups_overage: true` in its detail. When an administrator gets demoted, check this field first. App Roles do not have this limit.

#### Other identity providers

- **Google Workspace**: the token has no groups claim, so leave `SX_OIDC_ADMIN_VALUE` empty; all single sign-on users are staff. When you need administrators, create a separate local administrator account.
- **Keycloak**: `SX_OIDC_ISSUER=https://kc.corp.example/realms/<realm>`; if you use an internal CA, set `SX_OIDC_CA`. For administrator mapping, make Keycloak emit a role or group claim in the token, then set `SX_OIDC_ADMIN_CLAIM` / `SX_OIDC_ADMIN_VALUE`.

#### Account behavior

- The account is **created automatically on first login** as staff; email and display name are updated on every later login. The email is taken from `email`; if absent, from `preferred_username`, then from `upn`, but those two **must contain `@`** to be accepted (a value without `@`, such as `alice`, is skipped); if none qualifies, login is impossible. `email_verified` is not required.
- Single sign-on accounts are **never merged with local or domain accounts**: even with the same email they are independent accounts (the unique identifier is `iss` + `sub`), single sign-on never lands in a local or domain account, and local password login still goes to the local account.
- **The role is re-evaluated on every login**; you cannot change the role or reset TOTP on the "Users" page. External administrators are not counted in the [last administrator](#the-last-administrator) check, so keep at least one local administrator.
- Administrators can **disable** an account locally; a disabled account cannot log in (audit stage `disabled`).
- A login session lasts at most `SX_SESSION_TTL` (default 12 hours, absolute and never extended). The system **does not periodically re-check with the identity provider**, so after you disable a user in Entra it takes effect only when their session expires; to cut them off immediately, also disable the account on the "Users" page.
- Single sign-on accounts have **no TOTP** and are not covered by [site-wide mandatory two-factor authentication](#site-wide-mandatory-two-factor-authentication); multi-factor authentication is handled by Entra Conditional Access.
- Logging out of this system only ends the session in this system; it does **not** log out of Microsoft (the identity provider).
- After you remove `SX_OIDC_ISSUER` (turning off single sign-on), existing single sign-on sessions end at their next request (audit `auth.session.end` with reason `oidc_disabled`).

#### Troubleshooting

When a login fails, the user is sent back to `/login?oidc_error=<code>`; go to the "Audit log" page and look for `auth.login.fail` whose detail has `source` set to `oidc`, with these `stage` values:

| stage | Page code | Explanation and action |
|---|---|---|
| `oidc_denied` | `denied` | The identity provider returned an error (for example the user clicked cancel, or was not assigned access). `idp_error` in the detail is the provider's error code (up to 64 characters). |
| `oidc_state` | `invalid` | `state` does not match the browser cookie, or the cookie is missing or malformed (10-minute timeout, different browser, or a suspected forged login request). Ask the user to click the button again from the login page. |
| `oidc_token` | `invalid` | The token was rejected: the authorization code is invalid or already used, ID token signature / `iss` / `aud` / expiry validation failed, `nonce` mismatch, the token has no `sub` (Keycloak 25 and later omits `sub` if the `basic` scope is missing), or fetching the keys (JWKS) to verify the signature failed. Most often `SX_OIDC_CLIENT_ID` is wrong or the identity provider's key endpoint is temporarily unreachable (ask the user to retry). |
| `oidc_no_email` | `invalid` | None of `email`, `preferred_username` and `upn` in the token has a usable value (`preferred_username` and `upn` must contain `@`). Add an email at the identity provider. |
| `oidc_unavailable` | `unavailable` | The identity provider is unreachable (discovery or token endpoint timed out after 10 seconds / 5xx), or the **client was rejected** (`invalid_client`, usually an expired or wrong client secret, logged by the server as ERROR). A **wrong issuer** also ends up here at the discovery stage: the server WARN log (`oidc callback` / `oidc start`) contains `issuer` or `did not match`; common causes are using `common`, using a domain name instead of the tenant GUID, or an extra trailing `/`. `SX_OIDC_ISSUER` must use the tenant GUID and **have no trailing slash**. Also check the network, the expiry date of `SX_OIDC_CLIENT_SECRET`, and `SX_OIDC_CA` for an internal CA. Local login is not affected. |
| `email_conflict` | `email_conflict` | Another single sign-on account already holds the same email; see below. |
| `disabled` | `invalid` | An administrator disabled the account locally. |

On a database error (logged as `oidc upsert` / `oidc session`), the user sees `oidc_error=unavailable` but **no audit record is written**; check the server log.

#### Email held by an old single sign-on account (`email_conflict`)

When a user is deleted and recreated in Entra (`sub` changes, same email), or an email is reassigned to someone else, the old single sign-on account in the system still holds that email, and every login is blocked. Go to the "Audit log" page and find the `auth.login.fail` with stage `email_conflict`; the `external_id` in its detail is the new account's identifier, in the form `iss` + one space + `sub` (for example `https://login.microsoftonline.com/<tenant-id>/v2.0 <sub>`). Run the SQL below with `docker compose exec postgres psql -U sx -d sx -c "…"`, replacing `<email>` with that email:

- **The same person** (rehired, account recreated): rebind the old account to the new `external_id`; files and shares are kept.

  ```sh
  docker compose exec postgres psql -U sx -d sx -c \
    "UPDATE users SET external_id='<new external_id, including iss and the space>' WHERE auth_source='oidc' AND lower(email)=lower('<email>');"
  ```

- **The email now belongs to a different person**: release the email and keep the old account disabled; the new person gets a brand-new account on their next login.

  ```sh
  docker compose exec postgres psql -U sx -d sx -c \
    "UPDATE users SET email = email || '.retired-' || left(id::text, 8), disabled = true WHERE auth_source='oidc' AND lower(email)=lower('<email>');"
  ```

## 6. Vendor account management

### Creation policy

`SX_VENDOR_CREATION` decides who can create vendor accounts:

| Value | Behavior |
|---|---|
| `staff` | Any staff member creates one and the invitation is sent immediately. |
| `approval` (default) | Vendors created by staff go to "Pending approval" and all administrators get a notification email; vendors created by an administrator get the invitation directly. |
| `admin` | Only administrators can create them; staff see "You do not have permission to do that". |

### Approving and rejecting

On the "Vendors" page, in the "Pending approval" section at the top, administrators can:

- **Approve**: sends the invitation email and the status becomes "Invited".
- **Reject**: the status becomes "Rejected".

> A rejected vendor's email can be created again: adding a vendor with the same email reuses the original account and puts it back into "Pending approval" according to the current mode (or sends the invitation directly if an administrator created it). A vendor in "Pending approval" or "Rejected" status cannot be disabled or have its expiry changed.

### Invitation and activation

- The invitation link is valid for 7 days and single use. The vendor opens it, sets a password (at least 12 characters) and binds an authenticator app; two-factor authentication is mandatory.
- "Reinvite" sends a new link and invalidates the old one; it applies only to the "Invited" status.

### Disabling, expiry and extending

- **Disable**: immediately ends all of that vendor's active sessions. **Enable** restores it.
- **Expiry date**: set at creation (from tomorrow up to three years out); after it passes, the vendor cannot log in. Use "Change expiry" to extend it; an expired account can be extended too.
- The creator and administrators can manage a vendor; other staff can only share files with "Active" vendors.

### A vendor loses their authenticator device

First verify the person's identity, then go to the "Users" page and click "Reset TOTP" on that vendor. The system clears the vendor's password and two-factor authentication, ends all of their sessions, and **automatically sends a new invitation email**; the vendor opens the link and sets a new password and authenticator app.

### What vendors can see and do

- They only see content shared with them that has not expired or been revoked. View-count limits, IP restrictions, watermark rules and one-time shares work as for other shares, and the watermark shows the vendor's email.
- They can only upload to **staff who have shared with them** or **the staff member who created their account**, and cannot see the full staff list. Files uploaded by vendors are always virus-scanned.

## 7. Mandatory rules

Administrators can set site-wide rules in the web UI that are enforced on all staff and external users. After logging in, click "Rules" at the top (visible to administrators only); there are 14 settings in five groups: Security, Sharing, Recipients, External uploads and Storage. They take effect as soon as you click "Save": the system re-reads the rules on every request, so no restart is needed. After saving, the page shows "Affected shares: N".

### Settings overview

**Security**

| Setting | Description |
|---|---|
| Require two-factor authentication for local staff and administrators | Applies only to local staff and administrators; see "Site-wide mandatory two-factor authentication". |

**Sharing**

| Setting | Description |
|---|---|
| Always apply a watermark | Every share must be watermarked; the option is locked when staff create a share. |
| Forbid downloads (view only) | Every share is online-view only; "Allow download" is locked when staff create a share. |
| Maximum share lifetime (days) | 1 to 365 days. This is also the maximum lifetime of upload requests. |
| Default share lifetime (days) | The default lifetime when creating a share; must be between 1 day and the maximum lifetime. |
| Maximum share size (MiB) | Total size of all files in one share; `0` means unlimited. |

**Recipients**

| Setting | Description |
|---|---|
| Blocked email domains | One domain per line. |
| Allowed email domains | One domain per line; empty means all are allowed, and when filled in only these domains are allowed. |
| Allowed networks for external users | CIDR (a single IP also works), one per line; empty means no restriction. |

**External uploads**

| Setting | Description |
|---|---|
| Allowed upload extensions | One per line (`pdf` or `.pdf`, case-insensitive); empty means all are allowed. |
| Maximum external upload size (MiB) | Per-file limit for external uploaders and vendor uploads; `0` means unlimited. |

**Storage**

| Setting | Description |
|---|---|
| Maximum file size (MiB) | `0` means limited only by `SX_MAX_FILE_SIZE`; a value you enter cannot exceed `SX_MAX_FILE_SIZE`. |
| Storage quota per user (MiB) | `0` means unlimited. |
| Retention (days) | `0` means no automatic cleanup; see "Automatic cleanup" below. |

Field limits: at most 200 domains each, 200 extensions and 100 networks. Domains and extensions are lowercased and de-duplicated automatically; extensions may contain only letters and digits. If the format is wrong, the page shows an error next to the field and the whole rule set is not saved.

### Effect on staff sharing options

Options locked by a rule are greyed out in the create-share dialog and labeled "Set by administrator"; even if the UI is bypassed and the API called directly, the server refuses ("Download is disabled by the administrator", "The administrator requires a watermark").

### Effect on existing shares: the stricter rule wins

"Forbid downloads", "Always apply a watermark" and the domain rules are re-checked on **every view and download**, so after tightening a rule, **shares that already exist** (one-time shares and shares to vendors) are restricted immediately, with no need to revoke them one by one:

- After downloads are forbidden, recipients of existing shares can only view online even if the share allowed downloads. Files that cannot be previewed online therefore become inaccessible, and recipients see "This file is currently unavailable (download is disabled by the administrator)"; a newly created view-only share containing such files is rejected.
- After "Always apply a watermark" is turned on, views and downloads of existing shares are watermarked.
- Domain rules: blocked domains **take precedence over** the allow list; a domain in a list also covers its subdomains (blocking `example.com` also blocks `mail.example.com`). The rules also apply to vendor account emails (when creating a vendor, sharing to a vendor, and when a vendor accesses a share). When a recipient's email is blocked by the rules, they still receive a verification code (proving identity), but after verifying they are refused and see "Your email domain is not allowed to access this share".
- Staff downloading **their own files** are not affected by these rules.

The share lifetime limit, default lifetime and the various size limits are checked only at **creation** and do not affect existing shares retroactively.

### External IP list

"Allowed networks for external users" restricts only **external users**: share recipients, uploaders of upload requests, and vendors (including vendor login and the invitation activation page). Staff and administrators are not affected. An empty list means no restriction. The source IP depends on `SX_TRUSTED_PROXIES` (see [Configuration reference](#4-configuration-reference)); a misconfigured reverse proxy can make everyone look like the same IP. Blocked external users see "Access from your network location is not allowed". Make sure your own network will not be blocked by mistake before saving; administrators themselves are not subject to this list and will not be locked out by it. When a vendor logs in from a disallowed network, the response is identical to a wrong password (HTTP 401 `invalid_credentials`), so as not to reveal whether the password was correct; the audit `auth.login.fail` record has reason `ip_denied`. In addition, a half-finished login where only the password was entered and TOTP has not been completed is valid for only 10 minutes, and is extended to the normal session time (`SX_SESSION_TTL`) only after verification completes; rate limiting is computed per /64 network for IPv6.

### External upload restrictions

"Allowed upload extensions" and "Maximum external upload size" apply to uploaders of upload requests and to vendor uploads. If an upload request has its own extension or size limits, the **stricter** of the two applies. When blocked, the uploader sees "This file type is not allowed" or "File is too large".

### Storage quota

The quota is calculated per staff member and **includes files that external people uploaded to them** (upload requests and vendor uploads); deleted (soft-deleted) files do not count. When exceeded, a staff upload shows "Storage is full", and an external upload to that staff member shows "The recipient's storage is full".

### Automatic cleanup (retention days)

When retention days is greater than 0, the system scans once an hour and deletes files that meet these conditions:

- the file was put into a share, or was received through an upload request;
- and **all** shares and upload requests that reference it have ended (expired or revoked) for more than N days.

Files that were never shared, and files uploaded directly by vendors and never shared, are **not** cleaned up. Cleanup is written to the audit log as `file.retention_delete` (`actor_type` is `system`). Cleanup cannot be undone, so confirm your backups before lowering the retention days.

### Expired-data cleanup

Every hour the system automatically deletes login sessions (staff, share recipients, upload request parties) and one-time verification codes that expired more than 24 hours ago, vendor view records of shares that expired more than 24 hours ago, and unsent mail that has given up retrying (reached the retry limit) and was created more than 30 days ago. Data that has not expired and mail that is still retrying are not deleted; cleanup is not written to the audit log.

### Notification email when rules are tightened

When "Forbid downloads", "Always apply a watermark" or the domain rules are tightened, the owner of each affected share receives **one** summary email listing the affected shares. After the administrator saves, the rules page shows the number of affected shares.

### Audit and environment variables

- Every save writes the audit record `rules.update`, whose `detail` contains the complete rules before and after the change.
- `SX_SHARE_MAX_DAYS` is now **used only to set the initial value on the first start**; afterwards the rules page is authoritative, and changing the environment variable has no effect. If at startup it differs from the value in the database, a warning is logged.
- `SX_MAX_FILE_SIZE` is still the hard limit; the "Maximum file size" on the rules page can only be lower.

## 8. Leak tracing (tracking down leaks)

Every download by a recipient (including vendors) generates a tracking code (`SX-` plus 10 characters) and records the recipient, IP and time; depending on the file type, the tracking code is embedded in the file:

| File type | Watermark on | Watermark off |
|---|---|---|
| PDF | Regenerated as a PDF with visible and invisible watermarks; the tracking code is also written to the metadata and a hidden text layer | The tracking code is written to the PDF metadata |
| Office (doc/docx/xls/xlsx/ppt/pptx/odt/ods/odp/rtf) | Converted to a watermarked PDF | docx/xlsx/pptx and odt/ods/odp: written to document properties; doc/xls/ppt/rtf: not embedded |
| JPEG／PNG | Visible plus invisible watermark | Invisible watermark only (images with either side under 192 pixels are not embedded) |
| Other (video, archives, etc.) | Only the downloader and file fingerprint are recorded | Same as left |

### How to look up

After logging in, an administrator clicks "Leak tracing" at the top and can search in three ways:

1. **Tracking code**: the `SX-…` read from the visible watermark or from the file.
2. **SHA-256**: the fingerprint of the leaked file; it finds the original file and all download records.
3. **Upload a suspect file**: the system analyzes it only in memory and does not store it; it reads the metadata, the hidden text layer and the invisible watermark. For files larger than `SX_MARK_MAX_BYTES`, only the SHA-256 is compared.

Results list the source (download / online view / original upload), how it was found, the tracking code, file, owner, downloader, IP and time. When nothing is found, "Undetermined" is shown.

**Screenshots or photos of the screen** carry no embedded mark; read the tracking code from the visible watermark on the screen, then search using the "Tracking code" method.

Each lookup is itself recorded in the audit log (`trace.lookup`).

## 9. Virus scanning (ClamAV)

All **external** uploads are scanned: uploaders of upload requests, and direct uploads by vendors. Files that staff upload themselves are not scanned.

### How it works

- After a file finishes uploading its status is "Scanning"; the worker decrypts it only in memory and streams it to clamd. clamd buffers the stream in the in-memory `/tmp` tmpfs, so plaintext never touches disk.
- Outcomes:
  - **No virus found**: the file is released, and the receiving staff member gets a notification email.
  - **Infected**: the file is quarantined and cannot be downloaded, previewed or shared. The receiving staff member and **all administrators** get a notification email.
  - **Scan failed**: after 5 consecutive scan failures the file is blocked and the receiving staff member is notified.
  - **Not scanned**: the file is larger than `SX_SCAN_MAX_BYTES`, so it is released without scanning, with a warning in the notification email and on screen. This is a known exception today; an option to block instead will come later.
- When clamd is temporarily unreachable, scanning is postponed and retried without using up failure attempts.

### Operational notes

- **The first start** needs a few minutes to download the virus signatures. Uploads during that time stay in "Scanning" and are processed automatically once clamd is ready.
- The signatures are updated automatically by the clamav container (through the `updates` network, which has internet access).
- clamd uses about 1.5 to 3 GB of memory (limit `mem_limit: 4g`).
- "No virus found" means no virus was found within ClamAV's scan time, size and archive-depth limits; it is not proof that the file is safe.
- To raise the scan limit, all of the following must be raised to at least the new value: `SX_SCAN_MAX_BYTES`, `StreamMaxLength` and `MaxFileSize` in `clamd.conf`, and the size of clamav's `/tmp` tmpfs in `docker-compose.yml`. ClamAV's own hard limit is about 4000 MiB.

Check the scan status:

```sh
docker compose logs --tail=100 clamav
docker compose exec postgres psql -U sx -d sx -c \
  "SELECT scan_status, count(*) FROM files WHERE deleted_at IS NULL GROUP BY scan_status;"
```

### Container resource limits and networks

| Container | Memory (no swap) | Other |
|---|---|---|
| app | 4 GiB | Process limit 512 |
| worker | 6 GiB | 2 CPUs, process limit 512 |
| clamav | 4 GiB | — |

- Basis for the app's 4 GiB: "marked" downloads (PDF metadata, images) load the whole file into memory, at most 2 at a time; under the default limits (`SX_MARK_MAX_BYTES` 256 MiB, `SX_MARK_MAX_PIXELS` 50 million pixels) an image needs about 1.5 GiB each, so 2 × 1.5 GiB + 512 MiB, rounded up to 4 GiB. When you raise these two limits, raise `mem_limit` as well.
- The app has `GOMEMLIMIT: 3584MiB` (a soft memory limit slightly under the 4 GiB cap) so Go reclaims memory before the OOM killer is triggered; adjust it together with `mem_limit` when you raise that.
- When both marking slots are taken, other downloads wait up to 2 minutes and then get a 503 (`busy`, `Retry-After: 30`), and no download record is left behind.
- Networks: `scan` (an internal network with no route to the outside) connects only the worker and clamav. clamav is no longer on `backend`, so it cannot reach PostgreSQL or the app; only the worker connects to clamd, and the app does not need to.

## 10. Online preview worker

The worker uses LibreOffice, poppler and FFmpeg to process untrusted files, so it is strictly isolated:

- No outbound network; it can only reach the database and internal services.
- The root filesystem is read-only; decrypted files live only in the `/work` tmpfs (4 GiB) and are deleted when each job ends.
- No swap is used (`memswap_limit` equals `mem_limit`), so decrypted data cannot be swapped out to disk. The worker refuses to start if `/work` is not a tmpfs.
- 6 GiB of memory (including the 4 GiB tmpfs), 2 CPUs, 512 processes, all capabilities dropped, runs as a non-root user, and every external program has a timeout.

**Capacity rule**: you must keep "largest preview input + output ≤ size of `/work` (4 GiB) < `mem_limit` (6 GiB)". When you raise the preview limits, also raise the worker's tmpfs size and `mem_limit` in `docker-compose.yml`. A job that fills `/work` is marked "Too large to preview".

The TTF font used for video watermarks can be set with `SX_FONT_FILE` (default DejaVu Sans).

## 11. Audit log

All security-related events are written to the `audit_log` table in the database. This table is **append-only, with no modification or deletion** (blocked by database rules), and each record also contains the hash of the previous one, forming a hash chain, so any tampering breaks the chain.

### Querying on the web

After logging in, an administrator clicks "Audit log" in the top navigation (`/admin/audit`). You can filter by the following conditions and page through the results after clicking "Filter":

- **From**, **To**: the time range of the query.
- **Actor**: enter an email or a user id.
- **Action**: matched by prefix; for example enter `share.` to list all share-related events, or `auth.login.fail` to find failed logins.
- **Target**: enter a target id. If you enter a **share id**, the results also include the file view and download records under that share.

For example, to find "failed logins in the past day": set From to one day ago and put `auth.login.fail` in Action.

### Exporting CSV

Clicking "Export CSV" downloads according to the current filters. The file is UTF-8 with a BOM (so Excel opens Chinese text directly) and ordered by id ascending. To prevent cells from being executed as formulas in a spreadsheet, cells beginning with `=`, `+`, `-`, `@`, a Tab or a carriage return (CR) get a `'` prepended; to recover the original value, remove the leading `'`.

### Verifying the hash chain

Clicking "Verify hash chain" recomputes the whole chain. The result shows the number of records checked; if any record was tampered with or is missing, it shows the id of the first broken record.

**Exporting and verifying are themselves written to the audit log** (`audit.export`, `audit.verify`).

Common event types:

| Category | Events |
|---|---|
| Login | `auth.login.ok`, `auth.login.fail`, `auth.logout`, `auth.totp.enable` |
| Files | `file.upload`, `file.download`, `file.view`, `file.delete`, `file.scan` |
| Shares | `share.create`, `share.revoke`, `share.recipient.add`, `share.recipient.revoke`, `share.otp.request`, `share.otp.verify` |
| Upload requests | `request.create`, `request.revoke`, `request.otp.request`, `request.otp.verify` |
| Users | `user.create`, `user.activate`, `user.disable`, `user.enable`, `user.role`, `user.totp_reset`, `user.reinvite` |
| Vendors | `vendor.create`, `vendor.approve`, `vendor.reject`, `vendor.disable`, `vendor.enable`, `vendor.expiry`, `vendor.reinvite`, `vendor.activate` |
| Tracing and audit | `trace.lookup`, `audit.export`, `audit.verify` |
| Mandatory rules | `rules.update` (includes the rules before and after), `file.retention_delete` (automatic cleanup, `actor_type` is `system`) |

`actor_type` indicates the type of actor: `user` (staff, administrators), `vendor`, `recipient` (share recipients; a vendor viewing a share is also recorded as this type), `uploader` (uploaders of upload requests), `system` (automatic system jobs, such as virus scanning).

### 11.1 Forwarding to a SIEM (syslog)

Audit records can be forwarded in real time to a SIEM such as Splunk or ELK, as an independent backup outside the database.

| Variable | Default | Description |
|---|---|---|
| `SX_SYSLOG_ADDR` | empty (disabled) | SIEM address in the form `host:port`, e.g. `siem.example.com:6514` |
| `SX_SYSLOG_TRANSPORT` | `tls` | `udp`, `tcp` or `tls` |
| `SX_SYSLOG_CA` | empty | Used only by `tls`: the CA (PEM file path) to verify the SIEM certificate; if unset, the system root certificates are used |

It takes effect after a restart once configured.

**Format**: RFC 5424 syslog. The facility is 13 (log audit); events whose `result` is `ok` have severity 6 (info) and other results have severity 4 (warning), so the PRI values are `<110>` and `<108>` respectively. APP-NAME is `secure-exchange`, MSGID is the action name (for example `share.create`), and the message body is the JSON of that audit record: `id`, `at`, `actor_type`, `actor_id`, `ip`, `user_agent`, `action`, `target_type`, `target_id`, `result`, `detail`, `prev_hash`, `hash` (hashes are hexadecimal strings). TCP and TLS use octet-counting framing (RFC 6587); UDP sends one packet per record.

**SIEM-side setup**: in Splunk, create a TCP (or SSL) data input and set the sourcetype to `syslog`; in ELK, use Logstash's `syslog` or `tcp` input with TLS, then parse the body with a `json` filter. Make sure the input accepts octet-counting framing (RFC 6587). If your SIEM supports only newline framing, put a syslog collector that supports octet-counting (such as rsyslog or syslog-ng) in front of it.

**Behavior and limits**:

- It checks every 2 seconds, up to 500 records per batch, and retries every 10 seconds on failure. Progress is stored in the database, so after a service restart or SIEM outage it resumes from the last position. With multiple instances, only one does the forwarding.
- **On first enablement it sends the entire history starting from record 1**; if there are many records, check the SIEM capacity first.
- Delivery is **at-least-once**: if it crashes between sending and recording progress, or the SIEM goes down mid-write, in rare cases up to one batch (500 records) may be re-sent or lost. De-duplicate by `id` on the SIEM side.
- UDP cannot confirm delivery and may silently drop records; `tls` is recommended for production.
- With UDP, a single audit record larger than about 64 KB cannot be sent; forwarding then gets stuck on that record and a warning appears. If this is a concern, switch to TCP or `tls`.
- When forwarding has been failing for more than 15 minutes, a warning banner appears at the top of the admin UI.

## 12. Email

Invitations, verification codes and notifications are all sent over SMTP, and **the system does not start unless `SX_SMTP_HOST` and `SX_SMTP_FROM` are set**.

```sh
SX_SMTP_HOST=smtp.example.com
SX_SMTP_PORT=587
SX_SMTP_USERNAME=apikey-or-user
SX_SMTP_PASSWORD=secret
SX_SMTP_FROM="Secure Exchange <noreply@example.com>"
SX_SMTP_TLS=starttls        # starttls (default), tls (usually port 465) or none
```

`SX_SMTP_TLS=none` is only allowed for `localhost`, `127.0.0.1` and `mailpit`, for local testing only.

Mail is sent through a queue: a failed send is retried automatically, up to 10 times. To inspect mail that cannot be delivered:

```sh
docker compose logs app | grep "mail send failed"
docker compose exec postgres psql -U sx -d sx -c \
  "SELECT id, to_addr, attempts, next_attempt_at FROM mail_outbox WHERE sent_at IS NULL ORDER BY id DESC LIMIT 20;"
```

The mail content is stored encrypted in the database. It is recommended to set up SPF, DKIM and DMARC for the sending domain so invitations are not treated as spam.

## 13. Backup and restore

### Backup

The following three items **must be backed up together**; none can be skipped:

1. **The database**:
   ```sh
   docker compose exec -T postgres pg_dump -U sx sx > sx.sql
   ```
2. **File data** (the `sxdata` volume, or your S3 bucket):
   ```sh
   docker run --rm --volumes-from "$(docker compose ps -aq app)" -v "$PWD:/backup" \
     debian:bookworm-slim tar -C /data -czf /backup/sxdata.tgz .
   ```
3. **The `.env` file**: `SX_MASTER_KEYS` in it is the master key. **If the master key is lost, no file can ever be decrypted.** Store it separately in a safe place off the server.

Daily backups are recommended, along with periodic restore drills on a different host.

### Restore

A restore must use the **same `SX_MASTER_KEYS` and `SX_ACTIVE_KEY_ID` as at backup time**.

1. Put the backed-up `.env` back next to `docker-compose.yml`.
2. Create the containers and empty volumes, start only the database, and import:
   ```sh
   docker compose create
   docker compose up -d postgres
   docker compose exec -T postgres psql -U sx -d sx -v ON_ERROR_STOP=1 < sx.sql
   ```
3. Restore the file data:
   ```sh
   docker run --rm --volumes-from "$(docker compose ps -aq app)" -v "$PWD:/backup" \
     debian:bookworm-slim tar -C /data -xzf /backup/sxdata.tgz
   ```
4. Optional: restore `caddydata` the same way (replace `app` with `caddy`) to keep the TLS certificates; if you do not, Caddy requests new ones.
5. `docker compose up -d`.

## 14. Master key rotation

Periodically, or when you suspect a key leak, switch to a new master key:

1. Generate a new key: `openssl rand -base64 32`.
2. Add the new key to `SX_MASTER_KEYS` alongside the old one (`1:<old>,2:<new>`), and set `SX_ACTIVE_KEY_ID=2`.
3. **First** make all app and worker instances use the new key: `docker compose up -d`.
4. Run the rotation inside the app container, repeating until it reports `rotated 0 values`:
   ```sh
   docker compose exec app /secure-exchange rotate-keys
   ```
5. Only after confirming downloads work, remove the old key from `SX_MASTER_KEYS` and restart. Keep a backup of the old key before removing it.

## 15. Upgrading

1. Read the release notes on [GitHub Releases](https://github.com/tntrock/secure-exchange/releases), paying attention to new or changed environment variables and migration notes.
2. Back up the database and get the new code; right after `git pull`, compare the changes to `.env.example` and add any new variables to `.env`:

   ```sh
   cd secure-exchange
   docker compose exec -T postgres pg_dump -U sx sx > before-upgrade.sql
   git pull
   git diff ORIG_HEAD HEAD -- .env.example
   ```

3. Rebuild and start:

   ```sh
   docker compose up -d --build
   ```

The database schema is upgraded automatically when the app starts (a lock protects against several instances starting at once). After upgrading, check:

```sh
docker compose ps
docker compose logs --tail=50 app worker
curl -fsS https://<SX_DOMAIN>/healthz     # should return ok
```


> When upgrading to 7.3, migration 0009 creates an index on the audit log: on a large installation the first start can take several minutes, during which operations that must write audit records wait. Upgrade with a single instance.

> When upgrading to 7.4, migration 0010 changes the unique index on email to "unique per source" (a local account and a domain account may have the same email but are never merged), and adds a `checked_at` column to sessions. For the new settings needed, see [Domain accounts (LDAP/AD)](#domain-accounts-ldapad).

## 16. Monitoring and troubleshooting

### Health check

- `https://<SX_DOMAIN>/healthz` returning `ok` means the app is healthy.
- `docker compose ps` shows the state of each service; `docker compose logs -f <service>` follows the live log.

### Common problems

| Symptom | Likely cause and action |
|---|---|
| The system does not start and the log mentions SMTP | `SX_SMTP_HOST` or `SX_SMTP_FROM` is not set. |
| Nobody can log in, and the log shows `nobody can log in` | `SX_INIT_ADMIN_EMAIL`／`SX_INIT_ADMIN_PASSWORD` was not set on the first start. Set them and restart to create the administrator. |
| Cannot obtain a TLS certificate | The domain does not point at this host, or ports 80/443 are blocked by a firewall. |
| Recipients do not receive invitations or verification codes | Check the queue as described in [Email](#12-email); verify SPF/DKIM; ask the recipient to check their spam folder. |
| External uploads stay in "Scanning" | clamav is still downloading signatures, or the clamav container is out of memory. Check `docker compose logs clamav`. |
| Preview stays in "Processing" | Check `docker compose logs worker`; make sure the worker is running and has enough memory. |
| Preview shows "Too large to preview" | The preview limit was exceeded or `/work` filled up; see [Online preview worker](#10-online-preview-worker). |
| A download shows "The file is still being prepared, please try again shortly" | The watermarked version needs the preview to finish; wait until the preview is done. |
| The worker refuses to start and mentions tmpfs | `/work` is not a tmpfs. Use the `docker-compose.yml` that ships with the project. |
| Files cannot be decrypted | `SX_MASTER_KEYS` differs from the one at backup time, or an old key that is still in use was removed. |
| Users are blocked with "Too many attempts, try again later" | Login and verification codes have a per-IP rate limit; it clears after a few minutes. |

## 17. Security checklist

- [ ] `.env` (containing the master key) is stored in a safe place off the server.
- [ ] Two-factor authentication is enabled on administrator accounts (or site-wide mandatory two-factor authentication is turned on in the rules page).
- [ ] `SX_INIT_ADMIN_PASSWORD` was removed after the first start.
- [ ] The database and file data are backed up daily, and a restore has been rehearsed.
- [ ] SPF, DKIM and DMARC are set up for the sending domain.
- [ ] The host exposes only ports 80 and 443, and the OS and Docker are kept up to date.
- [ ] `SX_VENDOR_CREATION` is set according to company policy (the default requires administrator approval).
- [ ] If the company requires every leaked file to be traceable, `SX_UNMARKABLE_POLICY` is set to `block`.
- [ ] On the "Rules" page, download prohibition / watermark, share lifetime, storage quota and retention days are set according to company policy; if there are fixed partner networks, set the external IP list.
- [ ] Update regularly with `git pull` and `docker compose up -d --build` to get security fixes.
- [ ] Security issues are reported privately according to [SECURITY.md](../SECURITY.md).
