#!/usr/bin/env bash
# End-to-end smoke test. Builds and starts a throwaway compose stack (project
# "sxsmoke", own ports, mailpit via docker-compose.smoke.yml), then: login,
# resumable (tus) upload of a 210 MiB random file with a simulated interruption,
# download + sha256 compare, and the one-time share flow (invitation and
# verification code fetched from the mailpit API, recipient download + sha256).
# Tears everything down (volumes included) and removes its temporary .env.
#   scripts/smoke.sh        (refuses to run if a ./.env already exists)
set -euo pipefail
cd "$(dirname "$0")/.."

[ ! -e .env ] || { echo "refusing to overwrite existing .env; move it away first"; exit 1; }
SIZE_MB=${SIZE_MB:-210}
CHUNK=$((64 * 1024 * 1024))
BASE=https://localhost:58443
MAILPIT=http://localhost:58025
ADMIN=admin@example.com
PASS=smoke-test-passphrase-123
RCPT=recipient@example.org
tmp=$(mktemp -d)
dc() { docker compose -p sxsmoke -f docker-compose.yml -f docker-compose.smoke.yml "$@"; }
cleanup() { dc down -v >/dev/null 2>&1 || true; rm -rf "$tmp" .env; }
trap cleanup EXIT

cat >.env <<ENV
SX_DOMAIN=localhost
SX_HTTP_PORT=58080
SX_HTTPS_PORT=58443
POSTGRES_PASSWORD=$(openssl rand -hex 24)
SX_MASTER_KEYS=1:$(openssl rand -base64 32)
SX_ACTIVE_KEY_ID=1
SX_INIT_ADMIN_EMAIL=$ADMIN
SX_INIT_ADMIN_PASSWORD=$PASS
SX_SMTP_HOST=unused
SX_SMTP_FROM=noreply@example.com
ENV
dc up -d --build

c() { curl -fsSk -b "$tmp/jar" -c "$tmp/jar" -H "Origin: $BASE" "$@"; }
r() { curl -fsSk -b "$tmp/rjar" -c "$tmp/rjar" -H "Origin: $BASE" "$@"; }

for _ in $(seq 60); do
  [ "$(curl -fsSk "$BASE/healthz" 2>/dev/null || true)" = ok ] && break
  sleep 2
done
[ "$(curl -fsSk "$BASE/healthz")" = ok ] || { echo "healthz failed"; exit 1; }
echo "healthz ok"

printf '{"email":"%s","password":"%s"}' "$ADMIN" "$PASS" |
  c -H 'Content-Type: application/json' --data-binary @- "$BASE/api/auth/login" >/dev/null
echo "login ok"

head -c $((SIZE_MB * 1024 * 1024)) /dev/urandom >"$tmp/in.bin"
total=$(stat -c %s "$tmp/in.bin")
want=$(sha256sum "$tmp/in.bin" | cut -d' ' -f1)

name=$(printf 'smoke.bin' | base64)
loc=$(c -D - -o /dev/null -X POST -H 'Tus-Resumable: 1.0.0' -H "Upload-Length: $total" \
  -H "Upload-Metadata: filename $name" "$BASE/api/uploads/" | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}')
echo "created $loc"
case "$loc" in http*) url=$loc ;; *) url=$BASE$loc ;; esac

patch() { # offset, length -> prints response headers
  dd if="$tmp/in.bin" bs=1M iflag=skip_bytes,count_bytes skip="$1" count="$2" 2>/dev/null |
    c -D - -o /dev/null -X PATCH -H 'Tus-Resumable: 1.0.0' -H 'Content-Type: application/offset+octet-stream' \
      -H "Upload-Offset: $1" --data-binary @- "$url" | tr -d '\r'
}
patch 0 $CHUNK >/dev/null
echo "first part sent; simulating interruption"
off=$(c -I -H 'Tus-Resumable: 1.0.0' "$url" | tr -d '\r' | awk 'tolower($1)=="upload-offset:"{print $2}')
[ "$off" = "$CHUNK" ] || { echo "expected offset $CHUNK, got $off"; exit 1; }
echo "resuming from $off"
id=$(patch "$off" $((total - off)) | awk 'tolower($1)=="x-sx-file-id:"{print $2}')
[ -n "$id" ] || { echo "no file id after final PATCH"; exit 1; }

c -o "$tmp/out.bin" "$BASE/api/files/$id/content"
got=$(sha256sum "$tmp/out.bin" | cut -d' ' -f1)
[ "$got" = "$want" ] || { echo "sha256 mismatch: $got != $want"; exit 1; }
echo "owner download ok, sha256 $want"

# --- one-time share: invitation + verification code come from mailpit ---
# mail_body <pattern>: poll mailpit (up to 60 s) for the newest mail to $RCPT whose text matches the sed
# expression and print the captured group.
mail_body() {
  local mid text out
  for _ in $(seq 60); do
    mid=$(curl -fsS "$MAILPIT/api/v1/search?query=to:$RCPT" | grep -o '"ID":"[^"]*"' | head -1 | cut -d'"' -f4 || true)
    if [ -n "$mid" ]; then
      text=$(curl -fsS "$MAILPIT/api/v1/message/$mid")
      out=$(printf '%s' "$text" | sed -n "$1" | head -1)
      [ -n "$out" ] && { printf '%s' "$out"; return 0; }
    fi
    sleep 1
  done
  echo "no matching mail to $RCPT" >&2
  return 1
}

exp=$(date -u -d '+2 days' +%Y-%m-%dT%H:%M:%SZ)
printf '{"file_ids":["%s"],"emails":["%s"],"allow_download":true,"max_views":1,"expires_at":"%s","message":"smoke"}' "$id" "$RCPT" "$exp" |
  c -H 'Content-Type: application/json' --data-binary @- "$BASE/api/shares" >/dev/null
tok=$(mail_body 's#.*/s/\([A-Za-z0-9_-]*\).*#\1#p')
echo "invitation token received"

curl -fsS -X DELETE "$MAILPIT/api/v1/messages" >/dev/null # so the next mail is the code
printf '{"email":"%s"}' "$RCPT" | r -H 'Content-Type: application/json' --data-binary @- "$BASE/api/s/$tok/code" >/dev/null
code=$(mail_body 's/.*驗證碼是：\([0-9]\{6\}\).*/\1/p')
printf '{"email":"%s","code":"%s"}' "$RCPT" "$code" |
  r -H 'Content-Type: application/json' --data-binary @- "$BASE/api/s/$tok/verify" >/dev/null
echo "recipient verified"

r -o "$tmp/shared.bin" "$BASE/api/s/$tok/files/$id/content"
got=$(sha256sum "$tmp/shared.bin" | cut -d' ' -f1)
[ "$got" = "$want" ] || { echo "share sha256 mismatch: $got != $want"; exit 1; }
echo "PASS: ${SIZE_MB} MiB round-trip and one-time share, sha256 $want"
