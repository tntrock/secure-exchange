#!/usr/bin/env bash
# End-to-end smoke test against a running deployment: login, resumable (tus)
# upload of a 210 MiB random file with a simulated interruption, download,
# sha256 compare.
#   BASE=https://localhost SX_INIT_ADMIN_EMAIL=... SX_INIT_ADMIN_PASSWORD=... scripts/smoke.sh
# Falls back to reading the admin credentials from ./.env. Uses curl -k (self-signed ok).
set -euo pipefail

if [ -f .env ]; then
  : "${SX_INIT_ADMIN_EMAIL:=$(grep -E '^SX_INIT_ADMIN_EMAIL=' .env | cut -d= -f2-)}"
  : "${SX_INIT_ADMIN_PASSWORD:=$(grep -E '^SX_INIT_ADMIN_PASSWORD=' .env | cut -d= -f2-)}"
fi
BASE=${BASE:-https://localhost}
SIZE_MB=${SIZE_MB:-210}
CHUNK=$((64 * 1024 * 1024))
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
c() { curl -fsSk -b "$tmp/jar" -c "$tmp/jar" -H "Origin: $BASE" "$@"; }

[ "$(curl -fsSk "$BASE/healthz")" = ok ] || { echo "healthz failed"; exit 1; }
echo "healthz ok"

printf '{"email":"%s","password":"%s"}' "$SX_INIT_ADMIN_EMAIL" "$SX_INIT_ADMIN_PASSWORD" |
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
echo "PASS: ${SIZE_MB} MiB round-trip, sha256 $want"
