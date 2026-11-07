#!/usr/bin/env bash
# Browser end-to-end tests (Playwright, Chromium). Builds and starts a throwaway compose stack
# (project "sxe2e", own ports, mailpit + host ClamAV DB dir via docker-compose.e2e.yml), waits
# for it, then runs `npx playwright test` in e2e/ with any arguments passed through:
#   scripts/e2e.sh                         whole suite
#   scripts/e2e.sh tests/auth.spec.ts      one file (playwright args work too, e.g. --repeat-each=3)
#   E2E_KEEP=1 scripts/e2e.sh ...          leave the stack and .env up afterwards for debugging
# Refuses to run if a ./.env already exists. On exit the app/worker logs go to
# e2e/test-results/compose.log, then the stack (volumes included) and its temporary .env are removed.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

[ ! -e .env ] || { echo "refusing to overwrite existing .env; move it away first"; exit 1; }
BASE=https://localhost:59443
MAILPIT=http://localhost:59025
ADMIN=admin@e2e.test
PASS=$(openssl rand -hex 16)
dc() { docker compose -p sxe2e -f docker-compose.yml -f docker-compose.e2e.yml "$@"; }
cleanup() {
  cd "$ROOT" # the tests run from e2e/
  mkdir -p e2e/test-results
  dc logs --no-color app worker >e2e/test-results/compose.log 2>&1 || true
  if [ "${E2E_KEEP:-}" = 1 ]; then
    echo "E2E_KEEP=1: stack left running; tear down with: docker compose -p sxe2e -f docker-compose.yml -f docker-compose.e2e.yml down -v && rm .env"
    return
  fi
  dc down -v >/dev/null 2>&1 || true
  rm -f .env
}
trap cleanup EXIT
trap 'exit 130' INT TERM # run the EXIT trap on Ctrl-C too

mkdir -p .e2e-clamav
cat >.env <<ENV
SX_DOMAIN=localhost
SX_HTTP_PORT=59080
SX_HTTPS_PORT=59443
POSTGRES_PASSWORD=$(openssl rand -hex 24)
SX_MASTER_KEYS=1:$(openssl rand -base64 32)
SX_ACTIVE_KEY_ID=1
SX_INIT_ADMIN_EMAIL=$ADMIN
SX_INIT_ADMIN_PASSWORD=$PASS
SX_SMTP_HOST=unused
SX_SMTP_FROM=noreply@e2e.test
ENV
dc up -d --build

for _ in $(seq 90); do
  [ "$(curl -fsSk "$BASE/healthz" 2>/dev/null || true)" = ok ] && break
  sleep 2
done
[ "$(curl -fsSk "$BASE/healthz")" = ok ] || { echo "healthz failed after 3 min"; exit 1; }
echo "healthz ok"
# the first start downloads the signatures (~300 MB) unless .e2e-clamav already holds them
for _ in $(seq 120); do
  dc exec -T clamav clamdcheck.sh >/dev/null 2>&1 && break
  sleep 5
done
dc exec -T clamav clamdcheck.sh >/dev/null || { echo "clamd not answering after 10 min"; dc logs clamav | tail -30; exit 1; }
echo "clamd ok"

export E2E_BASE_URL=$BASE E2E_MAILPIT_URL=$MAILPIT E2E_ADMIN_EMAIL=$ADMIN E2E_ADMIN_PASSWORD=$PASS
cd e2e
[ -d node_modules ] || npm ci
npx playwright test "$@"
