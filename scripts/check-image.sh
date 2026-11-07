#!/bin/sh
# Usage: sh scripts/check-image.sh IMAGE...
# Each image must run as 65532:65532 and contain no .env, testdata/ or src/ paths.
rc=0
for img in "$@"; do
  ok=1
  u=$(docker inspect -f '{{.Config.User}}' "$img") || { rc=1; continue; }
  if [ "$u" != 65532:65532 ]; then
    echo "$img: user is '$u', expected 65532:65532" >&2
    ok=0
  fi
  c=$(docker create "$img") || { rc=1; continue; }
  bad=$(docker export "$c" | tar -t | grep -E '(^|/)\.env$|/testdata/|^src/')
  docker rm "$c" >/dev/null
  if [ -n "$bad" ]; then
    echo "$img: forbidden paths:" >&2
    echo "$bad" >&2
    ok=0
  fi
  if [ $ok = 1 ]; then echo "$img ok"; else rc=1; fi
done
exit $rc
