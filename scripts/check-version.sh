#!/bin/sh
# Usage: sh scripts/check-version.sh [tag]
# VERSION must match the image tags in docker-compose.yml (and the git tag, if given, as v<VERSION>).
cd "$(dirname "$0")/.." || exit 1
v=$(tr -d '[:space:]' <VERSION)
rc=0
n=$(grep -cE "^ +image: ghcr\.io/tntrock/secure-exchange(-worker)?:$v\$" docker-compose.yml)
if [ "$n" != 2 ]; then
  echo "docker-compose.yml: expected 2 image lines tagged $v, found $n:" >&2
  grep -n 'ghcr.io/tntrock' docker-compose.yml >&2
  rc=1
fi
if [ -n "$1" ] && [ "$1" != "v$v" ]; then
  echo "tag mismatch: expected v$v (from VERSION), got $1" >&2
  rc=1
fi
[ $rc = 0 ] && echo "version $v ok"
exit $rc
