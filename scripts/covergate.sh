#!/bin/sh
# Merge Go cover profiles (a block counts as covered if any profile covered it),
# drop paths Codecov ignores, fail if total statement coverage < MIN (default 90).
# usage: scripts/covergate.sh coverage.out coverage-tools.out ...
set -eu
MIN=${MIN:-90}
awk -v min="$MIN" '
  FNR == 1 && /^mode:/ { next }
  $1 ~ /internal\/db\/testdb\/|internal\/mail\/mailtest\/|_windows\.go:|_other\.go:/ { next }
  { k = $1; n[k] = $2; if ($3 > 0) hit[k] = 1 }
  END {
    for (k in n) { total += n[k]; if (k in hit) cov += n[k] }
    if (total == 0) { print "covergate: no statements"; exit 1 }
    pct = 100 * cov / total
    printf "Go statement coverage: %.2f%% (%d/%d), minimum %s%%\n", pct, cov, total, min
    exit (pct + 0 < min + 0)
  }' "$@"
