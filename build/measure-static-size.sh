#!/usr/bin/env bash
# 输出静态库趋势；可通过 ORYN_SIZE_LOG 追加 TSV 记录。
set -euo pipefail
PROFILE="${1:-release}"
MILESTONE="${2:-manual}"
STAMP="$(date -u +%FT%TZ)"
FAILED=0
if [[ -n "${ORYN_SIZE_LOG:-}" ]]; then
  mkdir -p "$(dirname "$ORYN_SIZE_LOG")"
  if [[ ! -s "$ORYN_SIZE_LOG" ]]; then printf 'utc\tmilestone\tprofile\ttarget\tbytes\n' > "$ORYN_SIZE_LOG"; fi
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
for target in aarch64-apple-ios aarch64-apple-ios-sim; do
  file="$ROOT/target/$target/$PROFILE/liboryncore.a"
  if [[ -f "$file" ]]; then
    if stat -f '%z' "$file" >/dev/null 2>&1; then
      bytes="$(stat -f '%z' "$file")"
    else
      bytes="$(stat -c '%s' "$file")"
    fi
    printf '%s %s %s bytes (%.2f MiB)\n' "$STAMP" "$target" "$bytes" "$(awk -v n="$bytes" 'BEGIN { printf "%.2f", n/1048576 }')"
    if [[ -n "${ORYN_SIZE_LOG:-}" ]]; then
      printf '%s\t%s\t%s\t%s\t%s\n' "$STAMP" "$MILESTONE" "$PROFILE" "$target" "$bytes" >> "$ORYN_SIZE_LOG"
    fi
  else
    FAILED=1
    printf '%s %s missing (%s)\n' "$STAMP" "$target" "$file" >&2
  fi
done

exit "$FAILED"
