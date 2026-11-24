#!/usr/bin/env bash
#
# Check host startup and shutdown paths with LeakSanitizer.
# Run this standalone after building hashcat with DEBUG=2.

set -u

OUT=${1:-./asan-lifecycle}

if [ ! -x ./hashcat ] || ! nm -D ./hashcat | grep -q __asan_init; then
  echo "error: build hashcat with DEBUG=2 before running lifecycle.sh" >&2
  exit 2
fi

mkdir -p "$OUT" || exit 2

export ASAN_OPTIONS="${ASAN_OPTIONS:+$ASAN_OPTIONS:}detect_leaks=1:use_sigaltstack=0:log_path=$OUT/asan"

result=0

for name in version help hash_info; do
  case "$name" in
    version) args=(--version) ;;
    help) args=(--help) ;;
    hash_info) args=(--hash-info -m 0) ;;
  esac

  rm -f "$OUT"/asan.*

  timeout 60 ./hashcat "${args[@]}" > "$OUT/$name.log" 2>&1
  rc=$?

  if [ "$rc" -ne 0 ] || grep -qE 'ERROR: (Address|Leak)Sanitizer' "$OUT/$name.log" "$OUT"/asan.* 2>/dev/null; then
    echo "$name: FAIL (rc=$rc)"
    result=1
  else
    echo "$name: OK"
  fi
done

exit "$result"
