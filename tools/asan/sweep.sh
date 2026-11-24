#!/usr/bin/env bash
#
# Run every module's host-side parser under AddressSanitizer, with mutations.
# No GPU, no backend, no CUDA driver.
#
# Usage:
#   tools/asan/build.sh
#   tools/asan/sweep.sh [results-dir]
#
# Takes roughly 25 minutes for all 594 modules.

set -u

HARNESS=${HARNESS:-./asan_harness}
OUT=${1:-./asan-sweep}

if [ ! -x "$HARNESS" ]; then
  echo "error: $HARNESS not found, run tools/asan/build.sh first" >&2
  exit 2
fi

mkdir -p "$OUT" || exit 2
LOG="$OUT/sweep.log"
: > "$LOG" || exit 2
result=0
shopt -s nullglob

# halt_on_error=0 keeps going after the first report, so a module with two
# distinct defects shows both rather than hiding the second behind the first.
# use_sigaltstack=0: harmless under the gcc runtime this script builds against
# by default, but mandatory under a clang runtime older than glibc 2.34, where
# SIGSTKSZ stopped being a compile-time constant and the runtime tries to
# allocate a 0-byte alternate signal stack. Without it the sanitizer aborts
# before main() and the sweep records a clean pass for every module: a
# false all-clear, the one failure direction that must never be silent.
export ASAN_OPTIONS="${ASAN_OPTIONS:+$ASAN_OPTIONS:}detect_leaks=1:halt_on_error=0:use_sigaltstack=0:log_path=$OUT/tmp_asan"

# UBSan reports look nothing like ASan's: one "file.c:12:34: runtime error: ..."
# line per finding, printed to stderr, and by default it keeps going without a
# stack trace. Ask for the trace, and let it continue so one module's first
# finding does not hide the rest.
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0:use_sigaltstack=0"

for so in modules/module_*.so; do
  base=$(basename "$so" .so)
  mode=$((10#${base#module_}))

  rm -f "$OUT"/tmp_asan.* 2>/dev/null

  timeout 600 "$HARNESS" "$so" "$mode" --mutate > "$OUT/m${mode}.out" 2>&1
  rc=$?

  logs=("$OUT/m${mode}.out" "$OUT"/tmp_asan.*)
  asan=$(grep -hF "ERROR: AddressSanitizer" "${logs[@]}" | wc -l)
  lsan=$(grep -hF "ERROR: LeakSanitizer" "${logs[@]}" | wc -l)
  # UBSan findings, deduplicated: the same runtime error inside a loop prints
  # once per iteration and would otherwise dominate the count
  ub=$(grep -hoP "^[^ ]+: runtime error: .*" "${logs[@]}" | sort -u | wc -l)
  total=$(( asan + lsan + ub ))

  # The harness returns 1 when the sanitizer reported a finding, 2 when it
  # could not run the module at all, and 0 for a clean run. A finding can also
  # show up as text (a UBSan run has no callback into the harness), so it is
  # counted either way.
  if [ "$total" -gt 0 ] || [ "$rc" = "1" ]; then
    result=1
    echo "m${mode}: *** ${total} SANITIZER ERRORS *** (asan=$asan lsan=$lsan ubsan=$ub rc=$rc)" | tee -a "$LOG"
    grep -hoP "ERROR: (?:Address|Leak)Sanitizer: \K.*" "${logs[@]}" | sort -u \
      | sed 's/^/    /' | tee -a "$LOG"
    grep -hoP "runtime error: \K.*" "${logs[@]}" | sed 's/[0-9]\+/N/g' | sort -u | head -4 \
      | sed 's/^/    ubsan: /' | tee -a "$LOG"
    grep -hoP "#[0-9]+ 0x[0-9a-f]+ in \K[a-z_0-9]+ [^ ]+\.c:[0-9]+" "${logs[@]}" | sort -u \
      | head -4 | sed 's/^/      /' | tee -a "$LOG"
    mkdir -p "$OUT/findings/m${mode}"
    cat "${logs[@]}" > "$OUT/findings/m${mode}/asan.log"
    cp "$OUT/m${mode}.out" "$OUT/findings/m${mode}/" 2>/dev/null
  elif [ "$rc" = "124" ]; then
    result=1
    echo "m${mode}: TIMEOUT (600s)" | tee -a "$LOG"
  elif [ "$rc" != "0" ]; then
    result=1
    # rc 2 is the harness's own "could not run": a failed dlopen, a missing
    # module_init, or a stale plugin tree (context size mismatch, rebuild the
    # plugins). Any other nonzero rc is an unexpected harness failure. Neither
    # is a clean run, and a stale tree would otherwise mark every module clean.
    echo "m${mode}: NOT RUN (harness rc=$rc)" | tee -a "$LOG"
    grep -m1 "^harness:" "$OUT/m${mode}.out" 2>/dev/null | sed 's/^/    /' | tee -a "$LOG"
    mkdir -p "$OUT/findings/m${mode}"
    cp "$OUT/m${mode}.out" "$OUT/findings/m${mode}/" 2>/dev/null
  else
    echo "m${mode}: clean" >> "$LOG"
  fi
done

rm -f "$OUT"/tmp_asan.* 2>/dev/null

echo "=== ASAN PARSER SWEEP DONE ===" | tee -a "$LOG"
grep -c ": clean$"      "$LOG" | sed 's/^/clean modes:       /' | tee -a "$LOG"
grep -c "SANITIZER ERRORS" "$LOG" | sed 's/^/modes with errors: /' | tee -a "$LOG"
grep -c ": NOT RUN"     "$LOG" | sed 's/^/modes not run:     /' | tee -a "$LOG"
grep -c "TIMEOUT"       "$LOG" | sed 's/^/timeouts:          /' | tee -a "$LOG"
echo "per-finding logs: $OUT/findings/"
exit "$result"
