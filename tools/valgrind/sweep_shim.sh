#!/usr/bin/env bash
##
## Drop-in replacement for a plain `./hashcat` invocation, used by
## tools/test.sh --valgrind[-pocl] and tools/test_edge.sh --valgrind[-pocl]
## via their BIN/HC_BIN indirection. Wraps the real hashcat invocation in
## `run.py exec --sweep` (transparent stdout/stderr/exit-code passthrough,
## so the calling script's own pass/fail parsing is unaffected) and routes
## results into the sweep's own results directory.
##
## Required env: VALGRIND_SWEEP_DIR (results directory for this sweep run)
## Optional env: VALGRIND_SWEEP_POCL=1 (adds --pocl, fast tier)
##              VALGRIND_SWEEP_POCL_FULL=1 (adds --pocl-full instead, slow diagnostic tier)
##

set -u

TDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "${TDIR}/../.." && pwd )"

if [ -z "${VALGRIND_SWEEP_DIR:-}" ]; then
  echo "sweep_shim.sh: VALGRIND_SWEEP_DIR must be set (internal error -- not meant to be invoked directly)" >&2
  exit 2
fi

SLUG="t$(date +%s%N)-$$"

POCL_FLAG=()
if [ "${VALGRIND_SWEEP_POCL_FULL:-0}" = "1" ]; then
  POCL_FLAG=(--pocl-full)
elif [ "${VALGRIND_SWEEP_POCL:-0}" = "1" ]; then
  POCL_FLAG=(--pocl)
fi

exec python3 "${TDIR}/run.py" exec "${SLUG}" "${POCL_FLAG[@]}" --sweep \
     --results-dir "${VALGRIND_SWEEP_DIR}" \
     -- "${REPO_ROOT}/hashcat-valgrind" "$@"
