# Plan: `tools/valgrind/` — Valgrind + PoCL memory-safety testing for Hashcat

## Context

We've been running Valgrind against hashcat ad hoc this session (raw `valgrind --leak-check=full ... | grep -B10 hashes.c`-style invocations) to verify memory-safety fixes in the hash-parsing-error-message feature. That doesn't scale: every run needs hand-written grep incantations, results aren't kept, and this environment's CUDA/WSL driver stack floods Valgrind with irrelevant noise (a real sample run produced **983 errors**, ~977 of which trace entirely into `libdxcore.so`/`libcuda.so` with zero hashcat frames) — automatic classification is not optional here.

The goal, after two rounds of scope revision: a `tools/valgrind/` toolkit, driven by Python (chosen over a bash-orchestrated design for maintainability — see "Orchestration language" below), that (1) builds a Valgrind-friendly hashcat via hashcat's own `DEBUG=1` mode, (2) runs arbitrary hashcat commands under Valgrind with automatic triage down to a hashcat **source line**, distinguishing **host C code** (`src/`, `include/`) from **OpenCL kernel code** (`OpenCL/*.cl`, executed via a CPU-side PoCL OpenCL implementation so Valgrind can actually see it) from **external/unknown** noise, (3) keeps every run's results without overwriting, (4) is drivable directly from the existing `tools/test.sh`/`tools/test_edge.sh` multi-hundred-mode sweeps via `--valgrind`/`--valgrind-pocl` flags, reusing their existing workload generation rather than building a parallel test suite.

**Orchestration language**: the original spec said "shell for orchestration, Python for XML/JSON parsing only." A later, more detailed spec pasted by the user uses an all-Python layout (`run.py`/`triage.py`/`report.py`). Asked directly, the user deferred to my judgment leaning toward "Python is easier to maintain" — agreed, especially once PoCL environment-variable juggling, device auto-detection via `hashcat -I` output parsing, and three-way classification enter the picture; a single Python CLI (`run.py` with subcommands) is meaningfully easier to keep consistent than three separate bash scripts hand-off to one Python module. `test.sh`/`test_edge.sh` themselves stay bash (they're large, existing, and out of scope to rewrite) and simply shell out to `python3 tools/valgrind/run.py exec ...`.

## Verified facts this plan relies on

- **hashcat already has the exact debug build mode needed**: `src/Makefile:395-422`, keyed on `DEBUG` (default `0` at `src/Makefile:7`, plain `:=` so `make DEBUG=1` on the command line overrides cleanly). `DEBUG=0` adds `-O2 -fomit-frame-pointer` + strip (`-s`). `DEBUG=1` adds `-DDEBUG -Og -ggdb`, no stripping, no frame-pointer omission. `DEBUG=2` additionally adds `-fsanitize=address` — hashcat's own existing, separate ASan mode; never combined with Valgrind, never used as the default for `--valgrind`/`--valgrind-pocl`.
- `CFLAGS_NATIVE`/`LFLAGS_NATIVE` (`src/Makefile:501-508`) apply identically to the main binary and all ~593 `modules/module_*.so`. One `make DEBUG=1` build debug-info's everything. Object files aren't DEBUG-tagged (`obj/%.NATIVE.o`), so switching modes always needs `make clean` first.
- **`hashcat` locates `modules/` relative to its own resolved binary path**: `src/folder.c:25` (`get_exec_path()`, `readlink /proc/<pid>/exe`) → `get_install_dir()` (`src/folder.c:127`, `dirname()` of that). A `cp ./hashcat ./hashcat-valgrind` in the same directory finds the same `modules/*.so` automatically — kept as a stable, explicitly-named target for `run.py exec` regardless of which build is currently named `./hashcat`.
- Confirmed via `readelf -S ./hashcat | grep -E '\.debug_(info|line)'`: the current release build has zero debug sections — the concrete "before" state the README's justification section describes.
- Valgrind memcheck XML (protocol v4, captured and inspected directly this session): `<error>` → `<kind>`, `<what>`/`<xwhat>`, one primary `<stack>` of `<frame>` (each `<ip>`/`<obj>`, plus `<fn>`/`<dir>`/`<file>`/`<line>` only when resolved), then zero or more `<auxwhat>`+`<stack>` pairs in document order for multi-stack errors (invalid free / use-after-free / leak allocation site).
- **`--error-exitcode` must not be used**: confirmed empirically (`./hashcat -m 999999` exits 255 both with and without `--error-exitcode=99` when Valgrind finds nothing to flag; *with* it set, a run that does find errors returns 99 instead, discarding hashcat's real code). `run.py exec` invokes Valgrind plainly, captures hashcat's real `$?`/return code itself, and determines "Valgrind found errors" purely by parsing `valgrind.xml`.
- `docs/exit_status_code.txt`: hashcat's own exit codes are small negative integers (`-1 = error`, `-11 = self-test failed`, `0 = OK/cracked`, ...); a shell exit code only carries 0-255, so raw and re-signed values both belong in the JSON/terminal output.
- **PIE/addr2line**: confirmed empirically (throwaway PIE binary with a real double-free, compared Valgrind's XML `<ip>` against the object's own `readelf -sW`/`nm` symbol table) that Valgrind's `<ip>` is the *runtime* (ASLR-relocated) address, not file-relative. Fix, verified working: for a given `<obj>`, find an anchor frame Valgrind *did* resolve, derive `load_base = anchor_runtime_ip - symtab_addr` from that function's own symbol-table address, apply the same base to translate any other unresolved frame from that object before calling `addr2line`. This same mechanism generalizes to any other `<obj>` Valgrind reports, including — pending the PoCL validation below — a PoCL-compiled kernel object.
- `example.dict` (repo root) contains `password` at line 99117 — real, reproducible `--username` crack fixture with no new assets.
- Backend-selection flags **confirmed present** (`grep` against `src/usage.c`/`src/user_options.c` this session, not assumed): `--backend-ignore-cuda`, `--backend-ignore-hip`, `--backend-ignore-metal`, `--backend-ignore-opencl` (`src/usage.c:105-108`); `-I`/`--backend-info` (`src/usage.c:109`); `-d`/`--backend-devices` and `-D`/`--opencl-device-types` (`src/usage.c:110,114`). These are what `--valgrind-pocl` mode uses to force a PoCL CPU OpenCL device rather than assuming a hardcoded `-d 1`.
- **NOT yet verified — genuine research risk, must be validated empirically early in implementation, before promising kernel-line resolution works**: whether PoCL (`pocl-opencl-icd`), built with `POCL_EXTRA_BUILD_FLAGS="-g -cl-opt-disable"` and `POCL_LEAVE_KERNEL_COMPILER_TEMP_FILES=1`, actually (a) produces a JIT'd kernel object with real DWARF debug info Valgrind can load, and (b) that debug info's `<file>` correctly names the original `OpenCL/mXXXXX*.cl` source rather than a synthetic/temp path. This session has not installed or tested PoCL at all. Everything downstream of this fact (OPENCL_KERNEL classification actually resolving to a `.cl:line`, not just "it's somewhere in a PoCL object") depends on it and needs its own early spike (see Implementation order below) rather than being assumed to work because the plan says so.
- `tools/test.sh` conventions: `#!/usr/bin/env bash`, no `set -e`/`set -u`, self-locating via `TDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"` (`tools/test.sh:13`). Builds a `CMD="./${BIN} ..."` string per test case and runs it via `output=$(eval ${CMD} 2>&1)` (`tools/test.sh:3616` etc.), `BIN="hashcat"` is a single variable (`tools/test.sh:4292`). `tools/test_edge.sh` does the same (`eval ${CMD} &> ${cmd_out}`) but hardcodes the literal `./hashcat` at ~8 call sites rather than using a variable. Both facts matter directly for how `--valgrind`/`--valgrind-pocl` get threaded in without breaking existing pass/fail parsing (which depends on `output`/`$?` being hashcat's own, untouched).
- Available in this environment: `valgrind 3.18.1` (`--xml=yes`, `--read-inline-info=yes`), `addr2line`/`readelf`/`objdump` (binutils 2.38), `python3` 3.10.12. `pocl-opencl-icd`/`clinfo` are **not currently installed** — installing them needs the user's renewed go-ahead at implementation time (the earlier sudo authorization this session was scoped narrowly to valgrind/shellcheck installation).

## Design

### Layout

```
tools/valgrind/
├── run.py          # CLI: build / check / exec / selftest subcommands
├── triage.py        # XML parsing, 3-way classification, addr2line fallback, JSON schema
├── report.py         # aggregates past runs into a table
├── hashcat.supp      # empty initially
├── README.md
├── fixtures/
│   ├── badsplit_many.hash   # malformed --username-style lines, non-zero hashcat exit expected
│   └── gooduser.hash        # "alice:5f4dcc3b5aa765d61d8327deb882cf99" (password, via example.dict)
└── results/           # gitignored; one dir per standalone run, never overwritten
```

Add to root `.gitignore`: `/tools/valgrind/results/` (anchored, matching the existing `/test_[0-9]*/` precedent).

### `run.py build`

Equivalent to the earlier bash `build-debug.sh` design, now a subcommand: `cd` to repo root, `make clean`, `make DEBUG=1 -j$(nproc)` (fail loud, exit 2 on build failure), `shutil.copy("./hashcat", "./hashcat-valgrind")` (same directory as `modules/`, resolves identically per the `folder.c` behavior above). **Build sanity check, hard stop**: run `./hashcat-valgrind --version`, require exit 0 and non-empty output — if that fails, print the captured output and exit 2 *without* proceeding to the debug-info report, so a broken build is caught here rather than surfacing later as confusing Valgrind noise. Then `readelf -S ./hashcat-valgrind | grep -E '\.debug_(info|line)'` and report OK/WARNING. Closing message notes that `./hashcat` itself and every `modules/*.so` are also now `DEBUG=1` builds (unavoidable, one `obj/` tree), and gives the exact restore command (`make clean && make -j$(nproc)`).

### `run.py check`

Diagnostic subcommand (answers the pasted spec's §13 ask, as a subcommand rather than a separate `check.sh`, consistent with the single-CLI design): reports, as a simple found/missing table —
```
Valgrind:            found (3.18.1)
Hashcat debug info:  found (./hashcat-valgrind)
PoCL platform:       found / NOT FOUND
PoCL CPU device:     found (backend device 2) / NOT FOUND
```
PoCL detection runs `./hashcat-valgrind -I` and parses its backend-listing output for an OpenCL platform whose device type is CPU (exact output format to be confirmed against a real `-I` run once PoCL is installed — do not hardcode assumptions about its text layout without checking).

### `run.py exec <test-name> [--pocl] [--sweep] [valgrind-opts...] -- <hashcat-command...>`

One entry point replaces the earlier two-script (`run.sh`/`wrap.sh`) design; `--sweep` toggles between the two I/O contracts:
- **Default (standalone/interactive)**: prints hashcat's output as it normally would, then a PASS/FAIL Valgrind summary banner; own exit code is the 0/1/2 Valgrind-verdict (0 = clean, 1 = relevant errors, 2 = wrapper/build/parse failure). Results land in `tools/valgrind/results/<timestamp>-<test-name>/`.
- **`--sweep`** (used when `test.sh`/`test_edge.sh` invoke it): stdout/stderr are hashcat's own, byte-for-byte, untouched — no banner on either stream. Exit code is hashcat's real `$?`. Still runs the identical Valgrind invocation and writes the identical artifacts, just to a directory nested under the *caller's* existing output tree — passed explicitly via `--results-dir <dir>` (so `test.sh`/`test_edge.sh` can point it at their own `test_edge_<timestamp>/valgrind/` directory, per the pasted spec's §11 request, rather than the standalone `tools/valgrind/results/` tree). Additionally appends one line (test-name/slug, hashcat rc, host/kernel/external error counts, first location) to a `sweep-findings.tsv` in that same directory, so `report.py --dir <that-dir>` can print a consolidated table afterward.

Shared logic regardless of mode:
- Splits args at a literal `--` into `HC_CMD` (a real list, never a shell string) — no `eval`, exact quoting/mask (`'?a'`, `'?l'`) preservation guaranteed by construction, not by careful escaping.
- Missing-tool checks (`valgrind`, `HC_CMD[0]`) and the **build sanity check** (`HC_CMD[0] --version`, exit 0 + non-empty output, else stop *before* invoking Valgrind at all — this was flagged explicitly: don't let a broken binary produce a wall of confusing Valgrind noise) happen before any results directory is touched.
- Debug-info check (`readelf -S <bin> | grep .debug_info`) warns but does not block (a release-build repro run is still legitimate; classification just degrades gracefully to `source_resolved=False`).
- **`--pocl`**: before running, sets `POCL_DEVICES=cpu`, `POCL_EXTRA_BUILD_FLAGS="-g -cl-opt-disable"`, `POCL_LEAVE_KERNEL_COMPILER_TEMP_FILES=1` in the child's environment (`POCL_ENABLE_UNINIT=1` is exposed as its own `--pocl-enable-uninit` opt-in flag, not a silent default, since the spec itself flags it as platform-dependent). Runs `./hashcat-valgrind -I` first (via `run.py check`'s detection logic) to find an actual PoCL CPU backend device id; if none is found, **fails clearly and does not run**, per the pasted spec's exact wording: `ERROR: --valgrind-pocl requested, but no PoCL CPU OpenCL device was found. Check: clinfo / ./hashcat-valgrind -I`. If found, injects `-d <id> -D 1 --backend-ignore-cuda --backend-ignore-hip --backend-ignore-metal` into `HC_CMD` (appended, not silently replacing anything the caller already passed — conflicting explicit `-d`/`-D` from the caller wins, with a warning).
- Results directory creation is collision-safe via atomic `mkdir` (retry a few times re-sampling the clock on `EEXIST`, then a PID-suffixed fallback) whether standalone or sweep-nested.
- Writes `command.txt`, `environment.txt` (git commit + dirty flag, compiler version, valgrind version, resolved hashcat binary path, debug-info detection result, PoCL version + device id when `--pocl`), then invokes Valgrind:
  ```
  valgrind --tool=memcheck --leak-check=full --show-leak-kinds=definite \
           --errors-for-leak-kinds=definite --num-callers=40 --read-inline-info=yes \
           --xml=yes --xml-file=<dir>/valgrind.xml --log-file=<dir>/valgrind.log \
           [--suppressions=hashcat.supp if present] \
           [extra valgrind-opts, e.g. --track-origins=yes, passed through] \
           -- <HC_CMD...>   # stdout/stderr handled per standalone-vs-sweep contract above
  ```
  No `--error-exitcode` (see verified facts). `--track-origins=yes` stays an explicit opt-in passthrough flag (matching the original spec's fixture example), not a silent default — it roughly doubles Valgrind's overhead, and that cost should be a deliberate choice per invocation, especially once whole sweeps are running under this.
- Calls into `triage.py` to parse `valgrind.xml`, render the terminal summary (standalone mode only), and write `summary.txt`/`summary.json`; `run.py exec`'s own exit code is exactly what `triage.py` returns.

### `triage.py`

Python 3 stdlib only (`xml.etree.ElementTree`, `json`, `argparse`, `subprocess`, `pathlib`, `re`, `os`). Core functions:

- **`classify_frame(frame, repo_root, binary_realpath, modules_dir_realpath, pocl_kernel_dirs) -> Classification`** — now **three-way**, not two:
  1. If `<file>` is present and its resolved repo-relative path is under `OpenCL/` (or, once verified, matches a PoCL kernel temp-object's recorded original source name) → `"OPENCL_KERNEL"`, `source_resolved=True`.
  2. Else if `<file>` is present and resolved path is under `src/` or `include/` → `"HASHCAT_HOST"`, `source_resolved=True`.
  3. Else if `<obj>`'s realpath matches the hashcat binary, `modules_dir_realpath`, or a known PoCL kernel-object temp path → `"HASHCAT_HOST"` or `"OPENCL_KERNEL"` respectively, `source_resolved=False` (candidate for the addr2line/load-base fallback).
  4. Else `"EXTERNAL_UNKNOWN"` if `<obj>` is set at all, else fully `"unknown"`.
  Always prefix-of-relpath matching, never substring; still no hardcoded function-name lists, matching against real paths.
- **`find_first_relevant_frame(stacks)`**: unchanged logic from the original design — scans the primary stack top-down for the first non-`EXTERNAL_UNKNOWN` frame, falling through to aux stacks (freed-at/allocated-at) in document order if the primary stack is pure noise. Reports separately whether the frame found was `HASHCAT_HOST` or `OPENCL_KERNEL`, since the terminal rendering treats them differently (spec §8's two distinct example formats).
- **`normalize_kind`**, **`derive_load_base`/`addr2line_fallback`**: unchanged from the original design (see verified PIE facts above); the load-base mechanism is reused as-is for PoCL kernel objects once the temp-object-location research spike (below) confirms where they live and whether they carry usable DWARF.
- **`error_summary(err)`**: same idea as before, now tagging `relevance` as one of the three categories and keeping the full stack(s) regardless (current free / previously freed / allocated context for InvalidFree/UseAfterFree; allocation site for leaks — all already covered by `find_first_relevant_frame` running over the correct stack).
- **`summary.json`** schema gains split counts: `host_errors`, `kernel_errors`, `external_errors` (replacing the old flat `relevant_errors`/`external_errors` pair), plus `pocl: {enabled, device_id, version}` in the `environment` block when `--pocl` was used. Written via temp-file + `os.replace` for atomicity (concurrent `report.py` safety). `wrapper_rc`: 2 on XML parse/preflight failure, else 1 if `host_errors + kernel_errors > 0` (an all-`unknown`-classified error still counts here — fail open, a documented judgment call), else 0.
- `render_terminal(...)`: implements the two distinct example layouts from the spec — a `HOST` finding shows `src/hashes.c:1842 / hashes_init_stage2()`; a kernel finding shows `OpenCL/m03711-pure.cl:527 / m03711_comp()` under an `OPENCL_KERNEL` heading — plus the final `Host errors / OpenCL errors / External errors` count block.

### `report.py`

Two usage modes: `report.py` (bare, `--test NAME`, `--failed`, `--latest [N]`) scans `tools/valgrind/results/*/` for standalone runs, same filtering semantics as the original design. `report.py --dir <path>` scans a specific sweep's nested results directory (e.g. a `test_edge_<timestamp>/valgrind/` tree) and reads its `sweep-findings.tsv` plus per-case `summary.json`s. Columns: `RUN`, `HC_RC`, `VG`, `HOST_ERR`, `KERNEL_ERR`, `FIRST LOCATION`. Malformed/missing `summary.json` degrades to a flagged row (`?`/`<malformed>`), never crashes the whole listing — each entry wrapped in its own `try/except`.

### `hashcat.supp`

Empty initially. No entries added proactively; per the pasted spec's explicit §15, an error is never suppressed *solely* because its top frame lands in libc/LLVM/PoCL/OpenCL-runtime/malloc/free/memcpy — hashcat (or a kernel) may have supplied the bad pointer, and `classify_frame` already looks at the *whole* stack, not just the top frame, before calling something external.

### PoCL kernel-debugging mode (`--valgrind-pocl` in the sweeps / `--pocl` in `run.py exec`)

This is the scope that was explicitly deferred, then reinstated after the user confirmed the reversal. Design above covers the mechanics (env vars, device forcing, classification); three things are called out as needing empirical validation *during* implementation, not assumed from this plan alone:

1. **Whether PoCL's `-g -cl-opt-disable` + `POCL_LEAVE_KERNEL_COMPILER_TEMP_FILES=1` actually yields Valgrind-visible, correctly-named DWARF for the compiled kernel object.** If it doesn't cleanly map back to `OpenCL/*.cl:line`, the honest fallback is: classify the frame as `OPENCL_KERNEL` (we still know *which* PoCL-managed object it's in) with `source_resolved=False`, keep the full stack, and say so plainly in the terminal output rather than fabricating a line number.
2. **Where PoCL actually puts the kernel temp files/objects** (exact path is undocumented here; `POCL_LEAVE_KERNEL_COMPILER_TEMP_FILES` docs are sparse) — needed both to point `classify_frame`'s `pocl_kernel_dirs` matching at the right place and to know what to clean up between runs.
3. **What `./hashcat-valgrind -I` actually prints** for a PoCL CPU platform (used by `run.py check`'s device-detection parsing) — to be confirmed against a real run, not assumed from OpenCL conventions.

Sections 5-9/17/19 of the pasted spec (forcing CPU execution, not silently falling back to CUDA/HIP, validating against a deliberately-injected kernel bug, then reverting it) are the acceptance test for this mode — see Verification below.

### Sweep integration: `test.sh` / `test_edge.sh`

- `test.sh`: `BIN="hashcat"` (`tools/test.sh:4292`) is already a single variable feeding every `CMD=` site. Add `--valgrind`/`--valgrind-pocl` flags; when set, verify (via `run.py check`, not a rebuild-every-time) that `./hashcat-valgrind` exists and passes its sanity check, export a fresh sweep id, point `BIN` at `"python3 ../tools/valgrind/run.py exec ${sweep_id}-${hash_type}-${attack_type} [--pocl] --sweep --results-dir ${OUTD}/valgrind -- ./hashcat-valgrind"` (threaded through each `CMD=` call site individually, since there are several, not one single substitution point).
- `test_edge.sh`: first refactor the ~8 hardcoded `./hashcat` literals into one `HC_BIN="./hashcat"` variable (contained, low-risk rename) — matching the pasted spec's "reuse via a common `run_hashcat`-style path, avoid duplicating test-generation logic" ask — then apply the same flag-driven substitution as above.
- Both scripts print a one-line pointer at the end of a `--valgrind`/`--valgrind-pocl` run (`Valgrind findings: N host, M kernel — see: tools/valgrind/report.py --dir <OUTD>/valgrind`) rather than dumping the full table inline.
- **Explicitly flagged, not hidden**: Valgrind overhead alone is commonly 10-50x; `--valgrind-pocl` stacks PoCL's CPU kernel compilation/execution on top of that. An unscoped full sweep (~600+ modes) under `--valgrind-pocl` could run for a very long time and produce one full result set per test case. Both scripts already support scoping (`test_edge.sh`'s `--hash-type`/`-a`/`-V`/etc., matching the pasted spec's own recommended workflow of `-m 3711 -a 3 -V 1 --valgrind-pocl`); the README leads with scoped examples, not an unscoped sweep, as the normal development workflow.

### Fixtures

- `fixtures/gooduser.hash`: `alice:5f4dcc3b5aa765d61d8327deb882cf99`, cracks against the repo's own tracked `example.dict` (line 99117 = `password`). Exercises the real successful-cleanup path (`hashes_destroy()`).
- `fixtures/badsplit_many.hash`: malformed `--username`-style lines, non-zero hashcat exit expected without hanging — primarily proves the exit-code decoupling and regression-guards the free-before-overwrite fix landed earlier this session, reusing the exact scenario from the original spec (`-m 3711 -a 3 --session vg_split --potfile-disable --quiet badsplit_many.hash '?a'`), runnable both as `run.py exec ... -- ./hashcat-valgrind ...` directly and via `test_edge.sh -m 3711 -a 3 -V 1 --valgrind`.

### `modules/` — a whole family of permanent, one-bug-each self-test fixtures (the ground-truth baseline)

Revises the earlier draft's plan to validate `--pocl` by temporarily injecting a bug into a real hashcat kernel and reverting it — riskier (easy to forget to revert before commit) and one-shot (not re-runnable as a regression check on the tool itself). Instead, add small, permanent, intentionally-buggy standalone artifacts, the same idea as the `pietest.c` throwaway already used and verified this session for the PIE/addr2line mechanism, but checked in for good, and covering **one deterministic bug class each** rather than just double-free — so every fixture produces exactly one clean finding with nothing else around it. This is the point: a real hashcat+CUDA-driver run drowns in ~983 errors of fluff, and the only way to trust the triage tool's classification of *that* is to first prove it against inputs where the correct answer is known exactly, not eyeballed.

```
tools/valgrind/modules/
├── Makefile               # builds every *.c fixture + cl_harness with -g -Og -fPIE -pie (mirrors hashcat's own DEBUG=1 flags)
├── expected.json           # bug name -> {expected kind_normalized, expected relevance, expected function name}
├── double_free.c            # InvalidFree            — malloc a buffer, free() it twice
├── use_after_free.c          # UseAfterFree            — free a buffer, then read/write through the stale pointer
├── invalid_read.c             # InvalidRead             — heap buffer over-read past its allocated size
├── invalid_write.c             # InvalidWrite            — heap buffer overflow write past its allocated size
├── leak_definite.c              # DefinitelyLost          — malloc a buffer, drop the only pointer to it, never free
├── uninit_value.c                 # UninitialisedValue / ConditionalJumpUninitialised — branch on a read of uninitialised heap memory
├── double_free.cl                  # OPENCL_KERNEL, intentional out-of-bounds __global buffer write (kept under this name per the request; see note below on why the on-device bug class is OOB-write, not a literal free())
├── oob_read.cl                      # OPENCL_KERNEL, intentional out-of-bounds __global buffer read
└── cl_harness.c                      # tiny generic OpenCL host loader (build+enqueue any .cl file/kernel via the active platform), used to run both .cl fixtures
```

- Each host `.c` fixture is deliberately minimal and single-purpose: one bug, nothing else happening in the program, so Valgrind's XML for that run contains exactly one meaningful `<error>` (modulo unavoidable libc/loader startup noise, which `classify_frame` already buckets as `EXTERNAL_UNKNOWN` and which the selftest comparison ignores). Not hashcat-specific, no dependency on the hashcat build — these validate the *tool*.
- **`double_free.cl`** / **`oob_read.cl`**: OpenCL C kernels don't call `free()` on-device the way host C does, so "double free" isn't a meaningful on-device bug class — the closest real equivalent, and what Memcheck can actually observe through a CPU-executing PoCL device, is an out-of-bounds `__global` buffer access. `double_free.cl` is kept under that name per the request, with a short comment clarifying this; `oob_read.cl` covers the read-side equivalent.
- **`cl_harness.c`**: tiny, generic, non-hashcat-specific CLI (`cl_harness <kernel.cl> <kernel_name> [global_size]`) doing the minimal `clGetPlatformIDs`/`clCreateContext`/`clCreateProgramWithSource`/`clBuildProgram`/`clCreateBuffer`/`clSetKernelArg`/`clEnqueueNDRangeKernel`/`clFinish` sequence against whichever platform the standard `POCL_DEVICES`-style env selects — this is the thing Valgrind actually wraps for a kernel fixture, since a bare `.cl` file has nothing to launch it.
- **`expected.json`**: one entry per fixture — `{"double_free": {"kind": "InvalidFree", "relevance": "HASHCAT_HOST", "function": "buggy_free"}, ...}` — the ground truth `run.py selftest` (below) asserts every fixture's actual triage output against.
- Optional/lower-priority, not blocking the initial pass: `PossiblyLost`/`IndirectlyLost` fixtures (need a more deliberate orphaned-but-still-reachable structure to construct convincingly) — noted as a natural follow-up, not required for this pass since `DefinitelyLost` already exercises the leak-detection path end-to-end.

### `run.py selftest`

New subcommand: builds `modules/` (if needed), runs `run.py exec` against every host fixture directly and every kernel fixture via `cl_harness` under `--pocl`, parses each resulting `summary.json`, and compares `kind_normalized`/`relevance` (and function name, where resolved) against `modules/expected.json`. Prints a compact per-fixture PASS/FAIL table and exits non-zero if any fixture's actual finding doesn't match its expected one — a fast, automated way to answer "is the triage tool itself still correct" after any change to `triage.py`'s classification logic, independent of hashcat's own current bug-free status. This is what Verification below actually runs, rather than manually eyeballing each fixture's output.

### README.md

Covers: why debug info matters (concrete before/after contrast), `run.py build` + the `readelf` verification command, the `./hashcat-valgrind` sibling-copy rationale, `run.py exec`/`report.py` usage (including `--track-origins=yes` passthrough, `--pocl`, repeated-run behavior), that `DEBUG=2` is hashcat's separate ASan mode and is never combined with Valgrind, the CUDA/WSL driver noise caveat, the `run.py check` diagnostic table, the exact PoCL package names (`pocl-opencl-icd`, `clinfo`) with an explicit note that this plan does not auto-install them, and — still relevant even with PoCL in scope — that actual on-GPU kernel bugs (real hardware, not PoCL's CPU fallback) remain outside what this tool can see and need vendor tools (e.g. NVIDIA Compute Sanitizer).

## Implementation order (front-load the risky unknowns)

1. `run.py build` + sanity check + `readelf` before/after proof (no new risk, already fully verified).
2. Get `valgrind`/`shellcheck` confirmed and, **with the user's renewed go-ahead**, install `pocl-opencl-icd`/`clinfo` — then immediately spike the three unverified PoCL facts above (temp-file location, DWARF quality/naming, `-I` output format) with a minimal one-off kernel run, *before* writing the full `triage.py` classification logic around assumptions. If PoCL's debug info turns out unusable, this plan's `OPENCL_KERNEL` classification degrades gracefully (frame identified, line not resolved) rather than silently producing wrong line numbers — decide which outcome actually happened before proceeding.
3. `triage.py` (host-only classification first, using the existing PIE/addr2line mechanism already verified), `run.py exec`/`report.py`, the host-side `modules/` fixtures (`double_free.c`, `use_after_free.c`, `invalid_read.c`, `invalid_write.c`, `leak_definite.c`, `uninit_value.c`) + `run.py selftest`, and the two hashcat fixtures (`gooduser.hash`/`badsplit_many.hash`) — this is the already-de-risked core from the original spec, now with an automated ground-truth check before moving on to PoCL.
4. Extend `triage.py`/`run.py exec --pocl` for kernel classification using whatever the step-2 spike found; add `cl_harness.c`, `double_free.cl`, `oob_read.cl` to `run.py selftest`.
5. `test.sh`/`test_edge.sh` integration (`HC_BIN` refactor, flag plumbing, nested results directories).

## Verification

0. Copy this finalized plan into `plan.md` at the repo root (first action after approval).
1. `run.py build`; confirm `readelf -S ./hashcat-valgrind` now shows debug sections (currently empty on the release build).
2. Sanity-check enforcement: point `run.py exec` at a deliberately broken/non-executable path and confirm a clear error + exit 2 with **no** Valgrind invocation attempted.
3. Standalone `success` and `split` fixtures (host-only, no `--pocl`): confirm PASS/0 and the exit-code decoupling respectively, matching results already obtained manually this session.
4. `run.py check`: confirm it correctly reports PoCL platform/device presence once installed (and correctly reports "NOT FOUND" beforehand).
5. **Ground-truth baseline (`run.py selftest`)**: run the full `modules/` fixture family and confirm every one of `double_free.c` (`InvalidFree`), `use_after_free.c` (`UseAfterFree`), `invalid_read.c` (`InvalidRead`), `invalid_write.c` (`InvalidWrite`), `leak_definite.c` (`DefinitelyLost`), and `uninit_value.c` (`UninitialisedValue`/`ConditionalJumpUninitialised`) is classified `HASHCAT_HOST` with the exact expected kind and resolves to the fixture's own source line — this is what proves the triage tool reports *exact* errors instead of drowning them in fluff, on inputs where the right answer is known in advance. Then, once PoCL is installed and the step-2 spike has run, extend `selftest` to `double_free.cl` and `oob_read.cl` via `cl_harness`, confirming `OPENCL_KERNEL` classification — resolved to `OpenCL/<file>:<line>`-equivalent if usable DWARF was found, otherwise a clearly-labeled unresolved-but-correctly-classified kernel frame. Do not consider `--pocl` support "done" without these self-test fixtures demonstrating both host and kernel bugs caught end-to-end. Only after `selftest` is fully green, spot-check one real, small hash mode run through `--pocl` (no injected bug expected — just confirming a real hashcat+PoCL run completes and produces sane `EXTERNAL_UNKNOWN` bucketing for genuine PoCL/LLVM runtime noise).
6. `report.py` (bare, `--test`, `--failed`, `--latest`, `--dir <sweep dir>`); corrupt one `summary.json` and confirm it's flagged, not crashing.
7. `test_edge.sh --valgrind` and `test_edge.sh --valgrind-pocl`, each scoped to one mode/attack/vector-width (not a full sweep) — confirm existing pass/fail output/exit-code checks are unaffected, a nested results dir + `sweep-findings.tsv` appears, and the end-of-run pointer prints.
8. Restore the release build: `make clean && make -j$(nproc)`.
