# tools/valgrind/ — Valgrind + PoCL memory-safety testing for hashcat

A reusable Valgrind runner for hashcat that triages every finding down to a
**hashcat source location** (`src/hashes.c:1842` in `hashes_init_stage2()`),
distinguishing hashcat's own host C code from OpenCL kernel code from
external/unknown noise, instead of leaving you to `grep` through a raw
Valgrind log. It can also run hashcat's OpenCL kernels through a CPU-side
OpenCL implementation (PoCL) so Valgrind can see inside kernel execution,
which it otherwise cannot do for anything that runs on a real GPU.

**Honest performance assessment, after tuning `--pocl` for speed (see the
fast/full split below)**: even the fast tier is still slow enough that it is
practical only for a single, small, targeted repro — a handful of candidates
against one hash, not a real wordlist or a sweep across many modes. In
practice a real KDF-heavy mode against a ~100K-word dictionary still took
12+ CPU-minutes under `--pocl` in this environment; running several `--pocl`
invocations concurrently also hit PoCL device-detection contention (`-I`
queries racing) rather than actually scaling wall-clock time down. Use it to
confirm/diagnose one specific finding on one specific candidate, not as a
routine CI-style regression gate — for that, a native (non-Valgrind) crash
reproduction, or a real GPU vendor sanitizer, will get you an answer in
seconds instead of minutes.

## Why debug info is required

hashcat's default release build strips symbols and omits frame pointers, so
Valgrind can only report raw addresses inside an opaque binary:

```
Invalid read of size 4
   at 0x10A1B4: ??? (in ./hashcat)
```

A `DEBUG=1` build (`-Og -ggdb`, no stripping — hashcat's own existing debug
mode, see `src/Makefile`) gives Valgrind a real source location instead:

```
Invalid read of size 4
   at 0x10A1B4: hashes_init_stage2 (src/hashes.c:1842)
```

Verify a binary has debug info before trusting Valgrind's output:

```
readelf -S ./hashcat-valgrind | grep -E '\.debug_(info|line)'
```

If that prints nothing, you're looking at a stripped build and every finding
will be an unresolved address, not a source line.

## `run.py build`

```
tools/valgrind/run.py build
```

Runs `make clean && make DEBUG=1 -j$(nproc)` from the repo root, then copies
`./hashcat` to a stable, explicitly-named `./hashcat-valgrind` sibling. That
copy exists because hashcat locates its `modules/` directory relative to its
own resolved binary path (`src/folder.c`), so a plain `cp` finds the same
`modules/*.so` automatically — no separate module tree needed, and you keep
a debug binary under a fixed name even after `./hashcat` gets rebuilt back
to a release build later.

**Note**: `DEBUG=1` rebuilds `./hashcat` itself and every `modules/*.so` too
(hashcat has one `obj/` tree, not one per debug level — this is unavoidable).
Restore the normal release build afterward with:

```
make clean && make -j$(nproc)
```

`run.py build` also runs a hard sanity check (`./hashcat-valgrind --version`
must exit 0 with non-empty output) before declaring success — a build that
doesn't even run is reported as a build failure, not silently handed off to
Valgrind to produce a wall of confusing noise.

`DEBUG=2` is hashcat's own, separate AddressSanitizer mode. It is never
combined with Valgrind (ASan and Valgrind actively conflict) and is not
used by any of these tools.

## `run.py check`

```
tools/valgrind/run.py check
```

Prints a found/missing diagnostic table: Valgrind itself, debug info on
`./hashcat-valgrind`, and (once PoCL is installed) PoCL's OpenCL platform
and CPU device. Useful before a `--pocl` run to confirm the prerequisites
are actually in place rather than finding out from a failed run.

## `run.py exec` — run one command

```
tools/valgrind/run.py exec <test-name> [--pocl | --pocl-full] [--undef-value-errors-no] [valgrind-opts...] -- <hashcat-command...>
```

Examples (matching the two fixtures under `fixtures/`):

```
tools/valgrind/run.py exec success \
  -- ./hashcat-valgrind -m 0 -a 0 -w 1 --potfile-disable --quiet \
     --username tools/valgrind/fixtures/gooduser.hash example.dict

tools/valgrind/run.py exec split --track-origins=yes \
  -- ./hashcat-valgrind -m 3711 -a 3 --session vg_split --potfile-disable --quiet \
     tools/valgrind/fixtures/badsplit_many.hash '?a'
```

**What these actually show, verified end-to-end in this environment**: `split`
correctly demonstrates the exit-code decoupling (hashcat exits `1`/"exhausted"
because every hash in the fixture is deliberately malformed; that's unrelated
to, and doesn't get conflated with, the Valgrind verdict). Neither fixture
comes back clean, though — both surface a real, reproducible finding in
hashcat's own code: `hc_cuDriverGetVersion()` (`src/ext_cuda.c:397`) shows a
"conditional jump depends on uninitialised value" every time it's called
(over a thousand times in one run, since it's probed repeatedly during
backend enumeration). Its own full stack shows the call originating a few
frames inside `/usr/lib/wsl/lib/libdxcore.so`/`libcuda.so` (WSL's CUDA
passthrough shim) — meaning the true fault may be in that driver shim, not
hashcat's own logic, which hashcat merely called into. `run.py exec` prints
that context automatically whenever it applies (see the `Called from N
external frame(s) above` note under a finding) precisely so a human doesn't
reflexively blame the labelled hashcat frame when the real culprit is code
it called. This is real, useful signal from a real environment, not a
fixture — treat it as a starting point for a hashcat maintainer to
investigate, not as this tool's own verification target (that's what
`run.py selftest` and `modules/` are for).

- Everything after `--` is the exact hashcat command, passed through as a
  real argument list (never `eval`'d), so masks like `'?a'` survive exactly.
- Anything **before** `--` that isn't `<test-name>`/`--pocl` is passed
  straight through to Valgrind — e.g. `--track-origins=yes` above. This is
  opt-in per invocation, not a default, since it roughly doubles Valgrind's
  overhead.
- Before touching Valgrind at all, `run.py exec` runs the same build-sanity
  check as `run.py build` against the binary you gave it, and warns (but
  does not block) if that binary has no debug info — a release-build repro
  run is still legitimate, it just won't resolve to source lines.
- hashcat's own exit code and Valgrind's findings are tracked **separately**.
  The `split` example above is expected to exit non-zero (the input is
  deliberately malformed) — that must not, and does not, get reported as a
  memory-safety failure. `run.py exec`'s own exit code reflects only the
  Valgrind verdict: `0` = clean, `1` = relevant findings, `2` =
  wrapper/build/parse failure.
- Every run gets its own timestamped `tools/valgrind/results/<timestamp>-<test-name>/`
  directory (never overwritten) with `command.txt`, `environment.txt`,
  `valgrind.log`, `summary.txt`, `summary.json`, plus `valgrind.xml` (full
  tier only — fast `--pocl` mode has no XML file, just the plain-text log).
- Re-running the same `<test-name>` is safe and expected — repeated runs
  each get their own directory.

### PoCL kernel mode: `--pocl` (fast) vs `--pocl-full` (deep diagnostic)

```
tools/valgrind/run.py exec kernel-check --pocl      -- ./hashcat-valgrind -m <mode> ...
tools/valgrind/run.py exec kernel-check --pocl-full -- ./hashcat-valgrind -m <mode> ...
```

Valgrind instruments the CPU process it wraps. A GPU kernel dispatched to a
real GPU runs entirely outside that process — no flag changes that. PoCL is
a CPU-only OpenCL implementation: both `--pocl` and `--pocl-full` force
hashcat onto PoCL's CPU device (`--backend-ignore-cuda --backend-ignore-hip
--backend-ignore-metal`, relying on hashcat's own CPU auto-fallback rather
than a hardcoded device index). If no PoCL CPU device is found, the run
fails clearly rather than silently falling back to a GPU backend:

```
ERROR: --pocl requested, but no PoCL CPU OpenCL device was found.
Check:
  clinfo
  ./hashcat-valgrind -I
```

Install PoCL first: `sudo apt-get install pocl-opencl-icd clinfo` (not done
automatically by any of these tools).

The two modes exist because Valgrind+PoCL overhead compounds badly on
anything slow to begin with (GPG's S2K key-stretching modes, for example,
took 18+ minutes for a single small run under the old always-maximal
settings). **`--pocl` is the routine, fast tier** — use it for everyday
regression runs, including sweeps. **`--pocl-full` is the slow, deep
diagnostic tier** — reach for it only to get maximal detail reproducing a
finding `--pocl` already flagged.

| | `--pocl` (fast) | `--pocl-full` (deep) |
|---|---|---|
| Leak checking | off (`--leak-check=no`) | full |
| Origin tracking | off (`--track-origins=no`) | on (`--track-origins=yes`) |
| Kernel build flags | `POCL_EXTRA_BUILD_FLAGS="-g"` (optimized, still labelled) | `"-g -cl-opt-disable"` (unoptimized, line-precise) |
| PoCL compute units | `POCL_CPU_MAX_CU_COUNT=1` (both — Valgrind serializes threads anyway) | same |
| hashcat dispatch | forced minimal: `-M -n 1 -u 1 -T 1 --backend-vector-width 1` | whatever the caller passed |
| Output format | plain-text `--error-markers`, parsed by `triage.parse_markers_log()` | `--xml=yes`, parsed by `triage.parse_xml()` |
| `--num-callers` | 40 | 40 |

**Fast-mode caveat on stack resolution**: Valgrind's plain-text
`--error-markers` output never reports a frame's `<dir>` together with its
`<file>:<line>` the way XML does — only a bare filename. `triage.py` closes
this gap with a basename index built from every file under `src/`,
`include/`, and `OpenCL/`, so a uniquely-named source file still classifies
correctly; a same-named file that exists in more than one of those
directories would not resolve unambiguously in fast mode (not observed in
practice, since hashcat's source filenames are unique). If a fast-mode
finding needs that ambiguity resolved, or needs the extra call-stack
precision that unoptimized kernels give, rerun the same command with
`--pocl-full`.

**Optional even-faster tier**: `--undef-value-errors-no` (only meaningful
alongside `--pocl`) additionally passes `--undef-value-errors=no`, skipping
Memcheck's uninitialized-value tracking entirely — address-only checking.
This is opt-in, never a default, since it defeats one of Memcheck's two
primary jobs (finding reads of uninitialized memory, which is most of what
`--pocl` mode exists to catch in kernels). Reach for it only when you
specifically want invalid-access checking alone, as fast as this tool gets.

**`--valgrind` (no `--pocl`/`--pocl-full`) stays the host-only tier**, XML
output, full leak checking, unchanged from before this split — origins
tracking is still an explicit passthrough opt-in there (`--track-origins=yes`),
not a default, since host-only runs are usually fast enough that this stays
a deliberate per-invocation choice.

**Known limitation, confirmed empirically**: PoCL copies kernel source into
a randomly-named temp file under `~/.cache/pocl/kcache/` before compiling
it, so Valgrind's resolved `<file>` for a kernel frame cites that temp path,
not the original `OpenCL/*.cl` file. Since the copy is byte-for-byte
identical, `triage.py` recovers the real path via a content hash against
every `OpenCL/*.cl` file in the repo whenever the temp file is still on disk
(`POCL_LEAVE_KERNEL_COMPILER_TEMP_FILES=1` keeps it around) — but if that
recovery fails (temp file already cleaned up, or the kernel source doesn't
match anything under `OpenCL/`, e.g. the self-test fixtures below), you'll
see the temp path instead of the real one. The line number itself is always
correct against the original source either way.

**Also confirmed empirically**: real, on-GPU kernel bugs (actual GPU
hardware, not PoCL's CPU fallback) remain outside what any of this can see.
For that, the right tools are vendor-specific (e.g. NVIDIA Compute
Sanitizer for CUDA), not Valgrind.

## `run.py selftest` — the ground-truth baseline

```
tools/valgrind/run.py selftest [--pocl]
```

A real hashcat run against this sandbox's CUDA/WSL driver stack can produce
close to a thousand Valgrind errors, nearly all of them noise from
`libdxcore.so`/`libcuda.so`. Trusting the triage tool's classification of
*that* requires first proving it against inputs where the correct answer is
known exactly — which is what `modules/` is for: eight small, permanent,
one-bug-each fixtures (`double_free.c`, `use_after_free.c`, `invalid_read.c`,
`invalid_write.c`, `leak_definite.c`, `uninit_value.c`, and two `.cl` kernel
fixtures run via `cl_harness`), each checked against an exact expected
`(relevance, kind)` in `modules/expected.json`.

Run it after touching `triage.py`'s classification logic, or any time you
want to confirm the tool itself is still correct before trusting it against
real hashcat output. Verified reliable across repeated clean-cache runs
(8/8 pass, 3 consecutive full runs during development).

Two of the fixtures are named `double_free.c`/`double_free.cl` and
`invalid_read.c`/`oob_read.cl` per their original naming request, with two
honestly-documented deviations from what those names might suggest:

- **OpenCL C kernels can't call `free()`** — there's no on-device double-free.
  `double_free.cl`'s actual bug (documented in the file) is an uninitialised
  private variable used in a branch.
- **Out-of-bounds kernel buffer access was tried first and abandoned.**
  Under PoCL's pthread CPU driver in this environment, small-buffer OOB
  reads/writes proved empirically unreliable to detect deterministically —
  sometimes silently absorbed by allocator padding, sometimes corrupting
  Valgrind's own bookkeeping outright, and flaky in between even at the same
  offset across repeated runs. Both `.cl` fixtures use uninitialised-value
  bugs instead (a different code shape each, so they're not just copies of
  each other), which were verified reliable.

## `report.py` — aggregate past runs

```
tools/valgrind/report.py                    # all runs in tools/valgrind/results/
tools/valgrind/report.py --test success     # filter by test name
tools/valgrind/report.py --failed           # only runs with relevant findings or a wrapper failure
tools/valgrind/report.py --latest 5         # last 5, after other filters
tools/valgrind/report.py --dir <sweep-dir>  # a test.sh/test_edge.sh sweep's own results directory
```

Prints a `RUN / HC_RC / VG / HOST_ERR / KERNEL_ERR / FIRST LOCATION` table.
A missing or malformed `summary.json` shows up as a flagged row (`?` /
`<malformed>`) rather than crashing the whole listing.

## Running from `tools/test.sh` / `tools/test_edge.sh`

Both existing regression sweeps accept `--valgrind`, `--valgrind-pocl`
(fast), and `--valgrind-pocl-full` (deep diagnostic), reusing their existing
hash-mode/attack-mode/vector-width test generation instead of a parallel
test suite:

```
tools/test_edge.sh -m 3711 -a 3 -V 1 --valgrind
tools/test_edge.sh -m 3711 --valgrind-pocl
tools/test_edge.sh -m 17010 --valgrind-pocl-full
tools/test.sh --valgrind
```

Requires `tools/valgrind/run.py build` to have been run first (both scripts
check for `./hashcat-valgrind` and exit with a clear error if it's missing).
Each hashcat invocation is transparently routed through
`tools/valgrind/sweep_shim.sh`, which wraps it in `run.py exec --sweep`:
hashcat's own stdout/stderr/exit code pass through completely untouched, so
the scripts' existing pass/fail parsing is unaffected — Valgrind's own
findings are written to a `tools/valgrind/results/sweep-<timestamp>/`
directory instead, printed as a pointer at the end of the run:

```
> Valgrind findings: see tools/valgrind/report.py --dir "tools/valgrind/results/sweep-20260812-140500"
```

**Performance note**: Valgrind's overhead is commonly 10-50x, and
`--valgrind-pocl[-full]` adds PoCL's own CPU kernel compilation/execution on
top of that — `--valgrind-pocl` (fast tier) keeps this as low as this tool
gets; reach for `--valgrind-pocl-full` only when reproducing a specific
finding, not for routine sweeps. An unscoped sweep across hashcat's 600+
modes could still run for a very long time even in fast mode. Use the
existing scoping flags (`test_edge.sh`'s `-m`/`-a`/`-V`/`--hash-type-min`/
`--hash-type-max`, etc.) to bound a run — that's the intended normal
workflow, not an unscoped sweep.

## `hashcat.supp`

Empty by default. A Valgrind suppression file, passed via `--suppressions=`
whenever it exists. Kept narrow deliberately: an error is never suppressed
solely because its top frame lands in libc/PoCL/the OpenCL runtime — hashcat
(or a kernel) may have supplied the bad pointer, and classification already
looks at the whole stack, not just the top frame, before calling something
external.

## Layout

```
tools/valgrind/
├── run.py          # CLI: build / check / exec / selftest
├── triage.py        # XML + plain-text (--error-markers) parsing, classification, addr2line + PoCL content-hash fallback, JSON schema
├── report.py         # aggregates past runs into a table
├── sweep_shim.sh      # BIN indirection target for test.sh/test_edge.sh --valgrind[-pocl]
├── hashcat.supp        # empty by default
├── fixtures/             # real hashcat scenarios (gooduser.hash, badsplit_many.hash)
├── modules/               # ground-truth self-test fixtures (see `run.py selftest` above)
└── results/                 # gitignored; one directory per run, never overwritten
```
