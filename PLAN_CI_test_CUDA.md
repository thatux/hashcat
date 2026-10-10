# Weekly CUDA GPU CI via vast.ai (hashcat issue #4941)

## Context

Issue #4941 asks to run the existing weekly test suite on a real NVIDIA GPU using the CUDA backend, because CUDA/NVIDIA is the largest share of hashcat usage and the current CI only exercises CPU OpenCL (PoCL). The issue lists AWS OSS credits, a GitHub-hosted T4 runner, Azure/GCP and self-hosted runners as provider options and asks to keep the first version simple: reuse the current weekly suite rather than write a CUDA-specific one.

This plan uses vast.ai, a GPU rental marketplace where the user has funded an account. It supersedes an earlier Lightning.ai version. The deliverable is a GitHub Actions workflow the user can trigger from the Actions tab (like `test`), which rents GPUs, runs the suite on them, and tears them down. It runs the optimized, pure and container kinds; it does not run the Python bridge kind.

Decisions already made: provider is vast.ai; the GPU is an RTX 3060 class card (Ampere, 12 GB, about 0.06 dollars per hour, the cheapest that is still modern and has the memory for the KDF-heavy modes); the run model is an SSH launcher rather than self-hosted runners (see below); the budget is a 10 dollar deposit, which is a hard ceiling. vast.ai also bills bandwidth per GB (roughly 0.003 to 0.016 dollars per GB); each box downloads a few GB at most (the CUDA image, often host-cached and then free, plus the checkout and the LUKS archives where needed), so bandwidth is under a dollar for a full run and a full run is roughly 2.5 to 3 dollars all in. Validation: the user pushes the branch to their fork, sets the `VAST_API_KEY` secret, and dispatches the workflow; `--dry-run` and local syntax checks happen regardless.

## Why an SSH launcher, not a self-hosted runner

Two ways reuse the weekly suite on GPUs: register vast.ai boxes as ephemeral self-hosted GitHub runners and reuse `test.yml`'s matrix, or have a normal runner rent boxes and drive them over SSH. The launcher was chosen because it needs only the `VAST_API_KEY` secret (a self-hosted runner needs a repo-admin registration token the fork cannot mint), the user can validate it end to end on their own fork, teardown lives in one place, and it never exposes a self-hosted runner to pull request code. It reuses the suite's real logic, the shard plan in `ci_matrix.py` and the per-kind `test.py` command, rather than the `test.yml` file itself. Reusing the literal workflow through `workflow_call` on self-hosted runners stays a possible later upgrade, noted but not built, since it is a maintainer-side change.

## How it reuses the existing machinery (no duplicated logic)

- Shard plan: `ci/vast/weekly_gpu.py` imports `.github/workflows/ci_matrix.py` (via importlib, since it is not on a package path) and uses `modes_on_disk("test")` for the kernel kinds, `container_modes()` for the container kind, and `mode_weight` to balance the shards. One source of truth; `ci_matrix.py` needs no edit.
- Per-mode run: the exact `test.py` options from `test.yml`'s test step, one per kind. opt is `-a all -t all`, pure is `-a all -t all -P`, container passes neither (the container families use their own fixed attack), and each runs with `-D 2 -f` in place of `-D 1 -f`. The bridge kind (`--bridge`) is not run. test.py is already GPU/CUDA-ready through `-D 2`.

## Files

### `ci/vast/weekly_gpu.py` (the launcher)

Runs on the GitHub runner, not on a GPU. Responsibilities:

- Resolve the repository and commit under test from the GitHub environment (`GITHUB_SERVER_URL`/`GITHUB_REPOSITORY`/`GITHUB_SHA`), falling back to the local checkout then upstream master, so each box tests exactly what was pushed.
- Build the (mode, kind) task list for the requested kinds and modes, drop mode 74000 (the Rust bridge, no GPU kernel) from the kernel kinds, and bin-pack the tasks into N instances by `mode_weight` (longest-processing-time, the same idea as `balance_shards`).
- Find offers over the vast.ai REST API (`GET /bundles`) filtered to a single modern NVIDIA (compute capability 7.5 and up, 12 GB class and up, CUDA 12 and up), verified, reliable, rentable, cheapest first, and pick the cheapest distinct hosts.
- For each instance: `vastai create instance` on the CUDA toolkit image with a disk and SSH; attach a throwaway SSH public key generated for this run (`vastai attach ssh`); wait until the box is running and a command succeeds over SSH; run the box's script over SSH; then `vastai destroy instance`, in a finally so a box is always torn down. All instances run in parallel threads, and an interrupt destroys any that are still up.
- The box script: install build deps and p7zip; init and fetch the exact commit; `make -j`; install `tools/requirements.txt`; set `LD_LIBRARY_PATH` to the CUDA toolkit so the runtime dlopen finds libnvrtc; fetch the LUKS container archives only when the box has a mode that needs them (the tc/vc/cl containers are in the tree); `./hashcat -I`; then run each of the box's tasks, OR-ing the per-task exit codes. A nonzero code fails the shard, and any failed shard fails the job.
- `--dry-run` prints the plan and the per-box scripts and rents nothing. `--modes`, `--kinds`, `--instances`, `--gpu-name`, `--max-dph` and `--image` tune the run; the last four also read `VAST_*` environment variables.

### `.github/workflows/test_cuda.yml` (the trigger)

`schedule` (weekly, offset from `test.yml`) and `workflow_dispatch`, no `pull_request` and no `push`. A dispatch chooses the modes, the three kinds (optimized, pure, container checkboxes) and the instance count; a schedule runs all three over every mode and only on the hashcat/hashcat repository, keeping `test.yml`'s "skip if master had no commit in seven days" guard. `permissions: contents: read`. Steps: checkout; setup-python; `pip install vastai`; run the launcher with `VAST_API_KEY` from the repository secret and the `VAST_*` tuning from repository variables.

### `ci/vast/README.md`

What the workflow does and why vast.ai; the one secret (`VAST_API_KEY`) and the optional tuning variables and where to set them; how to run it from the Actions tab or locally; the cost (about 2 dollars a run, 10 dollar hard ceiling); and the security notes (schedule and dispatch only, key never leaves the runner or reaches a box, throwaway SSH key, always destroy).

## Out of scope / deferred

- No change to `test.yml`, `ci_matrix.py` or `test.py`. Reusing the literal `test.yml` via `workflow_call` on self-hosted runners is a possible later upgrade, not done here.
- The Python bridge kind, and mode 74000 which only runs through the bridge.
- Multi-architecture GPU coverage and a dedicated CUDA suite, left for later per the issue.

## Verification

Static / local (done):

1. `python3 -c "import ast; ast.parse(open('ci/vast/weekly_gpu.py').read())"` passes.
2. `python ci/vast/weekly_gpu.py --dry-run` and `--modes "14600 34100 0"` print a balanced plan, the per-box scripts, and the LUKS fetch only on the boxes that need it.
3. The vast.ai REST offer search authenticates with the key and returns offers (confirmed the key has the needed access, and that RTX 3060 12 GB is about 0.06 dollars per hour).
4. ASCII and no `--` as punctuation in added lines, per repo rules.

End to end (the user, on their fork):

5. Push the branch, set `VAST_API_KEY`, dispatch **test-cuda** with a few modes first to calibrate the GPU build time and the per-mode time, then the full run. Watch the first run: confirm the CUDA backend initializes on the box (`./hashcat -I` shows the GPU, libnvrtc and libcuda load), the modes pass, and every instance is destroyed at the end.

## PR

Branch off master. Commit as thatux, no AI trailer. The PR description opens with what it does (weekly CUDA run on vast.ai), the provider rationale against the issue's listed options, the launcher-vs-self-hosted-runner choice, the cost and the 10 dollar ceiling, and the setup (one secret). docs/changes.txt is left to the maintainers with a `Changelog:` line in the PR description. Draft the PR body into a file for the user to post; do not post from here.
