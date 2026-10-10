# Weekly CUDA GPU CI on vast.ai

`.github/workflows/test_cuda.yml` runs the same test suite as `.github/workflows/test.yml`, but on real NVIDIA GPUs with the CUDA backend instead of the CPU through PoCL (issue #4941). It rents GPUs from [vast.ai](https://vast.ai) for the length of the run and destroys them afterwards.

## How it works

The workflow runs on a normal GitHub runner. `ci/vast/weekly_gpu.py` builds the mode shards with `.github/workflows/ci_matrix.py` (the same plan `test.yml` uses), rents one GPU per shard, and over SSH has each box clone hashcat at the commit under test, build it, and run `tools/test.py` for its modes with `-D 2` (the GPU device type) in place of the `-D 1` the GPU-less runners use. The per-kind `test.py` commands are the ones `test.yml` runs, so this is not a second suite. The one kind it does not run is the Python bridge.

A rented box has the host's NVIDIA driver (so `libcuda`), but the CUDA toolkit that hashcat needs to compile its kernels at run time (`libnvrtc`) comes from the docker image, which is why a `-devel` CUDA image is used. The offer search requires the host driver's CUDA version (the offer's `cuda_max_good`) to be at least the image's toolkit version, so the kernels the image builds will load; the launcher reads that minimum from the image tag, so changing `VAST_IMAGE` moves the floor with it.

Each box builds once and runs a balanced group of modes, so a handful of GPUs cover every mode in parallel rather than one box running them all in series.

vast.ai boxes share a physical host, so right after a box boots the launcher checks its load and that a GPU is visible; a host already slammed by other tenants (its load far above its CPU count) is destroyed and the next cheapest offer is rented in its place. The box checks once more right before the attacks, after the build, and drops itself for a replacement if the CUDA backend sees no device or the load has climbed. Each mode also runs under a timeout, so a single wedged mode fails that mode rather than running until the workflow's limit.

Each box runs its tasks detached from the SSH session and tees the output to a log on the box; the launcher polls for the run to finish and then pulls that log, so a dropped SSH connection does not kill a run that is in progress.

## Setup

One secret, set once under **Settings -> Secrets and variables -> Actions**:

- `VAST_API_KEY` (secret): your vast.ai API key, from the vast.ai console under **Account**. It is used only to call vast.ai and is never sent to a rented box.

Optional repository **variables** (same settings page, the Variables tab) tune the rental without touching the workflow:

- `VAST_GPU_NAME`: the GPU to rent, as a substring, default `RTX 3060`. Set it to `any` to take any GPU that fits the other filters. An empty value is treated as unset and keeps the default.
- `VAST_MAX_DPH`: the most to pay per GPU per hour, default `0.12`.
- `VAST_MIN_CPU_CORES`: the least host CPU cores the rental must get, default `8`. The build and the kernel compiles are CPU bound, so a box with too few cores is the slow link; raising this picks beefier hosts (fewer match), lowering it widens the pool.
- `VAST_IMAGE`: the CUDA docker image the box builds and runs in, default `nvidia/cuda:12.2.2-devel-ubuntu22.04`. Its toolkit version sets the minimum host driver CUDA the offer search accepts, so a higher image narrows the hosts that qualify.

## Running it

From the **Actions** tab, pick **test-cuda** and **Run workflow**. The form chooses the modes (`all` or a list), which of the optimized, pure and container kinds to run, and how many GPUs to rent in parallel. It also runs on a weekly schedule, which only fires on the hashcat/hashcat repository so a fork's cron does not spend the budget on its own; a fork runs it by hand.

Locally, with `VAST_API_KEY` in the environment and the `vastai` CLI installed (`pip install vastai`):

    python ci/vast/weekly_gpu.py --modes "0 100 1000"      # a few modes
    python ci/vast/weekly_gpu.py --dry-run                  # print the plan and the per-box scripts, rent nothing

`--dry-run` needs no key and rents nothing, so it is the way to see exactly what each box would run.

## Cost

A full run (optimized, pure and container, every mode) is roughly 30 GPU-hours of work spread across the rented boxes, about 2 US dollars on an RTX 3060 at around 0.06 dollars per hour.

vast.ai also bills bandwidth per GB at a rate the host sets, around 0.003 to 0.016 dollars per GB in practice. Each box downloads mostly the CUDA image (about 3.5 GB, often already cached on the host and then free), plus apt, the hashcat checkout and the Python packages (about 0.5 GB), plus the LUKS archives on the few boxes that test those modes (about 0.5 GB). That is at most a few GB per box, so under a dollar for a full run; upload is negligible. Storage is a fraction of a cent for a rental measured in hours.

So a full run is roughly 2.5 to 3 dollars all in. Even the worst case, every box running to the workflow's time limit at the price cap, stays well under 10 dollars, and vast.ai stops billing once the account balance runs out, so the deposit is a hard ceiling.

## Security

The workflow triggers on the weekly schedule and on manual dispatch only, never on pull requests, so the API key is never exposed to a fork's code. `permissions: contents: read` means the job cannot push or comment. The key stays on the GitHub runner: the rented boxes only clone hashcat and run tests and never see it. Each run generates a throwaway SSH key for talking to its boxes, so no private key is stored anywhere. The boxes are destroyed when the run ends, on success, on failure, and on cancel.
