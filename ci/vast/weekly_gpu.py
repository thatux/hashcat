#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

## Runs the weekly test suite on real NVIDIA GPUs through vast.ai, so the CUDA
## backend gets exercised (issue #4941). This runs on the GitHub runner, not on
## the GPU: it works out the mode shards, rents one vast.ai GPU per shard, and
## over SSH has each box clone hashcat at the commit under test, build it, and
## run tools/test.py for its modes with "-D 2" (the GPU device type) instead of
## the "-D 1" the GPU-less runners use. The boxes are destroyed when the run
## ends, pass or fail.
##
## The shard plan and the per-mode commands are the same ones
## .github/workflows/test.yml uses on the CPU: the mode pools and the balancing
## come from .github/workflows/ci_matrix.py, and the per-kind test.py line is
## the one from that workflow. Nothing here is a second test suite; the bridge
## kind is the one test.yml kind this does not run.
##
##   weekly_gpu.py                                  all kinds, all modes
##   weekly_gpu.py --modes "0 100 1000"             just those modes
##   weekly_gpu.py --kinds opt,container            only those kinds
##   weekly_gpu.py --instances 4 --dry-run          print the plan, rent nothing
##
## Authentication is the vast.ai API key in the VAST_API_KEY environment
## variable; it is used only to talk to vast.ai and is never sent to a rented
## box. Each box gets a throwaway SSH key generated for this run, so no private
## key is stored anywhere. The process exits non-zero when any shard fails.

import argparse
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

VAST_API = "https://console.vast.ai/api/v0"

# The upstream clone URL and ref a box falls back to when nothing in the
# environment names the repository and commit under test (a plain local run). In
# CI the GitHub environment overrides both, so the box tests exactly what was
# checked out.
DEFAULT_REPO_URL = "https://github.com/hashcat/hashcat"
DEFAULT_REF = "master"

# The per-kind test.py options, matching the "test.py" step in test.yml. opt is
# the optimized kernels, pure adds -P for the pure kernels, container cracks the
# shipped or fetched container files and takes no attack or kernel-type option
# because run_container_mode uses the family's own fixed attack. bridge is left
# out on purpose: this suite does not run the Python bridge pass.
KIND_OPTS = {
    "opt": "-a all -t all",
    "pure": "-a all -t all -P",
    "container": "",
}

# Container modes whose files are not in the tree and are fetched at run time,
# split by the two archives test.yml caches. The TrueCrypt, VeraCrypt and
# CryptoLoop containers are checked in, so they need no fetch.
LUKS1_MODES = {14600, 29511, 29512, 29513, 29521, 29522, 29523,
               29531, 29532, 29533, 29541, 29542, 29543}
LUKS2_MODES = {34100}

# Mode 74000 is the Rust bridge: it has no GPU kernel and only runs through the
# bridge, which this suite skips, so it is left out of the opt and pure passes
# rather than dragging a Rust toolchain onto every GPU box for a mode that would
# skip anyway.
BRIDGE_ONLY_MODES = {74000}


def load_ci_matrix():
    # ci_matrix.py reads src/modules and tools/test_modules relative to the
    # working directory at import time, so run from the repo root.
    os.chdir(REPO_ROOT)
    import importlib.util
    path = REPO_ROOT / ".github" / "workflows" / "ci_matrix.py"
    spec = importlib.util.spec_from_file_location("ci_matrix", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def wanted_modes(ci_matrix, pool, modes_arg):
    """The modes from pool the run should cover: all of it, or the asked subset."""
    if modes_arg.strip().lower() == "all":
        return set(pool)
    asked = {int(tok) for tok in modes_arg.replace(",", " ").split()}
    return asked & set(pool)


def plan_tasks(ci_matrix, kinds, modes_arg):
    """One (mode, kind) task per mode and requested kind.

    opt and pure draw from the kernel pool test.yml shards; container draws from
    test.py's own container list. The tasks are what the boxes run; they are
    bin packed into instances next.
    """
    kernel_pool = sorted(m for m in ci_matrix.modes_on_disk("test")
                         if m not in BRIDGE_ONLY_MODES)
    container_pool = sorted(ci_matrix.container_modes())

    tasks = []
    for kind in kinds:
        pool = container_pool if kind == "container" else kernel_pool
        for mode in sorted(wanted_modes(ci_matrix, pool, modes_arg)):
            tasks.append((mode, kind))
    return tasks


def balance(tasks, n, weight):
    """Longest-processing-time bin packing of tasks into n instances by weight.

    Same idea as ci_matrix.balance_shards, over (mode, kind) tasks rather than
    modes, so the heavy modes spread across the boxes instead of piling onto one.
    """
    n = max(1, min(n, len(tasks)))
    bins = [[] for _ in range(n)]
    load = [0] * n
    for mode, kind in sorted(tasks, key=lambda t: weight(t[0]), reverse=True):
        i = load.index(min(load))
        bins[i].append((mode, kind))
        load[i] += weight(mode)
    return [b for b in bins if b]


def repo_url_and_ref(args):
    # In GitHub Actions the event environment names the repository and the exact
    # commit; fall back to the local checkout, then to upstream master.
    url = args.repo_url
    if url is None:
        server = os.environ.get("GITHUB_SERVER_URL")
        repo = os.environ.get("GITHUB_REPOSITORY")
        url = f"{server}/{repo}" if server and repo else DEFAULT_REPO_URL

    ref = args.ref or os.environ.get("GITHUB_SHA")
    if ref is None:
        try:
            ref = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT,
                                 check=True, capture_output=True, text=True).stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            ref = DEFAULT_REF
    return url, ref


def remote_script(repo_url, ref, bin_tasks):
    """The whole job for one box: set up, fetch the commit under test, build, and
    run test.py for each of this box's tasks, OR-ing the per-task exit codes."""
    modes = {m for m, _ in bin_tasks}
    fetch = []
    if modes & LUKS1_MODES:
        fetch.append(
            'mkdir -p tools/luks_tests && ( cd tools/luks_tests && '
            'wget -q https://hashcat.net/misc/example_hashes/hashcat_luks_testfiles.7z && '
            '7z x -y hashcat_luks_testfiles.7z >/dev/null && rm -f hashcat_luks_testfiles.7z )')
    if modes & LUKS2_MODES:
        fetch.append(
            'mkdir -p tools/luks2_tests && ( cd tools/luks2_tests && '
            'wget -q https://hashcat.net/misc/example_hashes/luks2_tests.7z && '
            '7z x -y luks2_tests.7z >/dev/null && rm -f luks2_tests.7z )')

    runs = []
    for mode, kind in sorted(bin_tasks):
        opts = KIND_OPTS[kind]
        runs.append(f"run_one {mode} {opts}".rstrip())

    return TEMPLATE.format(
        repo_url=repo_url,
        ref=ref,
        fetch="\n".join(fetch),
        runs="\n".join(runs),
    )


TEMPLATE = r"""set -eu
export DEBIAN_FRONTEND=noninteractive

echo "::group::setup"
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    build-essential git wget ca-certificates p7zip-full python3 python3-pip
# Fetch exactly the commit under test, which may be a feature branch tip the
# default clone would not carry, so init and fetch the ref by name.
git init -q hashcat
cd hashcat
git remote add origin {repo_url}
git fetch -q --depth 1 origin {ref}
git checkout -q FETCH_HEAD
echo "testing $(git rev-parse HEAD)"
make -j"$(nproc)"
python3 -m pip install -q --break-system-packages -r tools/requirements.txt
# hashcat dlopens libnvrtc at run time; the toolkit image keeps it here, and the
# host provides libcuda on the GPU.
export LD_LIBRARY_PATH="/usr/local/cuda/lib64:${{LD_LIBRARY_PATH:-}}"
{fetch}
echo "::endgroup::"

echo "::group::backend info"
./hashcat -I || true
echo "::endgroup::"

fail=0
run_one () {{
  m="$1"; shift
  echo "::group::test.py -m $m $* -D 2"
  if python3 tools/test.py -m "$m" "$@" -D 2 -f; then rc=0; else rc=$?; fi
  echo "::endgroup::"
  if [ "$rc" -ne 0 ]; then fail=1; echo "FAIL mode $m [$*] rc=$rc"; fi
}}

{runs}

exit $fail
"""


class Vast:
    """The slice of the vast.ai API this launcher needs: find offers over REST,
    and create, key, watch and destroy instances through the vastai CLI."""

    def __init__(self, api_key):
        self.api_key = api_key

    def offers(self, q):
        url = VAST_API + "/bundles/?q=" + urllib.parse.quote(json.dumps(q))
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {self.api_key}"})
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r)["offers"]

    def _cli(self, *args, check=True):
        cmd = ["vastai", *args, "--api-key", self.api_key, "--raw"]
        out = subprocess.run(cmd, capture_output=True, text=True)
        if check and out.returncode != 0:
            raise RuntimeError(f"vastai {' '.join(args)} failed: {out.stderr.strip()}")
        return out.stdout

    def create(self, offer_id, image, disk, label):
        out = self._cli("create", "instance", str(offer_id), "--image", image,
                        "--disk", str(disk), "--ssh", "--direct", "--label", label)
        return json.loads(out)["new_contract"]

    def attach_ssh(self, instance_id, pub_key):
        # No --raw payload; a plain call is enough to register the key.
        subprocess.run(["vastai", "attach", "ssh", str(instance_id), pub_key,
                        "--api-key", self.api_key], check=True, capture_output=True, text=True)

    def show(self, instance_id):
        return json.loads(self._cli("show", "instance", str(instance_id)))

    def destroy(self, instance_id):
        subprocess.run(["vastai", "destroy", "instance", str(instance_id),
                        "--api-key", self.api_key], capture_output=True, text=True)


def image_cuda_version(image):
    """The CUDA toolkit version in a docker image tag, e.g. 12.2 from
    'nvidia/cuda:12.2.2-devel-ubuntu22.04'. The host driver must be at least this,
    or nvrtc from the image emits PTX the driver cannot load. Falls back to 12.0
    when the tag does not carry a version."""
    tag = image.split(":", 1)[1] if ":" in image else ""
    head = tag.split("-", 1)[0]       # "12.2.2"
    parts = head.split(".")
    try:
        major, minor = int(parts[0]), int(parts[1])
    except (ValueError, IndexError):
        return 12.0
    # CUDA majors are around 10 to 13; a tag outside that is not a CUDA version
    # (an ubuntu:22.04 base, say), so do not turn it into an impossible filter.
    return float(f"{major}.{minor}") if 9 <= major <= 20 else 12.0


def offer_query(args):
    # Single modern NVIDIA with room for the memory heavy modes, on a verified
    # and reliable host, cheapest first. compute_cap 750 is Turing, so Ampere
    # and Ada pass and old Pascal and Maxwell do not; 11 GB keeps the 12 GB class
    # and up. cuda_max_good is the host driver's top CUDA version, so it must be
    # at least the image's toolkit version. The numbers are vast.ai's: gpu_ram is
    # in MB, dph_total is $/hour.
    return {
        "verified": {"eq": True},
        "rentable": {"eq": True},
        "rented": {"eq": False},
        "num_gpus": {"eq": 1},
        "compute_cap": {"gte": 750},
        "cuda_max_good": {"gte": image_cuda_version(args.image)},
        "gpu_ram": {"gte": args.min_gpu_ram * 1024},
        "reliability2": {"gte": args.min_reliability},
        "dph_total": {"lte": args.max_dph},
        "disk_space": {"gte": args.disk},
        "type": "on-demand",
        "order": [["dph_total", "asc"]],
        "limit": 200,
    }


def pick_offers(offers, count, gpu_name):
    """The cheapest distinct hosts matching the GPU filter, one per host so a run
    does not pile several boxes onto one machine."""
    out, seen = [], set()
    for o in offers:
        if gpu_name and gpu_name.lower() not in o["gpu_name"].lower():
            continue
        host = o.get("host_id")
        if host in seen:
            continue
        seen.add(host)
        out.append(o)
        if len(out) >= count:
            break
    return out


def wait_ssh(vast, instance_id, key_path, deadline):
    """Wait until the box is running and a command runs over SSH, returning the
    (host, port). The image pull can take a few minutes, hence the long wait."""
    host = port = None
    while time.time() < deadline:
        info = vast.show(instance_id)
        if info.get("actual_status") == "running":
            host = info.get("ssh_host")
            port = info.get("ssh_port")
            if host and port and ssh_ok(host, port, key_path):
                return host, port
        time.sleep(10)
    raise TimeoutError(f"instance {instance_id} not reachable over SSH in time")


SSH_OPTS = ["-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=20", "-o", "ServerAliveInterval=30"]


def ssh_ok(host, port, key_path):
    r = subprocess.run(["ssh", "-i", key_path, "-p", str(port), *SSH_OPTS,
                        f"root@{host}", "true"], capture_output=True, text=True)
    return r.returncode == 0


def run_shard(vast, offer, bin_tasks, script, key_path, pub_key, args, result):
    """Rent one box, run its script over SSH, record the outcome, destroy the box."""
    name = f"s{result['idx']}"
    instance_id = None
    log_path = Path(args.logdir) / f"{name}.log"
    try:
        instance_id = vast.create(offer["id"], args.image, args.disk, f"hashcat-cuda-{name}")
        result["instance"] = instance_id
        print(f"[{name}] rented instance {instance_id} on {offer['gpu_name']} "
              f"(${offer['dph_total']:.3f}/h, {offer.get('geolocation')})", flush=True)
        vast.attach_ssh(instance_id, pub_key)
        host, port = wait_ssh(vast, instance_id, key_path, time.time() + args.boot_timeout)
        print(f"[{name}] up at {host}:{port}, running {len(bin_tasks)} tasks", flush=True)
        with open(log_path, "w") as log:
            proc = subprocess.run(
                ["ssh", "-i", key_path, "-p", str(port), *SSH_OPTS, f"root@{host}", "bash -s"],
                input=script, stdout=log, stderr=subprocess.STDOUT, text=True)
        result["rc"] = proc.returncode
    except Exception as exc:  # a shard that cannot run is a failed shard
        result["rc"] = 1
        result["error"] = str(exc)
        print(f"[{name}] error: {exc}", flush=True)
    finally:
        if instance_id is not None and not args.keep:
            vast.destroy(instance_id)
            print(f"[{name}] destroyed instance {instance_id}", flush=True)
    result["log"] = str(log_path)


def main():
    p = argparse.ArgumentParser(description="Run the weekly test suite on NVIDIA GPUs via vast.ai")
    p.add_argument("--modes", default="all", help='"all" or a list like "0 100 1000"')
    p.add_argument("--kinds", default="opt,pure,container",
                   help="comma list of opt,pure,container (bridge is not run here)")
    p.add_argument("--instances", type=int,
                   default=int(os.environ.get("VAST_CUDA_INSTANCES", "10")),
                   help="how many GPUs to rent and run in parallel")
    p.add_argument("--gpu-name", default=os.environ.get("VAST_GPU_NAME", "RTX 3060"),
                   help='substring the GPU must match, or "" for any that fits the filter')
    p.add_argument("--max-dph", type=float, default=float(os.environ.get("VAST_MAX_DPH", "0.12")),
                   help="most $/hour to pay for one GPU")
    p.add_argument("--min-gpu-ram", type=int, default=11, help="least GPU RAM in GB")
    p.add_argument("--min-reliability", type=float, default=0.98, help="least vast.ai reliability")
    p.add_argument("--image", default=os.environ.get("VAST_IMAGE", "nvidia/cuda:12.2.2-devel-ubuntu22.04"),
                   help="CUDA docker image the box builds and runs in; its toolkit version sets the "
                        "minimum host driver CUDA the offer search requires")
    p.add_argument("--disk", type=int, default=24, help="instance disk in GB")
    p.add_argument("--boot-timeout", type=int, default=900, help="seconds to wait for SSH")
    p.add_argument("--repo-url", default=None, help="clone URL under test (default: this CI repo)")
    p.add_argument("--ref", default=None, help="commit or branch under test (default: this CI commit)")
    p.add_argument("--keep", action="store_true", help="do not destroy the boxes (for debugging)")
    p.add_argument("--dry-run", action="store_true", help="print the plan and scripts, rent nothing")
    args = p.parse_args()

    kinds = [k.strip() for k in args.kinds.split(",") if k.strip()]
    bad = [k for k in kinds if k not in KIND_OPTS]
    if bad:
        sys.exit(f"unknown kind(s): {', '.join(bad)} (known: {', '.join(KIND_OPTS)})")

    ci_matrix = load_ci_matrix()
    tasks = plan_tasks(ci_matrix, kinds, args.modes)
    if not tasks:
        print("no testable modes in the requested set, nothing to run")
        return 0

    bins = balance(tasks, args.instances, ci_matrix.mode_weight)
    repo_url, ref = repo_url_and_ref(args)
    print(f"{len(tasks)} tasks ({'+'.join(kinds)}) in {len(bins)} instances "
          f"of {args.gpu_name or 'any'} from {repo_url}@{ref}", flush=True)

    scripts = [remote_script(repo_url, ref, b) for b in bins]

    if args.dry_run:
        for i, (b, s) in enumerate(zip(bins, scripts)):
            print(f"\n--- instance {i}: {len(b)} tasks "
                  f"({' '.join(f'{m}:{k}' for m, k in sorted(b))}) ---")
            print(s)
        return 0

    api_key = os.environ.get("VAST_API_KEY")
    if not api_key:
        sys.exit("no VAST_API_KEY in the environment")
    vast = Vast(api_key)

    offers = vast.offers(offer_query(args))
    picked = pick_offers(offers, len(bins), args.gpu_name)
    if len(picked) < len(bins):
        print(f"only {len(picked)} offers match (wanted {len(bins)}); "
              f"running the cheapest shards that fit", flush=True)
        bins = bins[:len(picked)]
        scripts = scripts[:len(picked)]
    if not picked:
        sys.exit("no vast.ai offers match the filter; raise --max-dph or clear --gpu-name")

    args.logdir = tempfile.mkdtemp(prefix="cuda-ci-")
    with tempfile.TemporaryDirectory() as keydir:
        key_path = os.path.join(keydir, "id_ed25519")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-q", "-f", key_path], check=True)
        pub_key = Path(key_path + ".pub").read_text().strip()

        results = [{"idx": i} for i in range(len(bins))]
        threads = []
        for i, (offer, b, s, res) in enumerate(zip(picked, bins, scripts, results)):
            t = threading.Thread(target=run_shard,
                                 args=(vast, offer, b, s, key_path, pub_key, args, res))
            t.start()
            threads.append(t)
            time.sleep(2)  # stagger the create calls a little
        try:
            for t in threads:
                t.join()
        except KeyboardInterrupt:
            print("interrupted; destroying any instances still up", flush=True)
            for res in results:
                if res.get("instance"):
                    vast.destroy(res["instance"])
            raise

    failed = [r for r in results if r.get("rc", 1) != 0]
    print("\n===== results =====")
    for r in sorted(results, key=lambda r: r["idx"]):
        status = "OK" if r.get("rc") == 0 else "FAIL"
        print(f"instance {r['idx']}: {status}"
              + (f"  ({r['error']})" if r.get("error") else ""))
        # Fold each box's full output into the GitHub log so a failure is readable.
        log = r.get("log")
        if log and os.path.exists(log):
            print(f"::group::instance {r['idx']} log")
            sys.stdout.write(Path(log).read_text())
            print("::endgroup::")
    print(f"\n{len(results) - len(failed)}/{len(results)} instances passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
