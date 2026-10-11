#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

## Runs the weekly test suite on real NVIDIA GPUs through vast.ai, so the CUDA
## backend gets exercised (issue #4941). This runs on the GitHub runner, not on
## the GPU. It builds one shared queue of (mode, kind) tasks and rents a set of
## worker boxes; each box clones and builds hashcat at the commit under test,
## sets up the oracles, then pulls tasks from the queue and runs tools/test.py
## for each with "-D 2" (the GPU device type) in place of the "-D 1" the GPU-less
## runners use. A box that dies mid-task puts the task back on the queue and a
## replacement box is rented; boxes are destroyed as the queue drains, and every
## task's output is streamed back as it finishes, so nothing is lost if a box is
## later lost.
##
## The mode pools and the per-kind test.py commands are the same ones
## .github/workflows/test.yml uses on the CPU: the pools come from
## .github/workflows/ci_matrix.py and the per-kind test.py line is that
## workflow's. Nothing here is a second test suite; the bridge kind is the one
## test.yml kind this does not run.
##
##   weekly_gpu.py                                  all kinds, all modes
##   weekly_gpu.py --modes "0 100 1000"             just those modes
##   weekly_gpu.py --kinds opt,container            only those kinds
##   weekly_gpu.py --instances 40 --dry-run         print the plan, rent nothing
##
## Authentication is the vast.ai API key in the VAST_API_KEY environment
## variable; it is used only to talk to vast.ai and is never sent to a rented
## box. Each box gets a throwaway SSH key generated for this run, so no private
## key is stored anywhere. The process exits non-zero when any task fails or any
## task never ran.

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from collections import deque
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

VAST_HOST = "https://console.vast.ai"
VAST_API = VAST_HOST + "/api/v0"

# Every instance this launcher rents carries this label, so the cleanup pass can
# find and destroy leftovers without touching instances rented for anything else.
INSTANCE_LABEL_PREFIX = "hashcat-cuda-"

# Exit code the setup script uses to say "this host is bad, drop it and try
# another" rather than "setup failed". acquire_box turns it into a retry.
REJECT_CODE = 77


def env_default(key, default):
    """An environment variable, treating unset and empty the same. GitHub passes
    an unset repository variable to the step as an empty string, so a plain
    os.environ.get(key, default) would hand back "" rather than the default."""
    value = os.environ.get(key, "")
    return value if value != "" else default

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
    """One (mode, kind) task per mode and requested kind, heaviest first.

    opt and pure draw from the kernel pool test.yml shards; container draws from
    test.py's own container list. The tasks become a shared queue the worker boxes
    pull from, so there is no per-box split: a box takes the next task whenever it
    is free, which balances the load without guessing. Ordering heaviest first (by
    ci_matrix.mode_weight) keeps the slow modes from all landing at the end on one
    straggler.
    """
    kernel_pool = sorted(m for m in ci_matrix.modes_on_disk("test")
                         if m not in BRIDGE_ONLY_MODES)
    container_pool = sorted(ci_matrix.container_modes())

    tasks = []
    for kind in kinds:
        pool = container_pool if kind == "container" else kernel_pool
        for mode in sorted(wanted_modes(ci_matrix, pool, modes_arg)):
            tasks.append((mode, kind))
    tasks.sort(key=lambda t: ci_matrix.mode_weight(t[0]), reverse=True)
    return tasks


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


SETUP_SCRIPT = r"""set -eu
export DEBIAN_FRONTEND=noninteractive
echo "setup on $(hostname), $(nproc) cpu"
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    build-essential git wget curl ca-certificates p7zip-full \
    libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev \
    libffi-dev liblzma-dev tk-dev libncursesw5-dev xz-utils
# Fetch exactly the commit under test, which may be a feature branch tip the
# default clone would not carry, so init and fetch the ref by name.
git init -q hashcat
cd hashcat
git remote add origin {repo_url}
git fetch -q --depth 1 origin {ref}
git checkout -q FETCH_HEAD
echo "testing $(git rev-parse HEAD)"
make -j"$(nproc)"
# Oracles via pyenv, the way hashcat documents (install_modules.sh compiles the
# latest CPython and installs tools/requirements.txt into it; a prebuilt
# interpreter would skip the compile but this keeps install_modules.sh as is).
export PYENV_ROOT="$HOME/.pyenv"
curl -fsSL https://pyenv.run | bash
export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init - bash)"
bash tools/install_modules.sh
export LD_LIBRARY_PATH="/usr/local/cuda/lib64:${{LD_LIBRARY_PATH:-}}"
# Health gate before the box joins the pool: the CUDA backend must see a device
# and the host must be sane, otherwise exit the reject code so the launcher drops
# this host and rents another rather than running every task on a bad box.
hcinfo=$(./hashcat -I 2>&1 || true)
if ! printf '%s' "$hcinfo" | grep -qiE 'CUDA[. ]?Info|Backend Device ID'; then
  echo "no CUDA device in hashcat -I, dropping host" >&2
  exit {reject_code}
fi
read l1 rest < /proc/loadavg
if [ "$(awk -v l="$l1" -v n="$(nproc)" 'BEGIN {{ print (l > {max_load} * n) ? 1 : 0 }}')" = "1" ]; then
  echo "host overloaded (load $l1 on $(nproc) cpu), dropping host" >&2
  exit {reject_code}
fi
echo "SETUP_OK"
"""


def setup_script(repo_url, ref, max_load):
    return SETUP_SCRIPT.format(repo_url=repo_url, ref=ref, max_load=max_load,
                               reject_code=REJECT_CODE)


def luks_fetch(mode, kind):
    """A command that fetches, once, the LUKS container archive a mode needs. The
    TrueCrypt, VeraCrypt and CryptoLoop containers are in the tree already."""
    if kind != "container":
        return ""
    if mode in LUKS1_MODES:
        return ('{ [ -d tools/luks_tests ] || ( mkdir -p tools/luks_tests && cd tools/luks_tests && '
                'wget -q https://hashcat.net/misc/example_hashes/hashcat_luks_testfiles.7z && '
                '7z x -y hashcat_luks_testfiles.7z >/dev/null && rm -f hashcat_luks_testfiles.7z ); } && ')
    if mode in LUKS2_MODES:
        return ('{ [ -d tools/luks2_tests ] || ( mkdir -p tools/luks2_tests && cd tools/luks2_tests && '
                'wget -q https://hashcat.net/misc/example_hashes/luks2_tests.7z && '
                '7z x -y luks2_tests.7z >/dev/null && rm -f luks2_tests.7z ); } && ')
    return ""


def task_command(mode, kind, mode_timeout):
    """The remote command for one (mode, kind) task on an already set up box: set
    the environment the build and pyenv left, fetch a LUKS archive if the mode
    needs one, then run test.py under a timeout. The command's exit code is
    test.py's, so the launcher reads pass or fail straight from the SSH exit."""
    opts = KIND_OPTS[kind]
    mode_opts = f"-m {mode}" + (f" {opts}" if opts else "")
    return (
        'cd /root/hashcat && '
        'export PATH="$HOME/.pyenv/shims:$HOME/.pyenv/bin:$PATH" && '
        'export LD_LIBRARY_PATH="/usr/local/cuda/lib64:${LD_LIBRARY_PATH:-}" && '
        + luks_fetch(mode, kind) +
        f'timeout -k 30 {mode_timeout} python3 tools/test.py {mode_opts} -D 2 -f 2>&1'
    )


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

    def _rest(self, method, path):
        req = urllib.request.Request(VAST_HOST + path, method=method,
                                     headers={"Authorization": f"Bearer {self.api_key}"})
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r)

    def list_instances(self):
        # The v0 list endpoint is deprecated and answers with an error object, so
        # read the v1 one. Returns every instance on the account.
        return self._rest("GET", "/api/v1/instances/").get("instances", [])

    def destroy(self, instance_id):
        # Delete over REST and report whether it worked. The vastai CLI destroy
        # did nothing in CI (it left the instances billing), while the v0 delete
        # endpoint returns {"success": true} and actually tears the instance down.
        try:
            return bool(self._rest("DELETE", f"/api/v0/instances/{instance_id}/").get("success"))
        except Exception as exc:
            print(f"destroy {instance_id} failed: {exc}", flush=True)
            return False


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
        # The rental's share of host CPUs. The build and the kernel compiles are CPU
        # bound, so a box with too few cores is the slow link; a floor keeps those out.
        "cpu_cores_effective": {"gte": args.min_cpu_cores},
        "type": "on-demand",
        "order": [["dph_total", "asc"]],
        "limit": 200,
    }


def offer_pool(offers, gpu_name, min_cpu_cores):
    """All matching offers, one per host, cheapest first, as a pool the shards
    pull from, so a shard whose host turns out to be bad can take the next one.
    The core floor is re-checked here as well as in the query, so a server that
    ignores the filter still cannot hand back an underpowered box."""
    out, seen = [], set()
    for o in offers:
        if gpu_name and gpu_name.lower() != "any" and gpu_name.lower() not in o["gpu_name"].lower():
            continue
        if (o.get("cpu_cores_effective") or 0) < min_cpu_cores:
            continue
        host = o.get("host_id")
        if host in seen:
            continue
        seen.add(host)
        out.append(o)
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


def ssh_run(host, port, key_path, remote_cmd, input_text=None, timeout=60):
    return subprocess.run(["ssh", "-i", key_path, "-p", str(port), *SSH_OPTS,
                           f"root@{host}", remote_cmd],
                          input=input_text, capture_output=True, text=True, timeout=timeout)


def run_detached(host, port, key_path, script, log_path, deadline, poll=15):
    """Run the box script detached from the SSH session and poll for it to finish.

    The script is written to the box, launched under setsid so it keeps running if
    the SSH connection drops, and teed to run.log with its exit code in run.rc.
    The launcher then polls run.rc over short lived connections, tolerating a
    dropped poll, and pulls run.log when it appears. Returns the exit code, or None
    if the deadline passes first. This survives the SSH drops that would otherwise
    kill a job running as a child of a single long lived connection."""
    ssh_run(host, port, key_path, "cat > /root/run.sh", input_text=script)
    ssh_run(host, port, key_path,
            "rm -f /root/run.rc; "
            "setsid sh -c 'bash /root/run.sh > /root/run.log 2>&1; echo $? > /root/run.rc' "
            "</dev/null >/dev/null 2>&1 &")
    while time.time() < deadline:
        time.sleep(poll)
        try:
            r = ssh_run(host, port, key_path, "cat /root/run.rc 2>/dev/null", timeout=40)
        except subprocess.TimeoutExpired:
            continue  # a dropped poll is fine, the job keeps running on the box
        rc_text = r.stdout.strip()
        if rc_text:
            try:
                Path(log_path).write_text(ssh_run(host, port, key_path, "cat /root/run.log",
                                                  timeout=180).stdout)
            except (subprocess.TimeoutExpired, OSError):
                pass
            try:
                return int(rc_text)
            except ValueError:
                return 1
    return None


def probe_host(host, port, key_path):
    """A quick health read of a freshly booted box: the host's one minute load,
    its CPU count and whether a GPU is visible. vast.ai boxes share a physical
    host, so one already slammed by other tenants (a load many times the CPU
    count) starves the CPU bound kernel build and must be avoided. Returns a dict
    or None when the box cannot even answer."""
    cmd = ('read l1 rest < /proc/loadavg; '
           'echo "$l1 $(nproc) $(nvidia-smi -L 2>/dev/null | grep -c GPU)"')
    try:
        r = subprocess.run(["ssh", "-i", key_path, "-p", str(port), *SSH_OPTS,
                            f"root@{host}", cmd], capture_output=True, text=True, timeout=40)
    except subprocess.TimeoutExpired:
        return None
    parts = r.stdout.split()
    if r.returncode != 0 or len(parts) < 3:
        return None
    try:
        return {"load1": float(parts[0]), "ncpu": int(parts[1]), "gpus": int(parts[2])}
    except ValueError:
        return None


class BoxDied(Exception):
    """A task's SSH did not return or the connection failed: the box is gone."""


FAIL_RE = re.compile(r"> (Error|Fault|Compare Error) :|oracle failed|did not round trip")


def run_task(host, port, key_path, mode, kind, args):
    """Run one task on a set up box. Returns (rc, output) where rc is test.py's own
    exit code. Raises BoxDied when SSH itself fails or does not return, so the task
    can be requeued for another box rather than counted as a mode failure."""
    cmd = task_command(mode, kind, args.mode_timeout)
    try:
        r = ssh_run(host, port, key_path, cmd, timeout=args.mode_timeout + 180)
    except subprocess.TimeoutExpired:
        raise BoxDied("ssh did not return in time")
    if r.returncode == 255:
        raise BoxDied("ssh connection failed: " + (r.stderr or "").strip()[:120])
    return r.returncode, r.stdout


def record_result(name, mode, kind, rc, out, args, stats, print_lock):
    """Stream one task's result as it finishes: write its log, fold its output into
    the run log, and annotate a failure, like test.yml's per-mode groups."""
    try:
        Path(args.logdir, f"m{mode}_{kind}.log").write_text(out)
    except OSError:
        pass
    reason = ""
    if rc != 0:
        if rc == 124:
            reason = f"timed out after {args.mode_timeout}s"
        else:
            m = FAIL_RE.search(out)
            reason = m.group(0) if m else "see the attack log above"
    with print_lock:
        print(f"::group::[{name}] test.py -m {mode} {KIND_OPTS[kind]} -D 2  (rc {rc})", flush=True)
        sys.stdout.write(out if out.endswith("\n") else out + "\n")
        print("::endgroup::", flush=True)
        if rc != 0:
            print(f"::error title=mode {mode} ({kind}) failed on CUDA (rc {rc})::{reason}", flush=True)
    with stats["lock"]:
        stats["done"] += 1
        if rc == 0:
            stats["ok"] += 1
        else:
            stats["failed"].append((mode, kind, rc))


def acquire_box(name, vast, get_offer, setup, key_path, pub_key, args, print_lock):
    """Rent offers until one boots, passes the health probe and finishes setup;
    return (instance_id, host, port). Return None when offers run out. A rejected
    or broken box is destroyed before the next offer is tried."""
    while True:
        offer = get_offer()
        if offer is None:
            return None
        instance_id = None
        try:
            instance_id = vast.create(offer["id"], args.image, args.disk, INSTANCE_LABEL_PREFIX + name)
            with print_lock:
                print(f"[{name}] rented {instance_id} on {offer['gpu_name']} "
                      f"(${offer['dph_total']:.3f}/h, {offer.get('geolocation')}), building", flush=True)
            vast.attach_ssh(instance_id, pub_key)
            host, port = wait_ssh(vast, instance_id, key_path, time.time() + args.boot_timeout)
            health = probe_host(host, port, key_path)
            if health is None or health["gpus"] < 1 \
                    or health["load1"] > args.max_load_per_cpu * health["ncpu"]:
                why = ("unreachable" if health is None else "no GPU" if health["gpus"] < 1
                       else f"load {health['load1']:.0f}/{health['ncpu']}cpu")
                with print_lock:
                    print(f"[{name}] rejecting host ({why})", flush=True)
                vast.destroy(instance_id)
                continue
            rc = run_detached(host, port, key_path, setup,
                              str(Path(args.logdir) / f"{name}_setup.log"),
                              time.time() + args.run_timeout)
            if rc != 0:
                why = ("rejected itself (no GPU or overloaded)" if rc == REJECT_CODE
                       else "setup timed out" if rc is None else f"setup failed rc {rc}")
                with print_lock:
                    print(f"[{name}] {why}, trying another host", flush=True)
                vast.destroy(instance_id)
                continue
            with print_lock:
                print(f"[{name}] ready ({health['ncpu']} cpu, {health['gpus']} gpu)", flush=True)
            return instance_id, host, port
        except Exception as exc:
            with print_lock:
                print(f"[{name}] acquire error: {exc}", flush=True)
            if instance_id is not None and not args.keep:
                vast.destroy(instance_id)
            continue


def worker(name, vast, get_offer, get_task, requeue, setup, key_path, pub_key, args, stats, print_lock):
    """One worker box: acquire a healthy box, then pull tasks from the shared queue
    and run them until the queue is empty. If the box dies mid-task the task is
    requeued and a replacement box is rented, up to args.max_attempts boxes."""
    for _ in range(args.max_attempts):
        box = acquire_box(name, vast, get_offer, setup, key_path, pub_key, args, print_lock)
        if box is None:
            with print_lock:
                print(f"[{name}] no more offers; stopping", flush=True)
            return
        instance_id, host, port = box
        try:
            while True:
                task = get_task()
                if task is None:
                    return  # queue drained; finally below destroys the box
                mode, kind = task
                try:
                    rc, out = run_task(host, port, key_path, mode, kind, args)
                except BoxDied as exc:
                    requeue(task)
                    with print_lock:
                        print(f"[{name}] box died on m{mode} ({exc}); requeued, replacing box",
                              flush=True)
                    break  # leave the task loop and acquire a replacement box
                record_result(name, mode, kind, rc, out, args, stats, print_lock)
        finally:
            if not args.keep:
                vast.destroy(instance_id)
    with print_lock:
        print(f"[{name}] gave up after {args.max_attempts} boxes", flush=True)


def cleanup_all(vast):
    """Destroy every instance this workflow labeled that is still up, so a main run
    killed before its own teardown (a timeout or a cancel) does not keep billing."""
    mine = [i for i in vast.list_instances()
            if str(i.get("label", "")).startswith(INSTANCE_LABEL_PREFIX)]
    print(f"cleanup: {len(mine)} leftover instance(s)")
    failed = 0
    for i in mine:
        ok = vast.destroy(i["id"])
        print(f"  {'destroyed' if ok else 'FAILED to destroy'} {i['id']} ({i.get('label')})")
        failed += 0 if ok else 1
    return 1 if failed else 0


def main():
    p = argparse.ArgumentParser(description="Run the weekly test suite on NVIDIA GPUs via vast.ai")
    p.add_argument("--modes", default="all", help='"all" or a list like "0 100 1000"')
    p.add_argument("--kinds", default="opt,pure,container",
                   help="comma list of opt,pure,container (bridge is not run here)")
    p.add_argument("--instances", type=int,
                   default=int(env_default("VAST_CUDA_INSTANCES", "10")),
                   help="how many GPUs to rent and run in parallel")
    p.add_argument("--gpu-name", default=env_default("VAST_GPU_NAME", "RTX 3060"),
                   help='substring the GPU must match, or "any" for anything that fits the filter')
    p.add_argument("--max-dph", type=float, default=float(env_default("VAST_MAX_DPH", "0.12")),
                   help="most $/hour to pay for one GPU")
    p.add_argument("--min-gpu-ram", type=int, default=11, help="least GPU RAM in GB")
    p.add_argument("--min-cpu-cores", type=float, default=float(env_default("VAST_MIN_CPU_CORES", "8")),
                   help="least host CPU cores the rental gets; the build and kernel compiles are CPU bound")
    p.add_argument("--min-reliability", type=float, default=0.98, help="least vast.ai reliability")
    p.add_argument("--image", default=env_default("VAST_IMAGE", "nvidia/cuda:12.2.2-devel-ubuntu22.04"),
                   help="CUDA docker image the box builds and runs in; its toolkit version sets the "
                        "minimum host driver CUDA the offer search requires")
    p.add_argument("--disk", type=int, default=24, help="instance disk in GB")
    p.add_argument("--boot-timeout", type=int, default=900, help="seconds to wait for SSH")
    p.add_argument("--run-timeout", type=int, default=18000,
                   help="seconds to wait for a box to finish its tasks before dropping it; keep it "
                        "under the workflow's own timeout-minutes so a slow box finishes rather than "
                        "being guillotined mid-run")
    p.add_argument("--max-load-per-cpu", type=float, default=4.0,
                   help="reject a freshly booted host whose one minute load exceeds this times its CPU count")
    p.add_argument("--max-attempts", type=int, default=3,
                   help="how many offers a shard may try before giving up")
    p.add_argument("--mode-timeout", type=int, default=1800,
                   help="seconds a single mode's test.py may run before it is killed")
    p.add_argument("--repo-url", default=None, help="clone URL under test (default: this CI repo)")
    p.add_argument("--ref", default=None, help="commit or branch under test (default: this CI commit)")
    p.add_argument("--keep", action="store_true", help="do not destroy the boxes (for debugging)")
    p.add_argument("--dry-run", action="store_true", help="print the plan and scripts, rent nothing")
    p.add_argument("--check", action="store_true",
                   help="validate the options, environment and plan, print a summary, rent nothing")
    p.add_argument("--cleanup", action="store_true",
                   help="destroy every leftover instance this workflow labeled, then exit")
    p.add_argument("--logdir", default=None,
                   help="directory for the per-instance logs (default: a temporary directory)")
    args = p.parse_args()

    if args.cleanup:
        api_key = os.environ.get("VAST_API_KEY")
        if not api_key:
            sys.exit("no VAST_API_KEY in the environment")
        return cleanup_all(Vast(api_key))

    kinds = [k.strip() for k in args.kinds.split(",") if k.strip()]
    bad = [k for k in kinds if k not in KIND_OPTS]
    if bad:
        sys.exit(f"unknown kind(s): {', '.join(bad)} (known: {', '.join(KIND_OPTS)})")

    ci_matrix = load_ci_matrix()
    tasks = plan_tasks(ci_matrix, kinds, args.modes)
    if not tasks:
        print("no testable modes in the requested set, nothing to run")
        return 0

    repo_url, ref = repo_url_and_ref(args)
    setup = setup_script(repo_url, ref, args.max_load_per_cpu)
    print(f"{len(tasks)} tasks ({'+'.join(kinds)}) from {repo_url}@{ref}, "
          f"up to {args.instances} parallel {args.gpu_name or 'any'} boxes pulling a shared queue",
          flush=True)

    # --check and --dry-run run every step up to here (options, environment, task
    # plan, setup script and a sample task command), so a mistake fails now rather
    # than after a GPU is rented. --dry-run also prints the scripts.
    if args.check or args.dry_run:
        print(f"plan OK: {len(tasks)} tasks, min host CUDA {image_cuda_version(args.image)}, "
              f"GPU {args.gpu_name or 'any'}, >= {args.min_cpu_cores} cpu, max ${args.max_dph}/h")
        if args.dry_run:
            print("\n--- setup script ---\n" + setup)
            m, k = tasks[0]
            print("\n--- sample task command ---\n" + task_command(m, k, args.mode_timeout))
        return 0

    api_key = os.environ.get("VAST_API_KEY")
    if not api_key:
        sys.exit("no VAST_API_KEY in the environment")
    vast = Vast(api_key)

    pool = offer_pool(vast.offers(offer_query(args)), args.gpu_name, args.min_cpu_cores)
    if not pool:
        sys.exit("no vast.ai offers match the filter; raise --max-dph, lower --min-cpu-cores, "
                 "or clear --gpu-name")
    nworkers = min(args.instances, len(pool))
    print(f"{len(pool)} candidate host(s) (>= {args.min_cpu_cores} cpu): starting {nworkers} "
          f"worker(s), the rest are spares for replacing dead hosts", flush=True)

    # The shared work: a queue of (mode, kind) tasks the workers pull from, and a
    # thread-safe source of offers so each worker takes a distinct host and a dead
    # host's work is replaced from the spares.
    queue = deque(tasks)
    qlock = threading.Lock()

    def get_task():
        with qlock:
            return queue.popleft() if queue else None

    def requeue(task):
        with qlock:
            queue.append(task)  # back of the queue, so it does not spin one box

    offer_lock = threading.Lock()
    offer_next = [0]

    def get_offer():
        with offer_lock:
            if offer_next[0] >= len(pool):
                return None
            o = pool[offer_next[0]]
            offer_next[0] += 1
            return o

    stats = {"ok": 0, "failed": [], "done": 0, "lock": threading.Lock()}
    print_lock = threading.Lock()

    if args.logdir:
        os.makedirs(args.logdir, exist_ok=True)
    else:
        args.logdir = tempfile.mkdtemp(prefix="cuda-ci-")

    with tempfile.TemporaryDirectory() as keydir:
        key_path = os.path.join(keydir, "id_ed25519")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-q", "-f", key_path], check=True)
        pub_key = Path(key_path + ".pub").read_text().strip()

        threads = []
        for i in range(nworkers):
            t = threading.Thread(target=worker,
                                 args=(f"w{i}", vast, get_offer, get_task, requeue, setup,
                                       key_path, pub_key, args, stats, print_lock))
            t.start()
            threads.append(t)
            time.sleep(1)  # stagger the create calls a little
        try:
            for t in threads:
                t.join()
        except KeyboardInterrupt:
            print("interrupted; destroying every instance we labeled", flush=True)
            cleanup_all(vast)
            raise

    remaining = list(queue)
    total = len(tasks)
    print("\n===== results =====", flush=True)
    print(f"{stats['done']}/{total} tasks ran: {stats['ok']} ok, {len(stats['failed'])} failed, "
          f"{len(remaining)} never ran", flush=True)
    if stats["failed"]:
        print("FAILED modes: " + " ".join(f"{m}:{k}(rc{rc})"
              for m, k, rc in sorted(stats["failed"])), flush=True)
    if remaining:
        shown = " ".join(f"{m}:{k}" for m, k in sorted(remaining)[:80])
        print(f"UNTESTED modes ({len(remaining)}): {shown}" + (" ..." if len(remaining) > 80 else ""),
              flush=True)
    # Green only when every task ran and every one passed.
    return 0 if (not stats["failed"] and not remaining) else 1


if __name__ == "__main__":
    sys.exit(main())
