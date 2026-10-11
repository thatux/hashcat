#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

## Runs the weekly test suite on real NVIDIA GPUs on AWS EC2, so the CUDA backend
## gets exercised (issue #4941). This is the AWS sibling of ci/vast/weekly_gpu.py:
## the queue, the worker-reuse, the streaming and the per-kind test.py commands
## are identical; only the provider layer (how a box is rented, reached by SSH and
## destroyed) is EC2 instead of vast.ai.
##
## AWS has no single "api token": it authenticates with an access key id and a
## secret access key, plus a region. Supply them the standard boto3 way, as the
## AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and AWS_REGION environment variables
## (or an attached IAM role). The IAM principal needs EC2 run/describe/terminate,
## spot requests, key-pair and security-group create/describe, and ssm:GetParameter
## (to resolve the GPU AMI). See ci/aws/README.md.
##
## Flow per box: launch a spot GPU instance (cheapest of a few instance types) from
## a Deep Learning AMI (NVIDIA driver and the CUDA toolkit already on it), with an
## ephemeral key pair and a security group that allows SSH; wait for it to run and
## get a public IP; build hashcat and install the oracles; then pull tasks from the
## shared queue and run tools/test.py with "-D 2". Instances are terminated as the
## queue drains and by an always-run cleanup.
##
## NOTE: this is implemented against the boto3/EC2 API but has not yet been run
## against a live AWS account; the box-side user/sudo/AMI details and the IAM
## policy are the things to validate first. ci/vast/weekly_gpu.py is the tested one.

import argparse
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections import deque
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Tag put on every instance this launcher starts, so cleanup finds only ours.
INSTANCE_TAG = "hashcat-cuda"

# Exit code the setup script uses to say "this host is bad, drop it" rather than
# "setup failed". acquire_box turns it into a retry on another instance.
REJECT_CODE = 77

# The Deep Learning AMI resolved through this SSM public parameter: Ubuntu 22.04
# with the NVIDIA driver (libcuda) and the CUDA toolkit (libnvrtc) already on it,
# so a box needs no docker image. SSM keeps it current and region independent.
AMI_SSM_PARAM = ("/aws/service/deeplearning/ami/x86_64/"
                 "base-oss-nvidia-driver-gpu-ubuntu-22.04/latest/ami-id")

# The box logs in as this user on the Deep Learning AMI; apt needs sudo, and the
# repo and run files live under its home rather than /root.
SSH_USER = "ubuntu"

DEFAULT_REPO_URL = "https://github.com/hashcat/hashcat"
DEFAULT_REF = "master"

KIND_OPTS = {"opt": "-a all -t all", "pure": "-a all -t all -P", "container": ""}

LUKS1_MODES = {14600, 29511, 29512, 29513, 29521, 29522, 29523,
               29531, 29532, 29533, 29541, 29542, 29543}
LUKS2_MODES = {34100}
BRIDGE_ONLY_MODES = {74000}


def env_default(key, default):
    value = os.environ.get(key, "")
    return value if value != "" else default


# -- shared planning (identical to the vast launcher) ------------------------

def load_ci_matrix():
    os.chdir(REPO_ROOT)
    import importlib.util
    path = REPO_ROOT / ".github" / "workflows" / "ci_matrix.py"
    spec = importlib.util.spec_from_file_location("ci_matrix", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def wanted_modes(ci_matrix, pool, modes_arg):
    if modes_arg.strip().lower() == "all":
        return set(pool)
    asked = {int(tok) for tok in modes_arg.replace(",", " ").split()}
    return asked & set(pool)


def plan_tasks(ci_matrix, kinds, modes_arg):
    """One (mode, kind) task per mode and requested kind, heaviest first, for the
    shared queue the worker boxes pull from."""
    kernel_pool = sorted(m for m in ci_matrix.modes_on_disk("test") if m not in BRIDGE_ONLY_MODES)
    container_pool = sorted(ci_matrix.container_modes())
    tasks = []
    for kind in kinds:
        pool = container_pool if kind == "container" else kernel_pool
        for mode in sorted(wanted_modes(ci_matrix, pool, modes_arg)):
            tasks.append((mode, kind))
    tasks.sort(key=lambda t: ci_matrix.mode_weight(t[0]), reverse=True)
    return tasks


def repo_url_and_ref(args):
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


# -- box-side scripts (Ubuntu DLAMI: sudo apt, home-relative paths) -----------

SETUP_SCRIPT = r"""set -eu
export DEBIAN_FRONTEND=noninteractive
echo "setup on $(hostname), $(nproc) cpu"
sudo apt-get update -qq
sudo apt-get install -y -qq --no-install-recommends \
    build-essential git wget curl ca-certificates p7zip-full \
    libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev \
    libffi-dev liblzma-dev tk-dev libncursesw5-dev xz-utils
cd "$HOME"
git init -q hashcat
cd hashcat
git remote add origin {repo_url}
git fetch -q --depth 1 origin {ref}
git checkout -q FETCH_HEAD
echo "testing $(git rev-parse HEAD)"
make -j"$(nproc)"
# Oracles via pyenv (CPython compiled here), the way hashcat documents.
export PYENV_ROOT="$HOME/.pyenv"
curl -fsSL https://pyenv.run | bash
export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init - bash)"
bash tools/install_modules.sh
# The Deep Learning AMI ships the CUDA toolkit here; the driver (libcuda) is on
# the host already, so hashcat's runtime dlopen finds both.
export LD_LIBRARY_PATH="/usr/local/cuda/lib64:${{LD_LIBRARY_PATH:-}}"
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
    return SETUP_SCRIPT.format(repo_url=repo_url, ref=ref, max_load=max_load, reject_code=REJECT_CODE)


def luks_fetch(mode, kind):
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
    opts = KIND_OPTS[kind]
    mode_opts = f"-m {mode}" + (f" {opts}" if opts else "")
    return (
        'cd "$HOME/hashcat" && '
        'export PATH="$HOME/.pyenv/shims:$HOME/.pyenv/bin:$PATH" && '
        'export LD_LIBRARY_PATH="/usr/local/cuda/lib64:${LD_LIBRARY_PATH:-}" && '
        + luks_fetch(mode, kind) +
        f'timeout -k 30 {mode_timeout} python3 tools/test.py {mode_opts} -D 2 -f 2>&1'
    )


# -- SSH (identical shape to the vast launcher, user is ubuntu) --------------

SSH_OPTS = ["-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=20", "-o", "ServerAliveInterval=30"]


def ssh_run(host, key_path, remote_cmd, input_text=None, timeout=60):
    return subprocess.run(["ssh", "-i", key_path, *SSH_OPTS, f"{SSH_USER}@{host}", remote_cmd],
                          input=input_text, capture_output=True, text=True, timeout=timeout)


def ssh_ok(host, key_path):
    return ssh_run(host, key_path, "true", timeout=25).returncode == 0


def probe_host(host, key_path):
    cmd = ('read l1 rest < /proc/loadavg; '
           'echo "$l1 $(nproc) $(nvidia-smi -L 2>/dev/null | grep -c GPU)"')
    try:
        r = ssh_run(host, key_path, cmd, timeout=40)
    except subprocess.TimeoutExpired:
        return None
    parts = r.stdout.split()
    if r.returncode != 0 or len(parts) < 3:
        return None
    try:
        return {"load1": float(parts[0]), "ncpu": int(parts[1]), "gpus": int(parts[2])}
    except ValueError:
        return None


def run_detached(host, key_path, script, log_path, deadline, poll=15):
    """Run the setup script detached under setsid (survives an SSH drop during the
    long build), teeing to run.log with the exit code in run.rc, then poll run.rc."""
    ssh_run(host, key_path, 'cat > "$HOME/run.sh"', input_text=script)
    ssh_run(host, key_path,
            'rm -f "$HOME/run.rc"; '
            'setsid sh -c \'bash "$HOME/run.sh" > "$HOME/run.log" 2>&1; echo $? > "$HOME/run.rc"\' '
            '</dev/null >/dev/null 2>&1 &')
    while time.time() < deadline:
        time.sleep(poll)
        try:
            r = ssh_run(host, key_path, 'cat "$HOME/run.rc" 2>/dev/null', timeout=40)
        except subprocess.TimeoutExpired:
            continue
        rc_text = r.stdout.strip()
        if rc_text:
            try:
                Path(log_path).write_text(ssh_run(host, key_path, 'cat "$HOME/run.log"',
                                                  timeout=180).stdout)
            except (subprocess.TimeoutExpired, OSError):
                pass
            try:
                return int(rc_text)
            except ValueError:
                return 1
    return None


# -- the EC2 provider (this is the whole AWS-specific part) -------------------

# A few single-GPU instance types with 8 or more vCPUs (the build and the kernel
# compiles are CPU bound, so the 4-vCPU g4dn.xlarge is a poor fit). T4, A10G and
# L4; the launcher takes whichever is cheapest on spot right now.
DEFAULT_INSTANCE_TYPES = ["g4dn.2xlarge", "g5.2xlarge", "g6.2xlarge"]


class AwsEc2:
    """The slice of EC2 this launcher needs. Credentials and region come from the
    standard boto3 environment (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
    AWS_REGION) or an attached role."""

    def __init__(self, region):
        import boto3  # imported here so --dry-run/--check need no AWS at all
        self.ec2 = boto3.client("ec2", region_name=region)
        self.ssm = boto3.client("ssm", region_name=region)
        self.region = region

    def resolve_ami(self, override):
        if override:
            return override
        return self.ssm.get_parameter(Name=AMI_SSM_PARAM)["Parameter"]["Value"]

    def ensure_key(self, pub_key):
        """Import the run's throwaway public key as an EC2 key pair, so instances
        launch already trusting it. Returns the key name."""
        name = f"{INSTANCE_TAG}-{uuid.uuid4().hex[:12]}"
        self.ec2.import_key_pair(KeyName=name, PublicKeyMaterial=pub_key.encode())
        return name

    def delete_key(self, name):
        try:
            self.ec2.delete_key_pair(KeyName=name)
        except Exception:
            pass

    def ensure_sg(self):
        """A security group in the default VPC that allows inbound SSH. Reused if it
        already exists from a previous run."""
        name = f"{INSTANCE_TAG}-ssh"
        try:
            sgs = self.ec2.describe_security_groups(
                Filters=[{"Name": "group-name", "Values": [name]}])["SecurityGroups"]
            if sgs:
                return sgs[0]["GroupId"]
        except Exception:
            pass
        sg = self.ec2.create_security_group(GroupName=name,
                                            Description="hashcat CUDA CI inbound SSH")
        gid = sg["GroupId"]
        self.ec2.authorize_security_group_ingress(
            GroupId=gid,
            IpPermissions=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
        return gid

    def spot_price(self, instance_type):
        """The latest Linux spot price for one instance type in the region, or None
        if it is not offered here. The launcher rents the cheapest that answers."""
        try:
            h = self.ec2.describe_spot_price_history(
                InstanceTypes=[instance_type], ProductDescriptions=["Linux/UNIX"],
                MaxResults=1)["SpotPriceHistory"]
            return float(h[0]["SpotPrice"]) if h else None
        except Exception:
            return None

    def create(self, instance_type, ami, disk, key_name, sg_id, max_price, label):
        r = self.ec2.run_instances(
            ImageId=ami, InstanceType=instance_type, MinCount=1, MaxCount=1,
            KeyName=key_name, SecurityGroupIds=[sg_id],
            BlockDeviceMappings=[{"DeviceName": "/dev/sda1",
                                  "Ebs": {"VolumeSize": disk, "VolumeType": "gp3",
                                          "DeleteOnTermination": True}}],
            InstanceMarketOptions={"MarketType": "spot",
                                   "SpotOptions": {"MaxPrice": str(max_price),
                                                   "SpotInstanceType": "one-time"}},
            TagSpecifications=[{"ResourceType": "instance",
                                "Tags": [{"Key": "Name", "Value": label},
                                         {"Key": INSTANCE_TAG, "Value": "1"}]}])
        return r["Instances"][0]["InstanceId"]

    def wait_running(self, instance_id, deadline):
        """Poll until the instance is running with a public IP; return the IP."""
        while time.time() < deadline:
            d = self.ec2.describe_instances(InstanceIds=[instance_id])
            inst = d["Reservations"][0]["Instances"][0]
            if inst["State"]["Name"] == "running" and inst.get("PublicIpAddress"):
                return inst["PublicIpAddress"]
            if inst["State"]["Name"] in ("terminated", "shutting-down"):
                raise RuntimeError("instance died before running")
            time.sleep(10)
        raise TimeoutError("instance not running in time")

    def destroy(self, instance_id):
        try:
            self.ec2.terminate_instances(InstanceIds=[instance_id])
            return True
        except Exception as exc:
            print(f"terminate {instance_id} failed: {exc}", flush=True)
            return False

    def our_instances(self):
        d = self.ec2.describe_instances(
            Filters=[{"Name": f"tag:{INSTANCE_TAG}", "Values": ["1"]},
                     {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]}])
        return [i["InstanceId"] for res in d["Reservations"] for i in res["Instances"]]


def image_label(ami):
    return ami


# -- queue, worker, streaming (same model as the vast launcher) ---------------

class BoxDied(Exception):
    pass


FAIL_RE = re.compile(r"> (Error|Fault|Compare Error) :|oracle failed|did not round trip")


def run_task(host, key_path, mode, kind, args):
    cmd = task_command(mode, kind, args.mode_timeout)
    try:
        r = ssh_run(host, key_path, cmd, timeout=args.mode_timeout + 180)
    except subprocess.TimeoutExpired:
        raise BoxDied("ssh did not return in time")
    if r.returncode == 255:
        raise BoxDied("ssh connection failed: " + (r.stderr or "").strip()[:120])
    return r.returncode, r.stdout


def record_result(name, mode, kind, rc, out, args, stats, print_lock):
    try:
        Path(args.logdir, f"m{mode}_{kind}.log").write_text(out)
    except OSError:
        pass
    reason = ""
    if rc != 0:
        reason = (f"timed out after {args.mode_timeout}s" if rc == 124
                  else (FAIL_RE.search(out).group(0) if FAIL_RE.search(out) else "see the attack log above"))
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


def acquire_box(name, ec2, get_offer, setup, ami, key_name, sg_id, key_path, args, print_lock):
    """Launch spot instances until one runs, passes the health probe and finishes
    setup; return (instance_id, host). Return None when offers run out."""
    while True:
        offer = get_offer()
        if offer is None:
            return None
        instance_type, price = offer
        instance_id = None
        try:
            instance_id = ec2.create(instance_type, ami, args.disk, key_name, sg_id,
                                     args.max_price, f"{INSTANCE_TAG}-{name}")
            with print_lock:
                print(f"[{name}] launched {instance_id} ({instance_type}, spot ~${price:.3f}/h), building",
                      flush=True)
            host = ec2.wait_running(instance_id, time.time() + args.boot_timeout)
            # EC2 is up before sshd is ready; wait for SSH to answer.
            deadline = time.time() + 180
            while time.time() < deadline and not ssh_ok(host, key_path):
                time.sleep(5)
            health = probe_host(host, key_path)
            if health is None or health["gpus"] < 1 \
                    or health["load1"] > args.max_load_per_cpu * health["ncpu"]:
                why = ("unreachable" if health is None else "no GPU" if health["gpus"] < 1
                       else f"load {health['load1']:.0f}/{health['ncpu']}cpu")
                with print_lock:
                    print(f"[{name}] rejecting host ({why})", flush=True)
                ec2.destroy(instance_id)
                continue
            rc = run_detached(host, key_path, setup,
                              str(Path(args.logdir) / f"{name}_setup.log"),
                              time.time() + args.run_timeout)
            if rc != 0:
                why = ("rejected itself (no GPU or overloaded)" if rc == REJECT_CODE
                       else "setup timed out" if rc is None else f"setup failed rc {rc}")
                with print_lock:
                    print(f"[{name}] {why}, trying another instance", flush=True)
                ec2.destroy(instance_id)
                continue
            with print_lock:
                print(f"[{name}] ready ({health['ncpu']} cpu, {health['gpus']} gpu)", flush=True)
            return instance_id, host
        except Exception as exc:
            with print_lock:
                print(f"[{name}] acquire error: {exc}", flush=True)
            if instance_id is not None and not args.keep:
                ec2.destroy(instance_id)
            continue


def worker(name, ec2, get_offer, get_task, requeue, setup, ami, key_name, sg_id,
           key_path, args, stats, print_lock):
    for _ in range(args.max_attempts):
        box = acquire_box(name, ec2, get_offer, setup, ami, key_name, sg_id, key_path, args, print_lock)
        if box is None:
            with print_lock:
                print(f"[{name}] no more offers; stopping", flush=True)
            return
        instance_id, host = box
        try:
            while True:
                task = get_task()
                if task is None:
                    return
                mode, kind = task
                try:
                    rc, out = run_task(host, key_path, mode, kind, args)
                except BoxDied as exc:
                    requeue(task)
                    with print_lock:
                        print(f"[{name}] box died on m{mode} ({exc}); requeued, replacing box",
                              flush=True)
                    break
                record_result(name, mode, kind, rc, out, args, stats, print_lock)
        finally:
            if not args.keep:
                ec2.destroy(instance_id)
    with print_lock:
        print(f"[{name}] gave up after {args.max_attempts} boxes", flush=True)


def cleanup_all(ec2):
    ids = ec2.our_instances()
    print(f"cleanup: {len(ids)} leftover instance(s)")
    bad = 0
    for i in ids:
        ok = ec2.destroy(i)
        print(f"  {'terminated' if ok else 'FAILED'} {i}")
        bad += 0 if ok else 1
    return 1 if bad else 0


def main():
    p = argparse.ArgumentParser(description="Run the weekly test suite on NVIDIA GPUs via AWS EC2")
    p.add_argument("--modes", default="all", help='"all" or a list like "0 100 1000"')
    p.add_argument("--kinds", default="opt,pure,container",
                   help="comma list of opt,pure,container (bridge is not run here)")
    p.add_argument("--instances", type=int, default=int(env_default("AWS_CUDA_INSTANCES", "10")),
                   help="how many GPU instances to run in parallel")
    p.add_argument("--region", default=env_default("AWS_REGION", env_default("AWS_DEFAULT_REGION", "us-east-1")),
                   help="AWS region (also read from AWS_REGION)")
    p.add_argument("--instance-types", default=env_default("AWS_INSTANCE_TYPES", ",".join(DEFAULT_INSTANCE_TYPES)),
                   help="comma list of single-GPU instance types, cheapest spot is used")
    p.add_argument("--max-price", type=float, default=float(env_default("AWS_MAX_PRICE", "0.60")),
                   help="most $/hour to bid for one spot instance")
    p.add_argument("--ami", default=env_default("AWS_AMI", ""),
                   help="AMI id; empty resolves the Deep Learning GPU AMI through SSM")
    p.add_argument("--disk", type=int, default=40, help="instance root EBS size in GB")
    p.add_argument("--boot-timeout", type=int, default=600, help="seconds to wait for the instance to run")
    p.add_argument("--run-timeout", type=int, default=18000,
                   help="seconds to wait for a box to finish setup before dropping it")
    p.add_argument("--max-load-per-cpu", type=float, default=4.0,
                   help="reject a booted host whose one minute load exceeds this times its CPU count")
    p.add_argument("--max-attempts", type=int, default=3, help="how many instances a worker may try")
    p.add_argument("--mode-timeout", type=int, default=1800, help="seconds a single mode's test.py may run")
    p.add_argument("--repo-url", default=None, help="clone URL under test (default: this CI repo)")
    p.add_argument("--ref", default=None, help="commit or branch under test (default: this CI commit)")
    p.add_argument("--keep", action="store_true", help="do not terminate the instances (for debugging)")
    p.add_argument("--dry-run", action="store_true", help="print the plan and scripts, launch nothing")
    p.add_argument("--check", action="store_true", help="validate options and plan, launch nothing")
    p.add_argument("--cleanup", action="store_true", help="terminate every instance this tool tagged, then exit")
    p.add_argument("--logdir", default=None, help="directory for the per-task logs")
    args = p.parse_args()

    if args.cleanup:
        return cleanup_all(AwsEc2(args.region))

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
    types = [t.strip() for t in args.instance_types.split(",") if t.strip()]
    print(f"{len(tasks)} tasks ({'+'.join(kinds)}) from {repo_url}@{ref}, up to {args.instances} "
          f"parallel EC2 spot boxes in {args.region} from {types}", flush=True)

    if args.check or args.dry_run:
        print(f"plan OK: {len(tasks)} tasks, region {args.region}, types {types}, "
              f"max ${args.max_price}/h spot")
        if args.dry_run:
            print("\n--- setup script ---\n" + setup)
            m, k = tasks[0]
            print("\n--- sample task command ---\n" + task_command(m, k, args.mode_timeout))
        return 0

    ec2 = AwsEc2(args.region)
    ami = ec2.resolve_ami(args.ami)
    # The offer pool is the instance types that are offered on spot here, cheapest
    # first; the spares beyond the worker count cover a type that cannot launch.
    priced = [(t, ec2.spot_price(t)) for t in types]
    pool = sorted([(t, pr) for t, pr in priced if pr is not None and pr <= args.max_price],
                  key=lambda x: x[1])
    if not pool:
        sys.exit(f"no instance type in {types} is on spot under ${args.max_price}/h in {args.region}")
    # Round-robin the (type, price) offers so N workers do not all pile on the one
    # cheapest type and exhaust its spot capacity.
    offers = [pool[i % len(pool)] for i in range(max(args.instances, len(pool)) * args.max_attempts)]
    nworkers = min(args.instances, len(offers))
    print(f"AMI {ami}; spot offers {[f'{t}:${pr:.3f}' for t, pr in pool]}; starting {nworkers} worker(s)",
          flush=True)

    queue = deque(tasks)
    qlock = threading.Lock()
    offer_lock = threading.Lock()
    offer_i = [0]

    def get_task():
        with qlock:
            return queue.popleft() if queue else None

    def requeue(task):
        with qlock:
            queue.append(task)

    def get_offer():
        with offer_lock:
            if offer_i[0] >= len(offers):
                return None
            o = offers[offer_i[0]]
            offer_i[0] += 1
            return o

    stats = {"ok": 0, "failed": [], "done": 0, "lock": threading.Lock()}
    print_lock = threading.Lock()
    args.logdir = args.logdir or tempfile.mkdtemp(prefix="cuda-ci-")
    os.makedirs(args.logdir, exist_ok=True)

    with tempfile.TemporaryDirectory() as keydir:
        key_path = os.path.join(keydir, "id_ed25519")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-q", "-f", key_path], check=True)
        pub_key = Path(key_path + ".pub").read_text().strip()
        key_name = ec2.ensure_key(pub_key)
        sg_id = ec2.ensure_sg()
        try:
            threads = []
            for i in range(nworkers):
                t = threading.Thread(target=worker,
                                     args=(f"w{i}", ec2, get_offer, get_task, requeue, setup, ami,
                                           key_name, sg_id, key_path, args, stats, print_lock))
                t.start()
                threads.append(t)
                time.sleep(1)
            try:
                for t in threads:
                    t.join()
            except KeyboardInterrupt:
                print("interrupted; terminating every instance we tagged", flush=True)
                cleanup_all(ec2)
                raise
        finally:
            ec2.delete_key(key_name)

    remaining = list(queue)
    total = len(tasks)
    print("\n===== results =====", flush=True)
    print(f"{stats['done']}/{total} tasks ran: {stats['ok']} ok, {len(stats['failed'])} failed, "
          f"{len(remaining)} never ran", flush=True)
    if stats["failed"]:
        print("FAILED modes: " + " ".join(f"{m}:{k}(rc{rc})" for m, k, rc in sorted(stats["failed"])),
              flush=True)
    if remaining:
        shown = " ".join(f"{m}:{k}" for m, k in sorted(remaining)[:80])
        print(f"UNTESTED modes ({len(remaining)}): {shown}" + (" ..." if len(remaining) > 80 else ""),
              flush=True)
    return 0 if (not stats["failed"] and not remaining) else 1


if __name__ == "__main__":
    sys.exit(main())
