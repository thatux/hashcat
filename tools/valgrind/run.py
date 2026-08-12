#!/usr/bin/env python3
"""Build a Valgrind-friendly hashcat and run commands under Valgrind with
hashcat-source-aware triage.

Subcommands:
    build      make DEBUG=1 build + ./hashcat-valgrind sibling copy
    check      diagnostic: valgrind/debug-info/PoCL presence
    exec       run one hashcat command under Valgrind, triage the result
    selftest   run tools/valgrind/modules/ ground-truth fixtures, assert
               triage.py's classification against modules/expected.json

See tools/valgrind/README.md for full usage and rationale.
"""

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
MODULES_FIXTURE_DIR = SCRIPT_DIR / "modules"
DEFAULT_RESULTS_DIR = SCRIPT_DIR / "results"

sys.path.insert(0, str(SCRIPT_DIR))
import triage  # noqa: E402


# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------

def sanity_check_binary(binary_path, timeout=30, env=None):
    """Hard build-sanity check: the binary must actually run. Used before
    build.py declares success and before exec ever invokes Valgrind."""
    try:
        proc = subprocess.run([binary_path, "--version"], capture_output=True,
                               text=True, timeout=timeout, env=env)
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e)
    if proc.returncode != 0 or not proc.stdout.strip():
        combined = (proc.stdout or "") + (proc.stderr or "")
        return False, combined.strip()
    return True, proc.stdout.strip()


def has_debug_info(binary_path):
    try:
        out = subprocess.run(["readelf", "-S", binary_path], capture_output=True,
                              text=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    return bool(re.search(r"\.debug_(info|line)\b", out))


def get_valgrind_version():
    try:
        out = subprocess.run(["valgrind", "--version"], capture_output=True,
                              text=True, timeout=10).stdout.strip()
        return out or None
    except (OSError, subprocess.SubprocessError):
        return None


def get_compiler_version():
    for cc in (os.environ.get("CC"), "gcc", "cc"):
        if not cc:
            continue
        try:
            out = subprocess.run([cc, "--version"], capture_output=True, text=True, timeout=10).stdout
            if out:
                return out.splitlines()[0].strip()
        except (OSError, subprocess.SubprocessError):
            continue
    return None


def get_git_commit():
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                                 cwd=REPO_ROOT, timeout=10).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True,
                                cwd=REPO_ROOT, timeout=10).stdout.strip() != ""
        return commit or None, dirty
    except (OSError, subprocess.SubprocessError):
        return None, None


def parse_backend_info(text):
    """Parses `hashcat -I` human-readable OpenCL platform/device listing.
    Format confirmed against src/terminal.c:2272-2363 (event_log_info calls
    for "OpenCL Platform ID #", "  Vendor..:", "  Name....:",
    "  Backend Device ID #", "    Type...........:", "    Name...........:")
    -- not guessed. Returns a list of {device_id, type, name,
    platform_vendor, platform_name}."""
    devices = []
    platform = {}
    device = None
    for raw in text.splitlines():
        if raw.startswith("OpenCL Platform ID #"):
            platform = {}
        elif raw.startswith("  Vendor..:"):
            platform["vendor"] = raw.split(":", 1)[1].strip()
        elif raw.startswith("  Name....:"):
            platform["name"] = raw.split(":", 1)[1].strip()
        elif raw.startswith("  Backend Device ID #"):
            if device is not None:
                devices.append(device)
            m = re.search(r"#(\d+)", raw)
            device = {
                "device_id": int(m.group(1)) if m else None,
                "platform_vendor": platform.get("vendor"),
                "platform_name": platform.get("name"),
                "type": None,
                "name": None,
            }
        elif device is not None:
            stripped = raw.strip()
            if stripped.startswith("Type") and "..." in stripped:
                device["type"] = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("Name") and "..." in stripped:
                device["name"] = stripped.split(":", 1)[1].strip()
    if device is not None:
        devices.append(device)
    return devices


def find_pocl_cpu_device(binary, extra_env=None):
    env = dict(os.environ)
    # POCL_DEVICES takes a PoCL *driver* name (e.g. "pthread"), not a device
    # type string -- confirmed empirically: "cpu" is not a valid driver name
    # and silently makes clGetDeviceIDs() return zero devices (CL_DEVICE_NOT_FOUND).
    env["POCL_DEVICES"] = "pthread"
    if extra_env:
        env.update(extra_env)
    try:
        proc = subprocess.run([binary, "-I"], capture_output=True, text=True, timeout=60, env=env)
    except (OSError, subprocess.SubprocessError) as e:
        return None, [], str(e)
    devices = parse_backend_info(proc.stdout)
    pocl_devices = [
        d for d in devices
        if "pocl" in " ".join(filter(None, [d.get("platform_vendor"), d.get("platform_name")])).lower()
    ]
    cpu = next((d for d in pocl_devices if (d.get("type") or "").upper() == "CPU"), None)
    return cpu, pocl_devices, None


def make_results_dir(base_dir, test_name):
    base_dir = Path(base_dir)
    for _ in range(5):
        ts = time.strftime("%Y%m%d-%H%M%S")
        candidate = base_dir / f"{ts}-{test_name}"
        try:
            candidate.mkdir(parents=True, exist_ok=False)
            return candidate, ts
        except FileExistsError:
            time.sleep(1)
    ts = time.strftime("%Y%m%d-%H%M%S")
    candidate = base_dir / f"{ts}-{test_name}-{os.getpid()}"
    candidate.mkdir(parents=True, exist_ok=True)
    return candidate, ts


def write_environment_file(path, binary, debug_ok, pocl_info):
    commit, dirty = get_git_commit()
    lines = [
        f"git_commit: {commit}",
        f"git_dirty: {dirty}",
        f"compiler: {get_compiler_version()}",
        f"valgrind: {get_valgrind_version()}",
        f"hashcat_binary: {os.path.realpath(binary)}",
        f"debug_info_detected: {debug_ok}",
    ]
    if pocl_info:
        lines.append(f"pocl: {json.dumps(pocl_info)}")
    path.write_text("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------

def cmd_build(args):
    nproc = os.cpu_count() or 1

    print("==> make clean")
    if subprocess.run(["make", "clean"], cwd=REPO_ROOT).returncode != 0:
        print("ERROR: make clean failed", file=sys.stderr)
        return 2

    print(f"==> make DEBUG=1 -j{nproc}")
    if subprocess.run(["make", "DEBUG=1", f"-j{nproc}"], cwd=REPO_ROOT).returncode != 0:
        print("ERROR: make DEBUG=1 failed", file=sys.stderr)
        return 2

    hashcat_bin = REPO_ROOT / "hashcat"
    target = REPO_ROOT / "hashcat-valgrind"
    if not hashcat_bin.exists():
        print(f"ERROR: build did not produce {hashcat_bin}", file=sys.stderr)
        return 2

    shutil.copy2(hashcat_bin, target)
    st = os.stat(target)
    os.chmod(target, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    ok, output = sanity_check_binary(str(target))
    if not ok:
        print("ERROR: build sanity check failed -- ./hashcat-valgrind does not run cleanly.", file=sys.stderr)
        print("Refusing to declare the build usable; not proceeding to the debug-info report.", file=sys.stderr)
        if output:
            print(output, file=sys.stderr)
        return 2
    print(f"OK: {output.splitlines()[0] if output else '(binary runs)'}")

    debug_ok = has_debug_info(str(target))
    print(f"Debug info (.debug_info/.debug_line): {'OK' if debug_ok else 'WARNING: NOT FOUND'}")
    print()
    print("Note: ./hashcat itself and every modules/*.so are also now a DEBUG=1 build")
    print("(one obj/ tree, no per-DEBUG-level object tagging -- this is unavoidable).")
    print("./hashcat-valgrind is a stable, explicitly-named copy for run.py exec to target")
    print("regardless of what ./hashcat gets rebuilt to later.")
    print(f"Restore the release build afterward with: make clean && make -j{nproc}")
    return 0


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------

def cmd_check(args):
    binary = args.binary or str(REPO_ROOT / "hashcat-valgrind")
    lines = []

    vg = get_valgrind_version()
    lines.append(f"Valgrind:            {'found (' + vg + ')' if vg else 'NOT FOUND'}")

    binary_exists = os.path.exists(binary)
    debug_ok = binary_exists and has_debug_info(binary)
    if not binary_exists:
        lines.append(f"Hashcat debug info:  NOT FOUND (no such binary: {binary})")
    else:
        lines.append(f"Hashcat debug info:  {'found (' + binary + ')' if debug_ok else 'NOT FOUND (' + binary + ')'}")

    if binary_exists:
        cpu, pocl_devices, err = find_pocl_cpu_device(binary)
        lines.append(f"PoCL platform:       {'found' if pocl_devices else 'NOT FOUND'}" + (f"  ({err})" if err else ""))
        lines.append(f"PoCL CPU device:     {'found (backend device ' + str(cpu['device_id']) + ')' if cpu else 'NOT FOUND'}")
    else:
        lines.append("PoCL platform:       NOT FOUND (no binary to query)")
        lines.append("PoCL CPU device:     NOT FOUND (no binary to query)")

    print("\n".join(lines))
    return 0


# ---------------------------------------------------------------------------
# exec
# ---------------------------------------------------------------------------

def cmd_exec(ns, valgrind_passthrough, hc_cmd):
    if not hc_cmd:
        print("ERROR: no hashcat command given after --", file=sys.stderr)
        return 2
    if not re.match(r"^[A-Za-z0-9_-]+$", ns.test_name):
        print(f"ERROR: test-name must match [A-Za-z0-9_-]+, got: {ns.test_name!r}", file=sys.stderr)
        return 2
    if shutil.which("valgrind") is None:
        print("ERROR: valgrind not found on PATH", file=sys.stderr)
        return 2

    hc_bin = hc_cmd[0]
    hc_bin_resolved = hc_bin if os.sep in hc_bin else shutil.which(hc_bin)
    if not hc_bin_resolved or not os.path.exists(hc_bin_resolved):
        print(f"ERROR: hashcat binary not found: {hc_bin}", file=sys.stderr)
        return 2

    ok, output = sanity_check_binary(hc_bin_resolved)
    if not ok:
        print(f"ERROR: build sanity check failed for {hc_bin_resolved} -- it does not run cleanly.", file=sys.stderr)
        print("Refusing to invoke Valgrind against a binary that doesn't even execute.", file=sys.stderr)
        if output:
            print(output, file=sys.stderr)
        return 2

    debug_ok = has_debug_info(hc_bin_resolved)
    if not debug_ok:
        print(f"WARNING: {hc_bin_resolved} was not built with usable debug information "
              f"(no .debug_info/.debug_line section).", file=sys.stderr)
        print("Source-level Valgrind output will be degraded to object/offset only.", file=sys.stderr)
        print("For source-level output run: tools/valgrind/run.py build", file=sys.stderr)

    env = dict(os.environ)
    pocl_info = None
    if ns.pocl:
        # POCL_DEVICES takes a PoCL *driver* name (e.g. "pthread"), not a device
        # type string -- confirmed empirically: "cpu" is not a valid driver name
        # and silently makes clGetDeviceIDs() return zero devices (CL_DEVICE_NOT_FOUND).
        env["POCL_DEVICES"] = "pthread"
        env["POCL_EXTRA_BUILD_FLAGS"] = "-g -cl-opt-disable"
        env["POCL_LEAVE_KERNEL_COMPILER_TEMP_FILES"] = "1"
        if ns.pocl_enable_uninit:
            env["POCL_ENABLE_UNINIT"] = "1"

        device, pocl_devices, err = find_pocl_cpu_device(hc_bin_resolved)
        if device is None:
            print("ERROR: --pocl requested, but no PoCL CPU OpenCL device was found.", file=sys.stderr)
            print("Check:", file=sys.stderr)
            print("  clinfo", file=sys.stderr)
            print(f"  {hc_bin_resolved} -I", file=sys.stderr)
            if err:
                print(f"  ({err})", file=sys.stderr)
            return 2

        pocl_info = {"enabled": True, "device_id": device["device_id"],
                     "platform_name": device.get("platform_name")}

        # Deliberately NOT injecting -d/-D here (tried first, confirmed
        # broken empirically): hashcat numbers backend devices across all
        # backends together, and once --backend-ignore-cuda removes CUDA's
        # device(s) from that list, the PoCL device's number shifts -- the
        # id find_pocl_cpu_device() detected from `-I` output no longer
        # matches, and hashcat reports "0 devices usable" / silently skips
        # it with no explanatory message. Omitting -d/-D entirely works
        # reliably instead: hashcat's own backend.c auto-enables
        # CL_DEVICE_TYPE_CPU whenever no GPU/accelerator is visible via
        # OpenCL ("automatically enable CPU device type support, since it's
        # disabled by default") -- exactly this case once CUDA is ignored
        # and PoCL is the only OpenCL platform. If the caller passes their
        # own -d/-D, that's left untouched (their choice, their risk).
        has_device_select = any(a in ("-d", "--backend-devices", "-D", "--opencl-device-types") for a in hc_cmd)
        if has_device_select:
            print("WARNING: -d/-D already present in the given command -- device numbering shifts once "
                  "--backend-ignore-cuda/hip are added, so this may not select the PoCL device you expect.",
                  file=sys.stderr)
        ignore_flags = ["--backend-ignore-cuda", "--backend-ignore-hip"]
        if sys.platform == "darwin":
            # --backend-ignore-metal only exists in hashcat's getopt table
            # on macOS (src/user_options.c: #if defined (__APPLE__)) --
            # passing it on any other platform is a hard "unrecognized
            # option" failure, confirmed empirically.
            ignore_flags.append("--backend-ignore-metal")
        hc_cmd = hc_cmd + ignore_flags

        # hashcat's own PoCL-version detection (src/backend.c, ~line 8362)
        # matches the platform version string against "PoCL " (capital P/C/L)
        # to decide whether it's new enough to use -- but PoCL's actual
        # string is lowercase ("OpenCL 2.0 pocl 1.8 ..."), confirmed via
        # both `clinfo` and hashcat's own `-I` output. The case-sensitive
        # match always fails against a real PoCL install, hitting hashcat's
        # `else { pocl_skip = true; }` fallback, which rejects the device as
        # "Outdated PoCL OpenCL runtime detected!" regardless of its actual
        # version. --force is hashcat's own documented escape hatch for
        # exactly this warning ("You can use --force to override, but do
        # not report related errors.") -- needed here purely to work around
        # this parsing bug, not because the run is actually risky.
        if "--force" not in hc_cmd:
            hc_cmd = hc_cmd + ["--force"]

    if ns.sweep:
        if not ns.results_dir:
            print("ERROR: --sweep requires --results-dir", file=sys.stderr)
            return 2
        base = Path(ns.results_dir)
    else:
        base = Path(ns.results_dir) if ns.results_dir else DEFAULT_RESULTS_DIR
    base.mkdir(parents=True, exist_ok=True)
    run_dir, ts = make_results_dir(base, ns.test_name)

    (run_dir / "command.txt").write_text("\n".join(hc_cmd) + "\n")
    write_environment_file(run_dir / "environment.txt", hc_bin_resolved, debug_ok, pocl_info)

    xml_path = run_dir / "valgrind.xml"
    log_path = run_dir / "valgrind.log"

    vg_cmd = [
        "valgrind", "--tool=memcheck",
        "--leak-check=full", "--show-leak-kinds=definite", "--errors-for-leak-kinds=definite",
        "--num-callers=40", "--read-inline-info=yes",
        "--xml=yes", f"--xml-file={xml_path}", f"--log-file={log_path}",
    ]
    supp = SCRIPT_DIR / "hashcat.supp"
    if supp.exists():
        vg_cmd.append(f"--suppressions={supp}")
    vg_cmd += valgrind_passthrough
    vg_cmd += ["--"] + hc_cmd

    try:
        proc = subprocess.run(vg_cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except (OSError, subprocess.SubprocessError) as e:
        print(f"ERROR: failed to invoke valgrind: {e}", file=sys.stderr)
        return 2

    (run_dir / "stdout.txt").write_text(proc.stdout)
    (run_dir / "stderr.txt").write_text(proc.stderr)

    if ns.sweep:
        sys.stdout.write(proc.stdout)
        sys.stderr.write(proc.stderr)

    rc = proc.returncode
    hashcat_rc_raw = (128 - rc) if rc < 0 else rc

    modules_dir = REPO_ROOT / "modules"
    summary = triage.analyze(
        str(xml_path), str(REPO_ROOT), hc_bin_resolved, str(modules_dir),
        pocl_kernel_dirs=(), test_name=ns.test_name, timestamp=ts,
        command=hc_cmd, hashcat_rc_raw=hashcat_rc_raw,
        debug_info_detected=debug_ok, pocl_info=pocl_info,
    )
    text = triage.write_summary(run_dir, summary)

    if ns.sweep:
        triage.append_sweep_finding(base, run_dir.name, summary)
        return hashcat_rc_raw

    print(text)
    return summary["run"].get("wrapper_rc", 2)


# ---------------------------------------------------------------------------
# selftest
# ---------------------------------------------------------------------------

def _run_make_modules():
    r = subprocess.run(["make"], cwd=MODULES_FIXTURE_DIR)
    return r.returncode == 0


def cmd_selftest(args):
    expected_path = MODULES_FIXTURE_DIR / "expected.json"
    if not expected_path.exists():
        print(f"ERROR: {expected_path} not found", file=sys.stderr)
        return 2
    expected = json.loads(expected_path.read_text())

    if not _run_make_modules():
        print("ERROR: failed to build tools/valgrind/modules/ fixtures", file=sys.stderr)
        return 2

    results_dir = DEFAULT_RESULTS_DIR / "selftest"
    if results_dir.exists():
        shutil.rmtree(results_dir)
    results_dir.mkdir(parents=True)

    rows = []
    all_ok = True
    for name, exp in expected.items():
        fixture_kind = exp.get("fixture_kind", "host")
        if fixture_kind == "kernel" and not args.pocl:
            rows.append((name, "SKIP", "kernel fixture, run with --pocl"))
            continue

        if fixture_kind == "host":
            fixture_bin = MODULES_FIXTURE_DIR / exp.get("binary", name)
            hc_cmd = [str(fixture_bin)]
            # These fixtures live under tools/valgrind/modules/, outside
            # src/include/OpenCL, so they need to be explicitly marked
            # relevant by their own source file -- narrowly, one file at a
            # time, so a kernel fixture's cl_harness.c wrapper code never
            # gets swept in as "relevant" and drowns out the real .cl finding.
            extra_relevant = {str((MODULES_FIXTURE_DIR / f"{exp.get('binary', name)}.c").resolve())}
        else:
            harness = MODULES_FIXTURE_DIR / "cl_harness"
            kernel_file = MODULES_FIXTURE_DIR / exp.get("cl_file", f"{name}.cl")
            hc_cmd = [str(harness), str(kernel_file), exp.get("kernel_name", name)]
            extra_relevant = set()

        # selftest fixtures are standalone binaries, not hashcat -- run the
        # shared Valgrind/triage pipeline directly rather than reusing
        # cmd_exec's hashcat-specific sanity/backend-selection logic.
        ok, actual_kind, actual_relevance, detail = _run_selftest_case(name, hc_cmd, results_dir, extra_relevant)
        want_kind = exp.get("kind")
        want_relevance = exp.get("relevance")
        passed = ok and actual_kind == want_kind and actual_relevance == want_relevance
        all_ok = all_ok and passed
        rows.append((name, "PASS" if passed else "FAIL",
                     f"expected {want_relevance}/{want_kind}, got {actual_relevance}/{actual_kind} ({detail})"))

    width = max(len(r[0]) for r in rows) if rows else 10
    for name, status, detail in rows:
        print(f"{name.ljust(width)}  {status:4s}  {detail}")

    return 0 if all_ok else 1


def _run_selftest_case(name, hc_cmd, results_dir, extra_relevant_files=()):
    run_dir, ts = make_results_dir(results_dir, name)
    xml_path = run_dir / "valgrind.xml"
    log_path = run_dir / "valgrind.log"
    vg_cmd = [
        "valgrind", "--tool=memcheck",
        "--leak-check=full", "--show-leak-kinds=definite,possible,indirect",
        "--errors-for-leak-kinds=definite,possible,indirect",
        "--num-callers=40", "--read-inline-info=yes",
        "--xml=yes", f"--xml-file={xml_path}", f"--log-file={log_path}",
        "--", *hc_cmd,
    ]
    env = dict(os.environ)
    if "cl_harness" in hc_cmd[0]:
        env["POCL_DEVICES"] = "pthread"
        env["POCL_EXTRA_BUILD_FLAGS"] = "-g -cl-opt-disable"
        env["POCL_LEAVE_KERNEL_COMPILER_TEMP_FILES"] = "1"
    try:
        proc = subprocess.run(vg_cmd, capture_output=True, text=True, env=env)
    except (OSError, subprocess.SubprocessError) as e:
        return False, None, None, str(e)

    (run_dir / "command.txt").write_text("\n".join(hc_cmd) + "\n")
    (run_dir / "stdout.txt").write_text(proc.stdout)
    (run_dir / "stderr.txt").write_text(proc.stderr)

    # No binary_path/modules_dir here (unlike real hashcat runs): these
    # fixtures aren't hashcat, so the obj-based binary-match fallback isn't
    # applicable -- relevance comes entirely from extra_relevant_files (host
    # fixtures) or the .cl-extension rule (kernel fixtures).
    summary = triage.analyze(
        str(xml_path), str(REPO_ROOT), None, None, (),
        test_name=name, timestamp=ts, command=hc_cmd,
        extra_relevant_files=extra_relevant_files,
    )
    triage.write_summary(run_dir, summary)

    if not summary["valgrind"]["xml_parse_ok"]:
        return False, None, None, "xml parse failed"

    # analyze() already sorts errors relevant-first, so the first entry with
    # a HASHCAT_HOST/OPENCL_KERNEL frame (if any) is exactly what we want.
    for err in summary["errors"]:
        frf = err.get("first_relevant_frame")
        if frf and frf.get("relevance") in ("HASHCAT_HOST", "OPENCL_KERNEL"):
            return True, err["kind_normalized"], frf["relevance"], f"{frf.get('file')}:{frf.get('line')}"

    if summary["errors"]:
        e0 = summary["errors"][0]
        return True, e0["kind_normalized"], e0["relevance"], "no HASHCAT_HOST/OPENCL_KERNEL frame found"

    return True, None, None, "no errors found"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def split_exec_args(argv):
    """Splits `exec`'s argv at the first literal '--' into (pre, post). No
    '--' present -> post is None (caller reports the usage error)."""
    if "--" not in argv:
        return argv, None
    idx = argv.index("--")
    return argv[:idx], argv[idx + 1:]


def build_exec_parser():
    p = argparse.ArgumentParser(prog="run.py exec", add_help=True,
                                 description="Run one hashcat command under Valgrind with triage.")
    p.add_argument("test_name")
    p.add_argument("--pocl", action="store_true", help="run OpenCL kernels via PoCL CPU device")
    p.add_argument("--pocl-enable-uninit", action="store_true",
                    help="set POCL_ENABLE_UNINIT=1 (platform-dependent, opt-in)")
    p.add_argument("--sweep", action="store_true",
                    help="non-interactive mode for test.sh/test_edge.sh: hashcat's stdout/stderr/exit-code "
                         "pass through untouched; requires --results-dir")
    p.add_argument("--results-dir", default=None)
    return p


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0

    subcmd, rest = argv[0], argv[1:]

    if subcmd == "build":
        return cmd_build(argparse.Namespace())

    if subcmd == "check":
        p = argparse.ArgumentParser(prog="run.py check")
        p.add_argument("--binary", default=None)
        return cmd_check(p.parse_args(rest))

    if subcmd == "selftest":
        p = argparse.ArgumentParser(prog="run.py selftest")
        p.add_argument("--pocl", action="store_true", help="also run the .cl kernel fixtures via PoCL")
        return cmd_selftest(p.parse_args(rest))

    if subcmd == "exec":
        pre, post = split_exec_args(rest)
        if post is None:
            print("ERROR: exec requires a '--' separator before the hashcat command", file=sys.stderr)
            return 2
        parser = build_exec_parser()
        ns, unknown = parser.parse_known_args(pre)
        return cmd_exec(ns, unknown, post)

    print(f"ERROR: unknown subcommand: {subcmd}", file=sys.stderr)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
