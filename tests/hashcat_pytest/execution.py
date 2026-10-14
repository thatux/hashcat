##
## Author......: See docs/credits.txt
## License.....: MIT
##



from dataclasses import dataclass
import os
import json
from pathlib import Path
import signal
import subprocess
import sys
import time

from . import catalog, hardware, runtime, scheduling



def selftest_opts(args):
  opts = [] if args.verbose else ["--quiet"]
  opts += ["--potfile-disable", "--logfile-disable"]
  opts += runtime.ISOLATION
  if not args.pure:
    opts.append("-O")
  opts += ["--runtime", str(runtime.SELFTEST_RUNTIME), "-D", args.device]
  if args.backend_devices:
    opts += ["--backend-devices", args.backend_devices]
  if args.metal_compiler_runtime:
    opts += ["--metal-compiler-runtime", str(args.metal_compiler_runtime)]
  if args.force:
    opts.append("--force")
  return opts


def base_opts(args):
  opts = [] if args.verbose else ["--quiet"]
  opts += ["--potfile-disable", "--logfile-disable", "--deprecated-check-disable"]
  opts += runtime.ISOLATION
  if not args.pure:
    opts.append("-O")
  opts += ["--runtime", str(runtime.RUNTIME), "-D", args.device]
  if args.backend_devices:
    opts += ["--backend-devices", args.backend_devices]
  if args.metal_compiler_runtime:
    opts += ["--metal-compiler-runtime", str(args.metal_compiler_runtime)]
  if args.force:
    opts.append("--force")
  return opts


def edge_opts(args, optimized, width, pt_hex, outfile):
  opts = [] if args.verbose else ["--quiet"]
  opts += ["--potfile-disable", "--machine-readable", "--logfile-disable"]
  opts += runtime.ISOLATION
  opts += ["-D", args.device, "--runtime", str(runtime.EDGE_RUNTIME), "--self-test-disable"]
  if args.backend_devices:
    opts += ["--backend-devices", args.backend_devices]
  if args.metal_compiler_runtime:
    opts += ["--metal-compiler-runtime", str(args.metal_compiler_runtime)]
  if args.force:
    opts.append("--force")
  if optimized:
    opts.append("-O")
  opts += ["--backend-vector-width", str(width)]
  if pt_hex:
    opts.append("--hex-charset")
  opts += ["--outfile", outfile]
  return opts




@dataclass
class HashcatResult:
  command: list
  returncode: int
  stdout: bytes
  stderr: bytes
  duration_seconds: float


def run_command(command, stdin=None, directory_inputs=()):
  runtime.LAST_CMD = command
  active = runtime.ACTIVE
  inputs = active.capture_inputs(command, directory_inputs)
  started = time.monotonic()
  env = dict(os.environ, **runtime.ENV)
  if runtime.UNCAPPED:
    for key in ("HASHCAT_DEVICE_MEM_LIMIT", "HASHCAT_HOST_MEM_LIMIT"):
      env.pop(key, None)
  sanitizer_directory = None
  if "SANITIZER_SWEEP_TOOL" in env:
    sanitizer_directory = active.directory / "sanitizer" / ("invocation-%04d" % len(active.invocations))
    env["SANITIZER_SWEEP_DIR"] = str(sanitizer_directory)
  timeout = max(runtime.RUNTIME, runtime.SELFTEST_RUNTIME, runtime.EDGE_RUNTIME) + 300
  launch = [sys.executable, str(Path(__file__).with_name("guardian.py")), str(os.getpid())] + command
  proc = subprocess.Popen(launch, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                          cwd=runtime.ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          start_new_session=True, pass_fds=runtime.PASS_FDS)
  try:
    stdout, stderr = proc.communicate(stdin, timeout=timeout)
  except (subprocess.TimeoutExpired, KeyboardInterrupt):
    os.killpg(proc.pid, signal.SIGTERM)
    stdout, stderr = proc.communicate()
    result = HashcatResult(command, proc.returncode, stdout, stderr, time.monotonic() - started)
    active.save(command, stdin, result, inputs)
    raise
  result = HashcatResult(command, proc.returncode, stdout, stderr, time.monotonic() - started)
  active.save(command, stdin, result, inputs)
  if sanitizer_directory is not None:
    check_sanitizer(sanitizer_directory, active)
  if proc.returncode == 252 and any(key in runtime.ENV for key in ("HASHCAT_DEVICE_MEM_LIMIT", "HASHCAT_HOST_MEM_LIMIT")):
    raise scheduling.RetryWithFullMemory()
  return result


def run_hashcat(opts, mode, target, stdin_bytes, attack=0, extra=()):
  command = [runtime.BIN] + hardware.with_bridge_opts(opts, mode) + catalog.module_opts(mode)
  command += ["-a", str(attack), "-m", str(mode), target] + list(extra)
  directory_inputs = extra[:1] if attack == 4 else ()
  result = run_command(command, stdin_bytes, directory_inputs)
  return result.returncode, result.stdout + result.stderr


def edge_run(opts, mode, target, stdin_bytes, attack, extra):
  code, output = run_hashcat(opts, mode, target, stdin_bytes, attack, extra)
  if attack == 9 and code != 0 and b"Mixed iteration counts are not supported" in output:
    runtime.ACTIVE.omissions.append("association attack cannot combine mixed iteration counts")
  else:
    runtime.ACTIVE.check(code)
  return code, output


def check_sanitizer(directory, active):
  summaries = list(Path(directory).rglob("summary.json"))
  if not summaries:
    active.problems.append("Compute Sanitizer produced no summary")
  for path in summaries:
    try:
      record = json.loads(path.read_text())
      status = record["sanitizer"]
      if status["parse_ok"] == False or status["primary_errors"] > 0:
        active.problems.append("Compute Sanitizer findings: " + str(path))
    except (ValueError, KeyError, TypeError):
      active.problems.append("invalid Compute Sanitizer summary: " + str(path))
