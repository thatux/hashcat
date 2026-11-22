#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# The fork-only test workflow calls this runner to audit capped tests and measure warmup costs.

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

import test_iterations

ROOT = Path(__file__).resolve().parents[1]


def policies():
  supported = []
  capped = []
  for path in sorted((ROOT / "tools/test_modules").glob("m[0-9]*.py")):
    mode = int(path.stem[1:])
    if test_iterations.iteration_reduction_enabled(mode):
      supported.append(mode)
    if test_iterations.iteration_kernel_accel(mode) is not None:
      capped.append(mode)
  return supported, capped


def audit(mode, kind):
  expected = test_iterations.iteration_kernel_accel(mode)
  commands = []
  for path in ROOT.glob("test_*/logfull.txt"):
    for line in path.read_text(errors="replace").splitlines():
      if not line.startswith("> cmdline : "):
        continue
      command = shlex.split(line.removeprefix("> cmdline : "))
      if "-m" not in command or command[command.index("-m") + 1] != str(mode):
        continue
      accel = None
      if "--kernel-accel" in command:
        accel = int(command[command.index("--kernel-accel") + 1])
      commands.append(accel)
  record = {"mode": mode, "kind": kind, "expected_accel": expected, "native_commands": len(commands), "accels": sorted(set(commands), key=str)}
  output = ROOT / "cap-audit"
  output.mkdir(exist_ok=True)
  (output / ("%d-%s.json" % (mode, kind))).write_text(json.dumps(record, indent=2) + "\n")
  print("CAP_AUDIT " + json.dumps(record), flush=True)
  if any(accel != expected for accel in commands):
    raise RuntimeError("Native invocation used an unexpected kernel acceleration")
  if expected is not None and kind in ("pure", "edge", "smoke") and not commands:
    raise RuntimeError("A capped policy had no native execution")


def benchmark():
  output = ROOT / "cap-controls"
  output.mkdir(exist_ok=True)
  hash_value = "$gy$j7T$k2XAnEHBqQ1Ct2aMXFKNa/$/TqgmhB/JLs5mIvGDOJ3r7Dl8p6OJOCzHANFvdUBKf2"
  base = ["./hashcat", "-m", "36200", "-a", "3", "-D", "1", "--force", "--potfile-disable", "--logfile-disable", "--restore-disable", "--self-test-disable", "--cache-path", ".", "--backend-vector-width", "1", "--task-time-breakdown", hash_value, "AAAA"]
  rows = []
  for name, extra in (("uncapped", []), ("cap8", ["--kernel-accel", "8"])):
    command = base[:1] + extra + base[1:]
    print("COMMAND " + shlex.join(command), flush=True)
    started = time.monotonic()
    try:
      result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
      text = result.stdout.decode("utf-8", "replace")
      rc = result.returncode
    except subprocess.TimeoutExpired as error:
      text = (error.stdout or b"").decode("utf-8", "replace")
      rc = 124
    row = {"name": name, "command": command, "rc": rc, "seconds": time.monotonic() - started}
    for line in text.splitlines():
      stripped = line.strip()
      if stripped.startswith("Kernel autotune"):
        row["autotune_seconds"] = float(stripped.removeprefix("Kernel autotune").split()[0])
      if stripped.startswith("Compile kernels, cached afterwards"):
        row["compile_seconds"] = float(stripped.removeprefix("Compile kernels, cached afterwards").split()[0])
      if stripped.startswith("MEASURED TOTAL "):
        row["measured_seconds"] = float(stripped.removeprefix("MEASURED TOTAL").split()[0])
      if stripped.startswith("Speed.#01") and "@ Accel:" in stripped:
        row["accel"] = int(stripped.split("@ Accel:", 1)[1].split()[0])
    (output / (name + ".log")).write_text(text)
    rows.append(row)
    (output / "benchmark.json").write_text(json.dumps(rows, indent=2) + "\n")
    print(text, flush=True)
    print("BENCHMARK " + json.dumps(row), flush=True)
  if any(row["rc"] != 0 for row in rows) or rows[-1].get("accel") != 8:
    raise RuntimeError("Both benchmark runs must crack, and the capped run must use acceleration 8")


def smoke():
  _, capped = policies()
  failed = []
  for mode in capped:
    result = subprocess.run([sys.executable, "tools/test.py", "-S", "-m", str(mode), "-D", "1"])
    if result.returncode != 0:
      failed.append(mode)
    audit(mode, "smoke")
  if failed:
    raise RuntimeError("Capped smoke failures: " + str(failed))


def main():
  os.chdir(ROOT)
  os.environ["ARTIFICIALLY_LOW_ITERATION_COUNT"] = "true"
  action = sys.argv[1]
  if action == "inventory":
    supported, capped = policies()
    assert len(supported) == 232
    assert len(capped) == 22
    print(json.dumps({"supported": supported, "capped": capped}))
  elif action == "audit":
    audit(int(sys.argv[2]), sys.argv[3])
  elif action == "benchmark":
    benchmark()
  elif action == "smoke":
    smoke()
  else:
    raise ValueError("Unknown validation action: " + action)


if __name__ == "__main__":
  main()
