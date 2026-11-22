#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# The diagnostic test workflow calls this runner to compare yescrypt costs and compiler phases.

import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent / "test_modules"))
import m36200


def run_case(command, path, timeout):
  print("COMMAND " + shlex.join(command), flush=True)
  started = time.monotonic()
  timed_out = False
  sampled = False
  next_report = 60
  with path.open("w") as log:
    proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    while proc.poll() is None:
      elapsed = time.monotonic() - started
      if elapsed >= next_report:
        print("PROGRESS %.1fs %s" % (elapsed, path), flush=True)
        print("\n".join(path.read_text(errors="replace").splitlines()[-5:]), flush=True)
        next_report += 60
      if elapsed >= 90 and not sampled:
        sampled = True
        stack_command = ["sudo", "gdb", "--batch", "-nx", "-ex", "set pagination off", "-ex", "thread apply all bt 12", "-p", str(proc.pid)]
        with path.with_suffix(".stack").open("w") as stack:
          try:
            subprocess.run(stack_command, stdout=stack, stderr=subprocess.STDOUT, timeout=45)
          except subprocess.TimeoutExpired:
            pass
      if elapsed >= timeout:
        timed_out = True
        os.killpg(proc.pid, signal.SIGTERM)
        try:
          proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
          os.killpg(proc.pid, signal.SIGKILL)
        break
      time.sleep(1)
    rc = proc.wait()
  result = {"command": command, "seconds": time.monotonic() - started, "rc": rc, "timeout": timed_out}
  print("RESULT " + json.dumps(result), flush=True)
  print(path.read_text(errors="replace"), flush=True)
  return result


def main():
  root = Path(__file__).resolve().parents[1]
  os.chdir(root)
  output = root / "yescrypt-profile"
  output.mkdir(exist_ok=True)
  hashes = {cost: m36200.module_generate_hash(b"hashcat", "0123456789abcdef", params=params) for cost, params in ((4096, "j9T"), (1024, "j7T"))}
  for cost, hash_value in hashes.items():
    if not hash_value.startswith("$gy$j"):
      raise RuntimeError("libxcrypt did not produce the requested GOST-yescrypt vector: " + hash_value)
  outcomes = []
  widths = [int(value) for value in os.environ.get("PROFILE_WIDTHS", "1 4").split()]
  timeout = int(os.environ.get("PROFILE_TIMEOUT", "1800"))
  for width in widths:
    for cost, hash_value in hashes.items():
      cache = output / ("cache-n%d-v%d" % (cost, width))
      cache.mkdir(exist_ok=True)
      command = ["stdbuf", "-o0", "-e0", "./hashcat", "-m", "36200", "-a", "3", "-D", "1", "--force", "--potfile-disable", "--logfile-disable", "--restore-disable", "--self-test-disable", "--backend-vector-width", str(width), "--cache-path", str(cache), "--task-time-breakdown", hash_value, "hashcat"]
      for temperature in ("cold", "warm"):
        path = output / ("n%d-v%d-%s.log" % (cost, width, temperature))
        result = run_case(command, path, timeout)
        result.update(n=cost, width=width, cache=temperature)
        outcomes.append(result)
        (output / "results.json").write_text(json.dumps(outcomes, indent=2) + "\n")
        if result["rc"] != 0:
          break
  return int(any(result["rc"] != 0 for result in outcomes))


if __name__ == "__main__":
  sys.exit(main())
