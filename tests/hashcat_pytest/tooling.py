##
## Author......: See docs/credits.txt
## License.....: MIT
##

import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from . import execution, runtime


def run(command, stdin=None, environment=None, timeout=600, process_environment=None):
  active = runtime.ACTIVE
  inputs = active.capture_inputs(command) if active is not None else {}
  environment = dict(runtime.ENV, **(environment or {}))
  started = time.monotonic()
  launch = [sys.executable, str(Path(__file__).with_name("guardian.py")), str(os.getpid())] + command
  env = dict(os.environ, **environment) if process_environment is None else process_environment
  proc = subprocess.Popen(launch, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                          cwd=runtime.ROOT, env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, start_new_session=True, pass_fds=runtime.PASS_FDS)
  try:
    stdout, stderr = proc.communicate(stdin, timeout=timeout)
  except (subprocess.TimeoutExpired, KeyboardInterrupt):
    os.killpg(proc.pid, signal.SIGTERM)
    stdout, stderr = proc.communicate()
    if active is not None:
      result = execution.HashcatResult(command, proc.returncode, stdout, stderr, time.monotonic() - started)
      active.save(command, stdin, result, inputs, tool=True, environment=environment)
    raise
  result = execution.HashcatResult(command, proc.returncode, stdout, stderr, time.monotonic() - started)
  if active is not None:
    active.save(command, stdin, result, inputs, tool=True, environment=environment)
  return result
