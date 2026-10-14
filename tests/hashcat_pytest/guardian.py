##
## Author......: See docs/credits.txt
## License.....: MIT
##

import ctypes
import os
import signal
import subprocess
import sys


class StopGuardian(Exception):
  pass


def main():
  parent = int(sys.argv[1])
  child = None
  received = None

  def terminate(signum, frame):
    nonlocal received
    received = signum
    if child is None:
      return
    # Unwind Popen.wait before taking its waitpid lock again during cleanup.
    raise StopGuardian(signum)

  def stop_child():
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    if child is not None and child.poll() is None:
      try:
        os.killpg(child.pid, signal.SIGKILL)
      except ProcessLookupError:
        pass
      except PermissionError:
        if sys.argv[2:4] != ["sudo", "-n"]:
          raise
        subprocess.run(["sudo", "-n", "kill", "-KILL", "--", "-%d" % child.pid],
                       stdin=subprocess.DEVNULL, check=True, timeout=10)
      child.wait()

  signal.signal(signal.SIGTERM, terminate)
  signal.signal(signal.SIGINT, terminate)
  if sys.platform.startswith("linux"):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGTERM, 0, 0, 0) != 0:
      raise OSError(ctypes.get_errno(), "cannot arm parent-death signal")
  if os.getppid() != parent:
    return 143
  try:
    try:
      child = subprocess.Popen(sys.argv[2:], start_new_session=True, close_fds=True)
    except OSError as error:
      print(str(error), file=sys.stderr)
      return 125
    if received is not None:
      raise StopGuardian(received)
    if sys.platform.startswith("linux"):
      return child.wait()
    while True:
      try:
        return child.wait(timeout=0.02)
      except subprocess.TimeoutExpired:
        if os.getppid() != parent:
          raise StopGuardian(signal.SIGTERM)
  except StopGuardian as error:
    stop_child()
    return 128 + error.args[0]


if __name__ == "__main__":
  code = main()
  if code < 0:
    if -code not in (signal.SIGKILL, signal.SIGSTOP):
      signal.signal(-code, signal.SIG_DFL)
    os.kill(os.getpid(), -code)
  raise SystemExit(code)
