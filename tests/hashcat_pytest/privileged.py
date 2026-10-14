##
## Author......: See docs/credits.txt
## License.....: MIT
##

from contextlib import contextmanager
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import uuid

from . import runtime


@contextmanager
def resource(kind, backing_file, mapper_name=None):
  backing_file = Path(backing_file).resolve()
  if backing_file.is_file() == False or backing_file.stat().st_uid != os.getuid():
    raise ValueError("privileged resource needs a worker-owned backing file")
  if runtime.ACTIVE is not None and backing_file.is_relative_to(runtime.ACTIVE.directory.resolve()) == False:
    raise ValueError("privileged resource must use the private case directory")
  if kind not in ("loop", "mapper"):
    raise ValueError("unknown privileged resource: " + kind)
  if kind == "mapper":
    prefixes = ("luksgen%d_" % os.getpid(), "luks2gen%d_" % os.getpid())
    if not mapper_name or not mapper_name.startswith(prefixes) or not all(char.isascii() and (char.isalnum() or char == "_") for char in mapper_name):
      raise ValueError("mapper name must identify this worker's generated LUKS volume")
  status = backing_file.parent / (".resource-%s.json" % uuid.uuid4().hex)
  read_fd, write_fd = os.pipe()
  ready_read, ready_write = os.pipe()
  inherited = runtime.PASS_FDS
  command = [sys.executable, str(Path(__file__).with_name("resource_guardian.py")),
             "--kind", kind, "--backing-file", str(backing_file), "--status-file", str(status),
             "--control-fd", str(read_fd), "--ready-fd", str(ready_write)]
  if mapper_name is not None:
    command += ["--mapper-name", mapper_name]
  proc = None
  try:
    proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, start_new_session=True,
                            pass_fds=inherited + (read_fd, ready_write))
    os.close(read_fd)
    read_fd = None
    os.close(ready_write)
    ready_write = None
    readable, _, _ = select.select([ready_read], [], [], 10)
    if not readable or os.read(ready_read, 1) != b"1":
      raise RuntimeError("privileged resource watchdog did not register: " + str(status))
    # Tool guardians keep this writer until allocation processes have stopped.
    runtime.PASS_FDS = inherited + (write_fd,)
    yield
  finally:
    runtime.PASS_FDS = inherited
    for descriptor in (read_fd, write_fd, ready_read, ready_write):
      if descriptor is not None:
        os.close(descriptor)
    if proc is not None:
      interrupted = False
      while True:
        try:
          _, stderr = proc.communicate()
          break
        except KeyboardInterrupt:
          interrupted = True
      if proc.returncode != 0:
        try:
          error = json.loads(status.read_text())["error"]
        except (OSError, ValueError, KeyError):
          error = stderr.decode("utf-8", "replace")
        raise RuntimeError("privileged resource cleanup failed: " + error)
      if interrupted:
        raise KeyboardInterrupt
