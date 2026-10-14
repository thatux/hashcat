##
## Author......: See docs/credits.txt
## License.....: MIT
##

import contextlib
from pathlib import Path

from . import hardware


class RetryWithFullMemory(Exception):
  pass


@contextlib.contextmanager
def lease(directory, exclusive=False):
  # The gate stops new readers while an uncapped retry waits for existing readers.
  import fcntl

  Path(directory).mkdir(parents=True, exist_ok=True)
  with open(Path(directory, "gate"), "a+b") as gate, open(Path(directory, "resource"), "a+b") as resource:
    fcntl.flock(gate, fcntl.LOCK_EX)
    try:
      fcntl.flock(resource, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
      if exclusive == False:
        fcntl.flock(gate, fcntl.LOCK_UN)
      try:
        yield (resource.fileno(), gate.fileno()) if exclusive else (resource.fileno(),)
      finally:
        fcntl.flock(resource, fcntl.LOCK_UN)
    finally:
      fcntl.flock(gate, fcntl.LOCK_UN)


def memory_limits(device, workers, ids=None, inventory=None):
  if workers <= 1:
    return {}
  result = {}
  free = hardware.min_device_free_mib(device, devices=inventory, ids=ids)
  host = hardware.host_avail_mib()
  if host is not None:
    # Leave room for the worker interpreters, kernel compilation and backend bookkeeping.
    host = max(1, host * 3 // 4)
    if device == "1":
      free = host if free is None else min(free, host)
  for key, value in (("HASHCAT_DEVICE_MEM_LIMIT", free), ("HASHCAT_HOST_MEM_LIMIT", host)):
    if value is not None:
      result[key] = str(max(1, value // workers))
  return result


def physical_devices(inventory, device, selected=None):
  types = hardware.wanted_types(device)
  ids = set(hardware.backend_device_ids(selected) or []) if selected else None
  canonical = {d["id"]: d["alias"] or d["id"] for d in inventory}
  if ids is not None:
    ids |= {canonical.get(value, value) for value in ids}
  return [d for d in hardware.dedup_alias_devices(inventory)
          if (d["type"] in types) and (ids is None or d["id"] in ids)]
