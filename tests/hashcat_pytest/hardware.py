##
## Author......: See docs/credits.txt
## License.....: MIT
##

import json
import re
import subprocess
import sys
from pathlib import Path

from . import catalog, runtime


def host_avail_mib():
  if sys.platform == "darwin":
    try:
      proc = subprocess.run(["/usr/bin/vm_stat"], capture_output=True, text=True, timeout=10)
      return parse_vm_stat(proc.stdout) if proc.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
      return None
  available = None
  try:
    with open("/proc/meminfo") as fh:
      for line in fh:
        if line.startswith("MemAvailable:"):
          available = int(line.split()[1]) // 1024
          break
  except (OSError, ValueError):
    pass
  try:
    unified = next(line.split(":", 2)[2] for line in Path("/proc/self/cgroup").read_text().splitlines()
                   if line.startswith("0::"))
    bounded = cgroup_available_mib(Path("/sys/fs/cgroup"), unified)
    if bounded is not None:
      available = bounded if available is None else min(available, bounded)
  except (OSError, StopIteration):
    pass
  return available


def cgroup_available_mib(root, relative):
  directory = root / relative.lstrip("/")
  limits = []
  while directory.is_relative_to(root):
    try:
      maximum = (directory / "memory.max").read_text().strip()
      if maximum != "max":
        used = int((directory / "memory.current").read_text())
        limits.append(max(0, int(maximum) - used) // (1024 * 1024))
    except (OSError, ValueError):
      pass
    if directory == root:
      break
    directory = directory.parent
  return min(limits) if limits else None


def parse_vm_stat(text):
  try:
    page_size = int(text.split("page size of ", 1)[1].split(" bytes)", 1)[0])
    pages = {name: int(value.strip().rstrip(".")) for line in text.splitlines()[1:]
             for name, separator, value in [line.partition(":")] if separator and name.startswith("Pages ")}
    available = pages["Pages free"] + pages["Pages inactive"] + pages.get("Pages speculative", 0)
    return available * page_size // (1024 * 1024)
  except (IndexError, KeyError, ValueError):
    return None


def backend_devices(device=None):
  types = ["-D", device] if device else []
  try:
    proc = subprocess.run([runtime.METADATA_BIN, "-I", "--machine-readable"] + types + runtime.ISOLATION, cwd=runtime.ROOT,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
  except (OSError, subprocess.SubprocessError) as error:
    raise RuntimeError("backend inventory failed: " + str(error)) from error
  if proc.returncode != 0:
    raise RuntimeError("backend inventory returned %d: %s" %
                       (proc.returncode, proc.stderr.decode("utf-8", "replace")))
  text = proc.stdout.decode("utf-8", "replace")
  if isinstance(json.loads(text), dict) == False:
    raise ValueError("backend inventory is not a JSON object")
  return parse_backend_devices(text)


def parse_backend_devices(text):
  try:
    info = json.loads(text)
  except Exception:
    return []
  gpu_only = {"CUDA", "HIP", "METAL"}
  out      = []
  def add(backend, dev):
    try:
      did = int(dev["DeviceID"])
    except (KeyError, TypeError, ValueError):
      return
    typ = dev.get("Type")
    typ = typ.upper() if typ else ("GPU" if backend in gpu_only else None)
    free = None
    mem = dev.get("MemoryFree")
    if mem:
      head = str(mem).split()[0]
      if head.isdigit():
        free = int(head)
    alias = dev.get("Alias")
    try:
      alias = int(alias) if alias is not None else None
    except (TypeError, ValueError):
      alias = None
    out.append({"id": did, "type": typ, "free": free, "backend": backend, "alias": alias})
  for section, body in info.items():
    if not isinstance(body, dict):
      continue
    backend = section[:-4].upper() if section.endswith("Info") else section.upper()
    for dev in body.get("BackendDevices", []):
      add(backend, dev)
    for plat in body.get("Platforms", []):
      if isinstance(plat, dict):
        for dev in plat.get("BackendDevices", []):
          add(backend, dev)
  return out


def wanted_types(device):
  type_of = {"1": "CPU", "2": "GPU", "3": "FPGA"}
  return {type_of[d] for d in re.split(r"[ ,]+", device.strip()) if d in type_of}


def min_device_free_mib(device, devices=None, ids=None):
  want  = wanted_types(device)
  devs  = backend_devices() if devices is None else devices
  pick  = set(backend_device_ids(ids) or []) if ids else None
  frees = [d["free"] for d in devs
           if d["free"] is not None and (not want or d["type"] in want) and (pick is None or d["id"] in pick)]
  return min(frees) if frees else None


def dedup_alias_devices(devices):
  by_id = {d["id"]: d for d in devices}
  skip  = set()
  for d in devices:
    other = by_id.get(d["alias"])
    if other is not None and d["backend"] == "OPENCL" and other["backend"] != "OPENCL":
      skip.add(d["id"])
  return [d for d in devices if d["id"] not in skip]


def backend_ids_for(device, devices=None):
  want = wanted_types(device)
  devs = backend_devices() if devices is None else devices
  return [d["id"] for d in dedup_alias_devices(devs)
          if not want or d["type"] in want]


def backend_device_ids(spec):
  ids = []
  for field in spec.split(","):
    if field == "":
      continue
    value = field.strip().removeprefix("+")
    if value.isascii() == False or value.isdigit() == False or not 1 <= int(value) <= 255:
      return None
    ids.append(int(value))
  return ids or None


def cpu_backend_id():
  if runtime.CPU_BACKEND_ID != -1:
    return runtime.CPU_BACKEND_ID
  runtime.CPU_BACKEND_ID = next((d["id"] for d in backend_devices() if d["type"] == "CPU"), None)
  return runtime.CPU_BACKEND_ID


def bridge_opts(mode):
  if not catalog.is_bridged(mode):
    return []
  cid = cpu_backend_id()
  if cid is None:
    return []
  return ["-D", "1", "--backend-devices-virthost", str(cid)]


def with_bridge_opts(opts, mode):
  extra = bridge_opts(mode)
  if extra and "--backend-devices" in opts:
    i    = opts.index("--backend-devices")
    opts = opts[:i] + opts[i + 2:]
  return list(opts) + extra


def device_for(args, mode):
  if catalog.is_bridged(mode) and (cpu_backend_id() is not None):
    return "1"
  return args.device
