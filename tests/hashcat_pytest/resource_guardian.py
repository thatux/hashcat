##
## Author......: See docs/credits.txt
## License.....: MIT
##

import argparse
import base64
import json
import os
from pathlib import Path
import signal
import subprocess


class Resources:
  def __init__(self, backing_file, record):
    self.backing_file = str(Path(backing_file).resolve())
    self.record = record

  def run(self, command):
    argv = ["sudo", "-n"] + command
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=10, env=dict(os.environ, LC_ALL="C"))
    self.record["commands"].append({"argv": argv, "returncode": result.returncode,
      "stdout_b64": base64.b64encode(result.stdout).decode("ascii"),
      "stderr_b64": base64.b64encode(result.stderr).decode("ascii")})
    return result

  def loops(self):
    result = self.run(["losetup", "--json", "--list", "--output", "NAME,BACK-FILE"])
    if result.returncode != 0:
      raise RuntimeError("could not inspect loop devices: " + result.stderr.decode("utf-8", "replace"))
    rows = json.loads(result.stdout)["loopdevices"]
    if isinstance(rows, list) == False:
      raise ValueError("loop device inventory is not a list")
    return rows

  def matches(self, row):
    backing = row.get("back-file")
    if isinstance(backing, str) == False:
      return False
    if backing.endswith(" (deleted)"):
      backing = backing.removesuffix(" (deleted)")
    return backing == self.backing_file

  def cleanup_loops(self):
    for row in self.loops():
      if self.matches(row) == False:
        continue
      name = row["name"]
      number = name.removeprefix("/dev/loop")
      if not name.startswith("/dev/loop") or number.isascii() == False or number.isdigit() == False:
        raise ValueError("invalid generated loop device name")
      result = self.run(["losetup", "--detach", name])
      if result.returncode != 0:
        raise RuntimeError("could not detach generated loop device: " + result.stderr.decode("utf-8", "replace"))
    if any(self.matches(row) for row in self.loops()):
      raise RuntimeError("generated loop device remains attached")

  def mapper_device(self, mapper_name):
    executable = os.environ.get("CRYPTSETUP_BIN", "cryptsetup")
    result = self.run([executable, "status", mapper_name])
    if result.returncode == 4 and result.stdout.rstrip().endswith(b" is inactive."):
      return None
    if result.returncode != 0:
      raise RuntimeError("could not inspect generated mapper: " + result.stderr.decode("utf-8", "replace"))
    for line in result.stdout.decode("utf-8", "replace").splitlines():
      field, separator, value = line.partition(":")
      if separator and field.strip() == "device":
        return value.strip()
    raise ValueError("generated mapper status has no backing device")

  def cleanup_mapper(self, mapper_name):
    device = self.mapper_device(mapper_name)
    if device is not None:
      confirmed = device == self.backing_file or any(row.get("name") == device and self.matches(row) for row in self.loops())
      if confirmed == False:
        raise RuntimeError("generated mapper backing file does not match registered volume")
      executable = os.environ.get("CRYPTSETUP_BIN", "cryptsetup")
      result = self.run([executable, "close", mapper_name])
      if result.returncode != 0:
        raise RuntimeError("could not close generated mapper: " + result.stderr.decode("utf-8", "replace"))
      if self.mapper_device(mapper_name) is not None:
        raise RuntimeError("generated mapper remains open")
    self.cleanup_loops()


def write_status(path, record):
  temporary = path.with_suffix(".tmp")
  temporary.write_text(json.dumps(record, sort_keys=True) + "\n")
  temporary.replace(path)


def main():
  # Service shutdown must leave time to clean resources after allocation guardians exit.
  signal.signal(signal.SIGTERM, signal.SIG_IGN)
  signal.signal(signal.SIGINT, signal.SIG_IGN)
  parser = argparse.ArgumentParser()
  parser.add_argument("--kind", choices=("loop", "mapper"), required=True)
  parser.add_argument("--backing-file", required=True)
  parser.add_argument("--mapper-name")
  parser.add_argument("--status-file", type=Path, required=True)
  parser.add_argument("--control-fd", type=int, required=True)
  parser.add_argument("--ready-fd", type=int, required=True)
  args = parser.parse_args()
  record = {"state": "watching", "pid": os.getpid(), "kind": args.kind,
            "backing_file": args.backing_file, "mapper_name": args.mapper_name, "commands": []}
  write_status(args.status_file, record)
  os.write(args.ready_fd, b"1")
  os.close(args.ready_fd)
  while os.read(args.control_fd, 4096):
    pass
  os.close(args.control_fd)
  try:
    resources = Resources(args.backing_file, record)
    if args.kind == "mapper":
      resources.cleanup_mapper(args.mapper_name)
    else:
      resources.cleanup_loops()
    record["state"] = "cleaned"
  except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, RuntimeError) as error:
    record.update(state="failed", error=str(error))
  write_status(args.status_file, record)
  return int(record["state"] == "failed")


if __name__ == "__main__":
  raise SystemExit(main())
