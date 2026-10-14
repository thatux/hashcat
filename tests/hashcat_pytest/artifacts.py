##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
from dataclasses import asdict, dataclass, field
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil

from . import reporting, runtime


def encoded(value):
  return base64.b64encode(value).decode("ascii")


def write_json(path, value):
  Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def hash_file(path, digest):
  with path.open("rb") as source:
    for chunk in iter(lambda: source.read(65536), b""):
      digest.update(chunk)


PATH_OPTIONS = {"--homedir", "--output", "--outfile", "--cache-path", "--potfile-path",
                "--create", "--bridge-parameter1", "-sOutputFile"}
DIRECTORY_OPTIONS = {"--homedir", "--cache-path"}


def literal_arguments(command):
  argv = [os.fsdecode(arg) for arg in command]
  lengths = {"--passphrase": 1, "--password": 1, "--encrypt": 2, "--session": 1,
             "-P": 1, "-N": 1, "-C": 1, "-c": 1}
  result = set()
  for index, arg in enumerate(argv):
    result.update(range(index + 1, min(len(argv), index + 1 + lengths.get(arg, 0))))
  program = 2 if argv[:2] == ["sudo", "-n"] else 0
  if len(argv) > program and Path(argv[program]).name == "expect":
    result.add(program + 3)
  return result


def argument_path(command, index, literals):
  if index in literals:
    return None
  value = os.fsdecode(command[index])
  option, separator, remainder = value.partition("=")
  prefix = option + "=" if separator and option in PATH_OPTIONS else ""
  if prefix:
    value = remainder
  elif value.startswith("-"):
    return None
  if not value:
    return None
  path = Path(value)
  if path.is_absolute() == False:
    path = Path(runtime.ROOT, path)
  previous = os.fsdecode(command[index - 1]) if index > 0 else ""
  directory = (option if prefix else previous) in DIRECTORY_OPTIONS
  return path, prefix, directory


def repository_paths(command, inputs):
  root = Path(runtime.ROOT).resolve()
  paths = {}
  program = Path(os.fsdecode(command[0])).name
  interpreter = program.startswith("python") or program in ("perl", "bash", "sh", "expect")
  literals = literal_arguments(command)
  for index, arg in enumerate(command):
    value = os.fsdecode(arg)
    components = argument_path(command, index, literals)
    if components is None:
      continue
    path, prefix, directory = components
    try:
      relative = path.resolve().relative_to(root)
      bridge = prefix == "--bridge-parameter1=" or (index > 0 and os.fsdecode(command[index - 1]) == "--bridge-parameter1")
      code = index == 0 or bridge or (index == 1 and interpreter and relative.parts and relative.parts[0] in ("tools", "tests"))
      if code and path.is_file():
        paths[value] = str(relative)
    except (OSError, ValueError):
      continue
  return paths


def case_paths(command, directory):
  paths = {}
  literals = literal_arguments(command)
  for index in range(1, len(command)):
    components = argument_path(command, index, literals)
    if components is None:
      continue
    path, prefix, is_directory = components
    try:
      relative = path.resolve().relative_to(directory.resolve())
      paths[str(index)] = {"relative": str(relative), "prefix": prefix,
                           "directory": is_directory or path.is_dir()}
    except (OSError, ValueError):
      continue
  return paths


@dataclass
class CaseResults:
  directory: Path
  case: object
  environment: dict
  vectors: list = field(default_factory=list)
  problems: list = field(default_factory=list)
  omissions: list = field(default_factory=list)
  notes: list = field(default_factory=list)
  runtime_skips: list = field(default_factory=list)
  summaries: list = field(default_factory=list)
  labels: list = field(default_factory=list)
  invocations: list = field(default_factory=list)
  tool_runs: list = field(default_factory=list)

  def check(self, code):
    if code == 0:
      return
    message = reporting.REASONS.get(code, "hashcat returned %d" % code)
    if code in (252, 253):
      self.runtime_skips.append(message)
    else:
      self.problems.append(message)

  def capture_inputs(self, command, directory_inputs=()):
    mapping = {}
    argv = [os.fsdecode(arg) for arg in command]
    directories = {os.fsdecode(arg) for arg in directory_inputs}
    literals = literal_arguments(command)
    for index, arg in enumerate(argv[1:], 1):
      # An empty hash or mask is data, not a request to snapshot the working directory.
      if not arg or argv[index - 1] in ("--cache-path", "--session", "--outfile"):
        continue
      components = argument_path(command, index, literals)
      if components is None:
        continue
      path, prefix, private_directory = components
      try:
        is_file = path.is_file()
        is_dir = path.is_dir()
        private_directory = private_directory and path.resolve().is_relative_to(self.directory.resolve())
      except OSError:
        continue
      if is_file:
        digest = hashlib.sha256()
        hash_file(path, digest)
        dest = self.directory / "inputs" / digest.hexdigest() / path.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists() == False:
          shutil.copyfile(path, dest)
        mapping[arg] = str(dest.relative_to(self.directory))
      elif is_dir and (arg in directories or private_directory):
        if self.directory.resolve().is_relative_to(path.resolve()):
          raise ValueError("input directory contains the artifact directory: " + str(path))
        children = sorted(path.rglob("*"))
        if path.is_symlink() or any(child.is_symlink() for child in children):
          raise ValueError("input directory contains a symlink: " + str(path))
        files = [child for child in children if child.is_file()]
        digest = hashlib.sha256()
        for child in children:
          if child.is_dir():
            digest.update(b"D" + os.fsencode(child.relative_to(path)) + b"\0")
        for child in files:
          digest.update(b"F" + os.fsencode(child.relative_to(path)) + b"\0")
          digest.update(child.stat().st_size.to_bytes(8, "big"))
          hash_file(child, digest)
        dest = self.directory / "inputs" / digest.hexdigest() / path.name
        if dest.exists() == False:
          def special_files(directory, names):
            return [name for name in names if not Path(directory, name).is_file() and not Path(directory, name).is_dir()]
          shutil.copytree(path, dest, ignore=special_files)
        mapping[arg] = str(dest.relative_to(self.directory))
    return mapping

  def save(self, command, stdin, result, inputs, tool=False, environment=None):
    records = self.tool_runs if tool else self.invocations
    index = len(records)
    folder = self.directory / (("tool-%04d" if tool else "invocation-%04d") % index)
    folder.mkdir()
    (folder / "stdout.bin").write_bytes(result.stdout)
    (folder / "stderr.bin").write_bytes(result.stderr)
    argv = [os.fsdecode(arg) for arg in command]
    cracks = None
    if "--outfile" in argv:
      path = Path(argv[argv.index("--outfile") + 1])
      if path.is_file():
        cracks = path.read_bytes()
        (folder / "cracks.bin").write_bytes(cracks)
    (folder / "command.txt").write_text(shlex.join([os.fsdecode(arg) for arg in command]) + "\n", errors="backslashreplace")
    private_paths = case_paths(command, self.directory)
    source_paths = repository_paths(command, inputs)
    for index in private_paths:
      source_paths.pop(argv[int(index)], None)
    literals = literal_arguments(command)
    prefixes = {}
    for index in range(len(command)):
      components = argument_path(command, index, literals)
      if components is not None and components[1]:
        prefixes[str(index)] = components[1]
    record = {"argv_b64": [encoded(os.fsencode(arg)) for arg in command],
              "stdin_b64": None if stdin is None else encoded(stdin), "inputs": inputs,
              "repository_paths": source_paths, "case_paths": private_paths,
              "literal_arguments": sorted(literals), "path_prefixes": prefixes,
              "returncode": result.returncode, "duration_seconds": result.duration_seconds,
              "stdout_b64": encoded(result.stdout), "stderr_b64": encoded(result.stderr),
              "outfile_b64": None if cracks is None else encoded(cracks),
              "environment": self.environment if environment is None else environment}
    write_json(folder / "result.json", record)
    records.append(record)

  def finish(self):
    write_json(self.directory / "case.json", {"case": asdict(self.case), "environment": self.environment})
    write_json(self.directory / "vectors.json", self.vectors)
    write_json(self.directory / "result.json", {"problems": self.problems, "omissions": self.omissions, "notes": self.notes,
               "summaries": self.summaries, "labels": self.labels, "invocations": len(self.invocations),
               "tool_runs": len(self.tool_runs),
               "runtime_skips": self.runtime_skips,
               "outcome": "failed" if self.problems else "skipped" if self.omissions or self.runtime_skips else "passed" if self.invocations else "empty"})
    (self.directory / "reproduce.py").write_text(REPRODUCE)


REPRODUCE = '''#!/usr/bin/env python3
import argparse
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("invocation", type=int)
parser.add_argument("--tool", action="store_true")
parser.add_argument("--root", type=Path, required=True)
args = parser.parse_args()
args.root = args.root.resolve()
here = Path(__file__).resolve().parent
prefix = "tool" if args.tool else "invocation"
record = json.loads((here / ("%s-%04d" % (prefix, args.invocation)) / "result.json").read_text())
command = [base64.b64decode(value) for value in record["argv_b64"]]
stdin = None if record["stdin_b64"] is None else base64.b64decode(record["stdin_b64"])
with tempfile.TemporaryDirectory(prefix="hashcat-repro-") as cache:
  if not args.tool and os.fsdecode(command[0]) not in record.get("repository_paths", {}):
    command[0] = os.fsencode(args.root / "hashcat")
  for i, value in enumerate(command):
    if i in record.get("literal_arguments", []):
      continue
    original = os.fsdecode(value)
    prefix = record.get("path_prefixes", {}).get(str(i), "")
    if original in record.get("repository_paths", {}):
      command[i] = os.fsencode(prefix + str(args.root / record["repository_paths"][original]))
      continue
    private = record.get("case_paths", {}).get(str(i))
    saved = record["inputs"].get(original)
    if private is not None:
      destination = Path(cache, "case", private["relative"])
      destination.parent.mkdir(parents=True, exist_ok=True)
      if private["directory"]:
        destination.mkdir(exist_ok=True)
    elif saved is not None:
      destination = Path(cache, saved)
      destination.parent.mkdir(parents=True, exist_ok=True)
    else:
      continue
    if saved is not None:
      source = here / saved
      if source.is_dir():
        shutil.copytree(source, destination, dirs_exist_ok=True)
      else:
        shutil.copy2(source, destination)
    command[i] = os.fsencode(prefix + str(destination))
  for option, value in ((b"--cache-path", os.fsencode(cache)), (b"--session", b"pytest-repro")):
    if option in command:
      command[command.index(option) + 1] = value
  if b"--outfile" in command:
    command[command.index(b"--outfile") + 1] = os.fsencode(Path(cache, "cracks"))
  env = dict(os.environ, **record["environment"])
  if "SANITIZER_SWEEP_DIR" in env:
    env["SANITIZER_SWEEP_DIR"] = str(Path(cache, "sanitizer"))
  for key in ("HASHCAT_DEVICE_MEM_LIMIT", "HASHCAT_HOST_MEM_LIMIT"):
    env.pop(key, None)
  home = None
  for i, value in enumerate(command):
    if value == b"--homedir" and i + 1 < len(command):
      home = Path(os.fsdecode(command[i + 1]))
    elif value.startswith(b"--homedir="):
      home = Path(os.fsdecode(value.partition(b"=")[2]))
  gpgconf = None
  if args.tool and home is not None and home.is_relative_to(Path(cache)):
    if Path(os.fsdecode(command[0])).name in ("gpg", "gpg2") or b"--pinentry-mode" in command:
      gpgconf = shutil.which("gpgconf")
      if gpgconf is None:
        raise RuntimeError("gpgconf is required to clean the replayed GPG home")
  try:
    result = subprocess.run(command, input=stdin, cwd=args.root, env=env)
  finally:
    if gpgconf is not None:
      subprocess.run([gpgconf, "--homedir", str(home), "--kill", "gpg-agent"],
                     stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=10)
  if b"--outfile" in command:
    outfile = Path(os.fsdecode(command[command.index(b"--outfile") + 1]))
    if outfile.is_file():
      import sys
      sys.stdout.buffer.write(outfile.read_bytes())
  raise SystemExit(result.returncode)
'''
