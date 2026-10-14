##
## Author......: See docs/credits.txt
## License.....: MIT
##

import json
from pathlib import Path
import subprocess

from . import attacks, catalog, runtime

_INVENTORIES = {}


def validate_inventory():
  key = (runtime.METADATA_BIN, tuple(runtime.ISOLATION))
  if key not in _INVENTORIES:
    command = [runtime.METADATA_BIN, "--quiet", "--hash-info", "--machine-readable"] + runtime.ISOLATION
    proc = subprocess.run(command, cwd=runtime.ROOT, capture_output=True, timeout=60)
    if proc.returncode != 0:
      raise RuntimeError("compiled hash inventory failed: " + proc.stderr.decode("utf-8", "replace"))
    _INVENTORIES[key] = set(map(int, json.loads(proc.stdout)))
  compiled = _INVENTORIES[key]
  sources = set(catalog.source_modes())
  if compiled != sources:
    raise RuntimeError("compiled hash inventory differs from source, run make: missing %s, extra %s" %
                       (sorted(sources - compiled), sorted(compiled - sources)))


def selftest_vector_read(mode):
  validate_inventory()
  command = [runtime.METADATA_BIN, "--quiet", "-m", str(mode), "--hash-info", "--machine-readable"]
  proc = subprocess.run(command + catalog.module_opts(mode) + runtime.ISOLATION,
                        cwd=runtime.ROOT, capture_output=True, timeout=60)
  if proc.returncode != 0:
    raise RuntimeError("self-test metadata failed: " + proc.stderr.decode("utf-8", "replace"))
  row = json.loads(proc.stdout)[str(mode)]
  if row["example_hash"] in ("", "N/A"):
    return None
  return (row["example_hash"].encode("utf-8"), row["example_pass"].encode("utf-8"),
          row["example_hash_format"], row["is_deprecated"])


def selftest_write_hash(mode, digest, format_name, path):
  if format_name == "N/A":
    return False
  with open(path, "wb") as handle:
    handle.write(bytes.fromhex(digest.decode("ascii")) if "binary file only" in format_name else digest + b"\n")
  return True


def prepare(mode, attack, directory):
  vector = selftest_vector_read(mode)
  assert vector is not None, "module published no usable self-test vector"
  digest, password, format_name, deprecated = vector
  path = str(Path(directory, "selftest.hash"))
  assert selftest_write_hash(mode, digest, format_name, path)
  extra = attacks.build_container_extra(mode, attack, password, directory)
  assert extra is not None
  if deprecated:
    extra += ["--deprecated-check-disable"]
  extra += ["--self-test-disable"]
  expected = b"hashcat" if mode == 20510 else password
  return path, digest, expected, "binary file" in format_name, extra
