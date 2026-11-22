#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# The fork-only test workflow uses this entry point to plan and validate container tests.

import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys


def manager_module():
  spec = importlib.util.spec_from_file_location("container_manager", Path(__file__).with_name("test.py"))
  manager = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(manager)
  return manager


def inventory(manager):
  rows = []

  for mode in sorted(manager.CONTAINER_GEN_MODES | {14600}):
    boot = False
    prf = ""

    if mode in manager.VC_MODES:
      family = "veracrypt"
      digit = int(str(mode)[3])
      prf = manager.VC_HASH_DIGIT[digit]
      boot = digit in manager.VC_BOOT_DIGITS
      expected = 1 if boot else len(manager.VC_CASCADES[mode % 10])
    elif mode in manager.TC_MODES:
      family = "truecrypt"
      boot = (mode % 100) // 10 in manager.TC_BOOT_DIGITS
      expected = len(manager.TC_CASCADE_BY_COUNT[mode % 10])
    elif mode == 34100:
      family = "luks2"
      expected = len(list(manager.luks_variants()))
    elif mode == 14600:
      family = "legacy-luks"
      expected = 12 * len(list(manager.luks_variants()))
    else:
      family = "luks1"
      expected = len(list(manager.luks_variants(manager.LUKS1_HASH_CIPHER[mode][1])))

    for cost in ("reduced", "full"):
      rows.append({"mode": mode, "cost": cost, "family": family, "prf": prf,
                   "kind": "stored-boot" if boot else "prepared-legacy" if mode == 14600 else "generated",
                   "expected": expected})

  assert len(rows) == 186
  assert sum(row["kind"] == "generated" for row in rows) == 136
  return rows


def prepare_legacy(manager):
  directory = Path("ci-legacy-fixtures").resolve()
  directory.mkdir()
  manager.LUKS_TESTS_DIR = str(directory)

  for hash_name in ("sha1", "sha256", "sha512", "ripemd160"):
    for cipher in ("aes", "serpent", "twofish"):
      for layout, bits in manager.luks_variants(cipher):
        path = directory / ("hashcat_%s_%s_%s_%s.luks" % (hash_name, cipher, layout, bits))
        if not manager.luks1_generate(14600, hash_name, cipher, layout, bits, str(path)):
          raise RuntimeError("Could not prepare legacy LUKS fixture: %s" % path.name)


def check_metadata(manager, row):
  reduced = row["cost"] == "reduced"

  if row["kind"] == "stored-boot":
    return

  if row["family"] == "veracrypt":
    paths = sorted(Path(manager.VC_TESTS_DIR).glob("*.vc"))
    assert len(paths) == row["expected"]
    assert all(("_pim1.vc" in path.name) == reduced for path in paths)
    pim, password = manager.veracrypt_generation_parameters()
    assert pim == (1 if reduced else 0)
    assert not reduced or len(password.decode("utf-8")) >= 20
    return

  if row["family"] == "truecrypt":
    assert len(list(Path(manager.TC_TESTS_DIR).glob("*.tc"))) == row["expected"]
    return

  directory = manager.LUKS2_TESTS_DIR if row["family"] == "luks2" else manager.LUKS_TESTS_DIR
  paths = sorted(Path(directory).glob("*.img" if row["family"] == "luks2" else "*.luks"))
  assert len(paths) == row["expected"]
  metadata = {}

  for path in paths:
    if row["family"] == "luks2":
      raw = subprocess.check_output(["sudo", "-n", "cryptsetup", "luksDump", "--dump-json-metadata", str(path)])
      data = json.loads(raw)
      kdf = data["keyslots"]["0"]["kdf"]
      assert (kdf["type"], kdf["time"], kdf["memory"], kdf["cpus"]) == ("argon2id", 4, 32 if reduced else 16384, 1)
      metadata[path.name] = data
    else:
      with path.open("rb") as stream:
        header = stream.read(216)
      assert header[:8] == b"LUKS\xba\xbe\x00\x01"
      iterations = int.from_bytes(header[212:216], "big")
      assert iterations == 1000
      metadata[path.name] = {"iterations": iterations}

  Path("container-metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument("action", choices=("matrix", "run"))
  args = parser.parse_args()
  manager = manager_module()
  rows = inventory(manager)

  if args.action == "matrix":
    print(json.dumps({"include": rows}, separators=(",", ":")))
    return

  mode = int(os.environ["CONTAINER_MODE"])
  cost = os.environ["CONTAINER_COST"]
  row = next(item for item in rows if item["mode"] == mode and item["cost"] == cost)

  if row["family"] == "veracrypt" and row["prf"] == "ripemd160" and row["kind"] == "generated":
    os.environ["VERACRYPT_BIN"] = str(Path(".ci-veracrypt-legacy/usr/bin/veracrypt").resolve())

  if row["kind"] == "prepared-legacy":
    prepare_legacy(manager)

  flag = "--artificially-low-iteration-count" if cost == "reduced" else "--full-iteration-count"
  sys.argv = ["tools/test.py", "-m", str(mode), "-P", "-a", "0", "-t", "single", "-V", "1",
              "-D", "1", "-f", "--keep-tmp", "--logdir", "ci-container", flag]

  if row["kind"] == "generated":
    sys.argv.append("-g")

  rc = 0

  try:
    manager.main()
  except SystemExit as exc:
    rc = exc.code if isinstance(exc.code, int) else 2

  outcome = dict(row, returncode=rc, tests_passed=manager.TESTS_PASSED, errors=manager.ERRORS,
                 generation_skips=manager.GEN_SKIPS, argv=sys.argv)
  Path("container-outcome.json").write_text(json.dumps(outcome, indent=2) + "\n")
  print(json.dumps(outcome), flush=True)

  if rc != 0 or manager.ERRORS or manager.GEN_SKIPS or manager.TESTS_PASSED != row["expected"]:
    raise SystemExit(1)

  check_metadata(manager, row)


if __name__ == "__main__":
  main()
