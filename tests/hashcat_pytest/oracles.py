##
## Author......: See docs/credits.txt
## License.....: MIT
##

import os
import base64
import json
import sys

from . import attacks, catalog, runtime, tooling


def oracle_env(mode, optimized):
  env = dict(os.environ, **runtime.ENV)
  env["IS_OPTIMIZED"] = "1" if optimized else "0"
  env.pop("UNIQUE_SALT", None)
  env.pop("SHARED_SALT", None)
  hh = catalog.edge_hh(mode)
  if hh["same_salt_not"]:
    env["UNIQUE_SALT"] = "1"
  elif hh["salt_present"] and not hh["salt_virtual"]:
    env["SHARED_SALT"] = "1"
  return env


def oracle_spare(mode, optimized, length):
  pairs = read_pairs(mode, optimized, "spare", length)
  return pairs[0] if pairs else None


def a4_vectors(mode, pairs, optimized):
  if not pairs:
    return None
  if mode in catalog.LUKS_MODES or mode == 10300:
    return None
  if not any(word == b"" for word, _ in pairs):
    return None
  spare = oracle_spare(mode, optimized, 1)
  if spare is None or spare[0] == b"":
    return None
  return [spare if word == b"" else (word, digest) for word, digest in pairs]


def oracle_vectors(mode, optimized):
  return read_pairs(mode, optimized)


def multi_pairs(mode, i, optimized):
  minimum, fixed = attacks.multi_len_params(mode)
  return read_pairs(mode, optimized, "single", fixed or i)


def edge_oracle(mode, attack, optimized):
  records, code = read_records(mode, optimized, "edge", attack, int(optimized))
  vectors = [{"word_len": row["word_len"], "salt_len": row["salt_len"],
              "word": decode(row["password_b64"]), "salt": decode(row["salt_b64"]),
              "hash": decode(row["hash_b64"])} for row in records]
  return vectors, code


def bridge_family(mode):
  families = catalog.oracle_families(mode)
  return "p" if "pure" in families else "o" if "optimized" in families else None


def bridge_vectors(mode, family, hash_path, word_path):
  cmd = [sys.executable, os.path.join(runtime.TDIR, "test_bridge.py"), "vectors", str(mode), hash_path, word_path, "--json-summary"]
  if family == "p":
    cmd.append("-P")
  proc = tooling.run(cmd, timeout=400)
  if proc.returncode != 0 or not os.path.isfile(hash_path):
    raise RuntimeError("bridge oracle mode %d returned %d: %s" %
                       (mode, proc.returncode, proc.stderr.decode("utf-8", "replace")))
  summary = json.loads(proc.stdout)
  if summary["version"] != 1 or summary["mode"] != mode:
    raise ValueError("bridge metadata does not match requested case")
  with open(hash_path, "rb") as fh:
    count = sum(1 for line in fh if line.strip())
  if count != summary["written"]:
    raise ValueError("bridge vector count does not match generated hash file")
  return summary


def decode(value):
  return base64.b64decode(value, validate=True)


def read_records(mode, optimized, kind, *extra):
  env = oracle_env(mode, optimized)
  key = (mode, optimized, kind, extra, env.get("HCTEST_SEED"))
  if key not in runtime.ORACLE_CACHE:
    command = [sys.executable, runtime.RUNNER, kind, str(mode)]
    command += [str(value) for value in extra] + ["--json-lines"]
    selected = {key: env[key] for key in ("IS_OPTIMIZED", "UNIQUE_SALT", "SHARED_SALT") if key in env}
    proc = tooling.run(command, environment=selected, timeout=400, process_environment=env)
    if proc.returncode not in (0, 2):
      raise RuntimeError("oracle mode %d returned %d: %s" %
                         (mode, proc.returncode, proc.stderr.decode("utf-8", "replace")))
    records = [json.loads(line) for line in proc.stdout.splitlines()]
    for row in records:
      if row["version"] != 1 or row["mode"] != mode or row["optimized"] != optimized:
        raise ValueError("oracle metadata does not match requested case")
    runtime.ORACLE_CACHE[key] = (records, proc.returncode)
  records, code = runtime.ORACLE_CACHE[key]
  if runtime.ACTIVE is not None:
    runtime.ACTIVE.vectors.extend(dict(row, oracle_kind=kind, oracle_extra=list(extra),
                                      oracle_index=index, oracle_count=len(records))
                                 for index, row in enumerate(records))
  return records, code


def read_pairs(mode, optimized, kind="single", length=None):
  records, code = read_records(mode, optimized, kind, *(() if length is None else (length,)))
  if code == 2:
    return None
  return [(decode(row["password_b64"]), decode(row["hash_b64"]).decode("ascii")) for row in records]


def decode_hashfile(mode, digest):
  if mode in (22000, 22001):
    return (digest + "\n").encode("ascii")
  return base64.b64decode(digest)
