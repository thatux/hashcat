##
## Author......: See docs/credits.txt
## License.....: MIT
##

import argparse
import base64
from collections import Counter
import hashlib
import json
import os
from pathlib import Path


def decode(value):
  return base64.b64decode(value, validate=True)


def input_identity(value):
  if isinstance(value, dict):
    contents = {name: hashlib.sha256(decode(data)).hexdigest() for name, data in value.items()}
    value = json.dumps(contents, sort_keys=True).encode()
  else:
    value = decode(value)
  return "<input:" + hashlib.sha256(value).hexdigest() + ">"


def des_parity_plaintext(line):
  digest, separator, word = line.partition(b":")
  fields = digest.split(b"$")
  if not separator or len(fields) != 9 or fields[:2] != [b"", b"mfulc"]:
    return line
  if fields[2] not in (b"0", b"1") or fields[3] not in (b"1", b"2", b"3", b"4") or fields[4] not in (b"0", b"1", b"2"):
    return line
  for value, length in zip(fields[5:], (16, 16, 16, 32)):
    if len(value) != length or any(byte not in b"0123456789abcdefABCDEF" for byte in value):
      return line
  if word.startswith(b"$HEX[") and word.endswith(b"]"):
    word = word[5:-1]
    if len(word) != 8 or any(byte not in b"0123456789abcdefABCDEF" for byte in word):
      return line
    word = bytes.fromhex(word.decode("ascii"))
  elif len(word) == 8 and all(byte in b"0123456789abcdefABCDEF" for byte in word):
    word = bytes.fromhex(word.decode("ascii"))
  if len(word) != 4:
    return line
  # DES ignores the low parity bit of each key byte.
  canonical = bytes(byte & 0xfe for byte in word).hex().encode("ascii")
  return digest + b":$DESPARITY[" + canonical + b"]"


def normalize_output(raw, ordered=False, des_parity=False):
  output = []
  status = False
  for line in raw.split(b"\n"):
    if line.partition(b":")[0].rstrip(b".") == b"Session":
      status = True
    if status:
      if line == b"":
        status = False
      continue
    if line.startswith(b"STATUS\t") == False:
      output.append(des_parity_plaintext(line) if des_parity else line)
  return b"\n".join(output if ordered else sorted(output))


def normalize(invocation):
  argv = [os.fsdecode(decode(value)) for value in invocation["argv_b64"]]
  replacements = {path: input_identity(data) for path, data in invocation["inputs"].items()}
  argv[0] = "hashcat"
  for flag in ("--cache-path", "--session", "--outfile"):
    if flag in argv:
      index = argv.index(flag) + 1
      replacements[argv[index]] = "<" + flag.removeprefix("--") + ">"
  normalized = [replacements.get(value, value) for value in argv]
  result = {"argv": normalized, "stdin_b64": invocation["stdin_b64"], "returncode": invocation["returncode"]}
  for stream in ("stdout_b64", "stderr_b64", "outfile_b64"):
    if stream not in invocation:
      continue
    value = invocation[stream]
    if value is not None:
      raw = decode(value)
      if stream != "stderr_b64":
        mode = argv[argv.index("-m") + 1] if "-m" in argv else None
        raw = normalize_output(raw, ordered="--stdout" in argv, des_parity=mode == "37000")
      for path, replacement in sorted(replacements.items(), key=lambda item: len(item[0]), reverse=True):
        if path:
          raw = raw.replace(os.fsencode(path), replacement.encode("ascii"))
      value = base64.b64encode(raw).decode("ascii")
    result[stream] = value
  if "environment" in invocation:
    result["environment"] = {key: value for key, value in invocation["environment"].items()
                             if key in ("HCTEST_SEED", "HASHCAT_DEVICE_MEM_LIMIT", "HASHCAT_HOST_MEM_LIMIT")}
  return result


def native_manifest(directory):
  result = []
  groups = {}
  for case_path in sorted(Path(directory).rglob("case.json")):
    folder = case_path.parent
    if folder.name.startswith("attempt-") == False or folder.name.removeprefix("attempt-").isdigit() == False:
      raise ValueError("case artifact has no explicit attempt number: " + str(folder))
    groups.setdefault(folder.parent, []).append(case_path)
  for paths in groups.values():
    paths.sort(key=lambda path: int(path.parent.name.removeprefix("attempt-")))
    if len(paths) > 2:
      raise ValueError("case artifact has more than one memory retry: " + str(paths[0].parent.parent))
    identity = json.loads(paths[0].read_text())["case"]
    for index, path in enumerate(paths):
      if path.parent.name != "attempt-%d" % index:
        raise ValueError("case artifact attempts are not consecutive: " + str(path))
      metadata = json.loads(path.read_text())
      if metadata["case"] != identity:
        raise ValueError("case identity changed between attempts: " + str(path))
      if index < len(paths) - 1:
        outcome = json.loads((path.parent / "result.json").read_text())
        environment = metadata["environment"]
        if outcome["outcome"] != "skipped" or "worker memory cap, retrying without caps" not in outcome["omissions"]:
          raise ValueError("duplicate case artifact is not an explicit memory retry: " + str(path))
        if not any(key in environment for key in ("HASHCAT_DEVICE_MEM_LIMIT", "HASHCAT_HOST_MEM_LIMIT")):
          raise ValueError("memory retry artifact has no worker memory cap: " + str(path))
      elif index > 0 and any(key in metadata["environment"] for key in ("HASHCAT_DEVICE_MEM_LIMIT", "HASHCAT_HOST_MEM_LIMIT")):
        raise ValueError("final memory retry artifact still has worker caps: " + str(path))
    case_path = paths[-1]
    folder = case_path.parent
    case = json.loads(case_path.read_text())["case"]
    invocations = []
    for path in sorted(folder.glob("invocation-*/result.json")):
      invocation = json.loads(path.read_text())
      inputs = {}
      for name, relative in invocation["inputs"].items():
        saved = folder / relative
        encode = lambda value: base64.b64encode(value).decode("ascii")
        inputs[name] = ({str(child.relative_to(saved)): encode(child.read_bytes())
                         for child in sorted(saved.rglob("*")) if child.is_file()}
                        if saved.is_dir() else encode(saved.read_bytes()))
      invocation["inputs"] = inputs
      invocations.append(invocation)
    outcome = json.loads((folder / "result.json").read_text())["outcome"]
    result.append({"case": case, "invocations": invocations, "outcome": outcome,
                   "vectors": json.loads((folder / "vectors.json").read_text())})
  return result


def compare(baseline, candidate):
  key = lambda row: json.dumps(row["case"], sort_keys=True)
  problems = []
  for label, rows in (("baseline", baseline), ("native", candidate)):
    duplicates = [case for case, count in Counter(key(row) for row in rows).items() if count > 1]
    problems.extend("duplicate %s case: %s" % (label, case) for case in sorted(duplicates))
  if problems:
    return problems
  before = {key(row): row for row in baseline}
  after = {key(row): row for row in candidate}
  for case in sorted(before.keys() | after.keys()):
    if case not in before or case not in after:
      problems.append("case selection differs: " + case)
      continue
    old_invocations = before[case]["invocations"]
    new_invocations = after[case]["invocations"]
    old = [normalize(invocation) for invocation in old_invocations]
    new = [normalize(invocation) for invocation in new_invocations]
    for left, right in zip(old, new):
      for field in ("stdout_b64", "stderr_b64", "outfile_b64", "environment"):
        if field not in left:
          right.pop(field, None)
    if old != new:
      problems.append("invocations differ: " + case)
    counts = before[case].get("counts")
    if counts is not None and "outcome" in after[case]:
      failed = any(counts.get(field, 0) for field in ("errors", "nf", "nm", "err", "to"))
      skipped = counts.get("rs", 0) > 0
      expected = "failed" if failed else "skipped" if skipped else "passed"
      if after[case]["outcome"] != expected:
        problems.append("verification outcome differs: " + case)
  return problems


def vector_inventory(rows):
  fields = ("mode", "optimized", "password_b64", "hash_b64", "salt_b64", "word_len", "salt_len")
  inventory = {}
  counts = {}
  for row in rows:
    required = ("mode", "optimized", "oracle_kind", "oracle_extra", "oracle_index", "oracle_count")
    if any(field not in row for field in required):
      raise ValueError("oracle operation metadata missing, vector multiplicity cannot be verified")
    key = json.dumps({field: row[field] for field in required[:4]}, sort_keys=True)
    index, count = row["oracle_index"], row["oracle_count"]
    if type(index) is not int or type(count) is not int or not 0 <= index < count:
      raise ValueError("invalid oracle row index or count: " + key)
    if key in counts and counts[key] != count:
      raise ValueError("inconsistent oracle operation row count: " + key)
    counts[key] = count
    value = {field: row[field] for field in fields if field in row}
    records = inventory.setdefault(key, {})
    if index in records and records[index] != value:
      raise ValueError("inconsistent cached oracle row: " + key)
    records[index] = value
  for key, records in inventory.items():
    if len(records) != counts[key]:
      raise ValueError("missing oracle operation rows: " + key)
  return {key: [records[index] for index in range(counts[key])] for key, records in inventory.items()}


def main():
  parser = argparse.ArgumentParser(description="Compare captured legacy and native hashcat invocations")
  parser.add_argument("baseline", type=Path)
  parser.add_argument("native", type=Path)
  args = parser.parse_args()
  baseline = json.loads(args.baseline.read_text())
  try:
    candidate = native_manifest(args.native)
  except (KeyError, ValueError) as error:
    print(str(error))
    return 1
  problems = compare(baseline["cases"], candidate)
  if "vectors" in baseline:
    try:
      old_vectors = vector_inventory(baseline["vectors"])
      new_vectors = vector_inventory([vector for row in candidate for vector in row["vectors"]])
      if old_vectors != new_vectors:
        problems.append("ordered oracle operation vectors differ")
    except (KeyError, ValueError) as error:
      problems.append(str(error))
  for problem in problems:
    print(problem)
  print("%d baseline cases, %d native cases, %d differences" % (len(baseline["cases"]), len(candidate), len(problems)))
  return int(bool(problems))


if __name__ == "__main__":
  raise SystemExit(main())
