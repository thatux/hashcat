##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import json

import pytest

from hashcat_pytest import parity


pytestmark = pytest.mark.framework


def vector(index, count=2, password=b"same password"):
  return {"mode": 0, "optimized": True, "oracle_kind": "single", "oracle_extra": [],
          "oracle_index": index, "oracle_count": count,
          "password_b64": base64.b64encode(password).decode("ascii"),
          "hash_b64": base64.b64encode(b"hash").decode("ascii")}


def test_ordered_oracle_rows_preserve_duplicates_and_cached_calls():
  rows = [vector(0), vector(1)]
  inventory = parity.vector_inventory(rows)
  assert len(next(iter(inventory.values()))) == 2
  assert parity.vector_inventory(rows + rows) == inventory
  assert parity.vector_inventory([vector(0, count=1)]) != inventory
  changed = [vector(0, password=b"other password"), vector(1)]
  assert parity.vector_inventory(changed) != inventory
  assert parity.vector_inventory([vector(0, password=b"left"), vector(1, password=b"right")]) != parity.vector_inventory([vector(0, password=b"right"), vector(1, password=b"left")])


@pytest.mark.parametrize("rows", [[vector(0)], [vector(0), vector(1, count=3)],
                                  [vector(0), vector(0, password=b"different")],
                                  [{"mode": 0, "optimized": True, "password_b64": "", "hash_b64": ""}]])
def test_incomplete_or_inconsistent_oracle_operations_fail(rows):
  with pytest.raises(ValueError):
    parity.vector_inventory(rows)


def test_duplicate_cases_fail_instead_of_overwriting_a_result():
  row = {"case": {"mode": 0}, "invocations": []}
  assert parity.compare([row, row], [row]) == ['duplicate baseline case: {"mode": 0}']
  assert parity.compare([row], [row, row]) == ['duplicate native case: {"mode": 0}']


def write_attempt(folder, index, environment, omissions=()):
  directory = folder / ("attempt-%d" % index)
  directory.mkdir(parents=True)
  (directory / "case.json").write_text(json.dumps({"case": {"mode": 0}, "environment": environment}))
  (directory / "result.json").write_text(json.dumps({"outcome": "skipped" if omissions else "passed", "omissions": omissions}))
  (directory / "vectors.json").write_text("[]")


def test_only_explicit_uncapped_retry_selects_final_attempt(tmp_path):
  folder = tmp_path / "case"
  write_attempt(folder, 0, {"HASHCAT_HOST_MEM_LIMIT": "1"}, ["worker memory cap, retrying without caps"])
  write_attempt(folder, 1, {})
  assert len(parity.native_manifest(tmp_path)) == 1
  (folder / "attempt-0" / "result.json").write_text(json.dumps({"outcome": "failed", "omissions": []}))
  with pytest.raises(ValueError, match="not an explicit memory retry"):
    parity.native_manifest(tmp_path)


def test_recovered_output_comparison_preserves_bytes_and_stdout_order():
  assert parity.normalize_output(b"hash:pass\xff\n") != parity.normalize_output(b"hash:pass\xfe\n")
  assert parity.normalize_output(b"second\nfirst\n", ordered=True) != parity.normalize_output(b"first\nsecond\n", ordered=True)


def test_recovered_lines_between_status_reports_remain_comparable():
  recovered = b"$gpg$*1*320*hash:pass\xea\xb0\x80\xff\n"
  running = b"Session..........: pytest\nStatus...........: Running\nSpeed.#01........: 1 H/s\nHardware.Mon.#01.: N/A\n"
  cracked = b"Session..........: pytest\nStatus...........: Cracked\nSpeed.#01........: 2 H/s\nHardware.Mon.#01.: N/A\n"
  assert parity.normalize_output(running + recovered + cracked) == parity.normalize_output(recovered + cracked)
  assert parity.normalize_output(running + recovered + cracked) == parity.normalize_output(recovered)
  assert parity.normalize_output(running + recovered + cracked) != parity.normalize_output(cracked)
  assert parity.normalize_output(running + recovered + cracked) != parity.normalize_output(recovered.replace(b"\xff", b"\xfe") + cracked)


def test_status_looking_stdout_candidates_and_interleaved_diagnostics_are_preserved():
  candidates = b"Session..........: word\nSTATUS\tword\n\n"
  assert parity.normalize_output(candidates, ordered=True) == candidates
  status = b"Session..........: pytest\nStatus...........: Running\n"
  diagnostic = b"WARNING: unexpected backend condition\n"
  assert parity.normalize_output(status + diagnostic) == parity.normalize_output(diagnostic)


@pytest.mark.parametrize("device", [b"01", b"100", b"255"])
def test_status_device_fields_preserve_minimum_width_numeric_ids(device):
  status = b"Session..........: pytest\n"
  for prefix, padding in ((b"Speed.#", 8), (b"Candidates.#", 3), (b"Hardware.Mon.#", 1), (b"Brain.Link.#", 3)):
    status += prefix + device + b"." * padding + b": value\n"
  status += b"Speed.#*.........: total\n"
  assert parity.normalize_output(status + b"hash:pass\n") == parity.normalize_output(b"hash:pass\n")


def test_mfulc_only_ignores_des_key_parity_bits():
  digest = b"$mfulc$1$3$0$0123456789abcdef$0123456789abcdef$0123456789abcdef$0123456789abcdef0123456789abcdef"
  line = digest + b":\xea\xb0\x804"
  equivalent = digest + b":\xea\xb0\x805"
  changed = digest + b":\xea\xb0\x806"
  assert parity.des_parity_plaintext(line) == parity.des_parity_plaintext(equivalent)
  assert parity.des_parity_plaintext(line) != parity.des_parity_plaintext(changed)
  assert parity.des_parity_plaintext(line) == parity.des_parity_plaintext(digest + b":$HEX[eab08035]")
  assert parity.des_parity_plaintext(line) == parity.des_parity_plaintext(digest + b":eab08035")
  assert parity.des_parity_plaintext(digest + b":$HEX[invalid]") == digest + b":$HEX[invalid]"
  assert parity.des_parity_plaintext(digest + b":$HEX[abcd]") == digest + b":$HEX[abcd]"
  assert parity.des_parity_plaintext(digest + b":longpassword") == digest + b":longpassword"
  malformed = digest.replace(b"$1$3$0$", b"$2$3$0$") + b":abcd"
  assert parity.des_parity_plaintext(malformed) == malformed
  changed_hash = digest.replace(b"0123456789abcdef$", b"1123456789abcdef$", 1) + b":\xea\xb0\x805"
  assert parity.des_parity_plaintext(line) != parity.des_parity_plaintext(changed_hash)
