##
## Author......: See docs/credits.txt
## License.....: MIT
##

from pathlib import Path

import crypt_r
import pytest

from hashcat_pytest import edge, execution, verification

pytestmark = pytest.mark.framework


@pytest.mark.parametrize("raw,hashes", [
  (b"", [b"hash"]),
  (b"hash\n", [b"hash"]),
  (b"other:word\n", [b"hash"]),
  (b"hash:word\nhash:word\n", [b"hash"]),
  (b"hash:word\n", [b"hash", b"other"]),
  (b"hash:word\nhash:word\n", [b"hash", b"other"]),
  (b"hash:word\nextra:word\n", [b"hash"]),
  (b"hash:word\n", [b"hash", b"hash"]),
])
def test_edge_verification_rejects_incomplete_or_duplicate_inventory(raw, hashes, tmp_path, monkeypatch):
  def unexpected_verify(*args):
    pytest.fail("invalid recovery inventory reached oracle verification")

  monkeypatch.setattr(verification, "run_verify", unexpected_verify)
  assert verification.edge_out_verifies(1500, raw, hashes, str(tmp_path)) is False


def test_edge_verification_requires_every_hash_and_is_mode_scoped(tmp_path, monkeypatch):
  checked = []

  def verify(mode, digest, lines, directory):
    checked.append((mode, digest, lines))
    return digest != "second"

  monkeypatch.setattr(verification, "run_verify", verify)
  raw = b"second:word\nfirst:word    (user password note)\n"
  assert verification.edge_out_verifies(1500, raw, [b"first", b"second"], str(tmp_path)) is False
  assert checked == [(1500, "first", [b"first:word"]), (1500, "second", [b"second:word"])]
  checked.clear()
  assert verification.edge_out_verifies(0, b"first:word\n", [b"first"], str(tmp_path)) is False
  assert checked == []


def des_vector(word, salt):
  return {"word": word, "word_len": len(word), "hash": crypt_r.crypt(word.decode("utf-8"), salt).encode("ascii"),
          "salt": salt.encode("ascii"), "salt_len": len(salt)}


def test_edge_verification_accepts_real_des_equivalence_and_rejects_wrong_plaintext(tmp_path):
  vector = des_vector(b"\xc3\xa9", "ab")
  assert crypt_r.crypt("C)", "ab").encode("ascii") == vector["hash"]
  assert verification.edge_out_verifies(1500, vector["hash"] + b":C)\n", [vector["hash"]], str(tmp_path))
  assert verification.edge_out_verifies(1500, vector["hash"] + b":$HEX[4329]\n", [vector["hash"]], str(tmp_path))
  assert verification.edge_out_verifies(1500, vector["hash"] + b":wrong\n", [vector["hash"]], str(tmp_path)) is False
  assert verification.edge_out_verifies(1500, vector["hash"] + b":$HEX[invalid]\n", [vector["hash"]], str(tmp_path)) is False


@pytest.mark.parametrize("target", ["single", "multi"])
def test_edge_paths_use_des_verification_after_literal_mismatch(target, tmp_path, monkeypatch):
  vectors = [des_vector(b"\xc3\xa9", "ab")]
  if target == "multi":
    vectors.append(des_vector(b"hashcat", "cd"))
  context = edge.EdgeCtx(1500, 0, "pure", False, {"cnt_max": -1, "same_salt_not": False},
                         False, False, False, False, False, False, False)
  outfile = tmp_path / "recovered"
  recovered = [vector["hash"] + b":" + (b"C)" if index == 0 else vector["word"])
               for index, vector in enumerate(vectors)]
  raw = b"\n".join(reversed(recovered)) + b"\n"

  def run(*args):
    outfile.write_bytes(raw)
    return 0, b""

  monkeypatch.setattr(execution, "edge_run", run)
  if target == "single":
    assert edge.edge_single(context, 1, [], str(outfile), vectors, str(tmp_path)) == (0, 1)
  else:
    assert edge.edge_multi(context, 1, [], str(outfile), vectors, str(tmp_path)) == (0, 1, False)
  assert Path(outfile).read_bytes() == raw


def test_literal_edge_match_does_not_invoke_fallback(tmp_path, monkeypatch):
  vector = des_vector(b"hashcat", "ab")
  context = edge.EdgeCtx(1500, 0, "pure", False, {}, False, False, False, False, False, False, False)
  outfile = tmp_path / "recovered"

  def run(*args):
    outfile.write_bytes(vector["hash"] + b":" + vector["word"] + b"\n")
    return 0, b""

  monkeypatch.setattr(execution, "edge_run", run)
  monkeypatch.setattr(verification, "edge_out_verifies", lambda *args: pytest.fail("literal match invoked fallback"))
  assert edge.edge_single(context, 1, [], str(outfile), [vector], str(tmp_path)) == (0, 1)
