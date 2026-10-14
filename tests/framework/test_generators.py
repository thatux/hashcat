##
## Author......: See docs/credits.txt
## License.....: MIT
##

from contextlib import contextmanager, nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from hashcat_pytest import generated, reporting, runtime

pytestmark = pytest.mark.framework


@pytest.fixture
def installed_tools(monkeypatch):
  ledger = SimpleNamespace(problems=[], omissions=[], notes=[])
  monkeypatch.setattr(runtime, "ACTIVE", ledger)
  monkeypatch.setattr(runtime, "GEN_SKIPS", [])
  monkeypatch.setattr(generated, "_have", lambda path: True)
  monkeypatch.setattr(generated.privileged, "resource", lambda *args: nullcontext())
  monkeypatch.setattr(generated.shutil, "which", lambda path: path)
  monkeypatch.setattr(generated, "gen_run", lambda command, **kwargs: (0, b"") if "--kill" in command else (1, b"producer failed"))
  return ledger


@pytest.mark.parametrize("family", ["veracrypt", "truecrypt", "luks1", "luks2", "pkzip", "gpg", "rar", "sevenzip", "pdf", "ssh"])
def test_installed_producer_failures_are_errors(tmp_path, installed_tools, family):
  output = str(tmp_path / "volume")
  args = SimpleNamespace(attack="0")
  if family == "veracrypt":
    generated.veracrypt_generate(13711, "sha512", "aes", output)
  elif family == "truecrypt":
    generated.truecrypt_generate(6211, "ripemd160", "aes", output, str(tmp_path))
  elif family == "luks1":
    generated.luks1_generate(29511, "sha1", "aes", "xts", "256", output)
  elif family == "luks2":
    generated.luks2_generate(34100, "xts", "256", output)
  else:
    mode = {"pkzip": 17200, "gpg": 17010, "rar": 12500, "sevenzip": 13600, "pdf": 10400, "ssh": 22931}[family]
    getattr(generated, "gen_" + family)(args, mode, str(tmp_path))
  assert installed_tools.problems
  assert all(kind != "Skip" for mode, kind, reason in runtime.GEN_SKIPS if "failed" in reason or "could not" in reason)


@pytest.mark.parametrize("status,version,unsupported", [(1, b"VeraCrypt 1.26.7\n", True),
                                                       (1, b"VeraCrypt 1.25.9\n", False),
                                                       (-11, b"VeraCrypt 1.26.7\n", False),
                                                       (1, b"unparseable version\n", False)])
def test_ripemd160_skip_requires_supported_version_evidence(tmp_path, installed_tools, monkeypatch, status, version, unsupported):
  monkeypatch.setattr(generated, "gen_run", lambda command, **kwargs: (0, version) if "--version" in command else (status, b"failed"))
  assert generated.veracrypt_generate(13711, "ripemd160", "aes", str(tmp_path / "volume")) == False
  assert bool(installed_tools.omissions) == unsupported
  assert bool(installed_tools.problems) == (unsupported == False)


def test_missing_tool_is_a_skip(tmp_path, installed_tools, monkeypatch):
  monkeypatch.setattr(generated, "_have", lambda path: False)
  assert generated.veracrypt_generate(13711, "sha512", "aes", str(tmp_path / "volume")) == False
  assert installed_tools.omissions
  assert installed_tools.problems == []


def test_partial_generator_notes_are_retained(installed_tools):
  reporting.gen_note(17010, "classic S2K producer unavailable")
  assert installed_tools.notes == ["classic S2K producer unavailable"]
  assert runtime.GEN_SKIPS == [(17010, "Note", "classic S2K producer unavailable")]


@pytest.mark.parametrize("status,unsupported", [(2, True), (-11, False), (139, False)])
def test_lzma_dependency_probe_crashes_are_errors(tmp_path, installed_tools, monkeypatch, status, unsupported):
  monkeypatch.setattr(generated, "gen_run", lambda command, **kwargs: (status, b"Can't locate Compress/Raw/Lzma.pm in @INC"))
  generated.gen_sevenzip(SimpleNamespace(attack="0"), 11600, str(tmp_path))
  assert bool(installed_tools.omissions) == unsupported
  assert bool(installed_tools.problems) == (unsupported == False)


@pytest.mark.parametrize("selection,fast,expected", [("0,1,3,6,7", False, [0, 1, 3, 6, 7]),
                                                    ("7,0,7,9", True, [7, 0]),
                                                    ("all", True, [0, 1, 3]),
                                                    ("all", False, [0])])
def test_archive_attack_lists(selection, fast, expected):
  assert generated.archive_attacks(SimpleNamespace(attack=selection), fast) == expected


def test_qpdf_failure_with_existing_output_is_not_success(tmp_path, installed_tools, monkeypatch):
  def produce(command, **kwargs):
    if command[0] == "gs":
      Path(command[command.index("-o") + 1]).write_bytes(b"plain PDF")
      return 0, b""
    Path(command[-1]).write_bytes(b"incomplete encrypted PDF")
    return 2, b"qpdf failed"
  monkeypatch.setattr(generated, "gen_run", produce)
  generated.gen_pdf(SimpleNamespace(attack="0"), 10400, str(tmp_path))
  assert installed_tools.problems == ["qpdf could not write a rc4-40 document"]


def test_ocb_only_generation_does_not_require_gpg1(tmp_path, installed_tools, monkeypatch):
  monkeypatch.setattr(generated.shutil, "which", lambda path: None if path == "gpg1" else path)
  def produce(command, **kwargs):
    if "--quick-generate-key" in command:
      home = Path(command[command.index("--homedir") + 1], "private-keys-v1.d")
      home.mkdir()
      (home / "key.key").write_bytes(b"openpgp-s2k3-ocb-aes")
    return 0, b"$gpg$synthetic-hash\n"
  monkeypatch.setattr(generated, "gen_run", produce)
  labels = []
  monkeypatch.setattr(generated, "archive_crack", lambda args, mode, hash_file, label, tmp, fast: labels.append(label))
  generated.gen_gpg(SimpleNamespace(attack="0"), 17050, str(tmp_path))
  assert len(labels) == 2
  assert installed_tools.notes == installed_tools.omissions == installed_tools.problems == []


@pytest.mark.parametrize("protection,unsupported", [(b"openpgp-s2k3-sha1-aes-cbc", True), (b"not a private key", False)])
def test_ocb_generation_distinguishes_unsupported_and_invalid_keys(tmp_path, installed_tools, monkeypatch, protection, unsupported):
  def produce(command, **kwargs):
    if "--quick-generate-key" in command:
      home = Path(command[command.index("--homedir") + 1], "private-keys-v1.d")
      home.mkdir()
      (home / "key.key").write_bytes(protection)
    return 0, b""
  monkeypatch.setattr(generated, "gen_run", produce)
  generated.gen_gpg(SimpleNamespace(attack="0"), 17050, str(tmp_path))
  assert bool(installed_tools.problems) == (unsupported == False)
  assert bool(installed_tools.omissions) == unsupported


@pytest.mark.parametrize("family", ["truecrypt", "luks1", "luks2"])
@pytest.mark.parametrize("fails", [False, True])
def test_privileged_generation_registers_before_allocation(tmp_path, installed_tools, monkeypatch, family, fails):
  events = []
  registered = False
  @contextmanager
  def resource(kind, backing_file, mapper_name=None):
    nonlocal registered
    assert Path(backing_file).is_file()
    assert registered == False
    registered = True
    events.append("registered")
    try:
      yield
    finally:
      assert Path(backing_file).is_file()
      events.append("cleaned")
      registered = False
  def produce(command, **kwargs):
    if command[0] == "losetup" or "open" in command or command[0] in ("expect", "mkfs.ext4"):
      assert registered
      events.append("allocation" if command[0] == "losetup" or "open" in command else "format")
      if fails:
        return 1, b"allocation failed"
    return 0, b"/dev/loop5\n" if command[0] == "losetup" else b""
  monkeypatch.setattr(generated.privileged, "resource", resource)
  monkeypatch.setattr(generated, "gen_run", produce)
  output = str(tmp_path / "volume")
  if family == "truecrypt":
    created = generated.truecrypt_generate(6211, "ripemd160", "aes", output, str(tmp_path))
  elif family == "luks1":
    created = generated.luks1_generate(29511, "sha1", "aes", "xts", "256", output)
  else:
    created = generated.luks2_generate(34100, "xts", "256", output)
  assert created == (fails == False)
  assert events[0] == "registered"
  assert events[-1] == "cleaned"
  assert events[1:-1] == (["allocation"] if fails else ["allocation", "format"])


@pytest.mark.parametrize("family,missing", [("truecrypt", "sudo"), ("truecrypt", "losetup"),
                                          ("luks1", "mkfs.ext4"), ("luks2", "losetup")])
def test_missing_privileged_dependency_is_skipped_before_allocation(tmp_path, installed_tools, monkeypatch, family, missing):
  monkeypatch.setattr(generated.shutil, "which", lambda path: None if path == missing else path)
  def forbidden(*args, **kwargs):
    pytest.fail("allocated a resource before checking its dependencies")
  monkeypatch.setattr(generated.privileged, "resource", forbidden)
  monkeypatch.setattr(generated, "gen_run", forbidden)
  output = str(tmp_path / "volume")
  if family == "truecrypt":
    created = generated.truecrypt_generate(6211, "ripemd160", "aes", output, str(tmp_path))
  elif family == "luks1":
    created = generated.luks1_generate(29511, "sha1", "aes", "xts", "256", output)
  else:
    created = generated.luks2_generate(34100, "xts", "256", output)
  assert created == False
  assert installed_tools.problems == []
  assert installed_tools.omissions == ["container generation needs missing tools: " + missing]
  assert Path(output).exists() == False
