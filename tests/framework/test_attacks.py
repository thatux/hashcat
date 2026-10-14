##
## Author......: See docs/credits.txt
## License.....: MIT
##

import importlib.util
import inspect
from pathlib import Path
from types import SimpleNamespace

import pytest

from hashcat_pytest import attacks, catalog, execution, oracles, runtime, verification

pytestmark = pytest.mark.framework


@pytest.fixture
def driver():
  path = Path(runtime.ROOT, "tests", "test_cracking.py")
  spec = importlib.util.spec_from_file_location("cracking_driver", path)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module.execute_invocations


def make_run(tmp_path, pairs, file_only=False):
  args = SimpleNamespace(pure=False)
  return attacks.Run(args, 0, pairs, 1, ["--quiet"], ["single", "multi"], file_only, file_only, str(tmp_path))


@pytest.mark.parametrize("attack,count", [(0, 11), (1, 8), (3, 9), (4, 11), (6, 14), (7, 14), (8, 11), (9, 10), (12, 29)])
def test_all_attack_families_only_build_lazy_invocations(tmp_path, monkeypatch, attack, count):
  pairs = [(b"0" * (index + 1), "digest-%d" % index) for index in range(10)]
  monkeypatch.setattr(catalog, "a4_optimized_skip", lambda *args: False)
  monkeypatch.setattr(oracles, "a4_vectors", lambda *args: None)
  monkeypatch.setattr(oracles, "multi_pairs", lambda *args: [(b"00000000", "one"), (b"11111111", "two")])
  def forbidden(*args, **kwargs):
    pytest.fail("an attack builder executed or verified hashcat")
  monkeypatch.setattr(execution, "run_hashcat", forbidden)
  monkeypatch.setattr(verification, "output_has_crack", forbidden)
  plan = attacks.ATTACKS[attack](make_run(tmp_path, pairs))
  assert inspect.isgenerator(plan)
  steps = list(plan)
  invocations = [step for step in steps if isinstance(step, attacks.Invocation)]
  assert len(invocations) == count
  assert all(step.attack == attack and step.expected for step in invocations)
  assert all(isinstance(step, (attacks.Invocation, attacks.Summary)) for step in steps)


def test_driver_executes_before_reusing_binary_target(tmp_path, monkeypatch, driver):
  pairs = [(b"first", "one"), (b"second", "two")]
  monkeypatch.setattr(oracles, "decode_hashfile", lambda mode, digest: digest.encode("ascii"))
  run = make_run(tmp_path, pairs, file_only=True)
  run.targets = ["single"]
  captured = []
  checked = []
  ledger = SimpleNamespace(summaries=[], omissions=[], check=checked.append)
  def execute(options, mode, target, stdin, attack, extra):
    assert len(captured) == len(verified)
    captured.append((Path(target).read_bytes(), stdin))
    return 0, b"output"
  verified = []
  def verify(mode, output, word, digest, pass_only, directory):
    assert captured[-1] == (digest.encode("ascii"), word + b"\n")
    assert Path(run.tmp, "m00000_filebased.bin").read_bytes() == digest.encode("ascii")
    verified.append((word, digest))
    return True
  monkeypatch.setattr(execution, "run_hashcat", execute)
  monkeypatch.setattr(verification, "output_has_crack", verify)
  driver(attacks.attack_0(run), ledger)
  assert captured == [(b"one", b"first\n"), (b"two", b"second\n")]
  assert verified == pairs
  assert checked == [0, 0]
  assert ledger.summaries == [{"cnt": 2, "nf": 0, "nm": 0, "to": 0, "rs": 0, "err": 0}]


def test_driver_accumulates_all_failures(tmp_path, monkeypatch, driver):
  pairs = [(b"word", "digest-%d" % index) for index in range(4)]
  run = make_run(tmp_path, pairs)
  run.targets = ["single"]
  codes = iter([1, 0, 4, 255])
  monkeypatch.setattr(execution, "run_hashcat", lambda *args, **kwargs: (next(codes), b"output"))
  monkeypatch.setattr(verification, "output_has_crack", lambda *args: False)
  checked = []
  ledger = SimpleNamespace(summaries=[], omissions=[], check=checked.append)
  driver(attacks.attack_0(run), ledger)
  assert checked == [1, 10, 4, 255]
  assert ledger.summaries == [{"cnt": 4, "nf": 1, "nm": 1, "to": 1, "rs": 0, "err": 1}]


def test_failed_hybrid_does_not_verify_recovered_output(tmp_path, monkeypatch, driver):
  counts = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0, "err": 0}
  step = attacks.invocation([], 0, "digest", None, [(b"word", "digest")], counts, False, str(tmp_path),
                            attack=6, verify_on_error=False)
  monkeypatch.setattr(execution, "run_hashcat", lambda *args, **kwargs: (1, b"output"))
  def forbidden(*args):
    pytest.fail("failed hybrid unexpectedly verified output")
  monkeypatch.setattr(verification, "output_has_crack", forbidden)
  checked = []
  ledger = SimpleNamespace(summaries=[], omissions=[], check=checked.append)
  driver([step, attacks.Summary(counts)], ledger)
  assert checked == [1]
  assert counts["nf"] == 1
