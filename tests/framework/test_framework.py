##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from hashcat_pytest import catalog, cases, hardware, runtime, scheduling

pytestmark = pytest.mark.framework


def test_selection_and_capabilities():
  assert cases.select_modes("0,100-110,20510", {0, 100, 110, 20510}) == [0, 100, 110, 20510]
  for selection in ("", "110-100", "garbage", "99"):
    with pytest.raises(ValueError):
      cases.select_modes(selection, {0, 100, 110})
  assert catalog.oracle_families(20510) == ["pure"]
  assert catalog.source_capabilities(9000)["cnt_max"] == 1
  assert 37000 in catalog.MASK_ONLY_MODES
  assert catalog.memory_hard(8900)
  assert catalog.memory_hard(34100)
  assert catalog.memory_hard(70200)
  assert catalog.memory_hard(11300)
  assert not catalog.memory_hard(0)


def test_alias_allocation():
  info = {"CUDAInfo": {"BackendDevices": [{"DeviceID": "01", "MemoryFree": "4096 MB"}]},
          "OpenCLInfo": {"Platforms": [{"BackendDevices": [
            {"DeviceID": "02", "Alias": "01", "Type": "GPU", "MemoryFree": "4096 MB"},
            {"DeviceID": "03", "Type": "CPU", "MemoryFree": "8000 MB"}]}]}}
  inventory = hardware.parse_backend_devices(json.dumps(info))
  assert [device["id"] for device in scheduling.physical_devices(inventory, "2")] == [1]
  assert [device["id"] for device in scheduling.physical_devices(inventory, "2", "2")] == [1]
  assert hardware.min_device_free_mib("2", inventory) == 4096
  assert [device["id"] for device in scheduling.physical_devices(inventory, "1")] == [3]


def test_json_oracle_preserves_bytes():
  env = dict(os.environ, HCTEST_SEED="12345", IS_OPTIMIZED="0")
  command = [sys.executable, runtime.RUNNER, "edge", "0", "0", "0", "--json-lines"]
  result = subprocess.run(command, env=env, capture_output=True, check=True)
  vectors = [json.loads(line) for line in result.stdout.splitlines()]
  assert vectors and all(row["version"] == 1 for row in vectors)
  assert base64.b64decode(vectors[0]["password_b64"], validate=True) == b""
  assert any(any(byte >= 128 for byte in base64.b64decode(row["password_b64"])) for row in vectors)
  again = subprocess.run(command, env=env, capture_output=True, check=True)
  assert result.stdout == again.stdout


def configure_pytester(pytester):
  pytester.makeconftest('pytest_plugins = ["hashcat_pytest.plugin"]')
  pytester.makeini("[pytest]\naddopts = --strict-markers")
  return ["--hash-modes", "0", "--targets", "single", "--widths", "1", "--device-type", "cpu", "-q"]


def fake_binary(pytester):
  binary = pytester.path / "hashcat-fake"
  binary.write_text("#!" + sys.executable + "\n" + '''
import json
import os
import sys
if "-I" in sys.argv:
  print(json.dumps({"OpenCLInfo": {"Platforms": [{"BackendDevices": [{"DeviceID": "01", "Type": "CPU", "MemoryFree": "100 MB"}]}]}}))
  raise SystemExit(0)
if os.environ.get("HASHCAT_DEVICE_MEM_LIMIT"):
  raise SystemExit(252)
sys.stdout.buffer.write(b"stdout\\xff\\n")
sys.stderr.buffer.write(b"stderr\\xfe\\n")
raise SystemExit(int(os.environ.get("FAKE_RC", "0")))
''')
  binary.chmod(0o755)
  return str(binary)


def test_collection_without_binary(pytester, monkeypatch):
  monkeypatch.setenv("PYTHONPATH", str(Path(runtime.ROOT, "tests")))
  options = configure_pytester(pytester)
  pytester.makepyfile(Path(runtime.ROOT, "tests", "test_cracking.py").read_text())
  args = [*options, "--hashcat-binary", "/no/compiled/hashcat", "--collect-only"]
  first = pytester.runpytest_subprocess(*args)
  second = pytester.runpytest_subprocess(*args)
  assert first.ret == second.ret == 0
  identifiers = lambda result: [line for line in result.stdout.lines if "::test_cracking[" in line]
  assert identifiers(first) == identifiers(second)
  assert len(identifiers(first)) == 1


def test_memory_cap_retry_is_final_result(pytester, monkeypatch):
  monkeypatch.setenv("PYTHONPATH", str(Path(runtime.ROOT, "tests")))
  options = configure_pytester(pytester)
  binary = fake_binary(pytester)
  pytester.makepyfile('''
from hashcat_pytest import execution, runtime
SUITE = "cracking"

def test_retry(case, run_case):
  runtime.ENV["HASHCAT_DEVICE_MEM_LIMIT"] = "1"
  def action(args, directory, ledger):
    result = execution.run_command([runtime.BIN])
    ledger.check(result.returncode)
  run_case(action)
''')
  result = pytester.runpytest_subprocess(*options, "--hashcat-binary", binary, "--keep-artifacts", "all")
  result.assert_outcomes(passed=1)
  result.stdout.fnmatch_lines(["*1 retried*"])
  folder = pytester.path / "pytest-artifacts" / "cracking" / "m0-a0-optimized-single-w1"
  attempts = sorted(folder.glob("attempt-*/invocation-0000/result.json"))
  assert [json.loads(path.read_text())["returncode"] for path in attempts] == [252, 0]


def test_assertion_failure_retains_byte_safe_reproduction(pytester, monkeypatch):
  monkeypatch.setenv("PYTHONPATH", str(Path(runtime.ROOT, "tests")))
  options = configure_pytester(pytester)
  binary = fake_binary(pytester)
  pytester.makepyfile('''
from pathlib import Path
from hashcat_pytest import execution, runtime
SUITE = "cracking"

def test_failure(case, run_case):
  def action(args, directory, ledger):
    path = Path(directory, "words")
    path.write_bytes(b"trailing space \\xff\\n")
    result = execution.run_command([runtime.BIN, str(path)], b"stdin\\xff")
    assert result.stdout == b"deliberate mismatch"
  run_case(action)
''')
  result = pytester.runpytest_subprocess(*options, "--hashcat-binary", binary)
  result.assert_outcomes(failed=1)
  folder = pytester.path / "pytest-artifacts" / "cracking" / "m0-a0-optimized-single-w1" / "attempt-0"
  assert (folder / "invocation-0000" / "stdout.bin").read_bytes() == b"stdout\xff\n"
  assert (folder / "invocation-0000" / "stderr.bin").read_bytes() == b"stderr\xfe\n"
  record = json.loads((folder / "invocation-0000" / "result.json").read_text())
  assert base64.b64decode(record["stdin_b64"]) == b"stdin\xff"
  assert len(record["inputs"]) == 1
  assert (folder / next(iter(record["inputs"].values()))).read_bytes() == b"trailing space \xff\n"
  assert (folder / "reproduce.py").is_file()


def test_empty_execution_cannot_pass(pytester, monkeypatch):
  monkeypatch.setenv("PYTHONPATH", str(Path(runtime.ROOT, "tests")))
  options = configure_pytester(pytester)
  binary = fake_binary(pytester)
  pytester.makepyfile('''
SUITE = "cracking"
def test_empty(case, run_case):
  run_case(lambda args, directory, ledger: None)
''')
  result = pytester.runpytest_subprocess(*options, "--hashcat-binary", binary)
  result.assert_outcomes(failed=1)
  result.stdout.fnmatch_lines(["*no applicable hashcat invocations*"])


def test_required_mode_cannot_hide_behind_source_audit(pytester, monkeypatch):
  monkeypatch.setenv("PYTHONPATH", str(Path(runtime.ROOT, "tests")))
  configure_pytester(pytester)
  pytester.makepyfile(test_cracking=Path(runtime.ROOT, "tests", "test_cracking.py").read_text(),
                     test_coverage=Path(runtime.ROOT, "tests", "test_coverage.py").read_text())
  result = pytester.runpytest_subprocess("--hash-modes", "20510", "--kernels", "optimized", "--require-coverage", "-q")
  assert result.ret != 0
  result.stderr.fnmatch_lines(["*no applicable integration cases*"])


def test_primary_sanitizer_errors_fail_successful_hashcat(tmp_path):
  from hashcat_pytest import artifacts, execution

  result = artifacts.CaseResults(tmp_path, cases.Case(0, "cracking"), {})
  summary = tmp_path / "summary.json"
  summary.write_text(json.dumps({"sanitizer": {"parse_ok": True, "primary_errors": 1}}))
  execution.check_sanitizer(tmp_path, result)
  assert result.problems
  result.problems.clear()
  summary.write_text("malformed JSON")
  execution.check_sanitizer(tmp_path, result)
  assert result.problems


def test_artifacts_capture_only_explicit_input_directories(tmp_path, monkeypatch):
  from hashcat_pytest import artifacts

  root = tmp_path / "repo"
  root.mkdir()
  monkeypatch.setattr(runtime, "ROOT", str(root))
  words = root / "words"
  words.write_bytes(b"password\xff\n")
  cache = root / "cache"
  cache.mkdir()
  (cache / "kernel").write_bytes(b"compiled kernel")
  outfile = root / "cracks"
  outfile.write_bytes(b"previous output")
  ruleset = root / "ruleset"
  ruleset.mkdir()
  (ruleset / "grammar.txt").write_bytes(b"X1\t1.0\n")
  directory = tmp_path / "artifacts"
  directory.mkdir()
  result = artifacts.CaseResults(directory, cases.Case(0, "cracking"), {})
  command = ["hashcat", "--cache-path", str(cache), "--outfile", str(outfile),
             "--session", str(root), b"", ".", str(root), str(words), str(ruleset)]
  inputs = result.capture_inputs(command, (str(ruleset),))
  assert set(inputs) == {str(words), str(ruleset)}
  assert (directory / inputs[str(words)]).read_bytes() == words.read_bytes()
  assert (directory / inputs[str(ruleset)] / "grammar.txt").read_bytes() == b"X1\t1.0\n"


def test_parity_detects_candidate_changes():
  from hashcat_pytest import parity

  encode = lambda value: base64.b64encode(value).decode("ascii")
  before = {"argv_b64": [encode(value) for value in (b"/old/hashcat", b"--session", b"old", b"/old/words")],
            "stdin_b64": None, "returncode": 0, "inputs": {"/old/words": encode(b"password\n")}}
  after = {"argv_b64": [encode(value) for value in (b"/new/hashcat", b"--session", b"new", b"/new/words")],
           "stdin_b64": None, "returncode": 0, "inputs": {"/new/words": encode(b"password\n")}}
  case = {"mode": 0}
  assert parity.compare([{"case": case, "invocations": [before]}], [{"case": case, "invocations": [after]}]) == []
  after["inputs"]["/new/words"] = encode(b"different password\n")
  assert parity.compare([{"case": case, "invocations": [before]}], [{"case": case, "invocations": [after]}])


def test_worker_death_terminates_hashcat_and_releases_lease(tmp_path):
  import fcntl
  import signal
  import time

  guardian = Path(runtime.ROOT, "tests", "hashcat_pytest", "guardian.py")
  worker_script = tmp_path / "worker.py"
  marker = tmp_path / "child-pid"
  resource = tmp_path / "resource"
  child_script = "import os,time; from pathlib import Path; Path(%r).write_text(str(os.getpid())); time.sleep(120)" % str(marker)
  worker_script.write_text('''
import fcntl
import os
from pathlib import Path
import subprocess
import sys
import time
path, guardian, script, marker = sys.argv[1:]
with open(path, "a+b") as resource:
  fcntl.flock(resource, fcntl.LOCK_EX)
  subprocess.Popen([sys.executable, guardian, str(os.getpid()), sys.executable, "-c", script],
                   pass_fds=(resource.fileno(),), start_new_session=True)
  while not Path(marker).exists():
    time.sleep(0.01)
  os._exit(0)
''')
  worker = subprocess.Popen([sys.executable, str(worker_script), str(resource), str(guardian), child_script, str(marker)])
  try:
    assert worker.wait(timeout=10) == 0
    with open(resource, "a+b") as handle:
      deadline = time.monotonic() + 5
      while True:
        try:
          fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
          break
        except BlockingIOError:
          assert time.monotonic() < deadline, "lease survived worker death"
          time.sleep(0.01)
      pid = int(marker.read_text())
      with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
  finally:
    if worker.poll() is None:
      worker.kill()
      worker.wait()
    if marker.exists():
      try:
        os.killpg(int(marker.read_text()), signal.SIGKILL)
      except ProcessLookupError:
        pass


@pytest.mark.parametrize("suite,mode", [("cracking", 0), ("bridge", 0), ("stdout", 2000)])
def test_worker_crash_is_counted_and_annotated(pytester, monkeypatch, suite, mode):
  import xml.etree.ElementTree as element_tree

  monkeypatch.setenv("PYTHONPATH", str(Path(runtime.ROOT, "tests")))
  monkeypatch.setenv("GITHUB_ACTIONS", "true")
  summary = pytester.path / "summary.md"
  monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
  options = configure_pytester(pytester)
  binary = fake_binary(pytester)
  pytester.makepyfile('''
import os
from pathlib import Path
from hashcat_pytest import execution, runtime
SUITE = %r

def test_crash(case, run_case):
  marker = Path("crashed-worker")
  if marker.exists() == False:
    marker.touch()
    os._exit(42)
  def action(args, directory, ledger):
    result = execution.run_command([runtime.BIN])
    ledger.check(result.returncode)
  run_case(action)
''' % suite)
  result = pytester.runpytest_subprocess(*options, "--widths", "1,4", "--hashcat-binary", binary,
                                       "--hash-modes", str(mode),
                                       "--profile", "full", "--kernels", "optimized", "--attacks", "0",
                                       "--require-coverage", "-n", "1", "--dist", "loadgroup",
                                       "--max-worker-restart", "1", "--junitxml", "results.xml")
  result.assert_outcomes(passed=2 if suite == "cracking" else 1, failed=1)
  result.stdout.fnmatch_lines(["*::error title=hashcat mode %d::*" % mode, "*Errors detected: 1*",
                              "*1 worker crashes, invocation count is incomplete*"])
  assert "Worker crashes: 1. Invocation count is incomplete." in summary.read_text()
  errors = element_tree.parse(pytester.path / "results.xml").findall(".//testcase/error")
  assert len(errors) == 1
  assert "crashed" in errors[0].get("message")


@pytest.mark.parametrize("suite,mode", [("bridge", 0), ("stdout", 2000)])
def test_mode_only_ids_enforce_parallel_coverage(pytester, monkeypatch, suite, mode):
  monkeypatch.setenv("PYTHONPATH", str(Path(runtime.ROOT, "tests")))
  options = configure_pytester(pytester)
  binary = fake_binary(pytester)
  pytester.makepyfile('''
from hashcat_pytest import execution, runtime
SUITE = %r

def test_skip(case, run_case):
  def action(args, directory, ledger):
    runtime.ENV["FAKE_RC"] = "252"
    result = execution.run_command([runtime.BIN])
    ledger.check(result.returncode)
  run_case(action)
''' % suite)
  result = pytester.runpytest_subprocess(*options, "--hash-modes", str(mode), "--hashcat-binary", binary,
                                       "--profile", "full", "--kernels", "optimized",
                                       "--require-coverage", "-n", "1", "--dist", "loadgroup")
  result.assert_outcomes(skipped=1, failed=1)
  result.stdout.fnmatch_lines(["*hashcat: 1 planned cases*", "*Errors detected: 1*"])


def test_stdout_does_not_require_gpu_inventory(pytester, monkeypatch):
  monkeypatch.setenv("PYTHONPATH", str(Path(runtime.ROOT, "tests")))
  options = configure_pytester(pytester)
  pytester.makepyfile(Path(runtime.ROOT, "tests", "test_stdout.py").read_text())
  binary = pytester.path / "hashcat-stdout"
  binary.write_text("#!" + sys.executable + "\n" + '''
from pathlib import Path
import sys
if "-HH" in sys.argv:
  print("Kernel.Type(s): pure")
  raise SystemExit(0)
if "--stdout" not in sys.argv:
  raise SystemExit("STDOUT should not query or initialize a device backend")
words = next(Path(arg) for arg in sys.argv[1:] if Path(arg).is_file())
sys.stdout.buffer.write(words.read_bytes())
''')
  binary.chmod(0o755)
  result = pytester.runpytest_subprocess(*options, "--hash-modes", "2000", "--device-type", "gpu",
                                       "--hashcat-binary", str(binary), "--require-coverage", "-n", "2", "--dist", "loadgroup")
  result.assert_outcomes(passed=1)
  result.stdout.fnmatch_lines(["*hashcat: 1 planned cases*", "*Errors detected: 0*"])


def test_required_coverage_allows_a_genuine_partial_memory_skip(pytester, monkeypatch):
  import xml.etree.ElementTree as element_tree

  monkeypatch.setenv("PYTHONPATH", str(Path(runtime.ROOT, "tests")))
  options = configure_pytester(pytester)
  binary = fake_binary(pytester)
  pytester.makepyfile('''
from hashcat_pytest import execution, runtime
SUITE = "cracking"
def test_limit(case, run_case):
  def action(args, directory, ledger):
    runtime.ENV["FAKE_RC"] = "252" if case.width == 1 else "0"
    result = execution.run_command([runtime.BIN])
    ledger.check(result.returncode)
  run_case(action)
''')
  result = pytester.runpytest_subprocess(*options, "--widths", "all", "--hashcat-binary", binary, "--require-coverage")
  result.assert_outcomes(passed=1, skipped=1)
  assert result.ret == 0
  monkeypatch.setenv("GITHUB_ACTIONS", "true")
  summary = pytester.path / "summary.md"
  monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
  result = pytester.runpytest_subprocess(*options, "--hashcat-binary", binary, "--require-coverage", "--junitxml", "coverage.xml")
  result.assert_outcomes(skipped=1, failed=1)
  assert result.ret != 0
  result.stdout.fnmatch_lines(["*::error title=hashcat required coverage::*", "*Errors detected: 1*"])
  assert "Required modes without a passed invocation: [0]" in summary.read_text()
  xml = element_tree.parse(pytester.path / "coverage.xml")
  assert len(xml.findall(".//testcase/failure")) == 1
  result = pytester.runpytest_subprocess(*options, "--widths", "all", "--hashcat-binary", binary,
                                       "--require-coverage", "-n", "2", "--dist", "loadgroup")
  result.assert_outcomes(passed=1, skipped=1)
  assert result.ret == 0


def test_sanitizer_sweep_preserves_binary_output_and_argv(tmp_path, monkeypatch, capfdbinary):
  import argparse
  import importlib.util

  directory = Path(runtime.TDIR, "compute_sanitizer")
  monkeypatch.syspath_prepend(str(directory))
  spec = importlib.util.spec_from_file_location("hashcat_sanitizer_run", directory / "run.py")
  wrapper = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(wrapper)
  fake = tmp_path / "compute-sanitizer"
  fake.write_text("#!" + sys.executable + "\n" + '''
import os
import sys
sys.stdout.buffer.write(os.fsencode(sys.argv[-3]) + b"\\xff\\n")
sys.stderr.buffer.write(b"stderr\\xfe\\n")
raise SystemExit(1)
''')
  fake.chmod(0o755)
  monkeypatch.setattr(wrapper, "find_compute_sanitizer", lambda: str(fake))
  monkeypatch.setattr(wrapper, "sanity_check_binary", lambda binary: (True, "version"))
  monkeypatch.setattr(wrapper, "has_debug_info", lambda binary: True)
  monkeypatch.setattr(wrapper, "find_cuda_device", lambda binary: ({"name": "test CUDA device"}, None))
  monkeypatch.setattr(wrapper, "write_environment_file", lambda *args: None)
  summary = {"sanitizer": {"parse_ok": True}}
  monkeypatch.setattr(wrapper.triage, "analyze", lambda *args, **kwargs: summary)
  monkeypatch.setattr(wrapper.triage, "write_summary", lambda *args, **kwargs: "")
  monkeypatch.setattr(wrapper.triage, "append_sweep_finding", lambda *args: None)
  options = argparse.Namespace(test_name="binary", tool="initcheck", leak_check="no", padding=128,
                               sweep=True, results_dir=str(tmp_path / "results"))
  assert wrapper.cmd_exec(options, [], [sys.executable, os.fsdecode(b"argument\xfd")]) == 1
  captured = capfdbinary.readouterr()
  assert captured.out == b"argument\xfd\xff\n"
  assert captured.err == b"stderr\xfe\n"
  folder = next((tmp_path / "results").iterdir())
  assert (folder / "stdout.txt").read_bytes() == captured.out
  assert (folder / "stderr.txt").read_bytes() == captured.err
  assert "\\udcfd" in (folder / "command.txt").read_text()


def test_compiled_selftest_inventory_detects_stale_build(monkeypatch):
  from hashcat_pytest import selftest

  monkeypatch.setattr(selftest, "_INVENTORIES", {})
  monkeypatch.setattr(runtime, "ISOLATION", [])
  monkeypatch.setattr(catalog, "source_modes", lambda: [0, 1000])
  result = subprocess.CompletedProcess([], 0, b'{"0": {}}', b"")
  monkeypatch.setattr(selftest.subprocess, "run", lambda *args, **kwargs: result)
  with pytest.raises(RuntimeError, match="missing \\[1000\\]"):
    selftest.validate_inventory()


def test_generated_tool_logs_do_not_count_as_hashcat_invocations(tmp_path, monkeypatch):
  from hashcat_pytest import artifacts, generated

  ledger = artifacts.CaseResults(tmp_path, cases.Case(0, "generated"), {})
  monkeypatch.setattr(runtime, "ACTIVE", ledger)
  monkeypatch.setattr(runtime, "PASS_FDS", ())
  script = "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read()); sys.stderr.buffer.write(b'error\\xff')"
  code, output = generated.gen_run([sys.executable, "-c", script], b"input\xfe")
  assert code == 0 and output == b"input\xfeerror\xff"
  assert ledger.invocations == [] and len(ledger.tool_runs) == 1
  assert (tmp_path / "tool-0000" / "stdout.bin").read_bytes() == b"input\xfe"
  assert (tmp_path / "tool-0000" / "stderr.bin").read_bytes() == b"error\xff"


def test_luks_generation_closes_mapping_after_failure(tmp_path, monkeypatch):
  from contextlib import contextmanager

  from hashcat_pytest import generated

  monkeypatch.setattr(generated, "_have", lambda value: True)
  monkeypatch.setattr(generated, "privileged_tools_available", lambda mode, tools: True)
  calls = []
  @contextmanager
  def resource(kind, backing_file, mapper_name=None):
    calls.append(["register", kind, mapper_name])
    try:
      yield
    finally:
      calls.append(["cleanup", mapper_name])
  monkeypatch.setattr(generated.privileged, "resource", resource)
  def invoke(command, **kwargs):
    calls.append(command)
    if command[0] == "mkfs.ext4":
      raise RuntimeError("format interrupted")
    return 0, b""
  monkeypatch.setattr(generated, "gen_run", invoke)
  for create in (lambda path: generated.luks1_generate(29511, "sha1", "aes", "cbc-plain64", "128", str(path)),
                 lambda path: generated.luks2_generate(34100, "xts-plain64", "512", str(path))):
    with pytest.raises(RuntimeError, match="format interrupted"):
      create(tmp_path / "volume.img")
    assert calls[-1][0] == "cleanup"
    assert calls[-2][0] == "mkfs.ext4"


def test_container_masks_follow_generated_password(monkeypatch):
  from hashcat_pytest import containers

  monkeypatch.setattr(runtime, "CONTAINER_PASSWORD", b"hashcat")
  assert containers.container_mask("last") == "hashca?l"
  assert containers.container_mask("first") == "hashc?lt"
  monkeypatch.setattr(runtime, "CONTAINER_PASSWORD", b"3\xe0\xa4\xb961227388")
  assert containers.container_mask("last") == b"3\xe0\xa4\xb96122738?d"
  assert containers.container_mask("first") == b"?d\xe0\xa4\xb961227388"


def test_memory_inventory_respects_cgroup_ancestors_and_macos_pages(tmp_path):
  parent = tmp_path / "slice"
  leaf = parent / "worker"
  leaf.mkdir(parents=True)
  (parent / "memory.max").write_text(str(2048 * 1024 * 1024))
  (parent / "memory.current").write_text(str(1024 * 1024 * 1024))
  (leaf / "memory.max").write_text("max")
  assert hardware.cgroup_available_mib(tmp_path, "/slice/worker") == 1024
  (leaf / "memory.max").write_text(str(512 * 1024 * 1024))
  (leaf / "memory.current").write_text(str(256 * 1024 * 1024))
  assert hardware.cgroup_available_mib(tmp_path, "/slice/worker") == 256
  output = "Mach Virtual Memory Statistics: (page size of 16384 bytes)\nPages free: 64.\nPages inactive: 128.\nPages speculative: 64.\nPages active: 512.\n"
  assert hardware.parse_vm_stat(output) == 4
  assert hardware.parse_vm_stat("missing statistics") is None


def test_source_audit_alone_cannot_satisfy_required_execution(pytester, monkeypatch):
  monkeypatch.setenv("PYTHONPATH", str(Path(runtime.ROOT, "tests")))
  options = configure_pytester(pytester)
  pytester.makepyfile(Path(runtime.ROOT, "tests", "test_coverage.py").read_text())
  result = pytester.runpytest_subprocess(*options, "--require-coverage")
  assert result.ret != 0
  result.stderr.fnmatch_lines(["*required coverage needs executable integration cases*"])


def test_parity_ignores_status_timing_but_compares_recovered_records():
  from hashcat_pytest import parity

  first = b"hash1:password1\nSession..........: old\nTime.Started.....: yesterday\n\nhash2:password2\n"
  second = b"hash2:password2\nSession..........: new\nTime.Started.....: today\n\nhash1:password1\n"
  assert parity.normalize_output(first) == parity.normalize_output(second)
  assert parity.normalize_output(first) != parity.normalize_output(second.replace(b"password1", b"different"))
  assert parity.normalize_output(b"first\nsecond\n", ordered=True) != parity.normalize_output(b"second\nfirst\n", ordered=True)


def test_ci_kinds_cover_supported_kernel_families(monkeypatch):
  import runpy

  monkeypatch.chdir(runtime.ROOT)
  planner = runpy.run_path(str(Path(runtime.ROOT, ".github", "workflows", "ci_matrix.py")))
  matrix = planner["test_matrix"]([[0, 10400, 20510]], ["opt", "pure", "bridge"])
  assert {row["kind"]: row["modes"] for row in matrix} == {
    "opt": "0 10400 20510", "pure": "0 20510", "bridge": "0 10400 20510"}
  assert planner["test_matrix"]([[10400]], ["pure"]) == []
  assert planner["MINIMAL_MODES"] is catalog.MINIMAL_MODES
  assert planner["container_modes"]() == catalog.CONTAINER_MODES
  for path in ("tests/requirements.txt", "tests/hashcat_pytest/plugin.py", "pytest.ini", "tools/test_bridge.py"):
    assert planner["TEST_SHARED"].fullmatch(path)


def test_backend_selection_rejects_trailing_junk():
  assert hardware.backend_device_ids("+001, 2") == [1, 2]
  for value in ("1junk", "0", "256", "-1", "abc"):
    assert hardware.backend_device_ids(value) is None


def test_gpg_generator_stops_agent_and_removes_home_on_failure(tmp_path, monkeypatch):
  from hashcat_pytest import generated

  commands = []
  monkeypatch.setattr(generated, "gen_run", lambda command: (commands.append(command) or 0, b""))
  with pytest.raises(RuntimeError, match="generation interrupted"):
    with generated.gpg_home(str(tmp_path), "gpgconf") as home:
      assert Path(home).is_dir()
      raise RuntimeError("generation interrupted")
  assert not Path(home).exists()
  assert commands == [["gpgconf", "--homedir", home, "--kill", "gpg-agent"]]


def test_saved_reproduction_uses_snapshot_after_original_input_is_removed(tmp_path):
  from hashcat_pytest import artifacts, execution

  root = tmp_path / "root"
  root.mkdir()
  binary = root / "hashcat"
  binary.write_text("#!" + sys.executable + "\n" + '''
from pathlib import Path
import sys
sys.stdout.buffer.write(Path(sys.argv[1]).read_bytes() + sys.stdin.buffer.read())
''')
  binary.chmod(0o755)
  words = root / "words"
  words.write_bytes(b"trailing space \xff\n")
  folder = tmp_path / "artifacts"
  folder.mkdir()
  ledger = artifacts.CaseResults(folder, cases.Case(0, "cracking"), {})
  command = [str(binary), str(words)]
  inputs = ledger.capture_inputs(command)
  ledger.save(command, b"stdin\xfe", execution.HashcatResult(command, 0, b"", b"", 0), inputs)
  ledger.finish()
  words.unlink()
  result = subprocess.run([sys.executable, str(folder / "reproduce.py"), "0", "--root", str(root)], capture_output=True)
  assert result.returncode == 0
  assert result.stdout == b"trailing space \xff\nstdin\xfe"


def test_parallel_source_checks_need_no_hashcat_binary(pytester, monkeypatch):
  monkeypatch.setenv("PYTHONPATH", str(Path(runtime.ROOT, "tests")))
  configure_pytester(pytester)
  pytester.makepyfile("def test_source():\n  assert True")
  result = pytester.runpytest_subprocess("-n", "2", "--hashcat-binary", "/missing/hashcat", "-q")
  result.assert_outcomes(passed=1)


def test_partial_generator_coverage_is_visible_and_strict(pytester, monkeypatch):
  monkeypatch.setenv("PYTHONPATH", str(Path(runtime.ROOT, "tests")))
  options = configure_pytester(pytester)
  binary = fake_binary(pytester)
  pytester.makepyfile('''
from hashcat_pytest import execution, runtime
SUITE = "cracking"
def test_partial(case, run_case):
  def action(args, directory, ledger):
    result = execution.run_command([runtime.BIN])
    ledger.check(result.returncode)
    ledger.notes.append("optional producer unavailable")
  run_case(action)
''')
  result = pytester.runpytest_subprocess(*options, "--hashcat-binary", binary)
  result.assert_outcomes(passed=1)
  result.stdout.fnmatch_lines(["*PytestWarning: optional producer unavailable*"])
  result = pytester.runpytest_subprocess(*options, "--hashcat-binary", binary, "--require-coverage")
  result.assert_outcomes(failed=1)
  folder = pytester.path / "pytest-artifacts" / "cracking" / "m0-a0-optimized-single-w1" / "attempt-0"
  metadata = json.loads((folder / "result.json").read_text())
  assert metadata["notes"] == ["optional producer unavailable"]
  assert metadata["outcome"] == "failed"
