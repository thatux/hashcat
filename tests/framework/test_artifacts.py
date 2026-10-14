##
## Author......: See docs/credits.txt
## License.....: MIT
##

import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys

import pytest

from hashcat_pytest import artifacts, cases, execution, runtime

pytestmark = pytest.mark.framework


def saved_tool(tmp_path, command, environment, case_directory=None):
  folder = case_directory or tmp_path / "artifacts"
  folder.mkdir(exist_ok=True)
  ledger = artifacts.CaseResults(folder, cases.Case(0, "bridge"), environment)
  inputs = ledger.capture_inputs(command)
  result = subprocess.run(command, capture_output=True, cwd=runtime.ROOT,
                          env=dict(os.environ, **environment), timeout=30)
  assert result.returncode == 0, result.stderr
  ledger.save(command, None, execution.HashcatResult(command, result.returncode,
              result.stdout, result.stderr, 0), inputs, tool=True)
  ledger.finish()
  return folder, result


def replay(folder, root=runtime.ROOT):
  return subprocess.run([sys.executable, str(folder / "reproduce.py"), "0", "--tool", "--root", root],
                        capture_output=True, cwd=runtime.ROOT, timeout=30)


def test_oracle_reproduction_preserves_script_imports(tmp_path):
  command = [sys.executable, runtime.RUNNER, "single", "0", "1", "--json-lines"]
  folder, original = saved_tool(tmp_path, command, {"HCTEST_SEED": "12345", "IS_OPTIMIZED": "1"})
  record = json.loads((folder / "tool-0000" / "result.json").read_text())
  assert record["repository_paths"][runtime.RUNNER] == "tools/test_module_runner.py"
  assert (folder / record["inputs"][runtime.RUNNER]).read_bytes() == Path(runtime.RUNNER).read_bytes()
  reproduced = replay(folder, ".")
  assert reproduced.returncode == 0, reproduced.stderr
  assert reproduced.stdout == original.stdout


def test_bridge_vector_reproduction_preserves_repository_paths(tmp_path):
  script = str(Path(runtime.TDIR, "test_bridge.py"))
  case_directory = tmp_path / "original-case"
  outputs = case_directory / "vectors"
  outputs.mkdir(parents=True)
  hashes = outputs / "bridge.hashes"
  words = outputs / "bridge.words"
  command = [sys.executable, script, "vectors", "0", str(hashes), str(words), "--json-summary"]
  folder, original = saved_tool(tmp_path, command, {"HCTEST_SEED": "12345"}, case_directory)
  record = json.loads((folder / "tool-0000" / "result.json").read_text())
  assert str(hashes) not in record["inputs"]
  assert record["case_paths"]["4"]["relative"] == "vectors/bridge.hashes"
  assert hashes.read_bytes() and words.read_bytes()
  retained = tmp_path / "retained"
  shutil.copytree(folder, retained)
  shutil.rmtree(case_directory)
  reproduced = replay(retained)
  assert reproduced.returncode == 0, reproduced.stderr
  assert reproduced.stdout == original.stdout
  assert case_directory.exists() == False


def test_private_home_replay(tmp_path):
  if not hasattr(socket, "AF_UNIX"):
    pytest.skip("private-home socket snapshot check needs Unix sockets")
  case_directory = tmp_path / "case"
  home = case_directory / "home"
  home.mkdir(parents=True, mode=0o700)
  (home / "key").write_bytes(b"known secret\xff")
  outputs = case_directory / "outputs"
  outputs.mkdir()
  output = outputs / "export"
  script = '''
import os
from pathlib import Path
import sys
home = Path(sys.argv[sys.argv.index("--homedir") + 1])
assert home.stat().st_mode & 0o777 == 0o700
password = sys.argv[sys.argv.index("--passphrase") + 1]
output = Path(next(arg.partition("=")[2] for arg in sys.argv if arg.startswith("--output=")))
data = (home / "key").read_bytes()
output.write_bytes(data)
(home / "key").write_bytes(b"changed by tool")
sys.stdout.buffer.write(os.fsencode(password) + b":" + data)
'''
  command = [sys.executable, "-c", script, "--homedir", str(home), "--output=" + str(output),
             "--passphrase", str(home)]
  with socket.socket(socket.AF_UNIX) as agent_socket:
    agent_socket.bind(str(home / "agent"))
    folder, original = saved_tool(tmp_path, command, {}, case_directory)
  record = json.loads((folder / "tool-0000" / "result.json").read_text())
  snapshot = folder / record["inputs"][str(home)]
  assert (snapshot / "key").read_bytes() == b"known secret\xff"
  assert (snapshot / "agent").exists() == False
  assert record["case_paths"]["5"]["prefix"] == "--output="
  assert "7" not in record["case_paths"]
  shutil.rmtree(home)
  retained = tmp_path / "retained"
  shutil.copytree(folder, retained)
  shutil.rmtree(case_directory)
  reproduced = replay(retained)
  assert reproduced.returncode == 0, reproduced.stderr
  assert reproduced.stdout == original.stdout
  assert case_directory.exists() == False
  assert (retained / record["inputs"][str(home)] / "key").read_bytes() == b"known secret\xff"


def test_relative_case_outputs_replay_after_directory_removal(tmp_path, monkeypatch):
  root = tmp_path / "root"
  case_directory = root / "private-case"
  case_directory.mkdir(parents=True)
  output = "private-case/generated"
  script = '''
from pathlib import Path
import sys
Path(sys.argv[1]).write_bytes(b"generated bytes")
sys.stdout.buffer.write(Path(sys.argv[1]).read_bytes())
'''
  monkeypatch.setattr(runtime, "ROOT", str(root))
  command = [sys.executable, "-c", script, output]
  folder, original = saved_tool(tmp_path, command, {}, case_directory)
  record = json.loads((folder / "tool-0000" / "result.json").read_text())
  assert record["case_paths"]["3"]["relative"] == "generated"
  retained = tmp_path / "retained"
  shutil.copytree(folder, retained)
  shutil.rmtree(case_directory)
  reproduced = replay(retained, str(root))
  assert reproduced.returncode == 0, reproduced.stderr
  assert reproduced.stdout == original.stdout
  assert case_directory.exists() == False


def test_gpg_keyring_replays_after_original_home_is_removed(tmp_path, monkeypatch):
  gpg = shutil.which("gpg")
  gpgconf = shutil.which("gpgconf")
  if gpg is None or gpgconf is None:
    pytest.skip("real GPG replay needs gpg and gpgconf")
  case_directory = tmp_path / "case"
  home = case_directory / "home"
  home.mkdir(parents=True, mode=0o700)
  generate = [gpg, "--homedir", str(home), "--batch", "--pinentry-mode", "loopback", "--passphrase", "hashcat",
              "--quick-generate-key", "Replay test <replay@hashcat.test>", "rsa1024", "sign", "0"]
  cleanup_log = tmp_path / "cleanup.log"
  programs = tmp_path / "bin"
  programs.mkdir()
  wrapper = programs / "gpgconf"
  wrapper.write_text("#!" + sys.executable + "\n" + '''
import os
from pathlib import Path
import sys
Path(%r).write_text(sys.argv[sys.argv.index("--homedir") + 1])
os.execv(%r, [%r] + sys.argv[1:])
''' % (str(cleanup_log), gpgconf, gpgconf))
  wrapper.chmod(0o755)
  monkeypatch.setenv("PATH", str(programs) + os.pathsep + os.environ["PATH"])
  try:
    created = subprocess.run(generate, capture_output=True, timeout=30)
    assert created.returncode == 0, created.stderr
    command = [gpg, "--homedir", str(home), "--batch", "--export"]
    folder, original = saved_tool(tmp_path, command, {}, case_directory)
    assert original.stdout
  finally:
    subprocess.run([gpgconf, "--homedir", str(home), "--kill", "gpg-agent"],
                   stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=10)
  retained = tmp_path / "retained"
  shutil.copytree(folder, retained)
  shutil.rmtree(case_directory)
  reproduced = replay(retained)
  assert reproduced.returncode == 0, reproduced.stderr
  assert reproduced.stdout == original.stdout
  assert case_directory.exists() == False
  replay_home = Path(cleanup_log.read_text())
  assert replay_home.parent.parent.name.startswith("hashcat-repro-")
  assert replay_home.exists() == False


def test_directory_snapshot_cannot_contain_artifacts(tmp_path):
  ledger = artifacts.CaseResults(tmp_path, cases.Case(0, "generated"), {})
  with pytest.raises(ValueError, match="contains the artifact directory"):
    ledger.capture_inputs([sys.executable, "--homedir", str(tmp_path)])
  assert (tmp_path / "inputs").exists() == False


def test_pathlike_literal_mask_is_preserved_after_case_removal(tmp_path):
  root = tmp_path / "root"
  root.mkdir()
  binary = root / "hashcat"
  binary.write_text("#!" + sys.executable + "\n" + '''
import os
import sys
sys.stdout.buffer.write(os.fsencode(sys.argv[-1]))
''')
  binary.chmod(0o755)
  case_directory = tmp_path / "case"
  case_directory.mkdir()
  literal = os.fsencode(case_directory / "unused-mask") + b"\xfd"
  command = [str(binary), "-a", "3", "-m", "0", "0" * 32, literal]
  ledger = artifacts.CaseResults(case_directory, cases.Case(0, "cracking"), {})
  inputs = ledger.capture_inputs(command)
  original = subprocess.run(command, capture_output=True, timeout=10)
  assert original.returncode == 0
  assert original.stdout == literal
  ledger.save(command, None, execution.HashcatResult(command, 0, original.stdout, original.stderr, 0), inputs)
  ledger.finish()
  record = json.loads((case_directory / "invocation-0000" / "result.json").read_text())
  assert "6" not in record["case_paths"]
  retained = tmp_path / "retained"
  shutil.copytree(case_directory, retained)
  shutil.rmtree(case_directory)
  reproduced = subprocess.run([sys.executable, str(retained / "reproduce.py"), "0", "--root", str(root)],
                              capture_output=True, timeout=10)
  assert reproduced.returncode == 0, reproduced.stderr
  assert reproduced.stdout == literal
  assert case_directory.exists() == False


def test_directory_snapshot_rejects_symlink_expansion(tmp_path):
  rules = tmp_path / "rules"
  rules.mkdir()
  external = tmp_path / "external"
  external.mkdir()
  (external / "unrelated").write_bytes(b"outside the input directory")
  (rules / "linked").symlink_to(external, target_is_directory=True)
  folder = tmp_path / "artifacts"
  folder.mkdir()
  ledger = artifacts.CaseResults(folder, cases.Case(0, "cracking"), {})
  with pytest.raises(ValueError, match="input directory contains a symlink"):
    ledger.capture_inputs([runtime.BIN, str(rules)], [str(rules)])
  assert (folder / "inputs").exists() == False


def test_directory_snapshot_separates_names_and_contents(tmp_path):
  rules = tmp_path / "rules"
  rules.mkdir()
  folder = tmp_path / "artifacts"
  folder.mkdir()
  ledger = artifacts.CaseResults(folder, cases.Case(0, "cracking"), {})
  (rules / "a").write_bytes(b"bc")
  first = ledger.capture_inputs([runtime.BIN, str(rules)], [str(rules)])[str(rules)]
  (rules / "a").unlink()
  (rules / "ab").write_bytes(b"c")
  second = ledger.capture_inputs([runtime.BIN, str(rules)], [str(rules)])[str(rules)]
  assert first != second
  assert (folder / first / "a").read_bytes() == b"bc"
  assert (folder / second / "ab").read_bytes() == b"c"


def test_reproduction_prints_binary_outfile_before_cleanup(tmp_path):
  root = tmp_path / "root"
  root.mkdir()
  binary = root / "hashcat"
  binary.write_text("#!" + sys.executable + "\n" + '''
from pathlib import Path
import sys
Path(sys.argv[sys.argv.index("--outfile") + 1]).write_bytes(bytes.fromhex("686173683afffe0a"))
''')
  binary.chmod(0o755)
  folder = tmp_path / "artifacts"
  folder.mkdir()
  ledger = artifacts.CaseResults(folder, cases.Case(0, "edge"), {})
  command = [str(binary), "--outfile", str(tmp_path / "original.out")]
  ledger.save(command, None, execution.HashcatResult(command, 0, b"", b"", 0), {})
  ledger.finish()
  result = subprocess.run([sys.executable, str(folder / "reproduce.py"), "0", "--root", str(root)],
                          capture_output=True, timeout=30)
  assert result.returncode == 0, result.stderr
  assert result.stdout == b"hash:\xff\xfe\n"


def test_repository_data_replays_snapshot_and_preserves_shim(tmp_path, monkeypatch):
  root = tmp_path / "root"
  shim = root / "tools" / "compute_sanitizer" / "sweep_shim.sh"
  shim.parent.mkdir(parents=True)
  shim.write_text("#!" + sys.executable + "\n" + '''
import os
from pathlib import Path
import sys
assert Path(os.environ["SANITIZER_SWEEP_DIR"]).parent.name.startswith("hashcat-repro-")
sys.stdout.buffer.write(Path(sys.argv[1]).read_bytes())
''')
  shim.chmod(0o755)
  words = root / "temporary-input"
  words.write_bytes(b"saved password\xff\n")
  folder = tmp_path / "artifacts"
  folder.mkdir()
  monkeypatch.setattr(runtime, "ROOT", str(root))
  ledger = artifacts.CaseResults(folder, cases.Case(0, "cracking"), {"SANITIZER_SWEEP_DIR": "/old/output"})
  command = [str(shim), str(words)]
  inputs = ledger.capture_inputs(command)
  ledger.save(command, None, execution.HashcatResult(command, 0, b"", b"", 0), inputs)
  ledger.finish()
  words.unlink()
  result = subprocess.run([sys.executable, str(folder / "reproduce.py"), "0", "--root", str(root)],
                          capture_output=True, timeout=30)
  assert result.returncode == 0, result.stderr
  assert result.stdout == b"saved password\xff\n"


def test_native_bridge_reproduction_preserves_module_resources(tmp_path, monkeypatch):
  root = tmp_path / "root"
  tools = root / "tools"
  tools.mkdir(parents=True)
  script = tools / "bridge.py"
  script.write_text('''
from pathlib import Path
import sys
def run(words):
  sys.stdout.buffer.write(Path(__file__).with_name("support").read_bytes() + Path(words).read_bytes())
''')
  (tools / "support").write_bytes(b"bridge resource\n")
  binary = root / "hashcat"
  binary.write_text("#!" + sys.executable + "\n" + '''
import runpy
import sys
runpy.run_path(sys.argv[sys.argv.index("--bridge-parameter1") + 1])["run"](sys.argv[-1])
''')
  binary.chmod(0o755)
  words = root / "temporary.words"
  words.write_bytes(b"password\xff\n")
  folder = tmp_path / "artifacts"
  folder.mkdir()
  monkeypatch.setattr(runtime, "ROOT", str(root))
  ledger = artifacts.CaseResults(folder, cases.Case(0, "bridge"), {})
  command = [str(binary), "--bridge-parameter1", str(script), str(words)]
  ledger.save(command, None, execution.HashcatResult(command, 0, b"", b"", 0), ledger.capture_inputs(command))
  ledger.finish()
  words.unlink()
  result = subprocess.run([sys.executable, str(folder / "reproduce.py"), "0", "--root", str(root)],
                          capture_output=True, timeout=30)
  assert result.returncode == 0, result.stderr
  assert result.stdout == b"bridge resource\npassword\xff\n"
