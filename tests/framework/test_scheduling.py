##
## Author......: See docs/credits.txt
## License.....: MIT
##

import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from hashcat_pytest import hardware, plugin, runtime, scheduling

pytestmark = pytest.mark.framework


@pytest.mark.parametrize("cpu", [None, 3])
def test_bridge_host_fallback(pytester, monkeypatch, cpu):
  monkeypatch.setenv("PYTHONPATH", str(Path(runtime.ROOT, "tests")))
  pytester.makeconftest('pytest_plugins = ["hashcat_pytest.plugin"]')
  binary = pytester.path / "hashcat-fake"
  inventory = {"CUDAInfo": {"BackendDevices": [{"DeviceID": "01", "MemoryFree": "4096 MB"}]}}
  if cpu is not None:
    inventory["OpenCLInfo"] = {"Platforms": [{"BackendDevices": [
      {"DeviceID": str(cpu), "Type": "CPU", "MemoryFree": "8192 MB"}]}]}
  binary.write_text("#!" + sys.executable + "\n" + '''
import json
import sys
if "-I" in sys.argv:
  print(%r)
raise SystemExit(0)
''' % json.dumps(inventory))
  binary.chmod(0o755)
  pytester.makepyfile(test_bridge='''
from hashcat_pytest import execution, hardware, runtime
SUITE = "bridge"

def test_gpu_bridge(case, run_case):
  def action(args, directory, ledger):
    assert args.device == %r
    assert hardware.bridge_opts(73000) == %r
    options = hardware.with_bridge_opts(["-D", "2", "--backend-devices", "1"], 73000)
    assert ("--backend-devices" in options) == %r
    result = execution.run_command([runtime.BIN])
    ledger.check(result.returncode)
  run_case(action)
''' % ("2" if cpu is None else "1", [] if cpu is None else ["-D", "1", "--backend-devices-virthost", str(cpu)], cpu is None))
  result = pytester.runpytest_subprocess("test_bridge.py", "--hash-modes", "0", "--hashcat-binary", str(binary),
                                       "--require-coverage", "-q")
  result.assert_outcomes(passed=1)


def test_source_only_xdist_needs_no_binary(pytester, monkeypatch):
  monkeypatch.setenv("PYTHONPATH", str(Path(runtime.ROOT, "tests")))
  pytester.makeconftest('pytest_plugins = ["hashcat_pytest.plugin"]')
  pytester.makepyfile('''
from hashcat_pytest import catalog

def test_sources():
  assert 0 in catalog.source_modes()
''')
  result = pytester.runpytest_subprocess("--hashcat-binary", "/no/compiled/hashcat", "-n", "2", "-q")
  result.assert_outcomes(passed=1)


def test_gpu_slots_reused_after_worker_exit(tmp_path):
  class Config:
    _hashcat_seed = "12345"
    _hashcat_resource_dir = str(tmp_path)
    _hashcat_allocations = {}

    def getoption(self, name):
      return {"collectonly": False, "device_type": "gpu", "gpu_strategy": "depth"}[name]

  config = Config()
  # xdist nodes use identity hashing.
  nodes = [type("Node", (), {"config": config})() for unused in range(3)]
  first, second, replacement = nodes
  for node in nodes:
    node.workerinput = {}
  plugin.pytest_configure_node(first)
  plugin.pytest_configure_node(second)
  plugin.pytest_testnodedown(first, RuntimeError("worker exited"))
  plugin.pytest_configure_node(replacement)
  assert second.workerinput["hashcat_gpu_slot"] == 1
  assert replacement.workerinput["hashcat_gpu_slot"] == 0


def test_gpu_alias_memory_uses_selected_physical_device(monkeypatch):
  inventory = hardware.parse_backend_devices(json.dumps({
    "CUDAInfo": {"BackendDevices": [{"DeviceID": "01", "MemoryFree": "4096 MB", "Alias": "02"}]},
    "OpenCLInfo": {"Platforms": [{"BackendDevices": [
      {"DeviceID": "02", "MemoryFree": "4096 MB", "Type": "GPU", "Alias": "01"},
      {"DeviceID": "03", "MemoryFree": "512 MB", "Type": "GPU"}]}]}}))
  monkeypatch.setattr(hardware, "host_avail_mib", lambda: 8192)
  devices = scheduling.physical_devices(inventory, "2", "2")
  assert [device["id"] for device in devices] == [1]
  assert scheduling.memory_limits("2", 2, "2", inventory)["HASHCAT_DEVICE_MEM_LIMIT"] == "2048"


def test_uncapped_retry_blocks_new_readers_while_waiting(tmp_path):
  import fcntl

  directory = tmp_path / "leases"
  ready = tmp_path / "exclusive-ready"
  release = tmp_path / "release"
  script = '''
import sys
import time
from pathlib import Path
from hashcat_pytest import scheduling
directory, ready, release = map(Path, sys.argv[1:])
with scheduling.lease(directory, exclusive=True):
  ready.touch()
  deadline = time.monotonic() + 10
  while release.exists() == False:
    assert time.monotonic() < deadline
    time.sleep(0.01)
'''
  environment = dict(os.environ, PYTHONPATH=str(Path(runtime.ROOT, "tests")))
  writer = None
  try:
    with scheduling.lease(directory):
      writer = subprocess.Popen([sys.executable, "-c", script, str(directory), str(ready), str(release)], env=environment)
      with open(directory / "gate", "a+b") as gate:
        deadline = time.monotonic() + 5
        while True:
          try:
            fcntl.flock(gate, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(gate, fcntl.LOCK_UN)
          except BlockingIOError:
            break
          assert writer.poll() is None
          assert time.monotonic() < deadline, "exclusive retry did not close the reader gate"
          time.sleep(0.01)
      assert ready.exists() == False
    deadline = time.monotonic() + 5
    while ready.exists() == False:
      assert writer.poll() is None
      assert time.monotonic() < deadline
      time.sleep(0.01)
    with open(directory / "resource", "a+b") as resource:
      with pytest.raises(BlockingIOError):
        fcntl.flock(resource, fcntl.LOCK_SH | fcntl.LOCK_NB)
    release.touch()
    assert writer.wait(timeout=5) == 0
    with scheduling.lease(directory):
      pass
  finally:
    if writer is not None and writer.poll() is None:
      writer.kill()
      writer.wait()
