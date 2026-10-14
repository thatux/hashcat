##
## Author......: See docs/credits.txt
## License.....: MIT
##

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from hashcat_pytest import privileged, runtime

pytestmark = [pytest.mark.framework, pytest.mark.skipif(os.name != "posix", reason="privileged resources need POSIX process and descriptor support")]


FAKE_TOOL = '''
import json
import os
from pathlib import Path
import shutil
import sys
import time

kind = Path(sys.argv[0]).name
args = sys.argv[1:]
if kind == "sudo":
  command = args[1:]
  os.execv(shutil.which(command[0]), command)
directory = Path(os.environ["RESOURCE_TEST_DIR"])
state_file = directory / "devices.json"
state = json.loads(state_file.read_text())

def save():
  state_file.write_text(json.dumps(state))

def allocated():
  (directory / "allocation.pid").write_text(str(os.getpid()))
  (directory / "allocated").touch()
  if os.environ.get("BLOCK_ALLOCATION"):
    while not (directory / "allow-allocation").exists():
      time.sleep(0.01)

def cleaning():
  allocation = directory / "allocation.pid"
  alive = False
  if allocation.exists():
    try:
      stat = Path("/proc", allocation.read_text(), "stat").read_text()
      alive = stat.rpartition(")")[2].split()[0] != "Z"
    except FileNotFoundError:
      pass
  marker = directory / "cleanup-started"
  temporary = marker.with_suffix(".tmp")
  temporary.write_text(json.dumps({"allocation_alive": alive}))
  temporary.replace(marker)
  if os.environ.get("BLOCK_CLEANUP"):
    while not (directory / "allow-cleanup").exists():
      time.sleep(0.01)
  if os.environ.get("FAIL_CLEANUP"):
    sys.stderr.write("simulated cleanup failure")
    raise SystemExit(1)

if kind == "losetup":
  if "--json" in args:
    print(json.dumps({"loopdevices": state["loops"]}))
  elif "--show" in args:
    state["loops"].append({"name": "/dev/loop7", "back-file": args[-1]})
    save()
    allocated()
    print("/dev/loop7")
  elif "--detach" in args:
    cleaning()
    state["loops"] = [row for row in state["loops"] if row["name"] != args[-1]]
    save()
  else:
    raise SystemExit(2)
elif kind == "cryptsetup":
  operation, name = args[0], args[-1]
  if operation == "open":
    state["loops"].append({"name": "/dev/loop7", "back-file": args[-2]})
    state["mappers"][name] = "/dev/loop7"
    save()
    allocated()
  elif operation == "status":
    if name not in state["mappers"]:
      print("/dev/mapper/" + name + " is inactive.")
      raise SystemExit(4)
    print("/dev/mapper/" + name + " is active.\\n  device: " + state["mappers"][name])
  elif operation == "close":
    cleaning()
    del state["mappers"][name]
    save()
  else:
    raise SystemExit(2)
else:
  raise SystemExit(2)
'''


@pytest.fixture
def fake_tools(tmp_path, monkeypatch):
  directory = tmp_path / "bin"
  directory.mkdir()
  for name in ("sudo", "losetup", "cryptsetup"):
    path = directory / name
    path.write_text("#!" + sys.executable + "\n" + FAKE_TOOL)
    path.chmod(0o755)
  state = {"loops": [{"name": "/dev/loop8", "back-file": str(tmp_path / "unrelated.img")}], "mappers": {}}
  (tmp_path / "devices.json").write_text(json.dumps(state))
  monkeypatch.setenv("PATH", str(directory) + os.pathsep + os.environ["PATH"])
  monkeypatch.setenv("RESOURCE_TEST_DIR", str(tmp_path))
  monkeypatch.delenv("CRYPTSETUP_BIN", raising=False)
  monkeypatch.setattr(runtime, "PASS_FDS", ())
  return tmp_path, state


def allocate(kind, image, mapper):
  command = ["sudo", "-n", "cryptsetup", "open", str(image), mapper] if kind == "mapper" else ["sudo", "-n", "losetup", "--show", "-f", str(image)]
  subprocess.run(command, check=True, stdout=subprocess.PIPE, timeout=10)


@pytest.mark.parametrize("kind", ["loop", "mapper"])
def test_normal_privileged_cleanup_preserves_unrelated_devices(fake_tools, kind):
  directory, original = fake_tools
  image = directory / "generated.img"
  image.write_bytes(b"private image")
  mapper = "luksgen%d_512" % os.getpid() if kind == "mapper" else None
  with privileged.resource(kind, image, mapper):
    allocate(kind, image, mapper)
  assert json.loads((directory / "devices.json").read_text()) == original
  record = json.loads(next(directory.glob(".resource-*.json")).read_text())
  assert record["state"] == "cleaned"
  assert record["commands"]
  assert all("stdout_b64" in command and "stderr_b64" in command for command in record["commands"])
  assert runtime.PASS_FDS == ()


WORKER = '''
import os
from pathlib import Path
import sys
from hashcat_pytest import privileged, runtime, scheduling, tooling
directory = Path(os.environ["RESOURCE_TEST_DIR"])
kind = sys.argv[1]
image = directory / "generated.img"
image.write_bytes(b"private image")
mapper = "luksgen%d_512" % os.getpid() if kind == "mapper" else None
with scheduling.lease(directory / "leases", exclusive=True) as descriptors:
  runtime.PASS_FDS = descriptors
  with privileged.resource(kind, image, mapper):
    command = ["sudo", "-n", "cryptsetup", "open", str(image), mapper] if kind == "mapper" else ["sudo", "-n", "losetup", "--show", "-f", str(image)]
    result = tooling.run(command)
    assert result.returncode == 0
    print("ready", flush=True)
    sys.stdin.readline()
'''


def await_file(path):
  deadline = time.monotonic() + 10
  while not path.exists() and time.monotonic() < deadline:
    time.sleep(0.01)
  assert path.exists(), str(path)


def await_cleanup(directory):
  deadline = time.monotonic() + 10
  while time.monotonic() < deadline:
    path = next(directory.glob(".resource-*.json"))
    record = json.loads(path.read_text())
    if record["state"] != "watching":
      assert record["state"] == "cleaned", record
      return
    time.sleep(0.01)
  pytest.fail("privileged watchdog did not finish cleanup")


@pytest.mark.parametrize("kind", ["loop", "mapper"])
@pytest.mark.parametrize("allocation_in_flight", [False, True])
def test_worker_death_cleans_resources_before_releasing_lease(fake_tools, monkeypatch, kind, allocation_in_flight):
  if sys.platform.startswith("linux") == False:
    pytest.skip("SIGKILL process liveness check needs Linux procfs")
  import fcntl

  directory, original = fake_tools
  monkeypatch.setenv("BLOCK_CLEANUP", "1")
  if allocation_in_flight:
    monkeypatch.setenv("BLOCK_ALLOCATION", "1")
  environment = dict(os.environ, PYTHONPATH=str(Path(runtime.ROOT, "tests")))
  worker = subprocess.Popen([sys.executable, "-c", WORKER, kind], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
  try:
    await_file(directory / "allocated")
    if allocation_in_flight == False:
      assert worker.stdout.readline() == b"ready\n"
    status = json.loads(next(directory.glob(".resource-*.json")).read_text())
    os.kill(status["pid"], signal.SIGTERM)
    worker.kill()
    worker.wait(timeout=10)
    await_file(directory / "cleanup-started")
    assert json.loads((directory / "cleanup-started").read_text())["allocation_alive"] == False
    with (directory / "leases" / "resource").open("a+b") as resource_fd:
      with pytest.raises(BlockingIOError):
        fcntl.flock(resource_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
      (directory / "allow-cleanup").touch()
      await_cleanup(directory)
      deadline = time.monotonic() + 10
      while True:
        try:
          fcntl.flock(resource_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
          break
        except BlockingIOError:
          assert time.monotonic() < deadline
          time.sleep(0.01)
    assert json.loads((directory / "devices.json").read_text()) == original
  finally:
    (directory / "allow-cleanup").touch()
    (directory / "allow-allocation").touch()
    if worker.poll() is None:
      worker.kill()
      worker.wait(timeout=10)
    worker.communicate(timeout=10)


def test_failed_privileged_cleanup_is_an_error(fake_tools, monkeypatch):
  directory, original = fake_tools
  image = directory / "generated.img"
  image.write_bytes(b"private image")
  monkeypatch.setenv("FAIL_CLEANUP", "1")
  with pytest.raises(RuntimeError, match="simulated cleanup failure"):
    with privileged.resource("loop", image):
      allocate("loop", image, None)
  record = json.loads(next(directory.glob(".resource-*.json")).read_text())
  assert record["state"] == "failed"
  assert original["loops"][0] in json.loads((directory / "devices.json").read_text())["loops"]


def test_mapper_cleanup_rejects_an_unrelated_backing_file(fake_tools):
  directory, original = fake_tools
  image = directory / "generated.img"
  image.write_bytes(b"private image")
  mapper = "luksgen%d_512" % os.getpid()
  state = dict(original, mappers={mapper: "/dev/loop8"})
  (directory / "devices.json").write_text(json.dumps(state))
  with pytest.raises(RuntimeError, match="backing file does not match"):
    with privileged.resource("mapper", image, mapper):
      pass
  assert json.loads((directory / "devices.json").read_text()) == state


def test_privileged_watchdog_rejects_files_outside_active_case(fake_tools, monkeypatch):
  directory, original = fake_tools
  image = directory / "unrelated.img"
  image.write_bytes(b"unrelated file")
  case_directory = directory / "case"
  case_directory.mkdir()
  monkeypatch.setattr(runtime, "ACTIVE", SimpleNamespace(directory=case_directory))
  with pytest.raises(ValueError, match="private case directory"):
    with privileged.resource("loop", image):
      pytest.fail("watchdog accepted an unrelated file")
  assert list(directory.glob(".resource-*.json")) == []
  assert json.loads((directory / "devices.json").read_text()) == original
