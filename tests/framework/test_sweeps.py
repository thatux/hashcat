##
## Author......: See docs/credits.txt
## License.....: MIT
##

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from hashcat_pytest import runtime

pytestmark = pytest.mark.framework


@pytest.mark.parametrize("status,expected", [(0, 0), (1, 1), (5, 1), (124, 1)])
def test_asan_sweep_preserves_specialized_suites_and_failures(tmp_path, status, expected):
  binary = tmp_path / "hashcat"
  binary.write_text("#!/bin/sh\nexit 0\n")
  binary.chmod(0o755)
  directory = tmp_path / "bin"
  directory.mkdir()
  python = directory / "python3"
  python.write_text("#!" + sys.executable + "\n" + '''
import json
import os
from pathlib import Path
import sys
with Path(os.environ["SWEEP_RECORD"]).open("a") as output:
  output.write(json.dumps(sys.argv[1:]) + "\\n")
raise SystemExit(int(os.environ["SWEEP_RC"]))
''')
  python.chmod(0o755)
  record = tmp_path / "commands.jsonl"
  environment = dict(os.environ, PATH=str(directory) + os.pathsep + os.environ["PATH"],
                     SWEEP_RECORD=str(record), SWEEP_RC=str(status))
  command = ["bash", str(Path(runtime.TDIR, "asan", "gpu_sweep.sh")), "--modes", "2000 14600 34100"]
  result = subprocess.run(command, cwd=tmp_path, env=environment, capture_output=True, timeout=20)
  assert result.returncode == expected, result.stderr
  commands = [json.loads(line) for line in record.read_text().splitlines()]
  assert len(commands) == 3
  for command in commands:
    assert {"tests/test_cracking.py", "tests/test_containers.py", "tests/test_stdout.py"} <= set(command)
    assert "--require-coverage" in command
  log = (tmp_path / "asan-gpu-sweep" / "sweep.log").read_text()
  assert (": clean" in log) == (status == 0)
