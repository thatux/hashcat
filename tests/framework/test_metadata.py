##
## Author......: See docs/credits.txt
## License.....: MIT
##

import json
from pathlib import Path
import subprocess

import pytest

from hashcat_pytest import catalog, runtime

pytestmark = pytest.mark.framework


def test_source_capabilities_match_compiled_inventory(request):
  binary = Path(request.config.getoption("hashcat_binary"))
  if binary.is_file() == False:
    pytest.skip("compiled metadata audit needs a hashcat binary")
  result = subprocess.run([str(binary.resolve()), "--quiet", "--hash-info", "--machine-readable"],
                          cwd=runtime.ROOT, capture_output=True, timeout=60)
  assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
  rows = json.loads(result.stdout)
  assert set(map(int, rows)) == set(catalog.source_modes())
  differences = []
  for number, row in rows.items():
    facts = catalog.source_capabilities(int(number))
    for source, compiled in (("kernel_types", "kernel_type"), ("slow", "slow_hash"), ("deprecated", "is_deprecated")):
      if facts[source] != row[compiled]:
        differences.append((int(number), source, facts[source], row[compiled]))
  assert differences == []
