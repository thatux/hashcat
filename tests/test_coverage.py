##
## Author......: See docs/credits.txt
## License.....: MIT
##

import pytest

from hashcat_pytest import catalog

SUITE = "coverage"


@pytest.mark.coverage
def test_coverage():
  containers = catalog.CONTAINER_MODES - catalog.CL_MODES | {14500}
  covered = set(catalog.discover_modes()) | containers | catalog.SELFTEST_MODES
  missing = set(catalog.source_modes()) - covered - set(catalog.COVERAGE_UNTESTABLE)
  orphaned = containers - set(catalog.source_modes())
  assert not missing, "modes need an oracle or documented exclusion: %s" % sorted(missing)
  assert not orphaned, "container catalog contains missing modules: %s" % sorted(orphaned)
