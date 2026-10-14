##
## Author......: See docs/credits.txt
## License.....: MIT
##

from pathlib import Path

import pytest

from hashcat_pytest import catalog, containers, generated, runtime

SUITE = "generated"


@pytest.mark.generated
@pytest.mark.requires_external_tools
def test_generated(case, run_case, request):
  if case.mode in catalog.GEN_SUDO_MODES and request.config.getoption("allow_privileged") == False:
    if request.config.getoption("require_coverage"):
      pytest.fail("container generator requires --allow-privileged")
    pytest.skip("container generator requires --allow-privileged")

  def crack(args, directory, result):
    runtime.GEN_PURE = args.pure
    previous = {name: getattr(runtime, name) for name in
                ("CONTAINER_PASSWORD", "TC_TESTS_DIR", "VC_TESTS_DIR", "LUKS_TESTS_DIR", "LUKS2_TESTS_DIR")}
    runtime.CONTAINER_PASSWORD = generated.gen_password_string()
    assert runtime.CONTAINER_PASSWORD, "password generator returned no password"
    for name in previous:
      if name.endswith("_TESTS_DIR"):
        setattr(runtime, name, str(Path(directory, name.lower())))
    try:
      if case.mode in catalog.CONTAINER_GEN_MODES:
        generated.generate_containers(args, case.mode, directory)
        containers.crack_container(args, case.mode, case.width, directory)
      else:
        generated.run_generate_archive(args, case.mode, directory)
    finally:
      for name, value in previous.items():
        setattr(runtime, name, value)
  run_case(crack)
