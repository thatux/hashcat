##
## Author......: See docs/credits.txt
## License.....: MIT
##

from hashcat_pytest import containers

SUITE = "containers"


def test_containers(case, run_case):
  def crack(args, directory, result):
    containers.crack_container(args, case.mode, case.width, directory)
    if not result.invocations and not result.problems and not result.omissions:
      result.omissions.append("missing container variant: " + str(case.variant))
  run_case(crack)
