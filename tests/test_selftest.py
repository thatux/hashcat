##
## Author......: See docs/credits.txt
## License.....: MIT
##

from hashcat_pytest import execution, selftest, verification

SUITE = "selftest"


def test_selftest(case, run_case):
  def crack(args, directory, result):
    path, digest, expected, pass_only, extra = selftest.prepare(case.mode, case.attack, directory)
    code, output = execution.run_hashcat(execution.selftest_opts(args), case.mode, path, None,
                                         attack=case.attack, extra=extra)
    result.check(code)
    assert code != 0 or verification.output_has_crack(case.mode, output, expected, digest.decode("ascii"), pass_only, directory)
  run_case(crack)
