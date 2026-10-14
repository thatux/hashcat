##
## Author......: See docs/credits.txt
## License.....: MIT
##

import pytest

from hashcat_pytest import attacks, catalog, execution, oracles, selftest, verification

SUITE = "cracking"


def execute_invocations(plan, result):
  for step in plan:
    if isinstance(step, attacks.Summary):
      result.summaries.append(dict(step.counts))
      continue
    if isinstance(step, attacks.Omission):
      result.omissions.append(step.reason)
      continue
    assert isinstance(step, attacks.Invocation), "unknown attack plan step"
    code, output = execution.run_hashcat(step.options, step.mode, step.target, step.stdin,
                                         attack=step.attack, extra=step.extra)
    context = step.context
    matched = False
    if code == 0 or context.verify_on_error:
      matched = all(verification.output_has_crack(step.mode, output, word, digest, context.pass_only,
                                                  context.directory) for word, digest in step.expected)
    verdict = 10 if code == 0 and matched == False else code
    counts = context.counts
    counts["cnt"] += 1
    if verdict != 0:
      field = {1: "nf", 4: "to", 10: "nm"}.get(verdict, "rs" if verdict == 30 or 246 <= verdict <= 253 else "err")
      counts[field] += 1
    result.check(verdict)


def test_cracking(case, run_case):
  def crack(args, directory, result):
    if case.variant == "selftest":
      path, digest, password, pass_only, extra = selftest.prepare(case.mode, case.attack, directory)
      options = execution.base_opts(args) + ["--backend-vector-width", str(case.width)]
      counts = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0, "err": 0}
      step = attacks.invocation(options, case.mode, path, None, [(password, digest.decode("ascii"))],
                                counts, pass_only, directory, attack=case.attack, extra=extra)
      execute_invocations([step, attacks.Summary(counts)], result)
      return
    pairs = oracles.oracle_vectors(case.mode, case.kernel == "optimized")
    if pairs is None:
      pytest.skip("oracle has no %s kernel family" % case.kernel)
    assert pairs, "oracle returned no vectors"
    options = execution.base_opts(args) + ["--backend-vector-width", str(case.width)]
    file_only = catalog.is_file_only(case.mode)
    run = attacks.Run(args, case.mode, pairs, case.width, options, [case.target], file_only,
                      file_only or case.mode in catalog.NOCHECK_ENCODING, directory)
    execute_invocations(attacks.ATTACKS[case.attack](run), result)
  run_case(crack)
