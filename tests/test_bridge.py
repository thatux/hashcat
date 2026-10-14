##
## Author......: See docs/credits.txt
## License.....: MIT
##

from pathlib import Path

from hashcat_pytest import execution, oracles, runtime

SUITE = "bridge"


def test_bridge(case, run_case):
  def crack(args, directory, result):
    family = oracles.bridge_family(case.mode)
    assert family is not None, "source mode has no bridge oracle family"
    hashes = str(Path(directory, "bridge.hashes"))
    words = str(Path(directory, "bridge.words"))
    summary = oracles.bridge_vectors(case.mode, family, hashes, words)
    count = summary["written"]
    if count == 0 and summary["too_long"] > 0:
      result.omissions.append("all oracle hashes exceed the bridge's 1024 byte salt limit")
      return
    assert count > 0, "oracle produced no bridge vectors"
    options = [value for value in execution.base_opts(args) if value != "-O"]
    code, output = execution.run_hashcat(options, 73000, hashes, None,
                                         extra=["--bridge-parameter1", str(Path(runtime.TDIR, "test_bridge.py")), words])
    result.check(code)
    if code == 0:
      expected = set(Path(hashes).read_bytes().splitlines())
      assert all(any(line.startswith(digest + b":") for line in output.splitlines()) for digest in expected), "not all bridge hashes recovered"
  run_case(crack)
