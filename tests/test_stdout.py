##
## Author......: See docs/credits.txt
## License.....: MIT
##

from pathlib import Path

from hashcat_pytest import execution, oracles, runtime

SUITE = "stdout"


def test_stdout(case, run_case):
  def check(args, directory, result):
    pairs = oracles.oracle_vectors(case.mode, False)
    assert pairs, "STDOUT oracle produced no vectors"
    expected = b"\n".join(word for word, digest in pairs) + b"\n"
    words = Path(directory, "words")
    words.write_bytes(expected)
    command = [runtime.BIN, "--stdout", "-a", "0"] + runtime.ISOLATION + [str(words)]
    if args.force:
      command.append("--force")
    output = execution.run_command(command)
    assert output.returncode == 0
    assert output.stdout == expected, "STDOUT candidates did not round trip byte for byte"
  run_case(check)
