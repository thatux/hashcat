#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Finite candidate-feed fixtures and independent MD5 checks for tools/test.py --feeds.

import hashlib
import itertools
import os
from dataclasses import dataclass
from pathlib import Path


FEEDS = ("stdin", "wordlist", "mask", "hybrid", "pcfg", "table", "association", "random", "rust_random", "prince")


@dataclass
class Case:
  name: str
  feed: str
  attack: int
  words: tuple
  arguments: tuple
  stdin: bytes = b""
  mode: int = 0
  usernames: tuple = ()
  expected: tuple = None
  options: tuple = ()
  device: bool = False


def random_words(count):
  state = 0x2545f4914f6cdd1d
  mask = (1 << 64) - 1
  alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789"

  def rand():
    nonlocal state
    state ^= state >> 12
    state ^= (state << 25) & mask
    state ^= state >> 27
    return (state * 0x2545f4914f6cdd1d) & mask

  words = []

  for _ in range(count):
    length = 6 + rand() % 8
    words.append(bytes(alphabet[rand() % len(alphabet)] for _ in range(length)))

  return words


def cases(directory, root):
  directory = Path(directory)

  def write(name, data):
    path = directory / name
    path.write_bytes(data)
    return str(path)

  words = (b"alpha", b"beta")
  wordlist = write("words.txt", b"\n".join(words) + b"\n")
  left = write("left.txt", b"ab\nxy\n")
  right = write("right.txt", b"cd\nzz\n")
  rule = write("append.rule", b"$!\n")

  yield Case("stdin", "stdin", 0, words, (), b"alpha\nbeta\n")
  yield Case("wordlist", "wordlist", 8, words, ("wordlist", wordlist))
  yield Case("wordlist-reject", "wordlist", 8, (b"gamma",), ("wordlist", wordlist), expected=())
  yield Case("mask-rules", "mask", 3, (b"base0!", b"base1!"), ("base?1",), options=("-1", "01", "-r", rule))

  lhs = (b"ab", b"xy")
  rhs = (b"cd", b"zz")
  digits = (b"0", b"1")
  opts = ("-1", "01", "-r", rule)
  yield Case("combinator-rules", "hybrid", 1, tuple(a + b + b"!" for a, b in itertools.product(lhs, rhs)), (left, right), options=("-r", rule))
  yield Case("hybrid-right-rules", "hybrid", 6, tuple(a + b + b"!" for a, b in itertools.product(lhs, digits)), (left, "?1"), options=opts)
  yield Case("hybrid-left-rules", "hybrid", 7, tuple(a + b + b"!" for a, b in itertools.product(digits, lhs)), ("?1", left), options=opts)
  yield Case("hybrid-two-wordlists-rules", "hybrid", 12, tuple(a + b + c + b"!" for a, b, c in itertools.product(digits, lhs, rhs)), ("?1?w?q", left, right), options=opts)

  grammar = directory / "pcfg"
  (grammar / "Grammar").mkdir(parents=True)
  (grammar / "Context").mkdir()
  (grammar / "Grammar" / "grammar.txt").write_bytes(b"X1\t1.0\n")
  (grammar / "Context" / "1.txt").write_bytes(b"alpha\t0.5\nbeta\t0.5\n")

  table_words = write("table-words.txt", b"ab\n")
  table = write("substitutions.txt", b"a\t@\nb\tB\nb\tbb\n")
  prince_words = write("prince-words.txt", b"a\nb\n")

  for suffix, options in (("", ()), ("-host", ("--slow-candidates",))):
    yield Case("pcfg" + suffix, "pcfg", 8, words, ("pcfg", str(grammar)), options=options, device=not options)
    yield Case("table" + suffix, "table", 5, (b"ab", b"aB", b"abb", b"@b", b"@B", b"@bb"), (table_words, table), options=options, device=not options)
    yield Case("prince" + suffix, "prince", 10, (b"aa", b"ab", b"ba", b"bb"), (prince_words, "pw-min=2", "pw-max=2", "elem-cnt-min=2", "elem-cnt-max=2"), options=options, device=not options)

  yield Case("table-no-identity", "table", 5, (b"@B", b"@bb", b"ab"), (table_words, table, "identity=0"), expected=(b"@B", b"@bb"), device=True)
  longest = write("longest.txt", b"a\tz\nab\tx\nab\tyz\n")
  yield Case("table-longest-match", "table", 5, (b"x", b"yz", b"zb"), (table_words, longest, "identity=0"), expected=(b"x", b"yz"), device=True)
  utf8_words = write("utf8.txt", b"\xc3\xa9b\n")
  utf8_table = write("utf8-table.txt", b"\xc3\xa9\tE\nb\tB\n")
  yield Case("table-utf8-source", "table", 5, (b"EB",), (utf8_words, utf8_table, "identity=0"), device=True)

  usernames = (b"alice", b"bob")
  yield Case("association-words", "association", 9, usernames, ("phases=words", "words.hints=1"), mode=10, usernames=usernames)
  yield Case("association-rules", "association", 9, (b"alice!", b"bob!"), ("phases=rules", "rules.rulefile=" + rule, "rules.rulemax=1", "rules.hints=1"), mode=10, usernames=usernames)

  random = random_words(8)
  extension = ".dll" if os.name == "nt" else ".so"

  for feed, plugin in (("random", "random"), ("rust_random", str(Path(root) / "feeds" / ("rust_random" + extension)))):
    yield Case(feed, feed, 8, (random[0], random[7]), (plugin,), options=("--limit", "8"))
    yield Case(feed + "-seek", feed, 8, (random[3], random[7]), (plugin,), options=("--skip", "3", "--limit", "5"))


def run(directory, root, selected, opts, run_hashcat, report):
  passed = 0
  total = 0

  for case in cases(directory, root):
    if case.feed not in selected:
      continue

    total += 1
    target = Path(directory) / (case.name + ".hashes")
    outfile = Path(directory) / (case.name + ".out")
    lines = []

    for index, word in enumerate(case.words):
      if case.mode == 10:
        salt = ("salt%d" % index).encode("ascii")
        digest = hashlib.md5(word + salt).hexdigest().encode("ascii")
        lines.append(case.usernames[index] + b":" + digest + b":" + salt)
      else:
        lines.append(hashlib.md5(word).hexdigest().encode("ascii"))

    target.write_bytes(b"\n".join(lines) + b"\n")
    # MD5's device candidate engine has a pure kernel only.
    options = [option for option in opts if not (case.device and option == "-O")]
    engine = None

    if case.feed in ("pcfg", "table", "prince"):
      # Keep the feed's engine announcement so a host fallback cannot pass as device coverage.
      options = [option for option in options if option != "--quiet"]
      engine = "device" if case.device else "host"

    options += ["--outfile", str(outfile), "--outfile-format", "3"] + list(case.options)
    expected = set(case.words if case.expected is None else case.expected)
    expected_rc = 0 if expected == set(case.words) else 1

    try:
      rc, output = run_hashcat(options, case.mode, str(target), case.stdin, attack=case.attack, extra=case.arguments)
      recovered = [bytes.fromhex(line) for line in outfile.read_text(encoding="ascii").splitlines()] if outfile.exists() else []
      ok = rc == expected_rc and set(recovered) == expected and len(recovered) == len(expected)
      reason = "rc=%d, recovered %d/%d" % (rc, len(recovered), len(expected))

      if engine is not None:
        prefix = "%s: %s engine," % (case.feed, engine)

        if case.feed == "pcfg" and case.device:
          prefix = "pcfg: device engine il="

        announced = any(line.strip().startswith(prefix.encode("ascii")) for line in output.splitlines())
        ok = ok and announced
        reason += ", %s engine %s" % (engine, "confirmed" if announced else "unconfirmed")

      if not ok:
        print(output.decode("utf-8", "replace"))
    except (OSError, ValueError) as exc:
      ok = False
      reason = str(exc)

    verdict = "OK" if ok else "Error"
    passed += int(ok)
    family = "optimized" if "-O" in options else "pure"
    report(verdict, "[ test.py feeds ] [ %s, %s ] > %s : %s" % (case.name, family, verdict, reason))

  print("[ test.py feeds ] > %d/%d cases passed" % (passed, total))
  return 0 if total and passed == total else 1
