#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# End-to-end tests for the hash extractors, against the fixtures under tools/2hashcat_tests. Each
# fixture is a real container plus the hash line the extractor should print from it, so this catches
# an extractor that stops parsing a format, which the per-mode crack tests in test.py do not: they
# feed hashcat a hash the oracle made, not one an extractor pulled out of a real artifact.
#
# A fixture is one entry in SPECS: how to build the command for an input container, how to turn the
# extractor's output into the comparable hash line, and how to find the (input, expected) pairs. The
# default pairing is "a file X whose sibling X.hash exists". An extractor that is not installed here
# is reported as a Skip, not a failure, so coverage follows the environment (the tiered-fixture
# approach): a present tool is tested, an absent one is named and skipped.

import importlib.util
import os
import shutil
import subprocess
import sys

TDIR  = os.path.dirname(os.path.abspath(__file__))
TESTS = os.path.join(TDIR, "2hashcat_tests")


def hash_pairs(subdir, suffixes, replace_ext=False):
  # Every input file under the fixture dir whose name ends in one of `suffixes` and has a matching
  # expected-hash file. Two naming conventions are in use: append ".hash" to the whole name (gpg's
  # X.key -> X.key.hash), or replace the suffix with ".hash" (keepass's X.kdbx -> X.hash), picked by
  # replace_ext. Walk so nested layouts (gpg's private-keys-v1.d) are covered.
  pairs = []

  for root, _dirs, files in os.walk(os.path.join(TESTS, subdir)):
    for name in files:
      suffix = next((s for s in suffixes if name.endswith(s)), None)

      if suffix is None:
        continue

      if replace_ext:
        expected = os.path.join(root, name[:-len(suffix)] + ".hash")
      else:
        expected = os.path.join(root, name + ".hash")

      if os.path.isfile(expected):
        pairs.append((os.path.join(root, name), expected))

  return sorted(pairs)


def keepass_argv(src):
  # keepass2john takes the .kdbx, plus -k <keyfile> when the fixture ships one (a sibling .key or
  # .keyfile, named for the withkeyfile variants).
  argv = ["keepass2john", src]

  base = src[:-len(".kdbx")]

  for ext in (".key", ".keyfile"):
    if os.path.isfile(base + ext):
      argv += ["-k", base + ext]
      break

  return argv


def strip_name_field(out):
  # john-style extractors print "<name>:<hash>"; the fixture stores the hash alone. The hash uses
  # '*' as its separator, not ':', so dropping everything up to the first ':' leaves it intact.
  text = out.decode("utf-8", "replace").strip()

  return text.split(":", 1)[1] if ":" in text else text


def plain(out):
  return out.decode("utf-8", "replace").strip()


def sha256_line(out):
  # gitea2hashcat.py prints a banner before the converted hash, so pick the mode-10900 line out.
  for line in out.decode("utf-8", "replace").splitlines():
    if line.startswith("sha256:"):
      return line.strip()

  return ""


def tool(name):
  return os.path.join(TDIR, name)


def container(rel):
  return os.path.join(TDIR, rel)


def argv_from_file(script):
  # The hash-string extractors (gitea) take the hash on the command line, not a file path, so read
  # the fixture file and pass its contents as the argument.
  return lambda src: [sys.executable, tool(script), open(src, encoding="utf-8").read().strip()]


# Fixture specs. "need" is the executable that must be on PATH (or a tools/ script); "cmd" builds the
# argv from the input path; "transform" maps the extractor output to the comparable line; "pairs"
# finds the (input, expected) pairs. Keeping the command per fixture is what lets each extractor's
# own calling convention be expressed.
SPECS = {
  "gpg-ocb-aes": {
    "need": os.path.join(TDIR, "gpg-ocb-aes2hashcat.py"),
    "cmd": lambda src: [sys.executable, os.path.join(TDIR, "gpg-ocb-aes2hashcat.py"), src],
    "transform": plain,
    "pairs": lambda: hash_pairs("gpg-ocb-aes", (".key",)),
  },
  "keepass": {
    "need": "keepass2john",
    "cmd": keepass_argv,
    "transform": strip_name_field,
    "pairs": lambda: hash_pairs("keepass", (".kdbx",), replace_ext=True),
  },
  "gitea": {
    "need": tool("gitea2hashcat.py"),
    "cmd": argv_from_file("gitea2hashcat.py"),
    "transform": sha256_line,
    "pairs": lambda: hash_pairs("gitea", (".giteahash",)),
  },
  "mozilla": {
    "need": tool("mozilla2hashcat.py"),
    "needs_module": "pyasn1",  # mozilla2hashcat.py parses the NSS key DB with pyasn1
    "cmd": lambda src: [sys.executable, tool("mozilla2hashcat.py"), src],
    "transform": plain,  # the hash is on stdout; the detected mode is printed to stderr
    "pairs": lambda: hash_pairs("mozilla", (".db",)),
  },
  "rar3": {
    "need": tool("rar32hashcat.py"),
    "cmd": lambda src: [sys.executable, tool("rar32hashcat.py"), src],
    "transform": plain,  # a single compressed entry yields one $RAR3$ line on stdout
    "pairs": lambda: hash_pairs("rar3", (".rar",)),
  },
}


# Smoke specs: run an extractor on a real container shipped in the tree and check it still produces a
# well-formed hash of the expected shape. This does not pin the exact bytes (the per-mode crack tests
# in test.py already crack these containers end to end), it catches the regression the crack tests
# cannot attribute cleanly: an extractor that stops parsing a format and yields nothing or garbage.
# Each entry is (container path, argv, expected prefix).
SMOKE = {
  "truecrypt": {
    "need": tool("truecrypt2hashcat.py"),
    "cases": [(container("tc_tests/hashcat_ripemd160_aes_boot.tc"),
               lambda p: [sys.executable, tool("truecrypt2hashcat.py"), p], "$truecrypt$")],
  },
  "veracrypt": {
    "need": tool("veracrypt2hashcat.py"),
    "cases": [(container("vc_tests/hashcat_blake2s_aes-twofish-serpent.vc"),
               lambda p: [sys.executable, tool("veracrypt2hashcat.py"), p], "$veracrypt$")],
  },
  "luks": {
    "need": tool("luks2hashcat.py"),
    "cases": [(container("luks_tests/hashcat_ripemd160_aes_cbc-essiv_128.luks"),
               lambda p: [sys.executable, tool("luks2hashcat.py"), p], "$luks$")],
  },
  "cryptoloop": {
    "need": tool("cryptoloop2hashcat.py"),
    "cases": [(container("cl_tests/hashcat_ripemd160_aes_128.img"),
               lambda p: [sys.executable, tool("cryptoloop2hashcat.py"), "--source", p,
                          "--hash", "ripemd160", "--cipher", "aes", "--keysize", "128"],
               "$cryptoapi$")],
  },
  "metamask": {
    "need": tool("metamask2hashcat.py"),
    "cases": [(os.path.join(TESTS, "metamask", "metamask2hashcat.%s.json" % variant),
               lambda p: [sys.executable, tool("metamask2hashcat.py"), "--vault", p],
               "$metamaskMobile$")
              for variant in ("android", "ios")],
  },
}


def have(need):
  if os.path.sep in need:
    return os.path.isfile(need)

  return shutil.which(need) is not None


def run_spec(name, spec):
  if not have(spec["need"]):
    print("[ 2hashcat ] [ %s ] > Skip : extractor %s not present" % (name, spec["need"]))

    return 0

  need_mod = spec.get("needs_module")

  if need_mod and importlib.util.find_spec(need_mod) is None:
    print("[ 2hashcat ] [ %s ] > Skip : Python module %s not installed" % (name, need_mod))

    return 0

  pairs = spec["pairs"]()

  if not pairs:
    print("[ 2hashcat ] [ %s ] > Skip : no fixtures" % name)

    return 0

  ok = bad = 0

  for src, expected in pairs:
    proc = subprocess.run(spec["cmd"](src), stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    got  = spec["transform"](proc.stdout)
    want = open(expected, encoding="utf-8").read().strip()

    if proc.returncode == 0 and got == want:
      ok += 1
    else:
      bad += 1
      print("[ 2hashcat ] [ %s ] > Error : %s did not match %s"
            % (name, os.path.relpath(src, TESTS), os.path.basename(expected)))

  print("[ 2hashcat ] [ %s ] > %s : %d/%d matched" % (name, "OK" if bad == 0 else "Error", ok, ok + bad))

  return bad


def run_smoke(name, spec):
  if not have(spec["need"]):
    print("[ 2hashcat ] [ %s ] > Skip : extractor %s not present" % (name, os.path.basename(spec["need"])))

    return 0

  ok = bad = 0

  for path, argv, prefix in spec["cases"]:
    if not os.path.isfile(path):
      print("[ 2hashcat ] [ %s ] > Skip : container %s not present" % (name, os.path.basename(path)))

      continue

    proc = subprocess.run(argv(path), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out  = proc.stdout.decode("utf-8", "replace").strip()

    if proc.returncode == 0 and out.startswith(prefix):
      ok += 1
    else:
      bad += 1
      print("[ 2hashcat ] [ %s ] > Error : %s did not yield a %s hash"
            % (name, os.path.basename(path), prefix))

  if ok or bad:
    print("[ 2hashcat ] [ %s ] > %s : %d/%d parsed" % (name, "OK" if bad == 0 else "Error", ok, ok + bad))

  return bad


def main():
  names = sys.argv[1:] or (sorted(SPECS) + sorted(SMOKE))
  errors = 0

  for name in names:
    if name in SPECS:
      errors += run_spec(name, SPECS[name])
    elif name in SMOKE:
      errors += run_smoke(name, SMOKE[name])
    else:
      print("[ 2hashcat ] [ %s ] > Skip : no fixture spec" % name)

  sys.exit(1 if errors else 0)


if __name__ == "__main__":
  main()
