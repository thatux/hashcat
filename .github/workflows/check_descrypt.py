#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# test-intel-qnx.yml uses these libcrypt vectors to validate DES on Intel CPU OpenCL.

import argparse
import ctypes
import ctypes.util
import json
from pathlib import Path
import subprocess

from check_qnx_sha512 import cpu_device


def crypt_function():
  library = ctypes.CDLL(ctypes.util.find_library("crypt") or "libcrypt.so.1")
  function = library.crypt
  function.argtypes = (ctypes.c_char_p, ctypes.c_char_p)
  function.restype = ctypes.c_char_p
  return function


def fixtures(crypt):
  alphabet = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
  salt_bits = [0, 4095] + [1 << bit for bit in range(12)] + [4095 ^ (1 << bit) for bit in range(12)]
  salts = [bytes((alphabet[value & 63], alphabet[value >> 6])) for value in salt_bits]
  words = [bytes(range(33, 33 + length)) for length in range(9)]
  words += [b"hashcat", b"password", b"12345678", b"A\nB", b"\x80\xffAa", "\u00e9\U0001f600".encode("utf-8")]
  targets = {crypt(word, salt).decode("ascii"): word for salt in salts for word in words}
  if crypt(b"hashcat", b"24") != b"24leDr0hHfb3A":
    raise RuntimeError("libcrypt does not implement the published DES vector")
  targets["24leDr0hHfb3A"] = b"hashcat"
  return words, targets


def check(binary, directory, command, expected, crypt):
  (directory / "cache").mkdir()
  outfile = directory / "cracked.txt"
  command = [str(binary)] + command + ["--potfile-disable", "--logfile-disable", "--restore-disable",
            "--outfile-format", "1,3", "--outfile", str(outfile), "--cache-path", str(directory / "cache")]
  (directory / "command.json").write_text(json.dumps(command, indent=2) + "\n")
  result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=240)
  (directory / "console.log").write_bytes(result.stdout + result.stderr)
  recovered = [line.split(":", 1) for line in outfile.read_text().splitlines()] if outfile.exists() else []
  valid = all(crypt(bytes.fromhex(word), value[:2].encode("ascii")) == value.encode("ascii") for value, word in recovered)
  passed = result.returncode == (0 if expected else 1) and {value for value, _ in recovered} == expected and len(recovered) == len(expected) and valid
  report = {"returncode": result.returncode, "recovered": len(recovered), "expected": len(expected), "passed": passed}
  (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")
  print(directory.name, json.dumps(report), flush=True)
  if not passed:
    print((result.stdout + result.stderr).decode("utf-8", "replace"), flush=True)
  return passed


def main():
  parser = argparse.ArgumentParser(description="Check DES salt bits, password lengths and byte inputs on Intel CPU OpenCL")
  parser.add_argument("--diagnostic-force", action="store_true", help="bypass the existing runtime exclusion for diagnosis")
  parser.add_argument("--output", type=Path, default=Path("descrypt-intel-results"))
  args = parser.parse_args()
  args.output.mkdir()
  binary = Path("hashcat").resolve()
  device = cpu_device(binary, args.output)
  crypt = crypt_function()
  words, targets = fixtures(crypt)
  hashes = args.output.resolve() / "hashes.txt"
  hashes.write_text("\n".join(targets) + "\n")
  opts = ["-m", "1500", "-D", "1", "-d", str(device)]
  if args.diagnostic_force:
    opts.append("--force")
  results = []
  for label, candidates, expected in (("forward", words, set(targets)), ("reverse", words[::-1], set(targets)), ("negative", [b"wrong"], set())):
    directory = args.output / label
    directory.mkdir()
    wordfile = directory.resolve() / "words.hex"
    wordfile.write_text("\n".join(word.hex() for word in candidates) + "\n")
    results.append(check(binary, directory, opts + ["-a", "0", "--hex-wordlist", str(hashes), str(wordfile)], expected, crypt))
  for label, selected in (("single-salt-mask", ["24leDr0hHfb3A"]), ("multi-salt-mask", [value for value, word in targets.items() if word == b"hashcat"])):
    directory = args.output / label
    directory.mkdir()
    hashfile = directory.resolve() / "hashes.txt"
    hashfile.write_text("\n".join(selected) + "\n")
    results.append(check(binary, directory, opts + ["-a", "3", "--hex-charset", str(hashfile), b"hashcat".hex()], set(selected), crypt))
  return 0 if all(results) else 1


if __name__ == "__main__":
  raise SystemExit(main())
