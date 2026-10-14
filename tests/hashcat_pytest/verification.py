##
## Author......: See docs/credits.txt
## License.....: MIT
##

import os
import re
import sys

from . import catalog, runtime, tooling


def match_search(digest, word, pass_only):
  if pass_only:
    return b":" + word
  return digest.encode("ascii") + b":" + word


def run_verify(mode, digest, crack_lines, tmp):
  hashes_file = os.path.join(tmp, "m%05d_verify_hashes" % mode)
  cracks_file = os.path.join(tmp, "m%05d_verify_cracks" % mode)
  out_file    = os.path.join(tmp, "m%05d_verify_out" % mode)
  with open(hashes_file, "wb") as fh:
    fh.write(digest.encode("ascii") + b"\n")
  with open(cracks_file, "wb") as fh:
    for line in crack_lines:
      fh.write(line + b"\n")
  open(out_file, "wb").close()
  result = tooling.run([sys.executable, runtime.RUNNER, "verify", str(mode), hashes_file, cracks_file, out_file], timeout=400)
  if result.returncode != 0:
    raise RuntimeError("oracle verification failed: " + result.stderr.decode("utf-8", "replace"))
  return os.path.getsize(out_file) > 0


def output_has_crack(mode, out, word, digest, pass_only, tmp):
  if match_search(digest, word, pass_only) in out:
    return True
  if catalog.edge_hexify_plain(mode):
    if match_search(digest, word.hex().encode("ascii"), pass_only) in out:
      return True
  if mode in catalog.MFULC_MODES:
    if digest.encode("ascii") + b":" in out:
      return True
  if pass_only:
    if b":$HEX[" + word.hex().encode("ascii") + b"]" in out:
      return True
    return False
  prefix = digest.encode("ascii") + b":"
  crack_lines = [line.rstrip(b"\r").rsplit(b"\r", 1)[-1] for line in out.split(b"\n") if prefix in line]
  if not crack_lines:
    return False
  return run_verify(mode, digest, crack_lines, tmp)


def edge_echo_norm(data):
  return b" ".join(data.split())


def edge_sort_lines(data):
  lines = data.split(b"\n")
  if lines and lines[-1] == b"":
    lines.pop()
  return sorted(lines)


def edge_strip_userpw(data):
  return re.sub(rb"    \(user password[^\n]*", b"", data)
