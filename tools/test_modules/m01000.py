#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

import os

from Crypto.Hash import MD4

# Optimized kernels widen each byte while pure kernels decode UTF-8.
# The runner supplies IS_OPTIMIZED so the oracle matches the requested family.

PW_CHARSET = "latin1"

if os.environ.get("IS_OPTIMIZED") == "0":
  PW_CHARSET = "utf-8"

# hashlib has no MD4 wherever OpenSSL ships without the legacy provider, which is most places now.
# pycryptodome carries its own, and tools/install_modules.sh already installs it.


def module_constraints():
  return [[0, 256], [-1, -1], [0, 27], [-1, -1], [-1, -1]]


def module_generate_hash(word, salt, iterations=None):
  utf16le = word.decode(PW_CHARSET).encode("utf-16-le")

  return MD4.new(utf16le).hexdigest()


def module_verify_hash(line):
  idx = line.find(b":")

  if idx < 0:
    return None

  hash_in, word = line[:idx], line[idx + 1:]

  return (module_generate_hash(word, None), word)
