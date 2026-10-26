### Hashcat test modules ###

A test module is `mXXXXX.py`, where XXXXX is the hash mode padded to five digits. It provides the
functions `module_constraints`, `module_generate_hash` and `module_verify_hash`.

* `module_constraints` returns the minimum and maximum length of the password, the salt and the
combination of password and salt, in this order: password (pure), salt (pure), password
(optimized), salt (optimized), combination (optimized). A pair is -1, -1 where the field does not
apply, so a mode without a salt sets both salt pairs that way. The last pair matters where the
password and the salt share one kernel buffer, which is typically raw hashes only.
* `module_generate_hash` takes the password as `bytes`, the salt as `str`, and an iteration count
that is None unless the caller pins one. It returns the hash line as `str`, in the exact format
hashcat accepts, or None where the mode cannot produce one for that input.
* `module_verify_hash` takes one line of the cracks file as `bytes`, without the newline, and
returns a `(hash, password)` pair, or None if the line is not one this mode can account for.

The password is `bytes` because it really is arbitrary bytes: it carries multi byte UTF-8, and once
`$HEX[...]` is unwrapped it can be bytes that are not text at all. `tools/test_module_runner.py`
unwraps that notation before a module sees the line, so no module handles it.

During `single` and `passthrough`, `module_generate_hash` generates whatever the hash needs that is
random, a salt for instance. `lib/test_helpers.py` offers `random_hex_string`,
`random_numeric_string`, `random_bytes` and `random_number`, and a module reaches them as
`from lib.test_helpers import random_bytes`. Write your own generator where the mode needs
something those do not cover.

During `verify`, `module_verify_hash` rebuilds the hash out of the hash. Everything the derivation
needs is carried in the string, so the salt, the iteration count and anything else that was drawn
at random are read back from it rather than drawn again. A module that generated a fresh salt here
could never reproduce its own output, and `tools/test_module_runner.py` refuses to print a vector
whose `module_verify_hash` does not round trip it.

A module may also define `module_get_random_password`, which takes the generated password and
returns the one the mode actually needs. That is for a mode whose candidate is a seed phrase, a
challenge response or anything else with a shape of its own rather than a free string.

A module may define `module_hash_identity(hash_str)` when different encodings represent the same hash and hashcat deduplicates them. It returns a hashable value containing the complete effective digest and salt. Verification accepts another encoding only after `module_verify_hash` validates its recovered password and its identity matches a requested hash. For example, `m00501.py` decrypts the wrapping IV and ciphertext to identify the underlying md5crypt value.

Where a family of modes shares a body, it lives in `lib` beside the helpers, and a module reaches
it as `from lib import gpg`.

#### Examples ####

* For a basic unsalted mode, see [m01000.py](m01000.py)
* For a mode whose artifact is a file rather than a hash string, see [m40011.py](m40011.py)
* For a body shared across a family, see [m17010.py](m17010.py) and [lib/gpg.py](lib/gpg.py)
* For a mode that drives its own cipher chaining, see [m20011.py](m20011.py) and
[lib/diskcryptor.py](lib/diskcryptor.py)

#### Test exclusions and verification rules ####

Mode-specific exceptions belong in `module_test_constraints()`, which returns a literal dictionary. The manager and CI planner read it through Python's AST without importing the oracle or its optional dependencies. Each suite (`ordinary`, `edge` or `selftest`) contains attack numbers and their rules. An `all` entry supplies rules shared by every attack in that suite. Every rule needs a nonempty reason. Invalid declarations fail rather than silently removing coverage.

```python
def module_test_constraints():
  return {
    'ordinary': {
      12: {'exclude': 'The hybrid mask fixture cannot express this candidate layout.'},
    },
    'edge': {
      'all': {'verify_output': 'A different valid plaintext can be recovered.'},
    },
  }
```

`exclude` omits an unsupported combination from automatic selection. Explicitly requesting an excluded ordinary attack fails. `exclude_empty` omits an edge mask vector whose candidate disappeared after removing a format prefix. `single_hash` omits multi-target fixtures. `password_only`, `hash_only` and `skip_output` identify which output comparisons are omitted. `verify_output` verifies an alternative result with the oracle instead of accepting it unchecked. `allow_same_salt` records an intentional shared-salt fixture override. `whole_word` marks structured ordinary candidates that require whole-word attacks, and `mask_only` selects the mask kernel for a self-test.

Generate the inventory with `python3 tools/test.py --list-test-exclusions`, or select one mode with `python3 tools/test.py -m 14000 --list-test-exclusions json`. The standalone equivalent is `python3 tools/test_policies.py --mode 14000 --format json`. It includes declarations, unavailable kernel families and shared conditional filters. Conditional rows describe when a fixture is omitted, not proof that it was omitted in a particular run. These are test-selection and verification rules, not permission to ignore runtime errors: memory refusals, timeouts, failed oracles and zero-result runs remain failures.

#### Reproducible runs ####

`HCTEST_SEED` is worth knowing about. Set it, and a run repeats: the same salts, the same passwords,
the same lengths. Leave it unset and the oracle draws at random, which is what the suite wants,
because a mode that only works for one salt is a mode that is broken.

#### Running an oracle inside hashcat ####

`tools/test_bridge.py` loads any oracle into hashcat's Python bridge, so hashcat cracks with the
oracle's own `module_generate_hash`/`module_verify_hash` instead of a kernel. It is a way to exercise
a mode's reference implementation through hashcat's real parser and candidate handling, or to step
through it, with no kernel involved:

    python3 tools/test_bridge.py vectors 1000 /tmp/b.hash /tmp/b.words
    ./hashcat -m 73000 --bridge-parameter1 tools/test_bridge.py /tmp/b.hash /tmp/b.words

The first command writes vectors for a mode (here 1000): `-P` picks the pure family, otherwise
optimized. A bridge line is `sha256(H)*MODE:FAMILY:base64(H)`, where H is the oracle's own hash line.
The bridge splits a line at its first `*` and many hash formats carry one, so H travels base64 encoded
in the salt half and the hash half is a fixed length digest of it; for each candidate the bridge calls
the oracle's `module_verify_hash` to regenerate H and digests the result, which equals the hash half
only when the candidate is the password. A hash line longer than the bridge's 1024 byte salt does not
fit and is skipped, which the `vectors` command reports.

The bridge runs each oracle in an ordinary Python process, so an oracle that imports pycryptodome
works the same as a hashlib-only one, on Linux, macOS and Windows alike. It needs a `python3` on PATH
and nothing else. See
[docs/hashcat-python-plugin-requirements.md](/docs/hashcat-python-plugin-requirements.md).
