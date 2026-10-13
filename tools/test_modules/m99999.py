#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Test profile: the per-mode test-harness parameters test.py reads instead of hardcoding them.
TEST_PROFILE = {
    # Plaintext passthrough: the hash is the plaintext itself, so there is no meaningful self-test
    # crack; the sweep runs it and prints its line but does not count it.
    "no_selftest": True,
}
