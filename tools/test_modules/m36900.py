#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Test profile: the per-mode test-harness parameters test.py reads instead of hardcoding them.
TEST_PROFILE = {
    # The candidate is the 8 byte iClass master key, the only length the oracle makes, so every
    # multi length slot is pinned to it or the multi run feeds hashcat an empty hash file.
    "multi_fixed_len": 8,
}
