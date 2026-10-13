#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Test profile: the per-mode test-harness parameters test.py reads instead of hardcoding them.
TEST_PROFILE = {
    # Collider #1: the candidate is the 5 byte RC4 key, the only length the oracle makes. Without a
    # fixed length every multi slot but one asks for a length the mode has no vector for, so the
    # multi run feeds hashcat an empty hash file (and, once the empty tail mask is dropped, no mask
    # either, which hashcat rejects). Pin every length slot to 5.
    "multi_fixed_len": 5,
}
