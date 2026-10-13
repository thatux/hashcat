#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Test profile: the per-mode test-harness parameters test.py reads instead of hardcoding them.
TEST_PROFILE = {
    # The candidate is the 13 byte RC4 key, the only length the oracle makes, so every multi length
    # slot is pinned to 13. The split keeps a 5 byte head so the hybrid masks still have a tail.
    "multi_min_len": 5,
    "multi_fixed_len": 13,
    "a6_multi_min": 8,      # fixed 13 byte key: start the attack_6 multi where the split stays valid
    "a7_multi_max": 3,      # keep the attack_7 brute-forced head to the shortest window
}
