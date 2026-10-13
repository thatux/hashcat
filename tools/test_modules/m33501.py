#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Test profile: the per-mode test-harness parameters test.py reads instead of hardcoding them.
TEST_PROFILE = {
    # The candidate is the 9 byte RC4 key, the only length the oracle makes, so every multi length
    # slot is pinned to 9. The split keeps a 5 byte head so the hybrid masks still have a tail.
    "multi_min_len": 5,
    "multi_fixed_len": 9,
    # The candidate is only a few characters once a multibyte byte is folded in, so a head of 8
    # would cover the whole word and leave the attack_6 mask empty. Start the multi at slot 5 so the
    # head stays short enough that every slot still has a tail for the mask.
    "a6_multi_min": 5,
    "a7_multi_max": 3,      # keep the attack_7 brute-forced head to the shortest window
}
