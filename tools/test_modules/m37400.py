#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Test profile: the per-mode test-harness parameters test.py reads instead of hardcoding them.
TEST_PROFILE = {
    # pw_min is 9 (module_constraints [9, 100]), so a length slot below it produces no vector and the
    # multi run would feed hashcat an empty hash file. Pin every slot to 9, and push the split toward
    # the tail (offset 4) so the mask the hybrid runs brute force stays one digit: the slot the
    # a6/a12 multi runs has a head of 8 of the 9 bytes, still leaving a one byte tail, since an empty
    # mask would drop the argument and fail the run.
    "multi_min_len": 4,
    "multi_fixed_len": 9,
    # pw_min 9: run only the longest slot (head 8 of the 9 bytes, one digit in the attack_6 mask) so
    # the hybrid does not brute force a long run of digits over a slow DES hash.
    "a6_multi_min": 8,
    "a7_multi_max": 3,      # keep the attack_7 brute-forced head to the shortest window
}
