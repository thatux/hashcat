#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Test profile: the per-mode test-harness parameters test.py reads instead of hardcoding them.
TEST_PROFILE = {
    # LM caps the password at 7 bytes (module_constraints [1, 7]), so the attack_6 and attack_7
    # multi length windows stop at 8 rather than the default 9.
    "a6_multi_max": 8,
    "a7_multi_max": 8,
    # Lengths 2 through 7 give 6 distinct multi length slots, so the attack_1 multi batch covers 6.
    "combinator_multi_offset": 6,
}
