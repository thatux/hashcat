#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Test profile: the per-mode test-harness parameters test.py reads instead of hardcoding them.
TEST_PROFILE = {
    # SAP CODVN B caps the password at 8 bytes, so the attack_6 and attack_7 multi length windows
    # stop at 8 rather than the default 9.
    "a6_multi_max": 8,
    "a7_multi_max": 8,
}
