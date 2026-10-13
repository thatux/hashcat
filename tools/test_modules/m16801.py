#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Test profile: the per-mode test-harness parameters test.py reads instead of hardcoding them.
TEST_PROFILE = {
    # The recovered line does not carry the hash we started from (WPA PMKID output), so the match is
    # on ":password" alone.
    "match_pass_only": True,
}
