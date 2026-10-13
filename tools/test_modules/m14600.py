#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Test profile: the per-mode test-harness parameters test.py reads instead of hardcoding them.
TEST_PROFILE = {
    # LUKS: the example hash is N/A and lives in external container files, so there is no meaningful
    # self-test crack; the sweep runs it and prints its line but does not count it.
    "no_selftest": True,
}
