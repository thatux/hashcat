#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Test profile: the per-mode test-harness parameters test.py reads instead of hardcoding them.
TEST_PROFILE = {
    # The oracle's generated password cannot be expressed by the mask attacks, so the mode is
    # treated as slow (SLOW_ALGOS) and run only with the attacks a slow mode runs, not brute
    # forced.
    "fake_slow": True,
}
