#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Test profile: the per-mode test-harness parameters test.py reads instead of hardcoding them.
TEST_PROFILE = {
    # Run as a fast hash on purpose, to cover the AMP kernel, even though its slow-hash cost would
    # otherwise put it on the slow-mode attack path.
    "force_fast": True,
}
