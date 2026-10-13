#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Test profile: the per-mode test-harness parameters test.py reads instead of hardcoding them.
TEST_PROFILE = {
    # STDOUT has an empty kernel and never cracks, so the self-test sweep runs it and prints its
    # line but does not count it as cracked or as a failure.
    "no_selftest": True,
    # and edge-cracking it only produces errors, so the edge suite skips it outright.
    "edge_skip": True,
}
