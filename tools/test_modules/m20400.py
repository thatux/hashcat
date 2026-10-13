#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Test profile: the per-mode test-harness parameters test.py reads instead of hardcoding them.
TEST_PROFILE = {
    # -HH reports same-salt is not allowed for this mode, but the edge suite runs it with a
    # shared salt anyway (test_edge.sh SKIP_SAME_SALT_HASH_TYPES).
    "edge_skip_same_salt": True,
}
