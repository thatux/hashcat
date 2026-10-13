#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Test profile: the per-mode test-harness parameters test.py reads instead of hardcoding them.
TEST_PROFILE = {
    # Edge: cracks a plaintext other than the one the hash was made from, so the outfile cannot be
    # compared to what the oracle generated.
    "edge_skip_out_match": True,
}
