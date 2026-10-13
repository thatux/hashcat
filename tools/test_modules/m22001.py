#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Test profile: the per-mode test-harness parameters test.py reads instead of hardcoding them.
TEST_PROFILE = {
    # Edge: writes the handshake parts rather than hash and plaintext, so the outfile cannot be
    # compared to what the oracle generated.
    "edge_skip_out_match": True,
    # The hash line is handed to hashcat as is (the handshake record), not base64-decoded into
    # a file the way a binary-hashfile mode is.
    "decode_hashfile_raw": True,
}
