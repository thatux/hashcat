#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Test profile: the per-mode test-harness parameters test.py reads instead of hardcoding them.
TEST_PROFILE = {
    # MIFARE Ultralight C ships an -a 3 (mask) kernel only, so attack_3 is the only attack its
    # vector is cracked with and every other attack has nothing to run.
    "mask_only": True,
    # MIFARE Ultralight C key recovery is not unique: hashcat may recover a different valid 4 byte
    # key segment than the oracle used. Its crack is scored by the hash appearing in the output
    # followed by a colon, whatever segment was printed with it.
    "match_digest_colon": True,
}
