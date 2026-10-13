#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Test profile: the per-mode test-harness parameters test.py reads instead of hardcoding them.
TEST_PROFILE = {
    # PKZIP master key, 6 byte optimization: hashcat is fed the key without its first 6 bytes and
    # reconstructs the whole password in the crack line. Every attack cuts the candidate by this
    # offset, and the harness still matches the recovered full word against it.
    "strip": 6,
    # attack_1 single index batch starts at 2: init() left the length 1 line out, so a hash's dict
    # line trails its index by one and the batch has to begin past that.
    "combinator_single": [2, 8],
    # attack_3 needs at least two '?d' groups left after the 6 byte cut, so the shortest mask index
    # that still spells a valid candidate is 2.
    "a3_min_groups": 2,
    # Only a single hash test exists, so a forced multi run is skipped and the edge suite loads at
    # most one hash for this mode.
    "single_only": True,
    # The hybrid and combinator runs rebuild the stripped candidate with the PKZIP master-key dict
    # construction (pkzip_masterkey_dicts) rather than the generic head/tail split.
    "pkzip_masterkey": True,
    # attack_12 varies a mask on both sides of the word, and this mode reports a plaintext that is
    # not the candidate it was given, so there is nothing to compare; skipped (attack_6 and attack_7
    # already cover it).
    "a12_skip": True,
}
