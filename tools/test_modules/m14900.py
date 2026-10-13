#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Test profile: the per-mode test-harness parameters test.py reads instead of hardcoding them.
TEST_PROFILE = {
    # Skip32 takes a fixed 10 byte key (module_constraints [10, 10]). With one valid candidate
    # length the single-hash runs cover one index, and the hybrid masks spell a fixed-width head.
    "a3_single_max": 1,         # one candidate length -> one hash in a single attack_3 run
    "a6_single": [0, 1],        # attack_6 single index range for the one fixed length
    "a7_single": [0, 1, 5],     # attack_7 single (min, max, mask_offset); 5 byte head before mask
    "combinator_init": [0, 5],    # init() (init_min, min_offset); drop line 0, split offset 5
    "combinator_single": [0, 5],  # attack_1 single index batch (min, max]; one fixed length
    # The oracle makes one password length only, so every multi length slot is pinned to it or the
    # hybrid multi runs feed hashcat an empty hash file. The split keeps the masked part to a few
    # bytes: the tail for attack_6, the head for attack_7 (which uses the smaller a7 offset).
    "multi_fixed_len": 10,
    "multi_min_len": 5,        # non-a7 split offset (fixed_len - 5)
    "multi_min_len_a7": 3,     # attack_7 pins the split low so the masked head stays a few bytes
    "a7_multi_max": 5,         # one fixed candidate length: a short attack_7 multi window suffices
    # attack_12 varies a mask on both sides of the word; with one candidate length there is
    # nothing to vary, so it is skipped (attack_6 and attack_7 already cover the mode).
    "a12_skip": True,
}
