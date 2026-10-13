#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# Test profile: the per-mode test-harness parameters test.py reads instead of hardcoding them.
TEST_PROFILE = {
    # WPA/WPA2 PSK carries an 8 byte minimum passphrase (module_constraints [8, 63]). Every cap
    # here follows from that length floor: the short-candidate pool shrinks the single-hash index
    # ranges, and the mask window starts at 8.
    "a3_single_max": 7,            # attack_3 single covers 7 of the short candidates, not 8
    "a3_multi_increment": [8, 9],  # attack_3 multi --increment window starts at the 8 byte floor
    "a3_custom_charsets": True,    # attack_3 multi pins the mask to a custom charset at bytes 6..9
    "a6_single": [1, 6],           # attack_6 single hash index range (min, max)
    "a7_single": [1, 5, 0],        # attack_7 single (min, max, mask_offset); no custom split
    "combinator_init": [1, 7],     # init() (init_min, min_offset); split shifts toward the tail
    "multi_min_len": 7,            # init() multi split offset 7, keeping the masked tail short
    "a6_multi_max": 5,             # slow PBKDF2 mode: keep the attack_6 multi length window short
    "a7_multi_max": 5,             # slow PBKDF2 mode: keep the attack_7 multi length window short
    "a12_single_max": 6,           # attack_12 single covers 6 of the short candidates
    "match_pass_only": True,       # recovered line omits the hash, so the match is on ":password"
    # Edge: writes the handshake parts rather than hash and plaintext, so the outfile cannot be
    # compared to what the oracle generated.
    "edge_skip_out_match": True,
    # The hash line is handed to hashcat as is (the handshake record), not base64-decoded into
    # a file the way a binary-hashfile mode is.
    "decode_hashfile_raw": True,
}
