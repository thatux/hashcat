# Static test inputs

A mode's "static" input is a prebuilt container checked into the tree, run through the mode's `*2hashcat.py` extractor to get the hash and then cracked. These are the container families: TrueCrypt (`tools/tc_tests/`), VeraCrypt (`tools/vc_tests/`), CryptoLoop (`tools/cl_tests/`) and LUKS (`tools/luks_tests/`, `tools/luks2_tests/`).

Each container mode declares this with a one-line `TEST_INPUT = {"kind": "static", "family": ...}` descriptor in `mNNNNN.py` here. test.py reads these without importing (as it reads the profiles) and derives `CONTAINER_MODES`, `TC_MODES`, `VC_MODES` and `CL_MODES` from them, so a mode's kind lives in a file next to the mode rather than in a hardcoded set. `run_container_mode` dispatches to the family's handler by the descriptor's `family`. The per-family hash and cipher parameters stay in test.py (the digit maps, the cascades, `LUKS1_HASH_CIPHER`), since they are derivation data the descriptor does not carry.
