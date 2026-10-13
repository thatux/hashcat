# Dynamic test inputs

A mode's "dynamic" input is a container built on the fly (`tools/test.py -g`) with a known password by the tool that owns the format, then extracted and cracked end to end. These are the archive and container generators: gpg, pkzip, rar, 7zip, pdf and ssh, plus the TrueCrypt/VeraCrypt/LUKS generators that `-g` can build.

Each generator mode declares this with a one-line `TEST_INPUT = {"kind": "dynamic", "family": ...}` descriptor in `mNNNNN.py` here. test.py reads these without importing and derives the `*_GEN_MODES` sets, `ARCHIVE_GEN_MODES` and `CONTAINER_GEN_MODES` from them, so a generator mode's family lives next to the mode rather than in a hardcoded set. `run_generate_archive` dispatches to the family's generator by the descriptor's `family`. A mode that has both a shipped container and a generator carries both a `static/` and a `dynamic/` descriptor.
