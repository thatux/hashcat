# Synthetic test inputs

A mode's "synthetic" input is its oracle: `module_generate_hash` builds a hash from a known password purely in Python, with no artifact on disk, and the suite then cracks that hash back to the password. This is how most modes are tested.

Each oracle lives in `mNNNNN.py` here (`module_constraints`, `module_generate_hash`, `module_verify_hash`, and any helpers they need from `lib/`). The per-mode test profile stays in the flat `tools/test_modules/mNNNNN.py` for the modes that have one, so a mode's declarative test parameters and its oracle body are separate files: test.py reads the profile without importing, and the runner imports the oracle from here. A mode with both a synthetic oracle and a shipped or generated container carries a `static/` or `dynamic/` descriptor as well.
