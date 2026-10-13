# Dynamic test inputs

A mode's "dynamic" input is a container built on the fly (`tools/test.py -g`) with a known password by the tool that owns the format, then extracted and cracked end to end. These are the archive and container generators: gpg, pkzip, rar, 7zip, pdf and ssh (the `*_GEN_MODES` sets), plus the TrueCrypt/VeraCrypt/LUKS generators that `-g` can build.

As with the static kind, these are deliberately not given a file per mode. Each family is one generator function in `tools/test.py`, dispatched through `ARCHIVE_GENERATORS` and `run_generate_archive`. The argv for each family lives with its function rather than in a per-mode recipe file, for the same reason the static families do: a file per mode would restate shared logic many times for no behaviour change. See `static/README.md` and the Implementation progress section of `plan_refactor_testpy.md` for the rationale.
