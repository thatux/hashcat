# Integration tests with pytest

The native pytest suite invokes hashcat directly. Reference implementations remain in `tools/test_modules/`, and `tools/test_module_runner.py --json-lines` supplies byte-safe vectors. See [the plugin development guide](../docs/hashcat-plugin-development-guide.md) for oracle hooks.

### Install

Use Python 3.12 or newer. From the repository root:

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r tools/requirements.txt -r tests/requirements.txt
make -j"$(nproc)"
```

`tools/install_dependencies.sh` installs the system packages and external generators. `tools/install_modules.sh` installs both Python dependency files into its pyenv interpreter.

### Run

```sh
python3 -m pytest tests/test_cracking.py --hash-modes 0
python3 -m pytest tests/test_cracking.py --hash-modes 0 --attacks all --kernels both
python3 -m pytest tests/test_edge.py --hash-modes 0
python3 -m pytest tests/test_selftest.py --hash-modes all
python3 -m pytest tests/test_bridge.py --hash-modes 1000
python3 -m pytest tests/test_containers.py --hash-modes 6211
python3 -m pytest tests/test_stdout.py --hash-modes 2000
python3 -m pytest tests/test_coverage.py
python3 -m pytest --help
```

On a CPU-only machine add `--device-type cpu --force`. Hashcat device numbers are selected with `--backend-devices 1,2`. `--hash-modes` accepts a mode, comma/space lists, inclusive ranges, `all`, or `minimal` (the 24 representative modes). Use `--attacks`, `--targets single|multi|all`, `--kernels pure|optimized|both` and `--widths` to narrow the matrix. Pytest's `-m` selects markers, and `-k` filters case IDs.

The default profile runs standard cracking, container fixtures, the self-test-only mode's normal path, STDOUT and the source coverage audit. Standard cracking uses attack 0, single and multi targets, widths 1 and 4, and optimized kernels when available, otherwise pure. Mode 23800 uses its published vector with the normal runtime and widths. The explicit self-test sweep uses a 60-second runtime and the backend's default width. Edge tests default to every applicable attack, both kernel families and widths 1, 2, 4, 8 and 16. `--profile full` adds edge, all published self-test vectors and bridge tests, and expands normal cracking to all attacks and available families. Generated artifacts require `--include-generated`. The framework's own regression tests are in `tests/framework/`.

Each cracking or edge item groups all applicable vectors for one mode, attack, kernel, target and width. Unsupported combinations are excluded using source capabilities. Runtime limitations are explicit skips. Empty vector sets, missing cracks, unexpected build errors and timeouts fail. `--require-coverage` also fails missing fixtures/tools and partial generator coverage, and requires execution of every requested mode, so CI cannot pass by skipping all work.

`--collect-only` reads source metadata and fixtures without running hashcat, creating containers or probing devices. Runtime preflight validates compiled metadata. Self-test collection uses source module IDs, then reads each published vector from `--hash-info --machine-readable` and cracks it with `--self-test-disable`.

### Parallel execution

```sh
python3 -m pytest tests/test_cracking.py --hash-modes 0,1000 --device-type cpu --force -n 2 --dist loadgroup
python3 -m pytest tests/test_cracking.py --hash-modes all -n 2 --dist loadgroup --gpu-strategy depth
python3 -m pytest tests/test_cracking.py --hash-modes all -n 4 --dist loadgroup --gpu-strategy breadth
```

Depth assigns one worker to each physical GPU, deduplicating backend aliases, and rejects excess workers. Breadth shares devices and partitions free device and host memory across workers. A capped memory failure is retried under an exclusive lease with caps removed, and only that retry's outcome is reported. Resource locks are released by the operating system if a worker exits. `loadgroup` keeps a mode's cases together for cache reuse. Resource leases currently use POSIX file locks (Linux and macOS).

Each worker has a private kernel/dictstat cache and session. Tests disable potfiles, logs and restore files. They do not use or clear `cache/kernels/`. Metadata uses the selected binary, and cracking runs from the repository root.

### Reproduction and reports

The default oracle seed is `12345`. Supply `--seed NUMBER` or `--seed random`. The actual seed appears in the pytest header and artifacts and is shared across workers. Oracle generation is cached per mode, kernel, operation, length/attack and seed.

Failures retain raw stdout/stderr, byte-safe argv/stdin, copies of input files, vectors, outcomes and the environment under `pytest-artifacts/SUITE/CASE/attempt-N/`. Replay a saved invocation with `python3 reproduce.py 0 --root /path/to/hashcat`. Each invocation also saves recovered outfile bytes. Oracle, extractor and generator commands have separate `tool-NNNN` logs and do not count as hashcat execution. Replay uses a fresh cache and removes worker memory caps. `--keep-artifacts all` retains successful cases too, and `--artifact-dir` selects the destination. Use `--junitxml=pytest-results.xml` for CI reports and `--lf` to rerun failures.

### Generated artifacts

```sh
python3 -m pytest tests/test_generated.py --include-generated --hash-modes 17200
python3 -m pytest --include-generated --hash-modes 17010 --attacks all
python3 -m pytest tests/test_generated.py --include-generated --hash-modes 34100 --allow-privileged
```

Run pytest as yourself. `--allow-privileged` opts into generators that need device-mapper or loop devices. Only those operations invoke `sudo -n`. Arrange sudo access before running them. Archive tests supplement oracles, while generated LUKS/TrueCrypt/VeraCrypt volumes replace shipped fixtures in that invocation.


Generated archives supplement the mode's normal oracle tests. Generated LUKS, TrueCrypt and VeraCrypt containers replace shipped fixtures. Missing tools produce explicit skips. Missing optional GPG producers produce a warning describing partial coverage. Installed tools that fail unexpectedly produce failures. `--require-coverage` fails missing or partial coverage.

| Format | Modes | Tools | Without them |
|---|---|---|---|
| GPG | 17010, 17020, 17030, 17040, 17050 | `gpg2`, `gpgconf`, `gpg1`, `gpg2john` | No `gpg1`: classic S2K combinations and the AES-128 (aux1) path are unavailable. Mode 17010 can still test GnuPG 2 variants with a partial coverage warning. Mode 17050 uses only GnuPG 2. No `gpg2john`: skipped. |
| PKZIP | 17200, 17210, 17220, 17225, 17230 | `zip`, `zip2john` | Skipped. |
| RAR | 12500, 13000, 23700, 23800 | `rar` 6.x or older, `rar2john` | Only RAR5 (13000) is built, the RAR3 modes are skipped. 23800 has no `test_module_runner.py` oracle at all, so its published self-test vector is used without generated artifacts. |
| 7-Zip | 11600 | `7z`, `7z2john.pl`, `Compress::Raw::Lzma` | Skipped. |
| WinZip AES | 13600 | `7z`, `zip2john` | Skipped. |
| PDF | 10400, 10500, 10700 | `qpdf`, `gs`, `pdf2john.pl` | Skipped. `gs` writes the plain PDF that `qpdf` then encrypts. |
| OpenSSH key | 22931 | `ssh-keygen`, `ssh2john.py` | Skipped. |
| LUKS1 | 29511 to 29543 | `cryptsetup`, `sudo` | Skipped. |
| LUKS2 | 34100 | `cryptsetup`, `sudo` | Skipped. |
| TrueCrypt | 6211 to 6243, 29311 to 29343 | `tcplay`, `expect`, `sudo` | Skipped. The boot (system-encryption) modes are always skipped, since tcplay cannot write them. |
| VeraCrypt | 13711 to 13783, 29411 to 29483 | `veracrypt` console build | No veracrypt: skipped. At 1.26 or newer: the RIPEMD-160 modes are skipped, since 1.26 dropped them. The boot modes are always skipped, since `veracrypt --create` only writes normal volumes. |

`install_dependencies.sh` installs all of it, including the ones that are easy to get wrong:

* **John jumbo** for `zip2john`, `gpg2john`, `rar2john`, `7z2john.pl`, `pdf2john.pl` and `ssh2john.py`. No package has them: `apt install john` is core John and ships none of them, so the script builds jumbo in `$HOME/john`. Override with `ZIP2JOHN=`, `GPG2JOHN=`, `RAR2JOHN=`, `SEVENZIP2JOHN=`, `PDF2JOHN=`, `SSH2JOHN=`. Otherwise lookup uses `PATH` then `$HOME/john/run/`.
* **rar 6.12** for the RAR3 modes. No package either: `apt install rar` is 7.x, which writes RAR5 only, so the script fetches RARLAB's static build into `$HOME/rar-old`. Override with `RAR_BIN=`.
* **gpg1** is the separate `gnupg1` package, installed alongside `gnupg` rather than instead of it. Override with `GPG1_BIN=`.
* **veracrypt 1.25.9** for the RIPEMD-160 modes, which 1.26 dropped and no distribution still carries. The script unpacks the console `.deb` into `$HOME/veracrypt-1.25.9` rather than installing it, because it shares a package name with a system veracrypt and would downgrade it. Override with `VERACRYPT_BIN=`.

CPU worker memory limits account for Linux cgroup limits. Host memory budgets reserve a quarter for interpreters, compilation and backend overhead. On macOS, host availability is estimated from free, inactive and speculative pages reported by `vm_stat`. GPU and host budgets are divided across workers in breadth mode.
