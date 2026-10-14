##
## Author......: See docs/credits.txt
## License.....: MIT
##

import ast
import os
import re
import subprocess
from functools import lru_cache
from pathlib import Path

from . import runtime


SINGLE_MAX = 32


NOCHECK_ENCODING = {16800, 16801, 22000}


MASK_ONLY_MODES = {37000}


MFULC_MODES = {37000}


LUKS_MODES = {29511, 29512, 29513, 29521, 29522, 29523, 29531, 29532, 29533, 29541, 29542, 29543,
              34100}


SELFTEST_MODES = {23800}


NO_SELFTEST = {2000, 14600, 99999}


ATTACK_ORDER = [0, 4, 8, 9, 1, 3, 6, 7, 12]


WHOLE_WORD   = (0, 4, 8, 9)


FAKE_SLOW = {28501, 28502, 28503, 28504, 28505, 28506, 30901, 30902, 30903, 30904, 30905, 30906,
             34700}


DEVICE_LABEL = {"1": "Cpu", "2": "Gpu", "3": "Fpga"}


@lru_cache(maxsize=None)
def discover_modes():
  return sorted(int(path.stem[1:]) for path in Path(runtime.TDIR, "test_modules").glob("m[0-9][0-9][0-9][0-9][0-9].py"))


@lru_cache(maxsize=None)
def module_source(mode):
  try:
    with open(os.path.join(runtime.ROOT, "src", "modules", "module_%05d.c" % mode), "rb") as fh:
      return fh.read()
  except OSError:
    return b""


def is_file_only(mode):
  return b"OPTS_TYPE_BINARY_HASHFILE" in module_source(mode)


def is_bridged(mode):
  return b"BRIDGE_NAME" in module_source(mode)


def module_opts(mode):
  if mode in runtime.MODULE_OPTS_CACHE:
    return runtime.MODULE_OPTS_CACHE[mode]
  opts = []
  path = os.path.join(runtime.TDIR, "test_modules", "m%05d.py" % mode)
  if os.path.isfile(path):
    with open(path) as f:
      tree = ast.parse(f.read())
    for node in tree.body:
      if isinstance(node, ast.Assign) is False:
        continue
      names = [t.id for t in node.targets if isinstance(t, ast.Name)]
      if "HASHCAT_ARGS" in names:
        opts = [str(x) for x in ast.literal_eval(node.value)]
  runtime.MODULE_OPTS_CACHE[mode] = opts
  return opts


def is_slow(mode):
  if mode == 400:
    return False
  return mode in FAKE_SLOW or b"ATTACK_EXEC_OUTSIDE_KERNEL" in module_source(mode)


def host_engine(mode):
  return source_constant(mode, "ATTACK_EXEC") == "ATTACK_EXEC_OUTSIDE_KERNEL"


def memory_hard(mode):
  source = module_source(mode).lower()
  return any(name in source for name in (b"scrypt", b"argon2", b"yescrypt")) or source_constant(mode, "HASH_CATEGORY") == "HASH_CATEGORY_CRYPTOCURRENCY_WALLET"


def is_timeout(mode):
  return mode in FAKE_SLOW or host_engine(mode)


def a4_optimized(mode):
  kernel = source_constant(mode, "KERN_TYPE")
  return kernel.isdigit() and Path(runtime.ROOT, "OpenCL", "m%05d_a4-optimized.cl" % int(kernel)).is_file()


def a4_optimized_skip(mode, optimized):
  return optimized and not host_engine(mode) and not a4_optimized(mode)


def has_multi_hash(mode):
  return mode == 20510 or source_capabilities(mode)["cnt_max"] == 1


A12_SKIP = {14000, 14100, 14900, 15400, 20510}


CONTAINER_MASK     = "hashca?l"


CONTAINER_MASK_MID = "hashc?lt"


LUKS1_HASH_CIPHER = {
  29511: ("sha1", "aes"),      29512: ("sha1", "serpent"),      29513: ("sha1", "twofish"),
  29521: ("sha256", "aes"),    29522: ("sha256", "serpent"),    29523: ("sha256", "twofish"),
  29531: ("sha512", "aes"),    29532: ("sha512", "serpent"),    29533: ("sha512", "twofish"),
  29541: ("ripemd160", "aes"), 29542: ("ripemd160", "serpent"), 29543: ("ripemd160", "twofish"),
}


TC_HASH_DIGIT  = {1: "ripemd160", 2: "sha512", 3: "whirlpool", 4: "ripemd160"}


TC_BOOT_DIGITS = {4}


TC_MODES = {base + h * 10 + k for base in (6200, 29300) for h in (1, 2, 3, 4) for k in (1, 2, 3)}


VC_HASH_DIGIT  = {1: "ripemd160", 2: "sha512", 3: "whirlpool", 4: "ripemd160",
                  5: "sha256", 6: "sha256", 7: "streebog", 8: "streebog",
                  9: "blake2s"}


VC_BOOT_DIGITS = {4, 6, 8}


VC_CASCADES    = {
  1: {0: "aes", 1: "serpent", 2: "twofish", 3: "camellia", 5: "kuznyechik"},
  2: {0: "aes-twofish", 1: "serpent-aes", 2: "twofish-serpent", 3: "camellia-kuznyechik",
      4: "camellia-serpent", 5: "kuznyechik-aes", 6: "kuznyechik-twofish"},
  3: {0: "aes-twofish-serpent", 1: "serpent-twofish-aes", 5: "kuznyechik-serpent-camellia"},
}


VC_MODES = {13711, 13712, 13713, 13721, 13722, 13723, 13731, 13732, 13733, 13741, 13742, 13743,
            13751, 13752, 13753, 13761, 13762, 13763, 13771, 13772, 13773, 13781, 13782, 13783,
            29411, 29412, 29413, 29421, 29422, 29423, 29431, 29432, 29433, 29441, 29442, 29443,
            29451, 29452, 29453, 29461, 29462, 29463, 29471, 29472, 29473, 29481, 29482, 29483,
            29491, 29492, 29493}


CL_HASH_DIGIT   = {1: "sha1", 2: "sha256", 3: "sha512", 4: "ripemd160", 5: "whirlpool"}


CL_CIPHER_DIGIT = {1: "aes", 2: "serpent", 3: "twofish"}


CL_MODES = {14511, 14512, 14513, 14521, 14522, 14523, 14531, 14532, 14533,
            14541, 14542, 14543, 14551, 14552, 14553}


GPG_GEN_MODES      = {17010, 17020, 17030, 17040, 17050}


PKZIP_GEN_MODES    = {17200, 17210, 17220, 17225, 17230}


RAR_GEN_MODES      = {12500, 13000, 23700, 23800}


SEVENZIP_GEN_MODES = {11600, 13600}


PDF_GEN_MODES      = {10400, 10500, 10700}


SSH_GEN_MODES      = {22931}


ARCHIVE_GEN_MODES = (GPG_GEN_MODES | PKZIP_GEN_MODES | RAR_GEN_MODES | SEVENZIP_GEN_MODES
                     | PDF_GEN_MODES | SSH_GEN_MODES)


CONTAINER_GEN_MODES = ({34100} | set(LUKS1_HASH_CIPHER) | TC_MODES | VC_MODES)


GEN_MODES = ARCHIVE_GEN_MODES | CONTAINER_GEN_MODES


GEN_SUDO_MODES = ({34100} | set(LUKS1_HASH_CIPHER) | TC_MODES)


TC_PRF_NAME    = {"ripemd160": "RIPEMD160", "sha512": "SHA512", "whirlpool": "whirlpool"}


TC_CIPHER_SPEC = {
  "aes": "AES-256-XTS", "serpent": "SERPENT-256-XTS", "twofish": "TWOFISH-256-XTS",
  "aes-twofish": "TWOFISH-256-XTS,AES-256-XTS", "serpent-aes": "AES-256-XTS,SERPENT-256-XTS",
  "twofish-serpent": "SERPENT-256-XTS,TWOFISH-256-XTS",
  "aes-twofish-serpent": "SERPENT-256-XTS,TWOFISH-256-XTS,AES-256-XTS",
  "serpent-twofish-aes": "AES-256-XTS,TWOFISH-256-XTS,SERPENT-256-XTS",
}


TC_CASCADE_BY_COUNT = {
  1: {0: "aes", 1: "serpent", 2: "twofish"},
  2: {0: "aes-twofish", 1: "serpent-aes", 2: "twofish-serpent"},
  3: {0: "aes-twofish-serpent", 1: "serpent-twofish-aes"},
}


CONTAINER_MODES = ({14600, 34100} | set(LUKS1_HASH_CIPHER) | TC_MODES | VC_MODES | CL_MODES)


COVERAGE_UNTESTABLE = {
  2000:  "STDOUT candidate generator (OPTS_TYPE_SELF_TEST_DISABLE), nothing to crack",
  2501:  "WPA-EAPOL-PMK, deprecated, superseded by 22001",
  16801: "WPA-PMKID-PMK, deprecated, superseded by 22001",
  9710:  "MS Office <= 2003 MD5 + RC4 collider #1, not a wordlist or mask crack",
  9720:  "MS Office <= 2003 MD5 + RC4 collider #2, not a wordlist or mask crack",
  9810:  "MS Office <= 2003 SHA1 + RC4 collider #1, not a wordlist or mask crack",
  9820:  "MS Office <= 2003 SHA1 + RC4 collider #2, not a wordlist or mask crack",
  10410: "PDF 1.1 - 1.3 collider #1, not a wordlist or mask crack",
  10420: "PDF 1.1 - 1.3 collider #2, not a wordlist or mask crack",
}


def module_hash_name(mode):
  m = re.search(rb'HASH_NAME\s*=\s*"([^"]*)"', module_source(mode))
  return m.group(1).decode("utf-8", "replace") if m else ""


MINIMAL_MODES = [0, 100, 110, 400, 500, 2600, 3000, 3200, 6211, 11600, 12500, 13711, 14200, 14511,
                 14600, 14900, 15400, 15700, 20510, 22000, 29511, 33000, 33500, 34100]


STDOUT_MODE = 2000


EDGE_ATTACKS    = [0, 1, 3, 4, 6, 7, 8, 9, 12]


EDGE_WHOLE_WORD = (0, 4, 8, 9)


EDGE_WIDTHS     = [1, 2, 4, 8, 16]


EDGE_SKIP_MODES = {2000}


EDGE_SKIP_OUT_MATCH = {14000, 14100, 22000, 22001, 31500, 31600}


# DES recovery may clear the top bit of each plaintext byte, so verify equivalent spellings.
EDGE_VERIFY_OUT = {1500}


EDGE_SKIP_SAME_SALT = {6600, 7100, 7200, 8200, 13400, 15300, 15310, 15900, 15910, 16900,
                       18300, 18900, 20200, 20300, 20400, 27000, 27100, 29700, 29930, 29940}


def edge_hh(mode):
  if mode in runtime.EDGE_HH_CACHE:
    return runtime.EDGE_HH_CACHE[mode]
  proc = subprocess.run([runtime.METADATA_BIN, "--quiet", "-m", str(mode), "-HH"] + module_opts(mode) + runtime.ISOLATION,
                        cwd=runtime.ROOT, capture_output=True, timeout=60)
  if proc.returncode != 0:
    raise RuntimeError("hash metadata failed: " + proc.stderr.decode("utf-8", "replace"))
  info = source_capabilities(mode)
  fields = {}
  for line in proc.stdout.decode("utf-8", "replace").splitlines():
    key, separator, value = line.partition(":")
    if separator:
      fields[key.strip().rstrip(".")] = value.strip()
  kernels = fields.get("Kernel.Type(s)", "").replace(",", "").split()
  if not kernels:
    raise ValueError("hash metadata names no kernel type for mode %d" % mode)
  info.update(deprecated=fields.get("Deprecated") == "Yes", kernel_types=kernels,
              slow=fields.get("Slow.Hash") == "Yes", salt_present="Salt.Type" in fields,
              salt_virtual=fields.get("Salt.Type") == "Virtual", pw_type=fields.get("Password.Type", ""),
              cnt_max=int(fields.get("Hashes.Count.Max", "-1")),
              same_salt_not=fields.get("Hashes.w/.Same.Salt") == "Not allowed",
              keep_guessing=fields.get("Keep.Guessing") == "Yes")
  runtime.EDGE_HH_CACHE[mode] = info
  return info


def edge_binary_hashfile(mode):
  src = module_source(mode)
  return b"OPTS_TYPE_BINARY_HASHFILE" in src and b"OPTS_TYPE_BINARY_HASHFILE_OPTIONAL" not in src


def edge_hexify_plain(mode):
  src = module_source(mode)
  return b"OPTS_TYPE_PT_ALWAYS_HEXIFY" in src and b"OPTS_TYPE_PT_HEX" not in src


def source_constant(mode, name):
  for line in module_source(mode).decode("utf-8", "replace").splitlines():
    left, separator, right = line.partition("=")
    if separator and left.split() and left.split()[-1].lstrip("*") == name:
      return right.split(";", 1)[0].strip()
  return ""


@lru_cache(maxsize=None)
def source_capabilities(mode):
  source = module_source(mode)
  salt = source_constant(mode, "SALT_TYPE")
  count = source_constant(mode, "hashes_count_max")
  kernel = source_constant(mode, "KERN_TYPE")
  kernel_mode = int(kernel) if kernel.isdigit() else mode
  kernels = []
  for family in ("pure", "optimized"):
    if family in kernel_inventory().get(kernel_mode, set()):
      kernels.append(family)
  if b"module_hash_recipe;" in source and "pure" not in kernels:
    kernels.insert(0, "pure")
  if is_bridged(mode):
    kernels = ["pure"]
  return {"deprecated": source_constant(mode, "module_ctx->module_deprecated_notice") == "module_deprecated_notice", "kernel_types": kernels,
          "slow": host_engine(mode), "salt_present": salt not in ("", "SALT_TYPE_NONE"),
          "salt_virtual": salt == "SALT_TYPE_VIRTUAL", "cnt_max": int(count) if count.isdigit() else -1,
          "same_salt_not": False, "keep_guessing": b"OPTS_TYPE_SUGGEST_KG" in source,
          "pw_type": "HEX" if b"OPTS_TYPE_PT_HEX" in source else ""}


@lru_cache(maxsize=None)
def oracle_constraints(mode):
  path = Path(runtime.TDIR, "test_modules", "m%05d.py" % mode)
  if path.is_file() == False:
    return None
  tree = ast.parse(path.read_text())
  for node in tree.body:
    if isinstance(node, ast.FunctionDef) and node.name == "module_constraints":
      for child in ast.walk(node):
        if isinstance(child, ast.Return):
          try:
            return ast.literal_eval(child.value)
          except (ValueError, TypeError):
            continue
  return None


@lru_cache(maxsize=None)
def oracle_families(mode):
  if Path(runtime.TDIR, "test_modules", "m%05d.py" % mode).is_file() == False:
    return []
  constraints = oracle_constraints(mode)
  if constraints is not None:
    return [family for index, family in ((0, "pure"), (2, "optimized"))
            if constraints[index] != [-1, -1]]
  return source_capabilities(mode)["kernel_types"]


def oracle_salt_range(mode, kernel):
  constraints = oracle_constraints(mode)
  return tuple(constraints[1 if kernel == "pure" else 3]) if constraints is not None else None


@lru_cache(maxsize=None)
def source_modes():
  return sorted(int(path.stem.removeprefix("module_")) for path in
                Path(runtime.ROOT, "src", "modules").glob("module_[0-9][0-9][0-9][0-9][0-9].c"))


def widths_for(spec):
  return [1, 4] if spec in ("all", "default") else [int(value) for value in spec.split(",")]


def die(message):
  raise ValueError(message)


@lru_cache(maxsize=1)
def kernel_inventory():
  result = {}
  for path in Path(runtime.ROOT, "OpenCL").iterdir():
    name = path.name
    if name.startswith("m") and name[1:6].isdigit():
      for family in ("pure", "optimized"):
        if name.endswith("-" + family + ".cl"):
          result.setdefault(int(name[1:6]), set()).add(family)
  return result
