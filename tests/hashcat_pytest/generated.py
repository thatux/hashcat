##
## Author......: See docs/credits.txt
## License.....: MIT
##

import glob
import os
import re
import shutil
import sys
import tempfile
from contextlib import contextmanager

from . import attacks, catalog, containers, execution, privileged, reporting, runtime, tooling


def gen_run(cmd, stdin=None, sudo=False, stdout_only=False):
  if sudo:
    cmd = ["sudo", "-n"] + cmd
  result = tooling.run(cmd, stdin, environment={"LC_ALL": runtime.GEN_LOCALE, "LANG": runtime.GEN_LOCALE})
  return result.returncode, result.stdout if stdout_only else result.stdout + result.stderr


def gen_password_string():
  previous = runtime.ENV
  runtime.ENV = dict(runtime.ENV)
  if not runtime.GEN_PURE:
    runtime.ENV["NO_NON_ASCII"] = "1"
  try:
    code, output = gen_run([sys.executable, runtime.RUNNER, "password", "0", "12"], stdout_only=True)
  finally:
    runtime.ENV = previous
  if code != 0:
    raise RuntimeError("password generator failed: " + output.decode("utf-8", "replace"))
  return output.rstrip(b"\n")


def _tool(env_name, name):
  override = os.environ.get(env_name)
  if override:
    return override
  found = shutil.which(name)
  if found:
    return found
  cand = os.path.join(os.path.expanduser("~"), "john", "run", name)
  return cand if os.path.exists(cand) else name


def _have(path):
  return shutil.which(path) is not None or os.path.exists(path)


def privileged_tools_available(mode, tools):
  missing = [tool for tool in tools if shutil.which(tool) is None]
  if missing:
    reporting.gen_skip(mode, "container generation needs missing tools: " + ", ".join(missing))
    return False
  return True


def _john_extract(raw, token_re):
  for line in raw.decode("utf-8", "replace").splitlines():
    m = re.search(token_re, line)
    if m:
      return m.group(0)
  return None


def write_hash(hash_file, token):
  with open(hash_file, "w") as fh:
    fh.write(token + "\n")


def archive_attacks(args, fast):
  if args.attack == "all":
    return [0, 1, 3] if fast else [0]
  selected = []
  for field in args.attack.replace(",", " ").split():
    attack = int(field)
    if attack in (0, 1, 3, 6, 7) and attack not in selected:
      selected.append(attack)
  return selected


def veracrypt_without_ripemd160(binary):
  code, output = gen_run([binary, "--text", "--version"])
  if code != 0:
    return False
  for line in output.decode("utf-8", "replace").splitlines():
    fields = line.split()
    if len(fields) < 2 or fields[0] != "VeraCrypt":
      continue
    version = fields[1].split(".")
    if len(version) >= 2 and all(part.isascii() and part.isdigit() for part in version[:2]):
      return tuple(map(int, version[:2])) >= (1, 26)
  return False


def archive_crack(args, mode, hash_file, label, tmp, fast):
  opts = execution.base_opts(args)
  for attack in archive_attacks(args, fast):
    extra = attacks.build_container_extra(mode, attack, runtime.CONTAINER_PASSWORD, tmp)
    if extra is None:
      continue
    for width in catalog.widths_for(args.vector):
      containers.container_crack(args, opts, mode, attack, hash_file, width, label, extra)


def vc_encryption_name(cascade):
  names = {"aes": "AES", "serpent": "Serpent", "twofish": "Twofish",
           "camellia": "Camellia", "kuznyechik": "Kuznyechik"}
  parts = []
  for part in cascade.split("-"):
    if part not in names:
      return None
    parts.append(names[part])
  return "-".join(parts)


def veracrypt_generate(mode, vc_hash, cascade, out_file):
  vbin = os.environ.get("VERACRYPT_BIN", "veracrypt")
  if not _have(vbin):
    reporting.gen_skip(mode, "veracrypt not found, so no VeraCrypt volume can be generated (set VERACRYPT_BIN=/path/to/veracrypt)")
    return False
  encryption = vc_encryption_name(cascade)
  if encryption is None:
    reporting.gen_skip(mode, "no veracrypt name for cipher cascade %s" % cascade)
    return False
  if os.path.exists(out_file):
    os.remove(out_file)
  code, _ = gen_run([vbin, "--text", "--create", out_file, "--size=1M",
           "--password=%s" % runtime.CONTAINER_PASSWORD.decode("utf-8"), "--volume-type=normal",
           "--encryption=%s" % encryption, "--hash=%s" % vc_hash, "--filesystem=none",
           "--pim=0", "--keyfiles=", "--random-source=/dev/urandom", "--non-interactive"])
  if code != 0 or not os.path.exists(out_file) or os.path.getsize(out_file) == 0:
    if os.path.exists(out_file):
      os.remove(out_file)
    if vc_hash == "ripemd160" and 0 < code < 128 and veracrypt_without_ripemd160(vbin):
      reporting.gen_skip(mode, "%s will not create RIPEMD-160 volumes. 1.26 dropped them, so point VERACRYPT_BIN "
                     "at a 1.25.9 or older build to cover these" % vbin)
    else:
      reporting.gen_error(mode, "veracrypt failed to create %s + %s volume (rc=%d)" % (vc_hash, encryption, code))
    return False
  return True


def truecrypt_generate(mode, prf, cascade, out_file, tmp):
  tcplay = _tool("TCPLAY_BIN", "tcplay")
  if not _have(tcplay):
    reporting.gen_skip(mode, "tcplay not found, so no TrueCrypt volume can be generated (apt install tcplay, or set TCPLAY_BIN=...)")
    return False
  if not shutil.which("expect"):
    reporting.gen_skip(mode, "expect not found, and tcplay reads its passphrase from a terminal (apt install expect)")
    return False
  if privileged_tools_available(mode, ("sudo", "losetup")) == False:
    return False
  prf_name = catalog.TC_PRF_NAME.get(prf)
  cipher   = catalog.TC_CIPHER_SPEC.get(cascade)
  if prf_name is None or cipher is None:
    reporting.gen_skip(mode, "tcplay has no PBKDF PRF/cipher chain for %s + %s" % (prf, cascade))
    return False
  exp = os.path.join(tmp, "tcplay_create.exp")
  with open(exp, "w") as fh:
    fh.write("set timeout 600\n"
             "set dev  [lindex $argv 0]\n"
             "set pass [lindex $argv 1]\n"
             "set prf  [lindex $argv 2]\n"
             "set ciph [lindex $argv 3]\n"
             "set bin  [lindex $argv 4]\n"
             "spawn $bin --create --device=$dev --cipher=$ciph --pbkdf-prf=$prf --insecure-erase --weak-keys\n"
             'expect "Passphrase:"        { send "$pass\\r" }\n'
             'expect "Repeat passphrase:" { send "$pass\\r" }\n'
             'expect "(y/n)"              { send "y\\r" }\n'
             "expect eof\n"
             "catch wait result\n"
             "exit [lindex $result 3]\n")
  if os.path.exists(out_file):
    os.remove(out_file)
  with open(out_file, "wb") as fh:
    fh.truncate(2 * 1024 * 1024)
  with privileged.resource("loop", out_file):
    rc, out = gen_run(["losetup", "--show", "-f", out_file], sudo=True, stdout_only=True)
    loop = out.decode("utf-8", "replace").strip()
    valid_loop = loop.startswith("/dev/loop") and loop[9:].isascii() and loop[9:].isdigit()
    if rc != 0 or valid_loop == False:
      reporting.gen_error(mode, "could not attach a loop device, which tcplay needs (sudo losetup)")
      rc = 1
    else:
      rc, _ = gen_run(["expect", exp, loop, runtime.CONTAINER_PASSWORD.decode("utf-8"), prf_name, cipher, tcplay], sudo=True)
      if rc != 0:
        reporting.gen_error(mode, "tcplay could not create a %s + %s volume" % (prf, cascade))
  if rc != 0:
    if os.path.exists(out_file):
      os.remove(out_file)
    return False
  if not os.path.exists(out_file) or os.path.getsize(out_file) == 0:
    reporting.gen_error(mode, "tcplay produced no %s + %s volume" % (prf, cascade))
    return False
  return True


def _luks_chain(lmode):
  return "cbc-essiv:sha256" if lmode == "cbc-essiv" else lmode


def luks1_generate(mode, luks_hash, luks_cipher, lmode, ksize, out_file):
  cryptsetup = _tool("CRYPTSETUP_BIN", "cryptsetup")
  if not _have(cryptsetup):
    reporting.gen_skip(mode, "cryptsetup not found, so no LUKS1 container can be generated")
    return False
  if privileged_tools_available(mode, ("sudo", "losetup", "mkfs.ext4")) == False:
    return False
  chain = _luks_chain(lmode)
  name  = "luksgen%d_%s" % (os.getpid(), ksize)
  if os.path.exists(out_file):
    os.remove(out_file)
  with open(out_file, "wb") as fh:
    fh.truncate(20 * 1024 * 1024)
  rc, _ = gen_run([cryptsetup, "luksFormat", "--batch-mode", "--type", "luks1",
                   "--cipher", "%s-%s" % (luks_cipher, chain), "--key-size", ksize,
                   "--hash", luks_hash, "--pbkdf-force-iterations", "1000", out_file],
                  stdin=runtime.CONTAINER_PASSWORD + b"\n", sudo=True)
  if rc != 0:
    os.remove(out_file)
    reporting.gen_error(mode, "cryptsetup refused %s + %s-%s at %s bits" % (luks_hash, luks_cipher, chain, ksize))
    return False
  with privileged.resource("mapper", out_file, name):
    rc, _ = gen_run([cryptsetup, "open", out_file, name], stdin=runtime.CONTAINER_PASSWORD + b"\n", sudo=True)
    if rc != 0:
      reporting.gen_error(mode, "could not open the generated %s + %s-%s container (device-mapper needs sudo)"
               % (luks_hash, luks_cipher, chain))
      return False
    rc, _ = gen_run(["mkfs.ext4", "-q", "/dev/mapper/%s" % name], sudo=True)
  if rc != 0:
    reporting.gen_error(mode, "could not format generated LUKS1 filesystem")
    return False
  if os.path.getsize(out_file) == 0:
    reporting.gen_error(mode, "the generated %s + %s-%s container came out empty" % (luks_hash, luks_cipher, chain))
    return False
  return True


def luks2_generate(mode, lmode, ksize, out_file):
  cryptsetup = _tool("CRYPTSETUP_BIN", "cryptsetup")
  if not _have(cryptsetup):
    reporting.gen_skip(mode, "cryptsetup not found, so no LUKS2 container can be generated")
    return False
  if privileged_tools_available(mode, ("sudo", "losetup", "mkfs.ext4")) == False:
    return False
  chain = _luks_chain(lmode)
  name  = "luks2gen%d_%s" % (os.getpid(), ksize)
  if os.path.exists(out_file):
    os.remove(out_file)
  with open(out_file, "wb") as fh:
    fh.truncate(48 * 1024 * 1024)
  rc, _ = gen_run([cryptsetup, "luksFormat", "--batch-mode", "--type", "luks2",
                   "--cipher", "aes-%s" % chain, "--key-size", ksize, "--hash", "sha256",
                   "--pbkdf", "argon2id", "--pbkdf-force-iterations", "4",
                   "--pbkdf-memory", "16384", "--pbkdf-parallel", "1", out_file],
                  stdin=runtime.CONTAINER_PASSWORD + b"\n", sudo=True)
  if rc != 0:
    os.remove(out_file)
    reporting.gen_error(mode, "cryptsetup refused aes-%s at %s bits for LUKS2" % (chain, ksize))
    return False
  with privileged.resource("mapper", out_file, name):
    rc, _ = gen_run([cryptsetup, "open", out_file, name], stdin=runtime.CONTAINER_PASSWORD + b"\n", sudo=True)
    if rc != 0:
      reporting.gen_error(mode, "could not open the generated aes-%s LUKS2 container (device-mapper needs sudo)" % chain)
      return False
    rc, _ = gen_run(["mkfs.ext4", "-q", "/dev/mapper/%s" % name], sudo=True)
  if rc != 0:
    reporting.gen_error(mode, "could not format generated LUKS2 filesystem")
    return False
  if os.path.getsize(out_file) == 0:
    reporting.gen_error(mode, "the generated aes-%s LUKS2 container came out empty" % chain)
    return False
  return True


def generate_containers(args, mode, tmp):
  if mode == 34100:
    os.makedirs(runtime.LUKS2_TESTS_DIR, exist_ok=True)
    for lmode, ksize in containers.luks_variants():
      out = os.path.join(runtime.LUKS2_TESTS_DIR, "luks2-aes-argon2id-t4-m16-p1-%s-%s.img" % (lmode, ksize))
      if not os.path.exists(out):
        luks2_generate(mode, lmode, ksize, out)
    return
  if mode in catalog.LUKS1_HASH_CIPHER:
    os.makedirs(runtime.LUKS_TESTS_DIR, exist_ok=True)
    luks_hash, luks_cipher = catalog.LUKS1_HASH_CIPHER[mode]
    for lmode, ksize in containers.luks_variants():
      name = "hashcat_%s_%s_%s_%s" % (luks_hash, luks_cipher, lmode, ksize)
      out  = os.path.join(runtime.LUKS_TESTS_DIR, name + ".luks")
      if not os.path.exists(out):
        luks1_generate(mode, luks_hash, luks_cipher, lmode, ksize, out)
    return
  if mode in catalog.TC_MODES:
    os.makedirs(runtime.TC_TESTS_DIR, exist_ok=True)
    s    = "%05d" % mode
    hfun = catalog.TC_HASH_DIGIT.get(int(s[-2]))
    boot = int(s[-2]) in catalog.TC_BOOT_DIGITS
    ncip = int(s[-1])
    if hfun is None or ncip not in (1, 2, 3):
      return
    if boot:
      reporting.gen_skip(mode, "tcplay cannot create system-encryption (boot) volumes, so -m %d is not generated" % mode)
      return
    for tc_mode in range(3):
      cascade = catalog.TC_CASCADE_BY_COUNT.get(ncip, {}).get(tc_mode)
      if cascade is None:
        continue
      out = os.path.join(runtime.TC_TESTS_DIR, "hashcat_%s_%s.tc" % (hfun, cascade))
      if not os.path.exists(out):
        truecrypt_generate(mode, hfun, cascade, out, tmp)
    return
  if mode in catalog.VC_MODES:
    os.makedirs(runtime.VC_TESTS_DIR, exist_ok=True)
    s    = "%05d" % mode
    hfun = catalog.VC_HASH_DIGIT.get(int(s[3]))
    if hfun is None:
      return
    if int(s[3]) in catalog.VC_BOOT_DIGITS:
      reporting.gen_skip(mode, "veracrypt --create only writes normal volumes, so the boot mode -m %d is not generated" % mode)
      return
    for cascade in catalog.VC_CASCADES.get(int(s[4]), {}).values():
      out = os.path.join(runtime.VC_TESTS_DIR, "hashcat_%s_%s.vc" % (hfun, cascade))
      if not os.path.exists(out):
        veracrypt_generate(mode, hfun, cascade, out)
    return


def gen_pkzip(args, mode, tmp):
  zip_bin  = _tool("ZIP_BIN", "zip")
  zip2john = _tool("ZIP2JOHN", "zip2john")
  if not shutil.which(zip_bin):
    reporting.gen_skip(mode, "'zip' not found (install InfoZip zip)")
    return
  if not _have(zip2john):
    reporting.gen_skip(mode, "zip2john not found (set ZIP2JOHN=/path/to/zip2john)")
    return
  pw   = runtime.CONTAINER_PASSWORD.decode("utf-8")
  zdir = os.path.join(tmp, "pkzip_%d" % mode)
  sdir = os.path.join(zdir, "src")
  os.makedirs(sdir, exist_ok=True)
  for i in (1, 2, 3, 4):
    with open(os.path.join(sdir, "t%d.txt" % i), "wb") as fh:
      fh.write(("pattern %d the quick brown fox " % i).encode() * 300)
  with open(os.path.join(sdir, "rand.bin"), "wb") as fh:
    fh.write(os.urandom(64))
  zf = os.path.join(zdir, "%d.zip" % mode)
  t  = lambda n: os.path.join(sdir, n)
  builds = {
    17200: ([zip_bin, "-9", "-e", "-P", pw, zf, t("t1.txt")], False),
    17210: ([zip_bin, "-0", "-e", "-P", pw, zf, t("t1.txt")], False),
    17220: ([zip_bin, "-9", "-e", "-P", pw, zf, t("t1.txt"), t("t2.txt"), t("t3.txt")], False),
    17225: ([zip_bin, "-e", "-P", pw, zf, t("t1.txt"), t("rand.bin"), t("t2.txt")], False),
    17230: ([zip_bin, "-9", "-e", "-P", pw, zf, t("t1.txt"), t("t2.txt"), t("t3.txt"), t("t4.txt")], True),
  }
  if mode not in builds:
    reporting.gen_skip(mode, "unsupported PKZIP mode for -g")
    return
  cmd, checksum = builds[mode]
  rc, _ = gen_run(cmd)
  if rc != 0 or not os.path.exists(zf) or os.path.getsize(zf) == 0:
    reporting.gen_error(mode, "zip failed to create %s" % zf)
    return
  hash_file = os.path.join(zdir, "%d.hash" % mode)
  extra     = ["-c"] if checksum else []
  rc, out   = gen_run([zip2john] + extra + [zf])
  token     = _john_extract(out, r"\$pkzip2?\$[^:]+")
  if rc != 0 or token is None:
    reporting.gen_error(mode, "zip2john produced no hash for %s" % zf)
    return
  write_hash(hash_file, token)
  archive_crack(args, mode, hash_file, "PKZIP-container", tmp, fast=True)


@contextmanager
def gpg_home(directory, gpgconf=None):
  with tempfile.TemporaryDirectory(prefix="gpg-home-", dir=directory) as home:
    try:
      yield home
    finally:
      if gpgconf is not None:
        code, output = gen_run([gpgconf, "--homedir", home, "--kill", "gpg-agent"])
        if code != 0:
          raise RuntimeError("could not stop generator's GPG agent: " + output.decode("utf-8", "replace"))


def gen_gpg(args, mode, tmp):
  previous_errors = len(runtime.ACTIVE.problems)
  gpg1    = os.environ.get("GPG1_BIN", "gpg1")
  gpg2    = os.environ.get("GPG2_BIN", "gpg")
  gpg2john = _tool("GPG2JOHN", "gpg2john")
  ocb     = os.environ.get("GPG_OCB_EXTRACT", os.path.join(runtime.TDIR, "gpg-ocb-aes2hashcat.py"))
  if not _have(gpg2john):
    reporting.gen_skip(mode, "gpg2john not found (set GPG2JOHN=/path/to/gpg2john)")
    return
  have_gpg1 = shutil.which(gpg1) is not None
  gpgconf = shutil.which("gpgconf")
  have_gpg2 = _have(gpg2) and gpgconf is not None
  if not have_gpg1 and mode in (17010, 17020, 17030, 17040):
    reporting.gen_note(mode, "%s (GnuPG 1.x) not found, so the classic S2K variants and the AES-128 (aux1) path "
                   "are skipped. Set GPG1_BIN=... if installed elsewhere" % gpg1)
  if mode in (17010, 17050) and not have_gpg2:
    reporting.gen_note(mode, "gpg2 or gpgconf not found, so GnuPG 2 variants are not generated")
  pw   = runtime.CONTAINER_PASSWORD.decode("utf-8")
  gdir = os.path.join(tmp, "gpg_%d" % mode)
  os.makedirs(gdir, exist_ok=True)
  producers = []
  def gpg1_key(digest, cipher, label):
    if not have_gpg1:
      return
    batch = ("Key-Type: RSA\nKey-Length: 1024\nKey-Usage: sign\nName-Real: %s\n"
             "Name-Email: %s@hashcat.test\nPassphrase: %s\nExpire-Date: 0\n%%commit\n"
             % (label, label, pw))
    with gpg_home(gdir) as home:
      rc, _ = gen_run([gpg1, "--homedir", home, "--batch", "--no-tty", "--s2k-digest-algo", digest,
               "--s2k-cipher-algo", cipher, "--s2k-mode", "3", "--s2k-count", "65536", "--gen-key"],
              stdin=batch.encode("utf-8"))
      if rc != 0:
        reporting.gen_error(mode, "gpg1 failed to generate %s key" % label)
        return
      rc, out = gen_run([gpg2john, os.path.join(home, "secring.gpg")])
      token = _john_extract(out, r"\$gpg\$[^:]*")
    if rc != 0 or token is None:
      reporting.gen_error(mode, "gpg2john produced no hash for %s key" % label)
    else:
      producers.append((label, token))
  def gpg2_key(label, extra_args):
    if not have_gpg2:
      return
    with gpg_home(gdir, gpgconf) as home:
      rc, _ = gen_run([gpg2, "--homedir", home, "--batch", "--pinentry-mode", "loopback", "--passphrase", pw]
              + extra_args + ["--quick-generate-key", "%s <%s@hashcat.test>" % (label, label),
                              "rsa1024", "sign", "0"])
      if rc != 0:
        reporting.gen_error(mode, "gpg2 failed to generate %s key" % label)
        return
      rc, sk = gen_run([gpg2, "--homedir", home, "--batch", "--pinentry-mode", "loopback",
                        "--passphrase", pw, "--export-secret-keys"], stdout_only=True)
      if rc != 0 or not sk:
        reporting.gen_error(mode, "gpg2 failed to export %s key" % label)
        return
      sk_file = os.path.join(gdir, "%d_%s.sk.gpg" % (mode, label))
      with open(sk_file, "wb") as fh:
        fh.write(sk)
      rc, out = gen_run([gpg2john, sk_file])
      token = _john_extract(out, r"\$gpg\$[^:]*")
    if rc != 0 or token is None:
      reporting.gen_error(mode, "gpg2john produced no hash for %s key" % label)
    else:
      producers.append((label, token))
  def gpg2_ocb_key(label, keytype):
    if not have_gpg2:
      return
    if not os.path.isfile(ocb):
      reporting.gen_skip(mode, "%s not found" % ocb)
      return
    token = None
    with gpg_home(gdir, gpgconf) as home:
      rc, _ = gen_run([gpg2, "--homedir", home, "--batch", "--pinentry-mode", "loopback", "--passphrase", pw,
               "--quick-generate-key", "%s <%s@hashcat.test>" % (label, label), keytype, "sign", "0"])
      if rc != 0:
        reporting.gen_error(mode, "gpg2 failed to generate %s key" % label)
        return
      keys = glob.glob(os.path.join(home, "private-keys-v1.d", "*.key"))
      if not keys:
        reporting.gen_error(mode, "gpg2 produced no private key for %s" % label)
        return
      with open(keys[0], "rb") as fh:
        blob = fh.read()
      if b"openpgp-s2k3-ocb-aes" not in blob:
        if any(protection in blob for protection in (b"openpgp-s2k3-sha1-aes-cbc", b"openpgp-s2k3-sha1-aes256-cbc")):
          reporting.gen_skip(mode, "gpg2 wrote a CBC-protected private key instead of OCB for %s" % label)
        else:
          reporting.gen_error(mode, "gpg2 wrote an unrecognized private key for %s" % label)
        return
      rc, out = gen_run([sys.executable, ocb, keys[0]])
      token = _john_extract(out, r"\$gpg\$[^:]*")
    if rc != 0 or token is None:
      reporting.gen_error(mode, "OCB extractor produced no hash for %s key" % label)
    else:
      producers.append((label, token))
  if mode == 17010:
    gpg1_key("SHA1", "AES", "gpg1-sha1-aes128")
    gpg1_key("SHA1", "AES256", "gpg1-sha1-aes256")
    gpg2_key("gpg2-default", [])
  elif mode == 17020:
    gpg1_key("SHA512", "AES", "gpg1-sha512-aes128")
    gpg1_key("SHA512", "AES256", "gpg1-sha512-aes256")
  elif mode == 17030:
    gpg1_key("SHA256", "AES", "gpg1-sha256-aes128")
    gpg1_key("SHA256", "AES256", "gpg1-sha256-aes256")
  elif mode == 17040:
    gpg1_key("SHA1", "CAST5", "gpg1-sha1-cast5")
  elif mode == 17050:
    gpg2_ocb_key("gpg2-ed25519-ocb", "ed25519")
    gpg2_ocb_key("gpg2-rsa2048-ocb", "rsa2048")
  else:
    reporting.gen_skip(mode, "unsupported GPG mode for -g")
    return
  if not producers:
    if len(runtime.ACTIVE.problems) == previous_errors:
      reporting.gen_skip(mode, "no matching GPG producer is available or supported by the local tools")
    return
  for label, token in producers:
    hash_file = os.path.join(gdir, "%d_%s.hash" % (mode, label))
    write_hash(hash_file, token)
    archive_crack(args, mode, hash_file, "GPG-container %s" % label, tmp, fast=False)


def gen_rar(args, mode, tmp):
  rar_bin = os.environ.get("RAR_BIN")
  if not rar_bin:
    old = os.path.join(os.path.expanduser("~"), "rar-old", "rar")
    rar_bin = old if os.path.exists(old) else "rar"
  rar2john = _tool("RAR2JOHN", "rar2john")
  if not _have(rar_bin):
    reporting.gen_skip(mode, "rar not found. Fetch rarlinux-x64-612.tar.gz from rarlab.com (NOT 'apt install rar', "
                   "that is rar 7.x = RAR5 only), or set RAR_BIN=/path/to/rar")
    return
  if not _have(rar2john):
    reporting.gen_skip(mode, "rar2john not found (set RAR2JOHN=/path/to/rar2john)")
    return
  pw   = runtime.CONTAINER_PASSWORD.decode("utf-8")
  rdir = os.path.join(tmp, "rar_%d" % mode)
  sdir = os.path.join(rdir, "src")
  os.makedirs(sdir, exist_ok=True)
  payload = os.path.join(sdir, "payload.txt")
  with open(payload, "wb") as fh:
    fh.write(b"pattern the quick brown fox jumps over the lazy dog " * 160)
  with tempfile.TemporaryDirectory() as probe_dir:
    probe_txt = os.path.join(probe_dir, "p.txt")
    with open(probe_txt, "wb") as fh:
      fh.write(b"probe\n")
    probe_rar = os.path.join(probe_dir, "a.rar")
    probe_rc, probe_out = gen_run([rar_bin, "a", "-ma4", "-p_", "-inul", probe_rar, probe_txt])
    has_ma4 = os.path.exists(probe_rar) and os.path.getsize(probe_rar) > 0
  if mode in (12500, 23700, 23800) and (probe_rc != 0 or not has_ma4):
    if 0 < probe_rc < 128 and any(marker in probe_out for marker in (b"Unknown option: ma4", b"Unknown option: -ma4")):
      reporting.gen_skip(mode, "%s cannot create RAR3 (-ma4). Fetch rarlinux-x64-612.tar.gz "
                     "from rarlab.com or set RAR_BIN=/path/to/rar<=6.x" % rar_bin)
    else:
      reporting.gen_error(mode, "rar failed the RAR3 creation probe (rc=%d)" % probe_rc)
    return
  arc   = os.path.join(rdir, "%d.rar" % mode)
  token_re = r"\$RAR3\$[^:]+"
  builds = {
    12500: ([rar_bin, "a", "-ma4", "-m3", "-hp" + pw, "-inul", arc, payload], "rar3-hp"),
    23700: ([rar_bin, "a", "-ma4", "-m0", "-p" + pw, "-inul", arc, payload], "rar3-p-store"),
    23800: ([rar_bin, "a", "-ma4", "-m3", "-p" + pw, "-inul", arc, payload], "rar3-p-compressed"),
    13000: ([rar_bin, "a", "-p" + pw, "-inul", arc, payload], "rar5"),
  }
  if mode not in builds:
    reporting.gen_skip(mode, "unsupported RAR mode for -g")
    return
  cmd, label = builds[mode]
  if mode == 13000:
    token_re = r"\$rar5\$[^:]+"
  rc, _ = gen_run(cmd)
  if rc != 0 or not os.path.exists(arc) or os.path.getsize(arc) == 0:
    reporting.gen_error(mode, "rar failed to create %s" % arc)
    return
  hash_file = os.path.join(rdir, "%d.hash" % mode)
  rc, out   = gen_run([rar2john, arc])
  token     = _john_extract(out, token_re)
  if rc != 0 or token is None:
    reporting.gen_error(mode, "rar2john produced no hash for %s" % arc)
    return
  write_hash(hash_file, token)
  archive_crack(args, mode, hash_file, "RAR-container %s" % label, tmp, fast=False)


def gen_sevenzip(args, mode, tmp):
  sevenzip = _tool("SEVENZIP_BIN", "7z")
  sz2john  = _tool("SEVENZIP2JOHN", "7z2john.pl")
  zip2john = _tool("ZIP2JOHN", "zip2john")
  if not shutil.which(sevenzip):
    reporting.gen_skip(mode, "7z not found (apt install p7zip-full, or set SEVENZIP_BIN=/path/to/7z)")
    return
  pw   = runtime.CONTAINER_PASSWORD.decode("utf-8")
  sdir = os.path.join(tmp, "7z_%d" % mode)
  os.makedirs(sdir, exist_ok=True)
  payload = os.path.join(sdir, "payload.txt")
  with open(payload, "wb") as fh:
    fh.write(b"pattern the quick brown fox jumps over the lazy dog " * 160)
  if mode == 11600:
    if not _have(sz2john):
      reporting.gen_skip(mode, "7z2john.pl not found (set SEVENZIP2JOHN=/path/to/7z2john.pl)")
      return
    if not shutil.which("perl"):
      reporting.gen_skip(mode, "perl not found, which 7z2john.pl needs")
      return
    rc, output = gen_run(["perl", "-MCompress::Raw::Lzma", "-e", "1"])
    if rc != 0:
      if 0 < rc < 128 and b"Can't locate Compress/Raw/Lzma.pm in @INC" in output:
        reporting.gen_skip(mode, "7z2john.pl needs Compress::Raw::Lzma (apt install libcompress-raw-lzma-perl)")
      else:
        reporting.gen_error(mode, "perl failed the Compress::Raw::Lzma dependency check")
      return
    variants = [("lzma2-header-encrypted", ["-mhe=on"]), ("lzma2-header-plain", ["-mhe=off"]),
                ("stored", ["-mhe=on", "-m0=Copy"]), ("bzip2", ["-mhe=on", "-m0=BZip2"])]
  elif mode == 13600:
    if not _have(zip2john):
      reporting.gen_skip(mode, "zip2john not found (set ZIP2JOHN=/path/to/zip2john)")
      return
    variants = [("aes128", ["-mem=AES128"]), ("aes256", ["-mem=AES256"])]
  else:
    reporting.gen_skip(mode, "unsupported 7z mode for -g")
    return
  for label, opts in variants:
    if mode == 13600:
      archive   = os.path.join(sdir, "%d_%s.zip" % (mode, label))
      rc, _ = gen_run([sevenzip, "a", "-tzip"] + opts + ["-p" + pw, archive, payload])
      if rc != 0 or not os.path.exists(archive) or os.path.getsize(archive) == 0:
        reporting.gen_error(mode, "7z failed to create %s archive" % label)
        continue
      rc, out   = gen_run([zip2john, archive])
      token     = _john_extract(out, r"\$zip2\$[^:]*")
    else:
      archive   = os.path.join(sdir, "%d_%s.7z" % (mode, label))
      rc, _ = gen_run([sevenzip, "a"] + opts + ["-p" + pw, archive, payload])
      if rc != 0 or not os.path.exists(archive) or os.path.getsize(archive) == 0:
        reporting.gen_error(mode, "7z failed to create %s archive" % label)
        continue
      rc, out   = gen_run(["perl", sz2john, archive])
      token     = _john_extract(out, r"\$7z\$[^:]*")
    if rc != 0 or token is None:
      reporting.gen_error(mode, "could not read a hash out of the generated %s archive" % label)
      continue
    hash_file = os.path.join(sdir, "%d_%s.hash" % (mode, label))
    write_hash(hash_file, token)
    archive_crack(args, mode, hash_file, "7z-container %s" % label, tmp, fast=False)


def gen_pdf(args, mode, tmp):
  qpdf     = _tool("QPDF_BIN", "qpdf")
  pdf2john = _tool("PDF2JOHN", "pdf2john.pl")
  if not shutil.which(qpdf):
    reporting.gen_skip(mode, "qpdf not found (apt install qpdf, or set QPDF_BIN=/path/to/qpdf)")
    return
  if not _have(pdf2john):
    reporting.gen_skip(mode, "pdf2john.pl not found (set PDF2JOHN=/path/to/pdf2john.pl); the .py needs pyhanko and is not used here")
    return
  if not shutil.which("perl"):
    reporting.gen_skip(mode, "perl not found, which pdf2john.pl needs")
    return
  pw   = runtime.CONTAINER_PASSWORD.decode("utf-8")
  pdir = os.path.join(tmp, "pdf_%d" % mode)
  os.makedirs(pdir, exist_ok=True)
  plain = os.path.join(pdir, "plain.pdf")
  if not shutil.which("gs"):
    reporting.gen_skip(mode, "no gs to write a plain PDF for qpdf to encrypt (apt install ghostscript)")
    return
  rc, _ = gen_run(["gs", "-q", "-o", plain, "-sDEVICE=pdfwrite", "-c", "showpage"])
  if rc != 0 or not os.path.exists(plain) or os.path.getsize(plain) == 0:
    reporting.gen_error(mode, "gs failed to write a plain PDF")
    return
  variants = {
    10400: [("rc4-40", ["--allow-weak-crypto", "--encrypt", pw, pw, "40", "--"])],
    10500: [("rc4-128", ["--allow-weak-crypto", "--encrypt", pw, pw, "128", "--"]),
            ("aes-128", ["--encrypt", pw, pw, "128", "--use-aes=y", "--"])],
    10700: [("aes-256", ["--encrypt", pw, pw, "256", "--"])],
  }
  if mode not in variants:
    reporting.gen_skip(mode, "unsupported PDF mode for -g")
    return
  for label, opts in variants[mode]:
    doc = os.path.join(pdir, "%d_%s.pdf" % (mode, label))
    rc, _ = gen_run([qpdf] + opts + [plain, doc])
    if rc not in (0, 3) or not os.path.exists(doc) or os.path.getsize(doc) == 0:
      reporting.gen_error(mode, "qpdf could not write a %s document" % label)
      continue
    rc, out = gen_run(["perl", pdf2john, doc])
    token   = _john_extract(out, r"\$pdf\$[^:]*")
    if rc != 0 or token is None:
      reporting.gen_error(mode, "pdf2john produced no hash for the %s document" % label)
      continue
    hash_file = os.path.join(pdir, "%d_%s.hash" % (mode, label))
    write_hash(hash_file, token)
    archive_crack(args, mode, hash_file, "PDF-container %s" % label, tmp, fast=False)


def gen_ssh(args, mode, tmp):
  keygen  = _tool("SSHKEYGEN_BIN", "ssh-keygen")
  ssh2john = _tool("SSH2JOHN", "ssh2john.py")
  if not shutil.which(keygen):
    reporting.gen_skip(mode, "ssh-keygen not found (set SSHKEYGEN_BIN=/path/to/ssh-keygen)")
    return
  if not _have(ssh2john):
    reporting.gen_skip(mode, "ssh2john.py not found (set SSH2JOHN=/path/to/ssh2john.py)")
    return
  pw   = runtime.CONTAINER_PASSWORD.decode("utf-8")
  kdir = os.path.join(tmp, "ssh_%d" % mode)
  os.makedirs(kdir, exist_ok=True)
  for keytype in ("rsa", "dsa"):
    key = os.path.join(kdir, "%d_%s" % (mode, keytype))
    for stale in (key, key + ".pub"):
      if os.path.exists(stale):
        os.remove(stale)
    rc, _ = gen_run([keygen, "-q", "-m", "PEM", "-t", keytype, "-N", pw, "-C", "hashcat", "-f", key])
    if rc != 0 or not os.path.exists(key) or os.path.getsize(key) == 0:
      reporting.gen_error(mode, "ssh-keygen would not write a PEM %s key" % keytype)
      continue
    rc, out = gen_run([sys.executable, ssh2john, key])
    token   = _john_extract(out, r"\$sshng\$[^:]*")
    if rc != 0 or token is None:
      reporting.gen_error(mode, "ssh2john produced no hash for the %s key" % keytype)
      continue
    hash_file = os.path.join(kdir, "%d_%s.hash" % (mode, keytype))
    write_hash(hash_file, token)
    archive_crack(args, mode, hash_file, "SSH-key %s" % keytype, tmp, fast=False)


ARCHIVE_GENERATORS = [
  (catalog.PKZIP_GEN_MODES,    gen_pkzip),
  (catalog.GPG_GEN_MODES,      gen_gpg),
  (catalog.RAR_GEN_MODES,      gen_rar),
  (catalog.SEVENZIP_GEN_MODES, gen_sevenzip),
  (catalog.PDF_GEN_MODES,      gen_pdf),
  (catalog.SSH_GEN_MODES,      gen_ssh),
]


def run_generate_archive(args, mode, tmp):
  for modes, fn in ARCHIVE_GENERATORS:
    if mode in modes:
      fn(args, mode, tmp)
