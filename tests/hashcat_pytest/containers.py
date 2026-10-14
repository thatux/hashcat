##
## Author......: See docs/credits.txt
## License.....: MIT
##

import glob
import os
import sys

from . import attacks, catalog, execution, reporting, runtime, tooling, verification


def crack_container(args, mode, width, directory):
  attack = container_attack(args)
  folder = runtime.LUKS2_TESTS_DIR if mode == 34100 else runtime.LUKS_TESTS_DIR if mode == 14600 or mode in catalog.LUKS1_HASH_CIPHER else runtime.TC_TESTS_DIR if mode in catalog.TC_MODES else runtime.VC_TESTS_DIR if mode in catalog.VC_MODES else runtime.CL_TESTS_DIR
  if os.path.isdir(folder) == False:
    runtime.ACTIVE.omissions.append("container fixtures missing: " + folder)
    return
  if mode == 34100:
    container_luks2(args, mode, attack, width, directory)
  elif mode == 14600:
    container_luks_legacy(args, mode, attack, width, directory)
  elif mode in catalog.LUKS1_HASH_CIPHER:
    container_luks1(args, mode, attack, width, directory)
  elif mode in catalog.TC_MODES:
    container_truecrypt(args, mode, width, directory)
  elif mode in catalog.VC_MODES:
    container_veracrypt(args, mode, width, directory)
  elif mode in catalog.CL_MODES:
    container_cryptoloop(args, mode, width, directory)
  else:
    raise ValueError("unknown container family")



def container_attack(args):
  if args.attack == "all":
    return 3
  return int(args.attack)


def container_mask(where):
  if runtime.CONTAINER_PASSWORD == b"hashcat":
    return catalog.CONTAINER_MASK_MID if where == "first" else catalog.CONTAINER_MASK
  return attacks.container_mask_from_password(runtime.CONTAINER_PASSWORD, where)


def container_extract(tool, container, hash_file, extra_args=()):
  proc = tooling.run([sys.executable, os.path.join(runtime.TDIR, tool), container] + list(extra_args), timeout=120)
  if proc.returncode != 0 or not proc.stdout:
    return False
  with open(hash_file, "wb") as fh:
    fh.write(proc.stdout)
  return True


def container_crack(args, opts, mode, attack, hash_file, width, label, extra, crack_mode=None,
                    report_attack=None):
  if extra is None:
    return None
  rc, output = execution.run_hashcat(opts + ["--backend-vector-width", str(width)], crack_mode or mode, hash_file,
                      None, attack=attack, extra=list(extra))
  if rc == 0 and verification.output_has_crack(mode, output, runtime.CONTAINER_PASSWORD, "", True, os.path.dirname(hash_file)) == False:
    runtime.ACTIVE.problems.append("container recovery did not contain the known password")
  reporting.log_result(rc)
  e = reporting.selftest_status(rc)
  reporting.container_report(args, mode, attack if report_attack is None else report_attack, width, label, e)
  return e


def container_luks2(args, mode, attack, width, tmp):
  opts = execution.base_opts(args)
  imgs = sorted(f for f in os.listdir(runtime.LUKS2_TESTS_DIR)
                if f.endswith(".img")) if os.path.isdir(runtime.LUKS2_TESTS_DIR) else []
  if not imgs:
    reporting.report_skip(args, mode, "single", width, "luks2 test files are missing", attack)
    return
  for img in imgs:
    if selected_variant(args, img) == False:
      continue
    hash_file = os.path.join(tmp, img + ".hash")
    if not container_extract("luks2hashcat.py", os.path.join(runtime.LUKS2_TESTS_DIR, img), hash_file):
      reporting.report_skip(args, mode, "single", width, "could not extract %s" % img, attack)
      continue
    extra = attacks.build_container_extra(mode, attack, runtime.CONTAINER_PASSWORD, tmp)
    container_crack(args, opts, mode, attack, hash_file, width, "LUKS2-mode %s" % img[:-4], extra)


def luks_variants():
  for lmode in ("cbc-essiv", "cbc-plain64", "xts-plain64"):
    for ksize in ("128", "256", "512"):
      if ksize == "128" and lmode == "xts-plain64":
        continue
      if ksize == "512" and lmode != "xts-plain64":
        continue
      yield lmode, ksize


def container_luks1(args, mode, attack, width, tmp):
  luks_hash, luks_cipher = catalog.LUKS1_HASH_CIPHER[mode]
  opts = execution.base_opts(args)
  for lmode, ksize in luks_variants():
    name      = "hashcat_%s_%s_%s_%s" % (luks_hash, luks_cipher, lmode, ksize)
    container = os.path.join(runtime.LUKS_TESTS_DIR, name + ".luks")
    label     = "Luks-Mode %s-%s-%s-%s" % (luks_hash, luks_cipher, lmode, ksize)
    if selected_variant(args, container) == False:
      continue
    if not os.path.isfile(container):
      reporting.report_skip(args, mode, "single", width, "missing fixture " + container, attack)
      continue
    hash_file = os.path.join(tmp, name + ".hash")
    if not container_extract("luks2hashcat.py", container, hash_file):
      reporting.report_skip(args, mode, "single", width, "could not extract %s" % name, attack)
      continue
    extra = attacks.build_container_extra(mode, attack, runtime.CONTAINER_PASSWORD, tmp)
    container_crack(args, opts, mode, attack, hash_file, width, label, extra)


def container_luks_legacy(args, mode, attack, width, tmp):
  opts = execution.base_opts(args)
  for luks_hash in ("sha1", "sha256", "sha512", "ripemd160"):
    for luks_cipher in ("aes", "serpent", "twofish"):
      for lmode, ksize in luks_variants():
        name      = "hashcat_%s_%s_%s_%s" % (luks_hash, luks_cipher, lmode, ksize)
        container = os.path.join(runtime.LUKS_TESTS_DIR, name + ".luks")
        label     = "luksMode %s-%s-%s-%s" % (luks_hash, luks_cipher, lmode, ksize)
        if selected_variant(args, container) == False:
          continue
        if not os.path.isfile(container):
          reporting.report_skip(args, mode, "single", width, "missing fixture " + container, attack)
          continue
        extra = attacks.build_container_extra(mode, attack, runtime.CONTAINER_PASSWORD, tmp)
        container_crack(args, opts, mode, attack, container, width, label, extra)


def container_truecrypt(args, mode, width, tmp):
  opts = execution.base_opts(args)
  s    = "%05d" % mode
  hfun = catalog.TC_HASH_DIGIT.get(int(s[-2]))
  boot = int(s[-2]) in catalog.TC_BOOT_DIGITS
  ncip = int(s[-1])
  if hfun is None or ncip not in (1, 2, 3):
    return
  prefix  = "hashcat_%s_" % hfun
  tc_mode = 0
  for fname in sorted(os.listdir(runtime.TC_TESTS_DIR)):
    if not fname.startswith(prefix) or not fname.endswith(".tc"):
      continue
    combo = fname[len(prefix):-len(".tc")]
    if boot != combo.endswith("_boot"):
      continue
    if boot:
      combo = combo[:-len("_boot")]
    if combo.count("-") != ncip - 1:
      continue
    container = os.path.join(runtime.TC_TESTS_DIR, fname)
    if selected_variant(args, container) == False:
      continue
    if mode < 29300:
      hash_arg = container
    else:
      hash_arg = os.path.join(tmp, fname + ".hash")
      if not container_extract("truecrypt2hashcat.py", container, hash_arg):
        reporting.report_skip(args, mode, "single", width, "could not extract %s" % fname, 3)
        continue
    mask = container_mask("last")
    container_crack(args, opts, mode, 3, hash_arg, width, "tcMode %d" % tc_mode, [mask])
    tc_mode += 1


def container_veracrypt(args, mode, width, tmp):
  opts = execution.base_opts(args)
  s = "%05d" % mode
  hfun = catalog.VC_HASH_DIGIT.get(int(s[3]))
  if hfun is None:
    return
  boot     = "_boot" if int(s[3]) in catalog.VC_BOOT_DIGITS else ""
  cascades = catalog.VC_CASCADES.get(int(s[4]), {})
  for variation in range(7):
    cascade = cascades.get(variation)
    if cascade is None:
      continue
    base     = "hashcat_%s_%s%s" % (hfun, cascade, boot)
    filename = os.path.join(runtime.VC_TESTS_DIR, base + ".vc")
    pim_opts = []
    if not os.path.isfile(filename):
      match = None
      for cand in sorted(glob.glob(os.path.join(runtime.VC_TESTS_DIR, base + "_pim*.vc"))):
        pim = cand[len(os.path.join(runtime.VC_TESTS_DIR, base)) + 4:-3]
        if pim.isdigit():
          match = (cand, pim)
          break
      if match is None:
        continue
      filename, pim = match
      pim_opts = ["--veracrypt-pim-start", pim, "--veracrypt-pim-stop", pim]
    if selected_variant(args, filename) == False:
      continue
    if mode < 29400:
      hash_arg = filename
    else:
      hash_arg = os.path.join(tmp, base + ".hash")
      if not container_extract("veracrypt2hashcat.py", filename, hash_arg):
        reporting.report_skip(args, mode, "single", width, "could not extract %s" % base, 3)
        continue
    mask = container_mask("first")
    container_crack(args, opts + pim_opts, mode, 3, hash_arg, width, "Cipher %s" % cascade,
                    [mask], report_attack=0)


def container_cryptoloop(args, mode, width, tmp):
  opts = execution.base_opts(args)
  s      = "%05d" % mode
  hfun   = catalog.CL_HASH_DIGIT.get(int(s[3]))
  cipher = catalog.CL_CIPHER_DIGIT.get(int(s[4]))
  if hfun is None or cipher is None:
    return
  for ksize in ("128", "192", "256"):
    img = os.path.join(runtime.CL_TESTS_DIR, "hashcat_%s_%s_%s.img" % (hfun, cipher, ksize))
    if selected_variant(args, img) == False:
      continue
    if not os.path.isfile(img):
      reporting.report_skip(args, mode, "single", width, "missing fixture " + img, 3)
      continue
    hash_arg = os.path.join(tmp, "hashcat_%s_%s_%s.hash" % (hfun, cipher, ksize))
    proc = tooling.run([sys.executable, os.path.join(runtime.TDIR, "cryptoloop2hashcat.py"),
                       "--source", img, "--hash", hfun, "--cipher", cipher, "--keysize", ksize], timeout=120)
    if proc.returncode != 0 or not proc.stdout:
      reporting.report_skip(args, mode, "single", width, "could not extract %s" % os.path.basename(img), 3)
      continue
    with open(hash_arg, "wb") as fh:
      fh.write(proc.stdout)
    mask = container_mask("last")
    container_crack(args, opts, mode, 3, hash_arg, width, "Key-Size %s" % ksize, [mask],
                    crack_mode=14500)


def container_variants(mode):
  if mode == 34100:
    return sorted(os.path.basename(path) for path in glob.glob(os.path.join(runtime.LUKS2_TESTS_DIR, "*.img"))) or ["fixture-set"]
  if mode in (14600, *catalog.LUKS1_HASH_CIPHER):
    hashes = [catalog.LUKS1_HASH_CIPHER[mode]] if mode != 14600 else [
      (hash_name, cipher) for hash_name in ("sha1", "sha256", "sha512", "ripemd160")
      for cipher in ("aes", "serpent", "twofish")]
    return ["hashcat_%s_%s_%s_%s.luks" % (hash_name, cipher, chain, size)
            for hash_name, cipher in hashes for chain, size in luks_variants()]
  text = "%05d" % mode
  if mode in catalog.TC_MODES:
    hash_name = catalog.TC_HASH_DIGIT[int(text[-2])]
    boot = "_boot" if int(text[-2]) in catalog.TC_BOOT_DIGITS else ""
    count = int(text[-1])
    return ["hashcat_%s_%s%s.tc" % (hash_name, cascade, boot)
            for cascade in catalog.TC_CIPHER_SPEC if cascade.count("-") == count - 1]
  if mode in catalog.VC_MODES:
    hash_name = catalog.VC_HASH_DIGIT[int(text[3])]
    boot = "_boot" if int(text[3]) in catalog.VC_BOOT_DIGITS else ""
    variants = []
    for cascade in catalog.VC_CASCADES[int(text[4])].values():
      base = "hashcat_%s_%s%s" % (hash_name, cascade, boot)
      direct = os.path.join(runtime.VC_TESTS_DIR, base + ".vc")
      choices = [direct] if os.path.isfile(direct) else sorted(glob.glob(os.path.join(runtime.VC_TESTS_DIR, base + "_pim*.vc")))[:1]
      variants.extend(os.path.basename(path) for path in choices or [direct])
    return variants or ["fixture-set"]
  if mode in catalog.CL_MODES:
    return ["hashcat_%s_%s_%s.img" % (catalog.CL_HASH_DIGIT[int(text[3])],
            catalog.CL_CIPHER_DIGIT[int(text[4])], size) for size in ("128", "192", "256")]
  raise ValueError("unknown container family")


def selected_variant(args, path):
  return args.variant is None or args.variant == "fixture-set" or os.path.basename(path) == args.variant
