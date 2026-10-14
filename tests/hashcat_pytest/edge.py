##
## Author......: See docs/credits.txt
## License.....: MIT
##

import base64
import os
import shutil

from . import attacks, catalog, execution, verification


def _w(path, data):
  with open(path, "wb") as fh:
    fh.write(data)


def edge_as_bytes(x):
  if isinstance(x, bytes):
    return x
  return os.fsencode(x)


def edge_noise_words(word, slow, suffix):
  cut_len = 1 if slow else 2
  if len(word) < cut_len:
    cut_len = len(word)
  if cut_len == 0:
    return [word + suffix]
  if cut_len == 2:
    tails = [("%d%d" % (a, b)).encode("ascii") for a in range(10) for b in range(10)]
  else:
    tails = [("%d" % a).encode("ascii") for a in range(10)]
  stem = word[:len(word) - cut_len]
  half = len(tails) // 2
  out = []
  for at, tail in enumerate(tails):
    if at == half:
      out.append(word + suffix)
    out.append(stem + tail + suffix)
  return out


def edge_mask_for(tok, text):
  out = tok * len(text)
  if tok == b"?d":
    return attacks.mask_literalize(out, text)
  return out


def edge_build_ruleset(ruleset, context_lines):
  shutil.rmtree(ruleset, ignore_errors=True)
  os.makedirs(os.path.join(ruleset, "Grammar"))
  os.makedirs(os.path.join(ruleset, "Context"))
  _w(os.path.join(ruleset, "Grammar", "grammar.txt"), b"X1\t1.0\n")
  _w(os.path.join(ruleset, "Context", "1.txt"), b"".join(l + b"\n" for l in context_lines))


class EdgeCtx:
  def __init__(self, mode, attack, ktype, optimized, hh, slow, binary,
               pt_hex, pt_base58, hexify_plain, no_salt, keep_guessing):
    self.mode         = mode
    self.attack       = attack
    self.ktype        = ktype
    self.optimized    = optimized
    self.hh           = hh
    self.slow         = slow
    self.binary       = binary
    self.pt_hex       = pt_hex
    self.pt_base58    = pt_base58
    self.hexify_plain = hexify_plain
    self.no_salt      = no_salt
    self.keep_guessing = keep_guessing


def edge_a3_split(ctx, word, word_len):
  if ctx.pt_hex:
    return word[:-2], b"?b"
  if ctx.pt_base58:
    return word[:-2], b"?a?a"
  if word_len == 2:
    w1, mask = word[:-1], b"?d"
  elif ctx.slow:
    w1, mask = word[:-2], b"?d?d"
  else:
    w1, mask = word[:-3], b"?d?d?d"
  return w1, attacks.mask_literalize(mask, word[len(w1):])


def edge_a6_split(ctx, word, word_len):
  if ctx.pt_hex:
    return word[:-2], b"?b"
  if ctx.pt_base58:
    return word[:-2], b"?a?a"
  tail_len = 1 if (word_len == 2 or ctx.slow) else 2
  split    = attacks.utf8_split_point(word, len(word) - tail_len)
  return word[:split], edge_mask_for(b"?d", word[split:])


def edge_a7_split(ctx, word, word_len):
  if ctx.pt_hex:
    return word[2:], b"?b"
  if ctx.pt_base58:
    return word[2:], b"?a?a"
  head_len = 1 if (word_len == 2 or ctx.slow) else 2
  split    = attacks.utf8_split_point(word, head_len)
  return word[split:], edge_mask_for(b"?d", word[:split])


def edge_a12_split(ctx, word):
  mask_c   = b"?d"
  cut_len  = 1
  both     = True
  if ctx.pt_hex:
    mask_c, cut_len, both = b"?b", 2, False
  elif ctx.pt_base58:
    mask_c = b"?a"
  if ctx.slow:
    both = False
  left  = cut_len
  right = len(word) - cut_len
  if mask_c == b"?d":
    left  = attacks.utf8_split_point(word, left)
    right = attacks.utf8_split_point(word, right)
  mid_len = right - left
  if both and mid_len >= 1:
    w1 = word[left:right]
    if mask_c == b"?d":
      mask = edge_mask_for(b"?d", word[:left]) + b"?w" + edge_mask_for(b"?d", word[right:])
    else:
      mask = mask_c + b"?w" + mask_c
  else:
    w1 = word[left:]
    if mask_c == b"?d":
      mask = edge_mask_for(b"?d", word[:left]) + b"?w"
    else:
      mask = mask_c + b"?w"
  return w1, mask


def edge_single_cmd(ctx, word, word_len, i, tmp):
  attack = ctx.attack
  pfx    = os.path.join(tmp, "edge_s_%d_%s_%d_%d" % (ctx.mode, ctx.ktype, attack, i))
  if attack == 0:
    return [], word + b"\n"
  if attack == 1:
    off = attacks.utf8_split_point(word, word_len // 2)
    f1  = pfx + ".1.word"
    f2  = pfx + ".2.word"
    _w(f1, word[:off] + b"\n")
    _w(f2, word[off:] + b"\n")
    return [f1, f2], None
  if attack == 3:
    w1, mask = edge_a3_split(ctx, word, word_len)
    return [w1 + mask], None
  if attack == 6:
    w1, mask = edge_a6_split(ctx, word, word_len)
    f = pfx + "_1.word"
    _w(f, w1)
    return [f, mask], None
  if attack == 7:
    w1, mask = edge_a7_split(ctx, word, word_len)
    f = pfx + "_2.word"
    _w(f, w1)
    return [mask, f], None
  if attack == 12:
    w1, mask = edge_a12_split(ctx, word)
    f = pfx + "_12.word"
    _w(f, w1)
    return [mask, f], None
  if attack == 4:
    ruleset = pfx + ".ruleset"
    edge_build_ruleset(ruleset, edge_noise_words(word, ctx.slow, b"\t1.0"))
    return [ruleset], None
  if attack == 8:
    f = pfx + "_8.word"
    _w(f, b"".join(l + b"\n" for l in edge_noise_words(word, ctx.slow, b"")))
    return ["wordlist", f], None
  if attack == 9:
    f = pfx + "_9.word"
    _w(f, word + b"\n")
    return [f], None
  return [], None


def edge_single(ctx, width, opts, outfile, vectors, tmp):
  errors = 0
  cells  = 0
  for i, v in enumerate(vectors, start=1):
    word     = v["word"]
    word_len = v["word_len"]
    dig      = v["hash"]
    word_compare = None
    if ctx.mode == 20510:
      word_compare = word
      word         = word[6:]
    if ctx.hexify_plain:
      word_compare = word.hex().encode("ascii")
    if ctx.mode == 20510 and word_len <= 6 and len(word) == 0 and ctx.attack in (3, 6, 7, 12):
      continue
    if ctx.attack == 4 and (len(word) == 0 or b"\t" in word):
      continue
    if ctx.binary:
      if os.path.exists(dig):
        target = dig
      else:
        target = os.fsencode(os.path.join(tmp, "edge_%d_%s_%d_%d.hashfile"
                             % (ctx.mode, ctx.ktype, ctx.attack, i)))
        _w(target, base64.b64decode(dig))
      hash_out = target
    else:
      target   = dig
      hash_out = dig
    extra, stdin = edge_single_cmd(ctx, word, word_len, i, tmp)
    try:
      os.remove(outfile)
    except OSError:
      pass
    rc, _ = execution.edge_run(opts, ctx.mode, target, stdin, ctx.attack, extra)
    cells += 1
    if rc != 0:
      if rc == 252:
        break
      errors += 1
      print("[ edge ] !> error (%d) Type %d, Attack %d, Kernel %s, Vector %d, Test %d, single"
            % (rc, ctx.mode, ctx.attack, ctx.ktype, width, i))
      if rc == 250:
        break
      continue
    if ctx.mode in catalog.EDGE_SKIP_OUT_MATCH or ctx.keep_guessing:
      continue
    try:
      with open(outfile, "rb") as fh:
        raw = fh.read()
    except OSError:
      raw = b""
    got  = verification.edge_echo_norm(verification.edge_strip_userpw(raw))
    want = verification.edge_echo_norm(hash_out + b":" + (word_compare if word_compare is not None else word))
    if got != want:
      errors += 1
      print("[ edge ] !> mismatch Type %d, Attack %d, Kernel %s, Vector %d, Test %d, single"
            % (ctx.mode, ctx.attack, ctx.ktype, width, i))
  return errors, cells


def edge_multi_cmd(ctx, selected, width, tmp):
  attack = ctx.attack
  pfx    = os.path.join(tmp, "edge_m_%d_%s_%d_%d" % (ctx.mode, ctx.ktype, attack, width))
  if attack == 0:
    return [], b"".join(w + b"\n" for w, _, _, _ in selected)
  if attack == 1:
    f1 = pfx + ".1.words"
    f2 = pfx + ".2.words"
    heads = []
    tails = []
    for word, word_len, _, _ in selected:
      off = attacks.utf8_split_point(word, word_len // 2)
      heads.append(word[:off])
      tails.append(word[off:])
    _w(f1, b"".join(x + b"\n" for x in heads))
    _w(f2, b"".join(x + b"\n" for x in tails))
    return [f1, f2], None
  if attack == 3:
    masks = pfx + ".masks"
    lines = []
    for word, word_len, _, _ in selected:
      w1, mask = edge_a3_split(ctx, word, word_len)
      lines.append(w1 + mask)
    _w(masks, b"".join(x + b"\n" for x in lines))
    return [masks], None
  if attack in (6, 7, 12):
    wf = pfx + ".words"
    mf = pfx + ".masks"
    ws = []
    ms = []
    for word, word_len, _, _ in selected:
      if attack == 6:
        w1, mask = edge_a6_split(ctx, word, word_len)
      elif attack == 7:
        w1, mask = edge_a7_split(ctx, word, word_len)
      else:
        w1, mask = edge_a12_split(ctx, word)
      ws.append(w1)
      ms.append(mask)
    _w(wf, b"".join(x + b"\n" for x in ws))
    _w(mf, b"".join(x + b"\n" for x in ms))
    if attack == 6:
      return [wf, mf], None
    return [mf, wf], None
  if attack == 4:
    ruleset = pfx + ".ruleset"
    edge_build_ruleset(ruleset, [w + b"\t1.0" for w, _, _, _ in selected])
    return [ruleset], None
  if attack == 8:
    wf = pfx + ".words"
    _w(wf, b"".join(w + b"\n" for w, _, _, _ in selected))
    return ["wordlist", wf], None
  if attack == 9:
    wf = pfx + ".words"
    _w(wf, b"".join(w + b"\n" for w, _, _, _ in selected))
    return [wf], None
  return [], None


def edge_multi(ctx, width, opts, outfile, vectors, tmp):
  mode   = ctx.mode
  attack = ctx.attack
  hh     = ctx.hh
  cnt_max = hh["cnt_max"]
  if mode == 20510 or ctx.binary:
    cnt_max = 1
  if cnt_max == 1:
    return 0, 0, False
  if attack == 9 and ctx.no_salt:
    return 0, 0, False
  same_salt = True
  if mode not in catalog.EDGE_SKIP_SAME_SALT and hh["same_salt_not"]:
    same_salt = False
  if attack == 9:
    same_salt = False
  if not vectors:
    return 0, 0, False
  selected   = []
  salts_seen = set()
  hash_cnt   = 0
  for v in vectors:
    if cnt_max > 1 and hash_cnt > cnt_max:
      continue
    word     = v["word"]
    word_len = v["word_len"]
    salt     = v["salt"]
    salt_len = v["salt_len"]
    dig      = v["hash"]
    word_compare = None
    if mode == 20510:
      word_compare = word
      word         = word[6:]
    if ctx.hexify_plain:
      word_compare = word.hex().encode("ascii")
    if not ctx.no_salt and not same_salt:
      key = (salt_len, salt)
      if key in salts_seen:
        continue
      salts_seen.add(key)
    if attack == 4 and (len(word) == 0 or b"\t" in word):
      continue
    hash_cnt += 1
    selected.append((word, word_len, word_compare, dig))
  if hash_cnt <= 1:
    return 0, 0, False
  use_compare = ctx.hexify_plain or mode == 20510
  hash_in = os.path.join(tmp, "edge_m_%d_%s_%d_%d.hashes" % (mode, ctx.ktype, attack, width))
  hcout  = []
  hlines = []
  for word, word_len, word_compare, dig in selected:
    hlines.append(dig)
    wline = word_compare if (use_compare and word_compare is not None) else word
    hcout.append(dig + b":" + wline)
  _w(hash_in, b"".join(h + b"\n" for h in hlines))
  extra, stdin = edge_multi_cmd(ctx, selected, width, tmp)
  try:
    os.remove(outfile)
  except OSError:
    pass
  rc, out = execution.edge_run(opts, mode, hash_in, stdin, attack, extra)
  if rc != 0:
    if rc == 252:
      return 0, 1, True
    if attack == 9 and b"Mixed iteration counts are not supported" in out:
      return 0, 1, False
    print("[ edge ] !> error (%d) Type %d, Attack %d, Kernel %s, Vector %d, multi"
          % (rc, mode, attack, ctx.ktype, width))
    return 1, 1, rc == 250
  if mode in catalog.EDGE_SKIP_OUT_MATCH or ctx.keep_guessing:
    return 0, 1, False
  try:
    with open(outfile, "rb") as fh:
      raw = fh.read()
  except OSError:
    raw = b""
  got  = verification.edge_sort_lines(verification.edge_strip_userpw(raw).rstrip(b"\n") + b"\n")
  want = verification.edge_sort_lines(b"".join(l + b"\n" for l in hcout))
  if got != want:
    print("[ edge ] !> mismatch Type %d, Attack %d, Kernel %s, Vector %d, multi"
          % (mode, attack, ctx.ktype, width))
    return 1, 1, False
  return 0, 1, False
