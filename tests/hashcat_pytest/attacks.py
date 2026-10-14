##
## Author......: See docs/credits.txt
## License.....: MIT
##

from dataclasses import dataclass
import os
import shutil

from . import catalog, oracles


@dataclass(frozen=True)
class Context:
  counts: dict
  pass_only: bool
  directory: str
  verify_on_error: bool


@dataclass(frozen=True)
class Invocation:
  options: tuple
  mode: int
  attack: int
  target: str | bytes
  stdin: bytes | None
  extra: tuple
  expected: tuple
  context: Context


@dataclass(frozen=True)
class Summary:
  counts: dict


@dataclass(frozen=True)
class Omission:
  reason: str


def invocation(opts, mode, target, stdin, expected, counts, pass_only, tmp, attack=0, extra=(), verify_on_error=True):
  context = Context(counts, pass_only, tmp, verify_on_error)
  return Invocation(tuple(opts), mode, attack, target, stdin, tuple(extra), tuple(expected), context)


def run_single(opts, mode, pairs, args, width, file_only, pass_only, tmp):
  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0, "err": 0}

  temp_file = os.path.join(tmp, "m%05d_filebased.bin" % mode)
  for word, digest in pairs[:catalog.SINGLE_MAX]:
    if file_only:
      with open(temp_file, "wb") as fh:
        fh.write(oracles.decode_hashfile(mode, digest))

      target = temp_file
    else:
      target = digest

    candidate = word

    if mode == 20510:
      candidate = word[6:]
    yield invocation(opts, mode, target, candidate + b"\n", [(word, digest)], c, pass_only, tmp)
  yield Summary(c)


def run_multi(opts, mode, pairs, args, width, file_only, pass_only, tmp):
  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0, "err": 0}

  hash_file = os.path.join(tmp, "m%05d_hashes.txt" % mode)

  if file_only:
    with open(hash_file, "wb") as fh:
      for _, digest in pairs:
        fh.write(oracles.decode_hashfile(mode, digest))
  else:
    with open(hash_file, "wb") as fh:
      fh.write(b"\n".join(d.encode("ascii") for _, d in pairs) + b"\n")

  stdin_bytes = b"\n".join(w for w, _ in pairs) + b"\n"
  yield invocation(opts, mode, hash_file, stdin_bytes, pairs, c, pass_only, tmp)
  yield Summary(c)


class Run:
  def __init__(self, args, mode, pairs, width, opts, targets, file_only, pass_only, tmp):
    self.args      = args
    self.mode      = mode
    self.pairs     = pairs
    self.width     = width
    self.opts      = opts
    self.targets   = targets
    self.file_only = file_only
    self.pass_only = pass_only
    self.tmp       = tmp


def attack_0(r):

  if "single" in r.targets:
    yield from run_single(r.opts, r.mode, r.pairs, r.args, r.width, r.file_only, r.pass_only, r.tmp)

  if "multi" in r.targets:
    if catalog.has_multi_hash(r.mode):
      return

    yield from run_multi(r.opts, r.mode, r.pairs, r.args, r.width, r.file_only, r.pass_only, r.tmp)


def build_ruleset(ruleset_dir, words):

  shutil.rmtree(ruleset_dir, ignore_errors=True)

  os.makedirs(os.path.join(ruleset_dir, "Grammar"))
  os.makedirs(os.path.join(ruleset_dir, "Context"))

  with open(os.path.join(ruleset_dir, "Grammar", "grammar.txt"), "wb") as fh:
    fh.write(b"X1\t1.0\n")

  with open(os.path.join(ruleset_dir, "Context", "1.txt"), "wb") as fh:
    for word in words:
      fh.write(word + b"\t1.0\n")


def whole_word_source(attack, words_file, ruleset_dir):

  if attack == 4:
    return [ruleset_dir]

  if attack == 8:
    return ["wordlist", words_file]

  if attack == 9:
    return [words_file]

  return []


def whole_word_single(r, attack):
  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0, "err": 0}

  optimized = not r.args.pure

  if attack == 4:
    subst   = oracles.a4_vectors(r.mode, r.pairs, optimized)
    vectors = subst if subst is not None else r.pairs
  else:
    vectors = r.pairs
  max_n = 12 if catalog.is_timeout(r.mode) else 32

  temp_file   = os.path.join(r.tmp, "m%05d_filebased.bin" % r.mode)
  words_file  = os.path.join(r.tmp, "m%05d_a%d_words" % (r.mode, attack))
  ruleset_dir = os.path.join(r.tmp, "m%05d_a%d_ruleset" % (r.mode, attack))

  for word, digest in vectors[:max_n]:
    candidate = word

    if r.mode == 20510:
      candidate = word[6:]

    if attack == 4 and len(candidate) == 0:
      c["rs"]  += 1
      c["cnt"] += 1

      continue

    if r.file_only:
      with open(temp_file, "wb") as fh:
        fh.write(oracles.decode_hashfile(r.mode, digest))

      target = temp_file
    else:
      target = digest

    with open(words_file, "wb") as fh:
      fh.write(candidate + b"\n")

    if attack == 4:
      build_ruleset(ruleset_dir, [candidate])

    extra = whole_word_source(attack, words_file, ruleset_dir)
    yield invocation(r.opts, r.mode, target, None, [(word, digest)], c, r.pass_only, r.tmp,
                     attack=attack, extra=extra)
  yield Summary(c)


def whole_word_multi(r, attack):
  if catalog.has_multi_hash(r.mode):
    return

  if attack == 9:
    return

  if attack == 4 and r.file_only:
    return

  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0, "err": 0}

  optimized = not r.args.pure

  if attack == 4:
    subst  = oracles.a4_vectors(r.mode, r.pairs, optimized)
    mpairs = subst if subst is not None else [(w, d) for w, d in r.pairs if w != b""]
  else:
    mpairs = r.pairs

  hash_file   = os.path.join(r.tmp, "m%05d_hashes.txt" % r.mode)
  words_file  = os.path.join(r.tmp, "m%05d_a%d_multi_words" % (r.mode, attack))
  ruleset_dir = os.path.join(r.tmp, "m%05d_a%d_multi_ruleset" % (r.mode, attack))

  if r.file_only:
    with open(hash_file, "wb") as fh:
      for _, digest in mpairs:
        fh.write(oracles.decode_hashfile(r.mode, digest))
  else:
    with open(hash_file, "wb") as fh:
      fh.write(b"\n".join(d.encode("ascii") for _, d in mpairs) + b"\n")

  with open(words_file, "wb") as fh:
    fh.write(b"\n".join(w for w, _ in mpairs) + b"\n")

  if attack == 4:
    build_ruleset(ruleset_dir, [w for w, _ in mpairs])

  extra = whole_word_source(attack, words_file, ruleset_dir)
  yield invocation(r.opts, r.mode, hash_file, None, mpairs, c, r.pass_only, r.tmp,
                   attack=attack, extra=extra)
  yield Summary(c)


def whole_word(r, attack):
  if attack == 4 and catalog.a4_optimized_skip(r.mode, not r.args.pure):
    return

  if "single" in r.targets:
    yield from whole_word_single(r, attack)

  if "multi" in r.targets:
    yield from whole_word_multi(r, attack)


def attack_4(r):
  yield from whole_word(r, 4)


def attack_8(r):
  yield from whole_word(r, 8)


def attack_9(r):
  yield from whole_word(r, 9)


def utf8_split_point(text, off):

  n = len(text)
  back = off

  while back > 0 and back < n and 0x80 <= text[back] <= 0xbf:
    back -= 1

  if back == 0 and off > 0:
    while off < n and 0x80 <= text[off] <= 0xbf:
      off += 1

    return off

  return back


def combinator_init_params(mode):

  init_min = 1
  min_offset = 0

  if mode == 2500:
    min_offset = 7
  elif mode == 14000:
    init_min = 0
    min_offset = 4
  elif mode == 14100:
    init_min = 0
    min_offset = 3
  elif mode == 14900:
    init_min = 0
    min_offset = 5
  elif mode == 15400:
    init_min = 0
    min_offset = 3
  elif mode == 16800:
    min_offset = 7
  elif mode == 22000:
    min_offset = 7

  return init_min, min_offset


def split_for_combinator(pairs, mode):

  init_min, min_offset = combinator_init_params(mode)

  dict1 = []
  dict2 = []
  i = 0

  for word, _ in pairs:
    i += 1

    if i <= init_min:
      continue

    p0 = i // 2
    p1 = p0 + 1
    pass_len = len(word)

    if pass_len > 1:
      p1 += min_offset
      p0 += min_offset

      if p1 > pass_len:
        p1 = pass_len
        p0 = p1 - 1

      p0 = utf8_split_point(word, p0)

      dict1.append(word[:p0])
      dict2.append(word[p0:])
    elif pass_len == 1:
      dict1.append(word)
      dict2.append(b"")
    else:
      dict1.append(b"")
      dict2.append(b"")

  return dict1, dict2


def combinator_single_range(mode):

  smin, smax = 1, 8

  if mode in (14000, 14100, 14900, 15400):
    smin, smax = 0, 5
  elif mode == 20510:
    smin = 2

  return smin, smax


def combinator_multi_offset(mode):

  if mode in (5800, 3000):
    return 6

  return 7


def pkzip_masterkey_dicts(dict1, dict2, line_nr):

  idx = line_nr - 1
  d1 = dict1[idx]
  d2 = dict2[idx]

  if len(d1) >= 6:
    new_d1 = d1[6:]
    new_d2 = d2
  else:
    num_to_steal = 6 - len(d1)
    num_steal_start = num_to_steal + 1

    if len(d2) >= 6:
      num_to_steal_new = (len(d2) - num_to_steal) // 2

      if num_to_steal_new > num_to_steal:
        num_to_steal = num_to_steal_new

    new_d1 = d2[:num_to_steal][num_steal_start - 1:]
    new_d2 = d2[num_to_steal:]

  out1 = dict1[:idx] + [new_d1] + dict1[idx + 2:]
  out2 = dict2[:idx] + [new_d2] + dict2[idx + 2:]

  return out1, out2


def write_dict(path, lines):
  with open(path, "wb") as fh:
    for line in lines:
      fh.write(line + b"\n")


def run_combinator_single(r, dict1_lines, dict2_lines, dict1_path, dict2_path):
  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0, "err": 0}

  smin, smax = combinator_single_range(r.mode)

  temp_file = os.path.join(r.tmp, "m%05d_filebased.bin" % r.mode)
  mod1_path = os.path.join(r.tmp, "m%05d_dict1_mod" % r.mode)
  mod2_path = os.path.join(r.tmp, "m%05d_dict2_mod" % r.mode)

  i = 0

  for word, digest in r.pairs:
    i += 1

    if i > smin:
      if r.file_only:
        with open(temp_file, "wb") as fh:
          fh.write(oracles.decode_hashfile(r.mode, digest))

        target = temp_file
      else:
        target = digest

      d1p, d2p = dict1_path, dict2_path

      if r.mode == 20510:
        if smin == 0:
          line_nr = i
        elif i > 1:
          line_nr = i - 1
        else:
          line_nr = 1

        out1, out2 = pkzip_masterkey_dicts(dict1_lines, dict2_lines, line_nr)

        write_dict(mod1_path, out1)
        write_dict(mod2_path, out2)

        d1p, d2p = mod1_path, mod2_path
      yield invocation(r.opts, r.mode, target, b"", [(word, digest)], c, r.pass_only, r.tmp,
                       attack=1, extra=[d1p, d2p])

    if i == smax:
      break
  yield Summary(c)


def run_combinator_multi(r, dict1_path, dict2_path):
  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0, "err": 0}

  offset = combinator_multi_offset(r.mode)
  sel = r.pairs[-offset:]

  hash_file = os.path.join(r.tmp, "m%05d_multihash_combi.bin" % r.mode)

  if r.file_only:
    with open(hash_file, "wb") as fh:
      for _, digest in sel:
        fh.write(oracles.decode_hashfile(r.mode, digest))
  else:
    with open(hash_file, "wb") as fh:
      fh.write(b"\n".join(d.encode("ascii") for _, d in sel) + b"\n")
  yield invocation(r.opts, r.mode, hash_file, b"", sel, c, r.pass_only, r.tmp,
                   attack=1, extra=[dict1_path, dict2_path])
  yield Summary(c)


def attack_1(r):

  dict1_lines, dict2_lines = split_for_combinator(r.pairs, r.mode)

  dict1_path = os.path.join(r.tmp, "m%05d_dict1" % r.mode)
  dict2_path = os.path.join(r.tmp, "m%05d_dict2" % r.mode)

  write_dict(dict1_path, dict1_lines)
  write_dict(dict2_path, dict2_lines)

  if "single" in r.targets:
    yield from run_combinator_single(r, dict1_lines, dict2_lines, dict1_path, dict2_path)
  if "multi" in r.targets and not catalog.has_multi_hash(r.mode):
    yield from run_combinator_multi(r, dict1_path, dict2_path)


def mask_dots(count):

  return b"?d" * count


def mask_3(pos):

  if pos <= 15:
    return b"?d" * pos

  return b"?d" * 15 + b"0" * (pos - 15)


def mask_literalize(mask, text):

  tokens = []
  pos = 0

  while pos < len(mask):
    if mask[pos:pos + 1] == b"?":
      tokens.append(mask[pos:pos + 2])
      pos += 2
    else:
      tokens.append(mask[pos:pos + 1])
      pos += 1

  if len(tokens) != len(text):
    return mask

  out = b""

  for k, tok in enumerate(tokens):
    byte = text[k:k + 1]

    if b"0" <= byte <= b"9":
      out += tok
    else:
      out += byte

  return out


def a3_single_max(mode):

  if mode in (14000, 14100, 14900, 15400):
    return 1

  if mode in (2500, 16800, 22000):
    return 7

  return 8


def a3_single_mask(mode, word, i):

  if mode in (14000, 14100):
    return word

  if mode == 20510:
    cand = word[6:]
    nd   = max(i - 6, 0)

    if nd > len(cand):
      nd = len(cand)

    return mask_literalize(mask_dots(nd), cand[:nd]) + cand[nd:]

  return mask_literalize(mask_dots(i), word[:i]) + word[i:]


def attack_3_single(r):
  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0, "err": 0}

  max_i     = a3_single_max(r.mode)
  temp_file = os.path.join(r.tmp, "m%05d_filebased.bin" % r.mode)

  i = 1

  for word, digest in r.pairs:
    if i > 6 and catalog.is_timeout(r.mode):
      break
    if len(word) < i:
      i += 1

      continue
    if r.mode == 20510 and i <= 1:
      i += 1

      continue

    if r.file_only:
      with open(temp_file, "wb") as fh:
        fh.write(oracles.decode_hashfile(r.mode, digest))

      target = temp_file
    else:
      target = digest

    mask = a3_single_mask(r.mode, word, i)
    yield invocation(r.opts, r.mode, target, None, [(word, digest)], c, r.pass_only, r.tmp,
                     attack=3, extra=[mask])

    if i == max_i:
      break

    i += 1
  yield Summary(c)


def a3_multi_increment(mode):

  increment_min = 1
  increment_max = 5 if catalog.is_timeout(mode) else 8

  if mode in (2500, 16800, 22000):
    increment_min = 8
    increment_max = 9

  return increment_min, increment_max


def a3_custom_charsets(mode, sel_passwords):

  if mode not in (2500, 16800, 22000):
    return []

  args = []

  for n, pos in ((1, 6), (2, 7), (3, 8), (4, 9)):
    if not sel_passwords:
      charset = str(n).encode("ascii")
    else:
      chars = set()

      for pw in sel_passwords:
        chars.add(pw[pos - 1:pos])

      charset = b"".join(sorted(chars))

    args += ["-%d" % n, charset]

  return args


def attack_3_multi(r):
  if catalog.has_multi_hash(r.mode):
    return

  increment_min, increment_max = a3_multi_increment(r.mode)

  words   = [w for w, _ in r.pairs]
  digests = [d for _, d in r.pairs]

  head_hashes = sum(1 for w in words if len(w) <= increment_max)
  tail_hashes = sum(1 for w in words if increment_min <= len(w) <= increment_max)

  need_hcmask = 0

  if tail_hashes > head_hashes:
    need_hcmask = 1

  if any(b > 0x7f for w in words for b in w):
    need_hcmask = 2

  if tail_hashes < 1:
    need_hcmask = 1

  hash_file   = os.path.join(r.tmp, "m%05d_multihash_bruteforce.txt" % r.mode)
  hcmask_path = os.path.join(r.tmp, "m%05d_multi_a3.hcmask" % r.mode)
  dict_path   = os.path.join(r.tmp, "m%05d_passwords.txt" % r.mode)

  if need_hcmask in (0, 2):
    sel = list(range(head_hashes - tail_hashes, head_hashes))
  else:
    tail_hashes = sum(1 for w in words if len(w) >= increment_min)

    if tail_hashes < 1:
      return

    sel = list(range(len(words) - tail_hashes, len(words)))

  if r.file_only:
    with open(hash_file, "wb") as fh:
      for k in sel:
        fh.write(oracles.decode_hashfile(r.mode, digests[k]))
  else:
    with open(hash_file, "wb") as fh:
      fh.write(b"\n".join(digests[k].encode("ascii") for k in sel) + b"\n")

  mask_pos = max(8, increment_min)

  if need_hcmask == 2:
    cracks_offset = head_hashes - tail_hashes

    with open(hcmask_path, "wb") as fh:
      for w in words:
        if increment_min <= len(w) <= increment_max:
          fh.write(mask_literalize(mask_dots(len(w)), w) + b"\n")

    mask_arg = hcmask_path
  elif need_hcmask == 0:
    cracks_offset = head_hashes - tail_hashes
    mask_arg      = mask_3(mask_pos)
  else:
    cracks_offset = len(words) - tail_hashes

    with open(dict_path, "wb") as fh:
      for w in words:
        fh.write(w + b"\n")

    mask_arg = dict_path

  custom = a3_custom_charsets(r.mode, words[:len(sel)])

  if r.mode in (2500, 16800, 22000):
    mask_arg = b"?d?d?d?d?d?1?2?3?4"

  increment_opts = []

  if need_hcmask == 0:
    increment_opts = ["--increment", "--increment-min", str(increment_min),
                      "--increment-max", str(increment_max)] + custom
  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0, "err": 0}

  expected = [(words[idx + cracks_offset], digests[k]) for idx, k in enumerate(sel)]
  yield invocation(r.opts, r.mode, hash_file, None, expected, c, r.pass_only, r.tmp,
                   attack=3, extra=increment_opts + [mask_arg], verify_on_error=False)
  yield Summary(c)


def attack_3(r):

  if "single" in r.targets:
    yield from attack_3_single(r)

  if "multi" in r.targets:
    yield from attack_3_multi(r)


def sed_line(lines, n):

  if 1 <= n <= len(lines):
    return lines[n - 1]

  return b""


def hybrid_extra(items):

  return [x for x in items if not (isinstance(x, bytes) and x == b"")]


def multi_len_params(mode, attack=None):

  min_len   = 0
  fixed_len = 0

  if mode == 2500:
    min_len = 7
  elif mode in (14000, 14100, 14900, 15400):
    fixed_len = {14000: 8, 14100: 24, 14900: 10, 15400: 32}[mode]
    min_len   = 3 if attack == 7 else fixed_len - 5
  elif mode == 16800:
    min_len = 7
  elif mode == 22000:
    min_len = 7
  elif mode in (9710, 9810, 10410):
    fixed_len = 5
  elif mode == 33500:
    fixed_len = 5
  elif mode == 33501:
    min_len   = 5
    fixed_len = 9
  elif mode == 33502:
    min_len   = 5
    fixed_len = 13
  elif mode == 36900:
    fixed_len = 8
  elif mode == 36901:
    fixed_len = 5
  elif mode == 37400:
    min_len   = 4
    fixed_len = 9

  return min_len, fixed_len


def build_multi_dicts(mode, i, pairs, attack=None):

  min_len, _ = multi_len_params(mode, attack)

  p0 = i // 2 + min_len

  dict1 = []
  dict2 = []

  for word, _ in pairs:
    p0 = utf8_split_point(word, p0)

    dict1.append(word[:p0])
    dict2.append(word[p0:])

  return dict1, dict2


def write_hashes(path, pairs, mode, file_only):

  with open(path, "wb") as fh:
    for _, digest in pairs:
      if file_only:
        fh.write(oracles.decode_hashfile(mode, digest))
      else:
        fh.write(digest.encode("ascii") + b"\n")


def a6_single_params(mode):

  min_i, max_i = 1, 8

  if mode == 2500:
    max_i = 6
  elif mode in (14000, 14100, 14900, 15400):
    min_i, max_i = 0, 1
  elif mode == 16800:
    max_i = 6
  elif mode == 22000:
    max_i = 6

  return min_i, max_i


def attack_6_single(r):
  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0, "err": 0}

  min_i, max_i = a6_single_params(r.mode)

  dict1_lines, dict2_lines = split_for_combinator(r.pairs, r.mode)

  temp_file = os.path.join(r.tmp, "m%05d_filebased.bin" % r.mode)
  dict1_a6  = os.path.join(r.tmp, "m%05d_a6_dict1" % r.mode)

  for idx, (word, digest) in enumerate(r.pairs):
    i = idx + 1
    if i > 6 and catalog.is_timeout(r.mode):
      break

    if i > min_i:
      if r.file_only:
        with open(temp_file, "wb") as fh:
          fh.write(oracles.decode_hashfile(r.mode, digest))

        target = temp_file
      else:
        target = digest

      pass_b = word

      if r.mode == 20510:
        pass_b = pass_b[6:]

      mask_len = i

      if mask_len >= len(pass_b):
        mask_len = len(pass_b) - 1

      if mask_len < 1:
        continue

      a6_split = utf8_split_point(pass_b, len(pass_b) - mask_len)

      write_dict(dict1_a6, dict1_lines + [pass_b[:a6_split]])

      mask = mask_literalize(b"?d" * (len(pass_b) - a6_split), pass_b[a6_split:])
      line_nr = i - 1 if i > 1 else 1
      search_word = sed_line(dict1_lines, line_nr) + sed_line(dict2_lines, line_nr)
      yield invocation(r.opts, r.mode, target, None, [(search_word, digest)], c, r.pass_only, r.tmp,
                       attack=6, extra=hybrid_extra([dict1_a6, mask]), verify_on_error=False)

    if i == max_i:
      break
  yield Summary(c)


def a6_multi_params(mode):

  min_i, max_i = 1, 9

  if mode == 2500:
    max_i = 5
  elif mode == 3000:
    max_i = 8
  elif mode in (7700, 7701):
    max_i = 8
  elif mode == 8500:
    max_i = 8
  elif mode == 16800:
    max_i = 5
  elif mode == 22000:
    max_i = 5
  elif mode == 33500:
    min_i = 5
  elif mode == 33501:
    min_i = 5
  elif mode == 33502:
    min_i = 8
  elif mode == 37400:
    min_i = 8
  if catalog.is_timeout(mode):
    max_i = 5

    if mode == 3200:
      max_i = 3

  return min_i, max_i


def attack_6_multi(r):
  if catalog.has_multi_hash(r.mode):
    return

  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0, "err": 0}

  min_i, max_i = a6_multi_params(r.mode)
  optimized    = not r.args.pure

  hash_file = os.path.join(r.tmp, "m%05d_a6_hashes_multi.txt" % r.mode)
  dict1_mp  = os.path.join(r.tmp, "m%05d_a6_dict1_multi" % r.mode)

  i = 2

  while i < max_i:
    if i < min_i:
      i += 1

      continue
    pairs  = oracles.multi_pairs(r.mode, i, optimized)

    if len(pairs) == 0:
      i += 1

      continue

    d1, d2 = build_multi_dicts(r.mode, i, pairs)

    write_hashes(hash_file, pairs, r.mode, r.file_only)
    write_dict(dict1_mp, d1)

    multi_model = pairs[0][0] if pairs else b""
    multi_head  = d1[0] if d1 else b""
    multi_tail  = multi_model[len(multi_head):]
    if not multi_tail:
      i += 1

      continue

    mask = mask_literalize(mask_dots(len(multi_tail)), multi_tail)
    expected = [(sed_line(d1, j + 1) + sed_line(d2, j + 1), digest) for j, (_, digest) in enumerate(pairs)]
    yield invocation(r.opts, r.mode, hash_file, None, expected, c, r.pass_only, r.tmp,
                     attack=6, extra=hybrid_extra([dict1_mp, mask]), verify_on_error=False)

    i += 1
  yield Summary(c)


def attack_6(r):

  if "single" in r.targets:
    yield from attack_6_single(r)

  if "multi" in r.targets:
    yield from attack_6_multi(r)


def a7_single_params(mode):

  min_i, max_i, mask_offset = 1, 8, 0

  if mode == 2500:
    max_i = 5
  elif mode == 14000:
    min_i, max_i, mask_offset = 0, 1, 4
  elif mode == 14100:
    min_i, max_i, mask_offset = 0, 1, 3
  elif mode == 14900:
    min_i, max_i, mask_offset = 0, 1, 5
  elif mode == 15400:
    min_i, max_i, mask_offset = 0, 1, 3
  elif mode == 16800:
    max_i = 5
  elif mode == 22000:
    max_i = 5

  return min_i, max_i, mask_offset


def attack_7_single(r):
  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0, "err": 0}

  min_i, max_i, mask_offset = a7_single_params(r.mode)
  optimized = not r.args.pure

  dict1_lines, dict2_lines = split_for_combinator(r.pairs, r.mode)

  temp_file  = os.path.join(r.tmp, "m%05d_filebased.bin" % r.mode)
  dict2_base = os.path.join(r.tmp, "m%05d_a7_dict2" % r.mode)
  dict2_cust = os.path.join(r.tmp, "m%05d_a7_dict2_custom" % r.mode)

  write_dict(dict2_base, dict2_lines)

  custom_active = (min_i == 0)
  cust_d1       = None
  cust_d2       = None

  if custom_active:
    first   = sed_line(dict1_lines, 1) + sed_line(dict2_lines, 1)
    cust_d1 = [first[:mask_offset]]
    cust_d2 = [first[mask_offset:]]

    write_dict(dict2_cust, cust_d2)

  for idx, (word, digest) in enumerate(r.pairs):
    i = idx + 1

    if i > min_i:
      if r.file_only:
        with open(temp_file, "wb") as fh:
          fh.write(oracles.decode_hashfile(r.mode, digest))

        target = temp_file
      else:
        target = digest

      line_nr = i - 1 if i > 1 else 1

      d1_lines = dict1_lines
      d2_lines = dict2_lines
      d2_path  = dict2_base
      active   = custom_active

      if r.mode == 20510:
        pass_full = sed_line(dict1_lines, line_nr) + sed_line(dict2_lines, line_nr)

        if len(pass_full) <= 6:
          continue

        cut        = pass_full[6:]
        mpairs     = oracles.multi_pairs(20510, i, optimized)
        md1, _     = build_multi_dicts(20510, i, mpairs)
        multi_head = md1[0] if md1 else b""
        mask_len   = len(mask_literalize(mask_dots(len(multi_head)), multi_head)) // 2

        if mask_len < 1:
          mask_len = 1

        if mask_len > len(cut):
          mask_len = len(cut)

        cust_d1 = [cut[:mask_len]]
        cust_d2 = [cut[mask_len:]]

        write_dict(dict2_cust, cust_d2)

        active = True

      read_nr = line_nr

      if active:
        d1_lines = cust_d1
        d2_lines = cust_d2
        d2_path  = dict2_cust
        read_nr  = 1

      dict1_line = sed_line(d1_lines, read_nr)
      mask       = mask_literalize(mask_dots(len(dict1_line)), dict1_line)
      search_word = sed_line(d1_lines, read_nr) + sed_line(d2_lines, read_nr)
      yield invocation(r.opts, r.mode, target, None, [(search_word, digest)], c, r.pass_only, r.tmp,
                       attack=7, extra=hybrid_extra([mask, d2_path]), verify_on_error=False)

    if i == max_i:
      break
  yield Summary(c)


def a7_multi_max(mode):

  max_i = 9

  if mode == 2500:
    max_i = 5
  elif mode == 3000:
    max_i = 8
  elif mode in (7700, 7701):
    max_i = 8
  elif mode == 8500:
    max_i = 8
  elif mode in (14000, 14100, 14900, 15400, 16800, 22000):
    max_i = 5
  elif mode in (33501, 33502):
    max_i = 3
  elif mode == 37400:
    max_i = 3
  if catalog.is_timeout(mode):
    max_i = 7

    if mode == 3200:
      max_i = 4

  return max_i


def attack_7_multi(r):
  if catalog.has_multi_hash(r.mode):
    return

  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0, "err": 0}

  max_i     = a7_multi_max(r.mode)
  optimized = not r.args.pure

  hash_file  = os.path.join(r.tmp, "m%05d_a7_hashes_multi.txt" % r.mode)
  dict2_mp   = os.path.join(r.tmp, "m%05d_a7_dict2_multi" % r.mode)
  dict2_long = os.path.join(r.tmp, "m%05d_a7_dict2_multi_longer" % r.mode)

  i = 2

  while i < max_i:
    pairs  = oracles.multi_pairs(r.mode, i, optimized)

    if len(pairs) == 0:
      i += 1

      continue

    d1, d2 = build_multi_dicts(r.mode, i, pairs, attack=7)

    multi_head = d1[0] if d1 else b""
    mask       = mask_literalize(mask_dots(len(multi_head)), multi_head)

    write_hashes(hash_file, pairs, r.mode, r.file_only)

    if r.file_only:
      mask_len   = len(mask) // 2
      long_lines = [(d1[j] + d2[j])[mask_len:] for j in range(len(pairs))]

      write_dict(dict2_long, long_lines)

      dict_file = dict2_long
    else:
      write_dict(dict2_mp, d2)

      dict_file = dict2_mp
    expected = [(sed_line(d1, j + 1) + sed_line(d2, j + 1), digest) for j, (_, digest) in enumerate(pairs)]
    yield invocation(r.opts, r.mode, hash_file, None, expected, c, r.pass_only, r.tmp,
                     attack=7, extra=hybrid_extra([mask, dict_file]), verify_on_error=False)

    i += 1
  yield Summary(c)


def attack_7(r):

  if "single" in r.targets:
    yield from attack_7_single(r)

  if "multi" in r.targets:
    yield from attack_7_multi(r)


def a12_single_max(mode):

  if mode in (2500, 16800, 22000):
    return 6

  return 8


def report_skip_counts(r, target_name):
  yield Omission("attack 12 cannot express this mode")


def attack_12_single(r):
  if r.mode in catalog.A12_SKIP:
    yield from report_skip_counts(r, "single")

    return

  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0, "err": 0}

  max_i = a12_single_max(r.mode)

  dict1_lines, dict2_lines = split_for_combinator(r.pairs, r.mode)

  temp_file = os.path.join(r.tmp, "m%05d_filebased.bin" % r.mode)
  dict1_a12 = os.path.join(r.tmp, "m%05d_a12_dict1" % r.mode)
  dict2_a12 = os.path.join(r.tmp, "m%05d_a12_dict2" % r.mode)

  for idx, (word, digest) in enumerate(r.pairs):
    i = idx + 1
    if i > 6 and catalog.is_timeout(r.mode):
      break

    if i > 1:
      if r.file_only:
        with open(temp_file, "wb") as fh:
          fh.write(oracles.decode_hashfile(r.mode, digest))

        target = temp_file
      else:
        target = digest

      pass_len = len(word)

      mask_len = i

      if mask_len > 4:
        mask_len = 4

      head_len = mask_len // 2
      word_len = pass_len - mask_len
      if word_len >= 1:
        head_end   = utf8_split_point(word, head_len)
        tail_start = utf8_split_point(word, head_len + word_len)

        mask_head = mask_literalize(mask_dots(head_end), word[:head_end])
        mask_tail = mask_literalize(mask_dots(pass_len - tail_start), word[tail_start:])

        for shape in ("first", "last", "middle", "q"):
          dicts = [dict1_a12]

          if shape == "first":
            word_end  = utf8_split_point(word, word_len)
            head_word = word[:word_end]
            mask      = b"?w" + mask_literalize(mask_dots(pass_len - word_end), word[word_end:])
          elif shape == "last":
            mask_start = utf8_split_point(word, mask_len)
            head_word  = word[mask_start:]
            mask       = mask_literalize(mask_dots(mask_start), word[:mask_start]) + b"?w"
          elif shape == "middle":
            head_word = word[head_end:tail_start]
            mask      = mask_head + b"?w" + mask_tail
          else:
            q_end = utf8_split_point(word, head_end + (tail_start - head_end) // 2)

            if q_end <= head_end or q_end >= tail_start:
              continue

            head_word = word[head_end:q_end]

            write_dict(dict2_a12, [word[q_end:tail_start]])

            mask  = mask_head + b"?w?q" + mask_tail
            dicts = [dict1_a12, dict2_a12]

          write_dict(dict1_a12, dict1_lines + [head_word])
          yield invocation(r.opts, r.mode, target, None, [(word, digest)], c, r.pass_only, r.tmp,
                           attack=12, extra=hybrid_extra([mask] + dicts), verify_on_error=False)

    if i == max_i:
      break
  yield Summary(c)


def attack_12_multi(r):
  if catalog.has_multi_hash(r.mode):
    return
  if r.mode in catalog.A12_SKIP:
    yield from report_skip_counts(r, "multi")

    return

  c = {"cnt": 0, "nf": 0, "nm": 0, "to": 0, "rs": 0, "err": 0}

  min_i, max_i = a6_multi_params(r.mode)
  optimized    = not r.args.pure

  hash_file = os.path.join(r.tmp, "m%05d_a12_hashes_multi.txt" % r.mode)
  dict1_mp  = os.path.join(r.tmp, "m%05d_a12_dict1_multi" % r.mode)
  dict2_mp  = os.path.join(r.tmp, "m%05d_a12_dict2_multi" % r.mode)

  i = 2

  while i < max_i:
    if i < min_i:
      i += 1

      continue
    pairs  = oracles.multi_pairs(r.mode, i, optimized)

    if len(pairs) == 0:
      i += 1

      continue

    d1, d2 = build_multi_dicts(r.mode, i, pairs)

    write_hashes(hash_file, pairs, r.mode, r.file_only)
    write_dict(dict1_mp, d1)
    write_dict(dict2_mp, d2)

    multi_model = pairs[0][0] if pairs else b""
    multi_head  = d1[0] if d1 else b""
    multi_tail  = multi_model[len(multi_head):]

    for shape in ("first", "last"):
      if shape == "first":
        dict_file = dict1_mp
        mask      = b"?w" + mask_literalize(mask_dots(len(multi_tail)), multi_tail)
      else:
        dict_file = dict2_mp
        mask      = mask_literalize(mask_dots(len(multi_head)), multi_head) + b"?w"
      expected = [(sed_line(d1, j + 1) + sed_line(d2, j + 1), digest) for j, (_, digest) in enumerate(pairs)]
      yield invocation(r.opts, r.mode, hash_file, None, expected, c, r.pass_only, r.tmp,
                       attack=12, extra=hybrid_extra([mask, dict_file]), verify_on_error=False)

    i += 1
  yield Summary(c)


def attack_12(r):

  if "single" in r.targets:
    yield from attack_12_single(r)

  if "multi" in r.targets:
    yield from attack_12_multi(r)


ATTACKS = {
  0: attack_0,
  1: attack_1,
  3: attack_3,
  4: attack_4,
  6: attack_6,
  7: attack_7,
  8: attack_8,
  9: attack_9,
  12: attack_12,
}


def container_mask_from_password(pw, where):

  n = len(pw)

  order = range(0, n) if where == "first" else range(n - 1, -1, -1)

  for i in order:
    if b"0" <= pw[i:i + 1] <= b"9":
      return pw[:i] + b"?d" + pw[i + 1:]

  return pw


def build_container_extra(mode, attack, vpass, tmp):

  dict1 = os.path.join(tmp, "%d_cont_dict1" % mode)
  dict2 = os.path.join(tmp, "%d_cont_dict2" % mode)

  plen = len(vpass)

  if attack == 0:
    with open(dict1, "wb") as fh:
      fh.write(vpass + b"\n")

    return [dict1]

  if attack == 1:
    split = utf8_split_point(vpass, plen // 2)

    with open(dict1, "wb") as fh:
      fh.write(vpass[:split] + b"\n")

    with open(dict2, "wb") as fh:
      fh.write(vpass[split:] + b"\n")

    return [dict1, dict2]

  if attack == 3:
    return [container_mask_from_password(vpass, "last")]

  if attack == 6:
    split = utf8_split_point(vpass, plen - 1)

    with open(dict1, "wb") as fh:
      fh.write(vpass[:split] + b"\n")

    return [dict1, container_mask_from_password(vpass[split:], "last")]

  if attack == 7:
    split = utf8_split_point(vpass, 1)

    if split <= 0:
      split = 1

    with open(dict1, "wb") as fh:
      fh.write(vpass[split:] + b"\n")

    return [container_mask_from_password(vpass[:split], "first"), dict1]

  return None
