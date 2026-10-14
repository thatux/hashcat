##
## Author......: See docs/credits.txt
## License.....: MIT
##

from dataclasses import dataclass

from . import catalog, containers


@dataclass(frozen=True)
class Case:
  mode: int
  suite: str
  attack: int | None = None
  kernel: str | None = None
  target: str | None = None
  width: int | None = None
  variant: str | None = None

  @property
  def node_id(self):
    fields = ["m%d" % self.mode]
    fields += ["a%d" % self.attack] if self.attack is not None else []
    fields += [value for value in (self.kernel, self.target) if value is not None]
    fields += ["w%d" % self.width] if self.width is not None else []
    fields += [self.variant] if self.variant is not None else []
    return "-".join(fields)


def select_modes(spec, pool):
  if spec == "all":
    return sorted(pool)
  if spec == "minimal":
    return sorted(set(catalog.MINIMAL_MODES) & set(pool))
  selected = set()
  for field in spec.replace(",", " ").split():
    ends = field.split("-")
    if len(ends) not in (1, 2) or any(value.isdigit() == False for value in ends):
      raise ValueError("invalid hash mode selection: " + field)
    low, high = int(ends[0]), int(ends[-1])
    if low > high:
      raise ValueError("reversed hash mode range: " + field)
    matches = {mode for mode in pool if low <= mode <= high}
    if not matches:
      raise ValueError("no testable hash modes in " + field)
    selected.update(matches)
  if not selected:
    raise ValueError("empty hash mode selection")
  return sorted(selected)


def values(spec, permitted):
  if spec in ("all", "both"):
    return list(permitted)
  result = []
  for value in spec.split(","):
    converted = int(value) if isinstance(permitted[0], int) else value
    if converted not in permitted:
      raise ValueError("unsupported selection: " + value)
    if converted not in result:
      result.append(converted)
  return result


def collect_cases(config, suite):
  pool = set(catalog.source_modes()) | set(catalog.discover_modes()) | catalog.CONTAINER_MODES
  modes = select_modes(config.getoption("hash_modes"), pool)
  attack_option = config.getoption("attacks")
  kernel_option = config.getoption("kernels")
  width_option = config.getoption("widths")
  targets = values(config.getoption("targets"), ["single", "multi"])
  full = config.getoption("profile") == "full"
  attacks = values(attack_option or ("all" if suite == "edge" or full else "0"), catalog.ATTACK_ORDER)
  kernels = values(kernel_option or ("both" if suite == "edge" else "optimized"), ["pure", "optimized"])
  widths = values(width_option or "all", catalog.EDGE_WIDTHS if suite == "edge" else [1, 4])
  broad = config.getoption("hash_modes").isdigit() == False
  cases = []
  for mode in modes:
    facts = catalog.source_capabilities(mode)
    if kernel_option is None and suite != "edge":
      available = catalog.oracle_families(mode)
      preferred = "optimized" if "optimized" in available else "pure"
      kernels = available if full and available else [preferred]
    if suite == "coverage":
      continue
    if suite == "stdout":
      if mode == catalog.STDOUT_MODE:
        cases.append(Case(mode, suite))
      continue
    if suite == "bridge":
      if mode in catalog.discover_modes() and mode not in catalog.CONTAINER_MODES:
        cases.append(Case(mode, suite))
      continue
    if suite == "selftest":
      if mode in catalog.source_modes() and mode not in catalog.NO_SELFTEST:
        for kernel in kernels:
          cases.append(Case(mode, suite, 3 if mode in catalog.MASK_ONLY_MODES else 0, kernel, "single"))
      continue
    if suite in ("containers", "generated"):
      permitted = catalog.CONTAINER_MODES if suite == "containers" else catalog.GEN_MODES
      if mode not in permitted:
        continue
      if suite == "containers" and config.getoption("include_generated") and mode in catalog.CONTAINER_GEN_MODES:
        continue
      fixed_mask = mode in catalog.TC_MODES or mode in catalog.VC_MODES or mode in catalog.CL_MODES
      if fixed_mask:
        family_attacks = [3]
      elif suite == "containers":
        family_attacks = [3] if attack_option == "all" or (full and attack_option is None) else [attack for attack in attacks if attack in (0, 1, 3, 6, 7)]
      elif attack_option == "all" or (full and attack_option is None):
        family_attacks = [0, 1, 3] if mode in catalog.PKZIP_GEN_MODES else [0]
      else:
        family_attacks = [attack for attack in attacks if attack in (0, 1, 3, 6, 7)]
      for kernel in kernels if suite == "generated" else ["pure"]:
        for width in widths:
          for variant in containers.container_variants(mode) if suite == "containers" else [None]:
            for attack in family_attacks:
              cases.append(Case(mode, suite, attack, kernel, "single", width, variant))
      continue
    if suite == "cracking" and mode in catalog.SELFTEST_MODES:
      family_attacks = [0] if attack_option in (None, "all") else [attack for attack in attacks if attack in (0, 1, 3, 6, 7)]
      for kernel in kernels:
        for width in widths:
          for attack in family_attacks:
            cases.append(Case(mode, suite, attack, kernel, "single", width, "selftest"))
      continue
    if mode not in catalog.discover_modes() or (suite == "cracking" and mode in catalog.CONTAINER_MODES) or mode == catalog.STDOUT_MODE:
      continue
    if suite == "edge" and facts["deprecated"]:
      continue
    families = catalog.oracle_families(mode)
    if suite == "edge":
      families = [family for family in families if family in facts["kernel_types"]]
    for attack in attacks:
      if suite == "cracking" and attack == 12 and mode in catalog.A12_SKIP:
        continue
      if mode in catalog.MASK_ONLY_MODES and attack != 3:
        continue
      if suite == "cracking" and catalog.is_slow(mode) and attack not in catalog.WHOLE_WORD:
        continue
      if suite == "edge" and broad and catalog.host_engine(mode) and mode != 400 and config.getoption("allow_all_attacks") == False:
        if 0 in attacks and attack not in catalog.WHOLE_WORD:
          continue
      location = "outside" if facts["slow"] else "inside"
      if config.getoption("attack_exec") not in ("all", location):
        continue
      for kernel in kernels:
        if kernel not in families:
          continue
        if attack == 4 and catalog.a4_optimized_skip(mode, kernel == "optimized"):
          continue
        for target in targets:
          if target == "multi":
            if mode == 20510 or facts["cnt_max"] == 1:
              continue
            if suite == "edge" and catalog.edge_binary_hashfile(mode):
              continue
            if suite == "cracking" and (attack == 9 or (attack == 4 and catalog.is_file_only(mode))):
              continue
            if suite == "edge" and attack == 9 and (facts["salt_present"] == False or facts["salt_virtual"]):
              continue
          for width in widths:
            cases.append(Case(mode, suite, attack, kernel, target, width))
  return cases
