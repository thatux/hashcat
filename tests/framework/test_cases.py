##
## Author......: See docs/credits.txt
## License.....: MIT
##

import pytest

from hashcat_pytest import cases, catalog

pytestmark = pytest.mark.framework


class Config:
  def __init__(self, **options):
    self.options = dict(hash_modes="29511", attacks="0,3,7", kernels="pure", widths="1",
                        targets="single", profile="default", include_generated=False,
                        allow_all_attacks=False, attack_exec="all")
    self.options.update(options)

  def getoption(self, name):
    return self.options[name]


@pytest.mark.parametrize("suite,mode", [("containers", 29511), ("generated", 29511), ("generated", 11600)])
def test_container_and_generator_attack_lists(suite, mode):
  selected = cases.collect_cases(Config(hash_modes=str(mode)), suite)
  assert {case.attack for case in selected} == {0, 3, 7}
  assert len({case.node_id for case in selected}) == len(selected)
  assert cases.collect_cases(Config(hash_modes=str(mode), attacks="4,8,9,12"), suite) == []


@pytest.mark.parametrize("suite", ["containers", "generated"])
@pytest.mark.parametrize("mode", [6211, 13721])
def test_fixed_mask_containers_preserve_family_attack(suite, mode):
  selected = cases.collect_cases(Config(hash_modes=str(mode)), suite)
  assert selected and {case.attack for case in selected} == {3}


@pytest.mark.parametrize("options", [{"attacks": "all"}, {"attacks": None, "profile": "full"}])
def test_full_artifact_defaults(options):
  assert {case.attack for case in cases.collect_cases(Config(**options), "containers")} == {3}
  assert {case.attack for case in cases.collect_cases(Config(**options), "generated")} == {0}
  assert {case.attack for case in cases.collect_cases(Config(hash_modes="17200", **options), "generated")} == {0, 1, 3}


@pytest.mark.parametrize("mode", [1310, 1320, 6050, 6060, 11400, 14700, 34400, 35700])
def test_edge_collection_uses_available_kernel_families(mode):
  selected = cases.collect_cases(Config(hash_modes=str(mode), attacks="0", kernels=None), "edge")
  assert selected and {case.kernel for case in selected} == {"pure"}


@pytest.mark.parametrize("mode", [70000, 70100, 70200, 73000, 74000])
def test_bridge_source_metadata_has_only_pure_kernels(mode):
  assert catalog.source_capabilities(mode)["kernel_types"] == ["pure"]


@pytest.mark.parametrize("mode", [2500, 2501, 16800, 16801])
def test_deprecated_modes_have_no_edge_cases(mode):
  assert catalog.source_capabilities(mode)["deprecated"]
  assert cases.collect_cases(Config(hash_modes=str(mode), attacks="all", kernels="both"), "edge") == []


def test_recipe_edge_selection_retains_inside_kernel_attacks():
  selected = cases.collect_cases(Config(hash_modes="4000,1000", attacks="all", kernels="pure", attack_exec="inside"), "edge")
  assert {case.attack for case in selected if case.mode == 4000} == set(catalog.ATTACK_ORDER)


def test_selftest_only_normal_path_preserves_widths():
  config = Config(hash_modes="23800", attacks="all", kernels="pure", widths="1,4")
  selected = cases.collect_cases(config, "cracking")
  assert {(case.attack, case.width, case.variant) for case in selected} == {(0, 1, "selftest"), (0, 4, "selftest")}
  assert len(cases.collect_cases(config, "selftest")) == 1
  config.options["attacks"] = "1,3"
  assert {case.attack for case in cases.collect_cases(config, "cracking")} == {1, 3}
