##
## Author......: See docs/credits.txt
## License.....: MIT
##

from collections import Counter
from contextlib import ExitStack
import os
from pathlib import Path
import secrets
import shutil
import tempfile
import warnings
from types import SimpleNamespace

import pytest

from . import artifacts, catalog, cases, hardware, runtime, scheduling


def pytest_addoption(parser):
  group = parser.getgroup("hashcat")
  group.addoption("--hash-modes", default="all", help="Mode, comma/space list, range, all or minimal")
  group.addoption("--attacks", default=None, help="Attack numbers separated by commas, or all")
  group.addoption("--kernels", choices=("pure", "optimized", "both"), default=None)
  group.addoption("--targets", choices=("single", "multi", "all"), default="all")
  group.addoption("--widths", default=None, help="Vector widths separated by commas, or all")
  group.addoption("--device-type", choices=("cpu", "gpu", "fpga"), default="gpu")
  group.addoption("--backend-devices", default=None)
  group.addoption("--force", action="store_true")
  group.addoption("--hashcat-binary", default=str(Path(runtime.ROOT, "hashcat")))
  group.addoption("--runtime", type=int, default=None)
  group.addoption("--metal-compiler-runtime", type=int, default=None)
  group.addoption("--hashcat-verbose", action="store_true")
  group.addoption("--seed", default="12345", help="Oracle seed, or random (always reported)")
  group.addoption("--profile", choices=("default", "full"), default="default")
  group.addoption("--include-generated", action="store_true")
  group.addoption("--allow-privileged", action="store_true")
  group.addoption("--require-coverage", action="store_true", help="Fail missing resources and unexecuted modes")
  group.addoption("--allow-all-attacks", action="store_true")
  group.addoption("--attack-exec", choices=("inside", "outside", "all"), default="all")
  group.addoption("--gpu-strategy", choices=("depth", "breadth"), default="depth")
  group.addoption("--sanitizer", choices=("memcheck", "racecheck", "synccheck", "initcheck"))
  group.addoption("--keep-artifacts", choices=("failures", "all", "none"), default="failures")
  group.addoption("--artifact-dir", default="pytest-artifacts")


def pytest_configure(config):
  for suite in ("cracking", "edge", "selftest", "bridge", "containers", "generated", "stdout", "coverage", "framework"):
    config.addinivalue_line("markers", suite + ": hashcat " + suite + " tests")
  config.addinivalue_line("markers", "requires_external_tools: real artifact generation")
  config._hashcat_counts = Counter()
  config.pluginmanager.register(Summary(config), "hashcat-summary")
  config._hashcat_executed = set()
  config._hashcat_reported_modes = set()
  config._hashcat_missing_modes = set()
  config._hashcat_allocations = {}
  config._hashcat_resource_dir = None
  config._hashcat_planned_cases = 0
  if hasattr(config, "workerinput"):
    config._hashcat_seed = config.workerinput["hashcat_seed"]
  else:
    value = config.getoption("seed")
    config._hashcat_seed = str(secrets.randbits(64)) if value == "random" else value
  if config._hashcat_seed.isdigit() == False:
    raise pytest.UsageError("--seed must be a nonnegative integer or random")
  for name in ("runtime", "metal_compiler_runtime"):
    value = config.getoption(name)
    if value is not None and value <= 0:
      raise pytest.UsageError("--%s must be positive" % name.replace("_", "-"))
  selected = config.getoption("backend_devices")
  if selected and hardware.backend_device_ids(selected) is None:
    raise pytest.UsageError("invalid --backend-devices list")
  if config.getoption("sanitizer") and config.getoption("numprocesses", default=0):
    raise pytest.UsageError("Compute Sanitizer requires serial execution")


def pytest_report_header(config):
  return "hashcat oracle seed: " + config._hashcat_seed


def suite_enabled(config, suite):
  explicit = any(Path(str(arg).split("::", 1)[0]).name == "test_" + suite + ".py" for arg in config.args)
  expression = config.getoption("markexpr")
  if suite == "generated" and config.getoption("include_generated") == False:
    return False
  return (explicit or config.getoption("profile") == "full" or suite in expression or
          suite in ("cracking", "containers", "stdout") or (suite == "generated" and config.getoption("include_generated")))


def pytest_generate_tests(metafunc):
  if "case" not in metafunc.fixturenames:
    return
  suite = metafunc.module.SUITE
  try:
    collected = cases.collect_cases(metafunc.config, suite) if suite_enabled(metafunc.config, suite) else []
  except ValueError as error:
    raise pytest.UsageError(str(error)) from error
  params = [pytest.param(case, id=case.node_id, marks=[getattr(pytest.mark, suite),
            pytest.mark.xdist_group(name="mode-%d" % case.mode)]) for case in collected]
  metafunc.parametrize("case", params)


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(config, items):
  excluded = [item for item in items if hasattr(item, "callspec") and "case" in item.callspec.params and isinstance(item.callspec.params["case"], cases.Case) == False]
  items[:] = [item for item in items if item not in excluded]
  config.hook.pytest_deselected(items=excluded)
  config._hashcat_selected_modes = {item.callspec.params["case"].mode for item in items
                                   if hasattr(item, "callspec") and "case" in item.callspec.params}
  config._hashcat_selected_suites = {item.callspec.params["case"].suite for item in items
                                    if hasattr(item, "callspec") and "case" in item.callspec.params}
  config._hashcat_planned_cases = sum(1 for item in items if hasattr(item, "callspec") and "case" in item.callspec.params)
  if not config._hashcat_selected_modes and excluded and config.getoption("collectonly") == False:
    raise pytest.UsageError("no applicable integration cases, check the selected suite and options")
  if config.getoption("require_coverage") and items and config.getoption("collectonly") == False:
    if not config._hashcat_selected_modes:
      raise pytest.UsageError("required coverage needs executable integration cases")
    if config._hashcat_selected_modes or excluded:
      asked = cases.select_modes(config.getoption("hash_modes"), set(catalog.source_modes()) | catalog.CONTAINER_MODES)
      if config.getoption("hash_modes") not in ("all", "minimal") or not config._hashcat_selected_modes:
        missing = set(asked) - config._hashcat_selected_modes
        if missing:
          raise pytest.UsageError("requested modes have no applicable cases: " + str(sorted(missing)))


@pytest.hookimpl(optionalhook=True)
def pytest_configure_node(node):
  config = node.config
  node.workerinput["hashcat_seed"] = config._hashcat_seed
  if config._hashcat_resource_dir is None:
    config._hashcat_resource_dir = tempfile.mkdtemp(prefix="hashcat-pytest-resources-")
  node.workerinput["hashcat_resource_dir"] = config._hashcat_resource_dir
  if config.getoption("collectonly"):
    return
  if config.getoption("device_type") == "gpu" and config.getoption("gpu_strategy") == "depth":
    occupied = set(config._hashcat_allocations.values())
    assigned = next(slot for slot in range(len(occupied) + 1) if slot not in occupied)
    config._hashcat_allocations[node] = assigned
    node.workerinput["hashcat_gpu_slot"] = assigned


@pytest.hookimpl(optionalhook=True)
def pytest_testnodedown(node, error):
  node.config._hashcat_allocations.pop(node, None)


@pytest.hookimpl(optionalhook=True)
def pytest_xdist_node_collection_finished(node, ids):
  selected = set()
  planned = 0
  for identifier in ids:
    mode = identifier.rpartition("[")[2].split("-", 1)[0].rstrip("]")
    if mode.startswith("m") and mode[1:].isdigit():
      selected.add(int(mode[1:]))
      planned += 1
  node.config._hashcat_selected_modes = selected
  node.config._hashcat_planned_cases = planned


@pytest.fixture(scope="session")
def worker_resources(request, tmp_path_factory):
  config = request.config
  binary = Path(config.getoption("hashcat_binary")).resolve()
  if binary.is_file() == False:
    pytest.fail("hashcat binary missing: %s. Run make first." % binary)
  runtime.BIN = str(binary)
  runtime.METADATA_BIN = str(binary)
  worker = getattr(config, "workerinput", {})
  resource_dir = worker.get("hashcat_resource_dir") or str(tmp_path_factory.mktemp("resources"))
  cache = tmp_path_factory.mktemp("kernel-cache")
  runtime.ISOLATION = ["--cache-path", str(cache), "--session", "pytest-%d" % os.getpid(), "--restore-disable"]
  device = {"cpu": "1", "gpu": "2", "fpga": "3"}[config.getoption("device_type")]
  selected = config.getoption("backend_devices")
  inventory = hardware.backend_devices()
  runtime.CPU_BACKEND_ID = next((entry["id"] for entry in inventory if entry["type"] == "CPU"), None)
  modes = getattr(config, "_hashcat_selected_modes", set())
  suites = getattr(config, "_hashcat_selected_suites", set())
  if runtime.CPU_BACKEND_ID is not None and (suites == {"bridge"} or (modes and all(catalog.is_bridged(mode) for mode in modes))):
    device, selected = "1", None
  devices = scheduling.physical_devices(inventory, device, selected)
  if not devices:
    reason = "selected backend devices are unavailable"
    if config.getoption("require_coverage"):
      pytest.fail(reason)
    pytest.skip(reason)
  workers = worker.get("workercount", 1)
  if device == "2" and config.getoption("gpu_strategy") == "depth" and "hashcat_gpu_slot" in worker:
    if workers > len(devices):
      pytest.fail("GPU depth scheduling needs one physical GPU per worker")
    selected = str(devices[worker["hashcat_gpu_slot"]]["id"])
  limits = scheduling.memory_limits(device, workers, selected, inventory)
  runtime.ENV = dict(limits, HCTEST_SEED=config._hashcat_seed)
  runtime.RUNTIME = config.getoption("runtime") or 400
  runtime.EDGE_RUNTIME = config.getoption("runtime") or 270
  runtime.SELFTEST_RUNTIME = config.getoption("runtime") or 60
  sanitizer = config.getoption("sanitizer")
  if sanitizer:
    if Path(runtime.ROOT, "hashcat-sanitizer").is_file() == False:
      pytest.fail("build hashcat-sanitizer with tools/compute_sanitizer/run.py build")
    runtime.BIN = str(Path(runtime.TDIR, "compute_sanitizer", "sweep_shim.sh"))
    runtime.ENV.update(SANITIZER_SWEEP_TOOL=sanitizer,
                       SANITIZER_SWEEP_DIR=str(Path(config.getoption("artifact_dir")).resolve() / "sanitizer"))
  if device == "2" and config.getoption("gpu_strategy") == "depth":
    runtime.ENV.pop("HASHCAT_DEVICE_MEM_LIMIT", None)
  depth_ids = [entry["id"] for entry in scheduling.physical_devices(inventory, device, selected)] if device == "2" and config.getoption("gpu_strategy") == "depth" else []
  return SimpleNamespace(directory=resource_dir, device=device, backend_devices=selected, workers=workers, depth_ids=depth_ids)


@pytest.fixture
def run_case(request, case, worker_resources, tmp_path):
  config = request.config
  args = SimpleNamespace(device=worker_resources.device, backend_devices=worker_resources.backend_devices,
                         pure=case.kernel == "pure", force=config.getoption("force"),
                         verbose=config.getoption("hashcat_verbose"),
                         metal_compiler_runtime=config.getoption("metal_compiler_runtime"),
                         vector=str(case.width or 1), attack=str(case.attack) if case.attack is not None else config.getoption("attacks") or "0", variant=case.variant)

  def run(action):
    retained = []
    retry = False
    succeeded = False
    environment = dict(runtime.ENV)
    try:
      while True:
        directory = tmp_path / ("attempt-%d" % len(retained))
        directory.mkdir()
        ledger = artifacts.CaseResults(directory, case, dict(runtime.ENV))
        retained.append(ledger)
        runtime.ACTIVE = ledger
        try:
          with ExitStack() as stack:
            descriptors = list(stack.enter_context(scheduling.lease(worker_resources.directory, exclusive=retry)))
            for device_id in worker_resources.depth_ids:
              lock_dir = Path(worker_resources.directory, "gpu-%d" % device_id)
              descriptors.extend(stack.enter_context(scheduling.lease(lock_dir, exclusive=True)))
            if catalog.memory_hard(case.mode):
              descriptors.extend(stack.enter_context(scheduling.lease(Path(worker_resources.directory, "memory-hard"), exclusive=True)))
            runtime.PASS_FDS = tuple(descriptors)
            action(args, str(directory), ledger)
          break
        except scheduling.RetryWithFullMemory:
          if retry:
            raise
          ledger.omissions.append("worker memory cap, retrying without caps")
          retry = True
          runtime.UNCAPPED = True
          for key in ("HASHCAT_DEVICE_MEM_LIMIT", "HASHCAT_HOST_MEM_LIMIT"):
            runtime.ENV.pop(key, None)
        except BaseException as error:
          if isinstance(error, pytest.skip.Exception):
            ledger.omissions.append(str(error))
          else:
            ledger.problems.append(str(error) or type(error).__name__)
          raise
        finally:
          runtime.PASS_FDS = ()
          ledger.finish()
      if ledger.problems:
        pytest.fail("\n".join(ledger.problems), pytrace=False)
      if ledger.notes:
        reason = "\n".join(dict.fromkeys(ledger.notes))
        request.node.add_report_section("call", "hashcat partial coverage", reason)
        if config.getoption("require_coverage"):
          ledger.problems.append(reason)
          pytest.fail(reason, pytrace=False)
        warnings.warn(reason, pytest.PytestWarning, stacklevel=2)
      if ledger.omissions:
        reason = "; ".join(dict.fromkeys(ledger.omissions))
        if config.getoption("require_coverage"):
          ledger.problems.append(reason)
          pytest.fail(reason, pytrace=False)
        pytest.skip(reason)
      if ledger.runtime_skips:
        pytest.skip("; ".join(dict.fromkeys(ledger.runtime_skips)))
      if not ledger.invocations:
        ledger.problems.append("no applicable hashcat invocations were executed")
        pytest.fail("no applicable hashcat invocations were executed", pytrace=False)
      succeeded = True
    finally:
      for ledger in retained:
        ledger.finish()
      request.node.user_properties.extend([("hashcat_mode", case.mode), ("hashcat_invocations", sum(len(ledger.invocations) for ledger in retained)),
                                          ("hashcat_retried", int(retry))])
      runtime.ACTIVE = None
      runtime.ENV = environment
      runtime.UNCAPPED = False
      keep = config.getoption("keep_artifacts")
      failed = succeeded == False
      if keep == "all" or (keep == "failures" and failed):
        destination = Path(config.getoption("artifact_dir"), case.suite, case.node_id)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
          destination = destination.with_name(destination.name + "-%d" % os.getpid())
        shutil.copytree(tmp_path, destination)
        request.node.add_report_section("call", "hashcat artifacts", str(destination.resolve()))
  return run


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
  outcome = yield
  report = outcome.get_result()
  case = getattr(item, "callspec", None)
  case = case.params.get("case") if case is not None else None
  if isinstance(case, cases.Case) and "hashcat_mode" not in dict(report.user_properties):
    report.user_properties.extend([("hashcat_mode", case.mode), ("hashcat_invocations", 0), ("hashcat_retried", 0)])


class Summary:
  def __init__(self, config):
    self.config = config
    self.failures = []

  def pytest_runtest_logreport(self, report):
    if dict(report.user_properties).get("hashcat_coverage_gate"):
      self.config._hashcat_counts["coverage_failures"] += 1
      self.failures.append((report.nodeid, str(report.longrepr)))
      if os.environ.get("GITHUB_ACTIONS") == "true":
        print("::error title=hashcat required coverage::" + str(report.longrepr))
      return
    if report.when != "call" and report.failed == False:
      return
    properties = dict(report.user_properties)
    if "hashcat_mode" not in properties:
      return
    self.config._hashcat_reported_modes.add(properties["hashcat_mode"])
    if report.failed:
      self.failures.append((report.nodeid, str(report.longrepr)))
    if report.failed and os.environ.get("GITHUB_ACTIONS") == "true":
      message = (report.nodeid + "\n" + str(report.longrepr))[:4000]
      message = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
      print("::error title=hashcat mode %d::%s" % (properties["hashcat_mode"], message))
    self.config._hashcat_counts[report.outcome] += 1
    if report.when == "call":
      self.config._hashcat_counts["invocations"] += properties["hashcat_invocations"]
      self.config._hashcat_counts["retried"] += properties["hashcat_retried"]
    if properties["hashcat_invocations"] > 0 and report.passed:
      self.config._hashcat_executed.add(properties["hashcat_mode"])

  def pytest_terminal_summary(self, terminalreporter):
    counts = self.config._hashcat_counts
    if counts:
      terminalreporter.write_line("hashcat: %d planned cases" % self.config._hashcat_planned_cases)
      terminalreporter.write_line("hashcat: %d invocations, %d passed, %d failed, %d skipped, %d retried" %
                                tuple(counts[key] for key in ("invocations", "passed", "failed", "skipped", "retried")))
      terminalreporter.write_line("Errors detected: %d" % (counts["failed"] + counts["coverage_failures"]))
    if self.config._hashcat_missing_modes:
      terminalreporter.write_line("Required modes without a passed invocation: " + str(sorted(self.config._hashcat_missing_modes)))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary and counts:
      with open(summary, "a", encoding="utf-8") as handle:
        handle.write("\n### hashcat integration tests\n\n")
        handle.write("%d planned cases, %d invocations, %d passed, %d failed, %d skipped, %d retried.\n" %
                     (self.config._hashcat_planned_cases, *(counts[key] for key in ("invocations", "passed", "failed", "skipped", "retried"))))
        if self.config._hashcat_missing_modes:
          handle.write("\nRequired modes without a passed invocation: " + str(sorted(self.config._hashcat_missing_modes)) + "\n")
        for identifier, reason in self.failures:
          handle.write("\n" + identifier + "\n\n```text\n" + reason[:4000] + "\n```\n")


@pytest.hookimpl(tryfirst=True)
def pytest_sessionfinish(session, exitstatus):
  config = session.config
  if config.getoption("require_coverage") and config.getoption("collectonly") == False and hasattr(config, "workerinput") == False:
    selected = getattr(config, "_hashcat_selected_modes", set())
    config._hashcat_missing_modes = selected - config._hashcat_executed
    if config._hashcat_missing_modes:
      if session.exitstatus == pytest.ExitCode.OK:
        reason = "Required modes without a passed invocation: " + str(sorted(config._hashcat_missing_modes))
        report = pytest.TestReport(nodeid="hashcat::required_coverage", location=("tests", 0, "required_coverage"),
                                   keywords={}, outcome="failed", longrepr=reason, when="call",
                                   user_properties=[("hashcat_coverage_gate", True)])
        config.hook.pytest_runtest_logreport(report=report)
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
  if config._hashcat_resource_dir:
    shutil.rmtree(config._hashcat_resource_dir, ignore_errors=True)
