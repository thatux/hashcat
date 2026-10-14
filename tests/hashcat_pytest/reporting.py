##
## Author......: See docs/credits.txt
## License.....: MIT
##

from . import runtime

REASONS = {
  245: "self-test failed", 246: "autotune failed", 247: "mixed backend errors",
  248: "invalid extra buffer size", 250: "kernel creation failed", 251: "kernel build failed",
  252: "memory hit limit", 253: "unstable module", 30: "container files missing",
  1: "password not found", 4: "runtime exceeded", 10: "recovered output did not match",
}


def classify(rc, matched, counts):
  counts["cnt"] += 1
  code = 10 if rc == 0 and matched == False else rc
  field = {1: "nf", 4: "to", 10: "nm"}.get(code, "rs" if code == 30 or 246 <= code <= 253 else "err")
  if code != 0:
    counts[field] += 1
  runtime.ACTIVE.check(code)


def report(args, mode, target_name, width, counts, attack=0):
  runtime.ACTIVE.summaries.append(dict(counts))


def report_skip(args, mode, target_name, width, reason, attack=0):
  runtime.ACTIVE.omissions.append(reason)
  if reason.startswith("could not extract"):
    runtime.ACTIVE.problems.append(reason)


def note_verdict(value):
  if value in ("Error", "Fault", "Compare Error"):
    runtime.ACTIVE.problems.append(value)


def record(value):
  return None


def log_result(code):
  return None


def log_output(command, output):
  return None


def logfull_append(message):
  return None


def container_report(args, mode, attack, width, label, status):
  runtime.ACTIVE.labels.append(label)


def selftest_status(code):
  runtime.ACTIVE.check(code)
  return code


def gen_record(mode, kind, reason):
  runtime.GEN_SKIPS.append((mode, kind, reason))
  if kind == "Error":
    runtime.ACTIVE.problems.append(reason)
  elif kind == "Skip":
    runtime.ACTIVE.omissions.append(reason)
  elif kind == "Note":
    runtime.ACTIVE.notes.append(reason)


def gen_skip(mode, reason):
  gen_record(mode, "Skip", reason)


def gen_note(mode, reason):
  gen_record(mode, "Note", reason)


def gen_error(mode, reason):
  gen_record(mode, "Error", reason)
