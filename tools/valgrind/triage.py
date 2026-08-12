#!/usr/bin/env python3
"""Parse Valgrind memcheck XML into an actionable, hashcat-source-aware summary.

Library used by run.py (subcommand: analyze one run) and by report.py
(subcommand: aggregate many runs). Stdlib only.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

SCHEMA_VERSION = 1

RELEVANT = ("HASHCAT_HOST", "OPENCL_KERNEL")

KIND_MAP = {
    "InvalidRead": "InvalidRead",
    "InvalidWrite": "InvalidWrite",
    "InvalidFree": "InvalidFree",
    "MismatchedFree": "InvalidFree",
    "UninitCondition": "ConditionalJumpUninitialised",
    "UninitValue": "UninitialisedValue",
    "Leak_DefinitelyLost": "DefinitelyLost",
    "Leak_IndirectlyLost": "IndirectlyLost",
    "Leak_PossiblyLost": "PossiblyLost",
}


# ---------------------------------------------------------------------------
# XML parsing
# ---------------------------------------------------------------------------

def parse_xml(xml_path):
    """Returns a list of raw error dicts: {kind_raw, what, stacks:[{label,frames}]}.

    Raises ET.ParseError / OSError on malformed/missing input -- callers must
    treat that as wrapper_rc=2, not as "zero errors found".
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    errors = []
    for err in root.findall("error"):
        kind_raw = err.findtext("kind") or ""

        what_el = err.find("what")
        if what_el is not None:
            what_text = what_el.text or ""
        else:
            xwhat = err.find("xwhat")
            what_text = (xwhat.findtext("text") or "") if xwhat is not None else ""

        stacks = []
        pending_label = "primary"
        for child in err:
            if child.tag == "stack":
                frames = []
                for f in child.findall("frame"):
                    frames.append({
                        "ip": f.findtext("ip"),
                        "obj": f.findtext("obj"),
                        "fn": f.findtext("fn"),
                        "dir": f.findtext("dir"),
                        "file": f.findtext("file"),
                        "line": f.findtext("line"),
                    })
                stacks.append({"label": pending_label, "frames": frames})
                pending_label = None
            elif child.tag == "auxwhat":
                pending_label = child.text or "aux"

        errors.append({"kind_raw": kind_raw, "what": what_text, "stacks": stacks})

    return errors


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

class Classification:
    __slots__ = ("relevance", "source_resolved", "rel_path", "line")

    def __init__(self, relevance, source_resolved=False, rel_path=None, line=None):
        self.relevance = relevance
        self.source_resolved = source_resolved
        self.rel_path = rel_path
        self.line = line

    def as_dict(self):
        return {
            "relevance": self.relevance,
            "source_resolved": self.source_resolved,
            "file": self.rel_path,
            "line": self.line,
        }


def _safe_realpath(p):
    try:
        return os.path.realpath(p)
    except (OSError, ValueError, TypeError):
        return None


_CL_HASH_CACHE = {}


def _repo_cl_file_hashes(repo_root):
    """sha256(content) -> repo-relative path, for every OpenCL/*.cl (and
    *.h) file. Cached per repo_root for the process lifetime."""
    if repo_root in _CL_HASH_CACHE:
        return _CL_HASH_CACHE[repo_root]

    import hashlib
    mapping = {}
    opencl_dir = os.path.join(repo_root, "OpenCL")
    if os.path.isdir(opencl_dir):
        for dirpath, _dirnames, filenames in os.walk(opencl_dir):
            for name in filenames:
                if not (name.endswith(".cl") or name.endswith(".h")):
                    continue
                full = os.path.join(dirpath, name)
                try:
                    with open(full, "rb") as f:
                        digest = hashlib.sha256(f.read()).hexdigest()
                except OSError:
                    continue
                mapping[digest] = os.path.relpath(full, repo_root)

    _CL_HASH_CACHE[repo_root] = mapping
    return mapping


def resolve_cl_temp_file(file_path, repo_root):
    """PoCL copies kernel source into a randomly-named temp file under its
    kcache before compiling (confirmed empirically), so its DWARF cites
    that temp path rather than the original OpenCL/*.cl file. Since the
    copy is byte-for-byte, a content hash against the repo's real .cl files
    recovers the original path when the temp file is still on disk."""
    if not file_path or not os.path.isfile(file_path):
        return None
    import hashlib
    try:
        with open(file_path, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None
    return _repo_cl_file_hashes(repo_root).get(digest)


def classify_frame(frame, repo_root, binary_realpath, modules_dir_realpath, pocl_kernel_dirs=(),
                    extra_relevant_realpaths=()):
    """Three-way classification: HASHCAT_HOST / OPENCL_KERNEL / EXTERNAL_UNKNOWN / unknown.

    Path-prefix matching only -- never substring, never a hardcoded function
    name list. `<file>` is checked first (most precise); `<obj>` is the
    fallback for frames Valgrind couldn't resolve down to a source line.

    `extra_relevant_realpaths` lets a caller mark specific files as
    HASHCAT_HOST-equivalent outside src/include/OpenCL -- used only by
    `run.py selftest` to recognize its own ground-truth fixture files
    (which live under tools/valgrind/modules/, not the hashcat source
    tree). Real hashcat runs never pass this.
    """
    file_ = frame.get("file")
    dir_ = frame.get("dir")

    if file_:
        abs_path = _safe_realpath(os.path.join(dir_, file_)) if dir_ else None

        if abs_path and extra_relevant_realpaths and abs_path in extra_relevant_realpaths:
            try:
                rel = os.path.relpath(abs_path, repo_root)
            except ValueError:
                rel = abs_path
            return Classification("HASHCAT_HOST", True, rel, frame.get("line"))

        rel = None
        if abs_path:
            try:
                rel = os.path.relpath(abs_path, repo_root)
            except ValueError:
                rel = None

        # DWARF <dir> can be a relative path (observed: glibc's own build
        # embeds relative dirs like "include"), and realpath() resolves a
        # relative path against the process's CWD -- which is normally
        # REPO_ROOT here, so a third-party relative dir can accidentally
        # collide with one of hashcat's own directory names (e.g. glibc's
        # "include/rtld-malloc.h" resolving as if it were hashcat's
        # include/rtld-malloc.h). Requiring the resolved path to actually
        # exist on disk rules that out cheaply.
        if rel is not None and not rel.startswith("..") and abs_path and os.path.isfile(abs_path):
            parts = Path(rel).parts
            if parts and parts[0] == "OpenCL":
                return Classification("OPENCL_KERNEL", True, rel, frame.get("line"))
            if parts and parts[0] in ("src", "include"):
                return Classification("HASHCAT_HOST", True, rel, frame.get("line"))

        # Not under the repo -- almost certainly a PoCL-compiled kernel temp
        # object (confirmed empirically: PoCL copies kernel source into
        # ~/.cache/pocl/kcache/.../tempfile_XXXXXX.cl before compiling, and
        # its DWARF cites that random temp path+line, NOT the original
        # OpenCL/*.cl filename -- but the line numbers themselves are
        # correct against the original source, and the temp file's content
        # is a byte-for-byte copy). Recover the real path via content hash
        # when the temp file still exists (POCL_LEAVE_KERNEL_COMPILER_TEMP_FILES=1
        # keeps it around); otherwise fall back to the temp path as-is.
        if file_.endswith(".cl"):
            abs_temp = os.path.join(dir_, file_) if dir_ else file_
            real_rel = resolve_cl_temp_file(abs_temp, repo_root)
            return Classification("OPENCL_KERNEL", True, real_rel or abs_temp, frame.get("line"))

        # Valgrind resolved a file for this frame, but it's neither hashcat
        # source nor a .cl kernel (e.g. a harness's own .c file, or some
        # other third-party file that happens to carry debug info). Do NOT
        # fall through to the obj-based binary-match check below -- that
        # check exists specifically for frames Valgrind could NOT resolve
        # to a source line at all, not to override a resolved-but-irrelevant
        # file. Without this, any frame inside the *tested binary itself*
        # (e.g. its own main()) would be misclassified HASHCAT_HOST purely
        # because it shares an <obj> with the process being run, even when
        # the actual file is unrelated to hashcat.
        return Classification("EXTERNAL_UNKNOWN" if frame.get("obj") else "unknown", False)

    obj_ = frame.get("obj")
    if obj_:
        obj_real = _safe_realpath(obj_) or obj_
        if binary_realpath and obj_real == binary_realpath:
            return Classification("HASHCAT_HOST", False)
        if modules_dir_realpath and (obj_real == modules_dir_realpath or obj_real.startswith(modules_dir_realpath + os.sep)):
            return Classification("HASHCAT_HOST", False)
        for d in pocl_kernel_dirs:
            if d and (obj_real == d or obj_real.startswith(d + os.sep)):
                return Classification("OPENCL_KERNEL", False)
        return Classification("EXTERNAL_UNKNOWN", False)

    return Classification("unknown", False)


def find_first_relevant_frame(stacks, classify_fn):
    """Scans the primary stack top-down, then falls through to aux stacks in
    document order (freed-at / allocated-at / etc.) if the primary stack is
    pure external/unknown noise. For leak errors the sole stack *is* the
    allocation stack, so this already returns the allocation site."""
    for stack in stacks:
        for frame in stack["frames"]:
            c = classify_fn(frame)
            if c.relevance in RELEVANT:
                return stack, frame, c
    return None, None, None


def normalize_kind(kind_raw, stacks):
    base = KIND_MAP.get(kind_raw, "Other")
    if base in ("InvalidRead", "InvalidWrite"):
        for s in stacks[1:]:
            label = (s.get("label") or "").lower()
            if "free" in label:
                return "UseAfterFree"
    return base


# ---------------------------------------------------------------------------
# addr2line / PIE load-base fallback
# ---------------------------------------------------------------------------

_SYMTAB_CACHE = {}


def read_symtab(obj_path):
    """Returns (name -> address, name -> occurrence_count) via `readelf -sW`
    (wide output, includes local/static symbols -- important since DEBUG=1
    doesn't strip them). Cached per obj_path for one process lifetime."""
    if obj_path in _SYMTAB_CACHE:
        return _SYMTAB_CACHE[obj_path]

    symtab, counts = {}, {}
    try:
        out = subprocess.run(
            ["readelf", "-sW", obj_path],
            capture_output=True, text=True, timeout=30,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        out = ""

    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 8:
            continue
        if not parts[0].endswith(":") or not parts[0][:-1].isdigit():
            continue
        try:
            value = int(parts[1], 16)
        except ValueError:
            continue
        type_ = parts[3]
        name = parts[-1]
        if type_ != "FUNC" or not name:
            continue
        counts[name] = counts.get(name, 0) + 1
        symtab[name] = value

    _SYMTAB_CACHE[obj_path] = (symtab, counts)
    return symtab, counts


def derive_load_base(obj_path, anchor_frames):
    """anchor_frames: frames Valgrind already resolved (have fn+file+line)
    from this same obj. Finds one whose function name is unambiguous in the
    object's own symbol table and derives runtime_ip - symtab_addr."""
    symtab, counts = read_symtab(obj_path)
    for frame in anchor_frames:
        fn = frame.get("fn")
        ip = frame.get("ip")
        if not fn or not ip or fn not in symtab or counts.get(fn, 0) != 1:
            continue
        try:
            runtime_ip = int(ip, 16)
        except ValueError:
            continue
        return runtime_ip - symtab[fn]
    return None


def addr2line_fallback(obj_path, frame, load_base):
    ip = frame.get("ip")
    if not ip or load_base is None:
        return None
    try:
        runtime_ip = int(ip, 16)
    except ValueError:
        return None
    file_addr = runtime_ip - load_base
    if file_addr < 0:
        return None
    try:
        out = subprocess.run(
            ["addr2line", "-e", obj_path, "-f", "-C", hex(file_addr)],
            capture_output=True, text=True, timeout=30,
        ).stdout.strip().splitlines()
    except (OSError, subprocess.SubprocessError):
        return None
    if len(out) < 2:
        return None
    func, fileline = out[0].strip(), out[1].strip()
    if func in ("", "??") or fileline.startswith("??"):
        return None
    if ":" not in fileline:
        return None
    file_, _, line_ = fileline.rpartition(":")
    line_ = line_.split()[0]
    if not line_.isdigit():
        return None
    return {"function": func, "file": file_, "line": line_}


class Resolver:
    """Applies the addr2line/load-base fallback to HASHCAT_HOST/OPENCL_KERNEL
    frames Valgrind itself couldn't resolve, using an anchor frame from the
    same object that Valgrind *did* resolve. One load_base per object,
    derived once and cached."""

    def __init__(self, repo_root, binary_path, modules_dir, pocl_kernel_dirs=(), extra_relevant_files=()):
        self.repo_root = repo_root
        self.binary_realpath = _safe_realpath(binary_path) if binary_path else None
        self.modules_dir_realpath = _safe_realpath(modules_dir) if modules_dir else None
        self.pocl_kernel_dirs = [d for d in (_safe_realpath(p) for p in pocl_kernel_dirs) if d]
        self.extra_relevant_realpaths = {d for d in (_safe_realpath(p) for p in extra_relevant_files) if d}
        self._load_base_cache = {}
        self._anchors_by_obj = {}

    def classify(self, frame):
        return classify_frame(frame, self.repo_root, self.binary_realpath,
                               self.modules_dir_realpath, self.pocl_kernel_dirs,
                               self.extra_relevant_realpaths)

    def note_anchor(self, frame):
        if frame.get("fn") and frame.get("file") and frame.get("line") and frame.get("obj"):
            self._anchors_by_obj.setdefault(frame["obj"], []).append(frame)

    def resolve(self, frame, classification):
        """Attempt the fallback for a frame classified relevant but
        source_resolved=False. Returns an updated Classification (or the
        same one unchanged if resolution wasn't possible)."""
        obj_ = frame.get("obj")
        if not obj_ or classification.source_resolved:
            return classification
        if obj_ not in self._load_base_cache:
            anchors = self._anchors_by_obj.get(obj_, [])
            self._load_base_cache[obj_] = derive_load_base(obj_, anchors)
        load_base = self._load_base_cache[obj_]
        if load_base is None:
            return classification
        resolved = addr2line_fallback(obj_, frame, load_base)
        if not resolved:
            return classification
        rel = resolved["file"]
        try:
            maybe_rel = os.path.relpath(_safe_realpath(resolved["file"]) or resolved["file"], self.repo_root)
            if not maybe_rel.startswith(".."):
                rel = maybe_rel
        except (ValueError, TypeError):
            pass
        frame["fn"] = frame.get("fn") or resolved["function"]
        return Classification(classification.relevance, True, rel, resolved["line"])


# ---------------------------------------------------------------------------
# exit code decoding
# ---------------------------------------------------------------------------

def load_exit_code_meanings(repo_root):
    path = os.path.join(repo_root, "docs", "exit_status_code.txt")
    meanings = {}
    try:
        with open(path, "r") as f:
            for line in f:
                m = re.match(r"^\s*(-?\d+)\s*=\s*(.+?)\s*$", line)
                if m:
                    meanings[int(m.group(1))] = m.group(2)
    except OSError:
        pass
    return meanings


def decode_hashcat_rc(raw_rc, repo_root):
    signed = raw_rc - 256 if raw_rc > 127 else raw_rc
    meanings = load_exit_code_meanings(repo_root)
    return signed, meanings.get(signed, "unknown")


# ---------------------------------------------------------------------------
# Full-error summarization
# ---------------------------------------------------------------------------

def error_summary(err, resolver):
    stacks_out = []
    first_relevant = None

    for stack in err["stacks"]:
        frames_out = []
        for frame in stack["frames"]:
            c = resolver.classify(frame)
            resolver.note_anchor(frame)
            if c.relevance in RELEVANT and not c.source_resolved:
                c = resolver.resolve(frame, c)
            frames_out.append({
                "ip": frame.get("ip"),
                "obj": frame.get("obj"),
                "fn": frame.get("fn"),
                "file": c.rel_path,
                "line": c.line,
                "relevance": c.relevance,
                "source_resolved": c.source_resolved,
                "resolved_by": "valgrind" if (c.source_resolved and frame.get("file")) else
                               ("addr2line" if c.source_resolved else "unresolved"),
            })
            if first_relevant is None and c.relevance in RELEVANT:
                first_relevant = frames_out[-1]
        stacks_out.append({"label": stack["label"], "frames": frames_out})

    relevance = first_relevant["relevance"] if first_relevant else (
        "EXTERNAL_UNKNOWN" if any(f["obj"] for s in stacks_out for f in s["frames"]) else "unknown"
    )

    return {
        "kind_raw": err["kind_raw"],
        "kind_normalized": normalize_kind(err["kind_raw"], err["stacks"]),
        "what": err["what"],
        "relevance": relevance,
        "first_relevant_frame": first_relevant,
        "stacks": stacks_out,
    }


def analyze(xml_path, repo_root, binary_path, modules_dir, pocl_kernel_dirs=(),
            test_name="", timestamp="", command=None, hashcat_rc_raw=None,
            debug_info_detected=None, pocl_info=None, extra_relevant_files=()):
    result = {
        "schema_version": SCHEMA_VERSION,
        "run": {
            "test_name": test_name,
            "timestamp": timestamp,
            "command": command or [],
        },
        "environment": {
            "debug_info_detected": debug_info_detected,
        },
        "valgrind": {
            "xml_parse_ok": False,
            "total_errors": 0,
            "host_errors": 0,
            "kernel_errors": 0,
            "external_errors": 0,
            "unknown_errors": 0,
        },
        "errors": [],
    }

    if pocl_info is not None:
        result["environment"]["pocl"] = pocl_info

    if hashcat_rc_raw is not None:
        signed, meaning = decode_hashcat_rc(hashcat_rc_raw, repo_root)
        result["run"]["hashcat_rc_raw"] = hashcat_rc_raw
        result["run"]["hashcat_rc_signed"] = signed
        result["run"]["hashcat_rc_meaning"] = meaning

    try:
        raw_errors = parse_xml(xml_path)
    except (ET.ParseError, OSError) as e:
        result["run"]["wrapper_rc"] = 2
        result["run"]["wrapper_status"] = "wrapper_failure"
        result["valgrind"]["parse_error"] = str(e)
        return result

    result["valgrind"]["xml_parse_ok"] = True

    resolver = Resolver(repo_root, binary_path, modules_dir, pocl_kernel_dirs, extra_relevant_files)
    errors_out = []
    for err in raw_errors:
        summary = error_summary(err, resolver)
        errors_out.append(summary)

    # relevant-first ordering
    errors_out.sort(key=lambda e: 0 if e["relevance"] in RELEVANT else 1)
    result["errors"] = errors_out

    counts = result["valgrind"]
    counts["total_errors"] = len(errors_out)
    for e in errors_out:
        if e["relevance"] == "HASHCAT_HOST":
            counts["host_errors"] += 1
        elif e["relevance"] == "OPENCL_KERNEL":
            counts["kernel_errors"] += 1
        elif e["relevance"] == "EXTERNAL_UNKNOWN":
            counts["external_errors"] += 1
        else:
            counts["unknown_errors"] += 1

    relevant_count = counts["host_errors"] + counts["kernel_errors"] + counts["unknown_errors"]
    if relevant_count > 0:
        result["run"]["wrapper_rc"] = 1
        result["run"]["wrapper_status"] = "relevant_errors"
    else:
        result["run"]["wrapper_rc"] = 0
        result["run"]["wrapper_status"] = "clean"

    return result


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _frame_location(frame):
    if not frame:
        return "(no relevant frame found)"
    loc = f"{frame['file']}:{frame['line']}" if frame.get("file") and frame.get("line") else \
          f"{frame.get('obj') or '?'} (unresolved)"
    fn = frame.get("fn") or "?"
    return f"{loc}\n  {fn}()"


def _external_context_above(err):
    """Frames in the primary stack, above the first relevant one, that are
    external/unknown. The "likely location" is the nearest hashcat-owned
    frame, but if hashcat merely called into external code that itself
    misbehaved (e.g. a bug inside a GPU driver shim), the true fault is in
    those frames, not in hashcat's own logic -- surfacing them prevents a
    human from reflexively blaming the hashcat frame just because it's the
    one that got labelled."""
    if not err["stacks"]:
        return []
    primary = err["stacks"][0]["frames"]
    context = []
    for f in primary:
        if f["relevance"] in RELEVANT:
            break
        context.append(f)
    return context


def render_terminal(summary):
    lines = []
    run = summary["run"]
    vg = summary["valgrind"]

    hc_rc = run.get("hashcat_rc_raw")
    hc_signed = run.get("hashcat_rc_signed")
    hc_meaning = run.get("hashcat_rc_meaning", "")
    hc_line = f"Hashcat exit code: {hc_rc}" if hc_rc is not None else "Hashcat exit code: (n/a)"
    if hc_signed is not None:
        hc_line += f" (signed: {hc_signed} = {hc_meaning})"

    status = run.get("wrapper_status", "wrapper_failure")
    header = "PASS" if status == "clean" else ("FAIL" if status == "relevant_errors" else "ERROR")

    lines.append(f"[{run.get('test_name', '?')}]  Valgrind: {header}")
    lines.append(hc_line)
    lines.append("")

    if status == "wrapper_failure":
        lines.append(f"Wrapper/parse failure: {vg.get('parse_error', 'unknown error')}")
        return "\n".join(lines)

    for i, err in enumerate(summary["errors"], 1):
        if err["relevance"] not in RELEVANT and err["relevance"] != "unknown":
            continue
        heading = "OPENCL_KERNEL" if err["relevance"] == "OPENCL_KERNEL" else \
                  ("HOST" if err["relevance"] == "HASHCAT_HOST" else "UNCLASSIFIED")
        lines.append(f"{i}. {heading} {err['kind_normalized']}")
        lines.append(f"   {err['what']}")
        lines.append(f"   Likely location:")
        loc = _frame_location(err["first_relevant_frame"])
        lines.append("     " + loc.replace("\n", "\n     "))

        context = _external_context_above(err)
        if context:
            lines.append(f"   Called from {len(context)} external frame(s) above -- the actual fault")
            lines.append(f"   may be there, not in hashcat's own logic:")
            for f in context[:3]:
                lines.append(f"     {f.get('fn') or '???'} (in {f.get('obj') or '?'})")
            if len(context) > 3:
                lines.append(f"     ... and {len(context) - 3} more (see valgrind.log / summary.json for the full stack)")

        lines.append("")

    lines.append(
        f"Result: {vg['host_errors']} host, {vg['kernel_errors']} kernel, "
        f"{vg['unknown_errors']} unclassified, {vg['external_errors']} external "
        f"(total {vg['total_errors']})"
    )
    return "\n".join(lines)


def write_summary(results_dir, summary):
    """Writes summary.txt (rendered) and summary.json (atomic via temp+replace).
    Shared by the `parse` CLI subcommand and direct library use from run.py."""
    results_dir = Path(results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    text = render_terminal(summary)
    (results_dir / "summary.txt").write_text(text + "\n")

    tmp_fd, tmp_path = tempfile.mkstemp(dir=str(results_dir), prefix=".summary.", suffix=".json")
    try:
        with os.fdopen(tmp_fd, "w") as f:
            json.dump(summary, f, indent=2)
        os.replace(tmp_path, str(results_dir / "summary.json"))
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return text


def append_sweep_finding(sweep_dir, run_dir_name, summary):
    """Appends one line to sweep-findings.tsv for report.py --dir to aggregate,
    without needing every per-case summary.json to be re-parsed to build the
    at-a-glance table."""
    findings_path = Path(sweep_dir) / "sweep-findings.tsv"
    run = summary["run"]
    vg = summary["valgrind"]
    first_loc = "-"
    for e in summary.get("errors", []):
        frf = e.get("first_relevant_frame")
        if frf and frf.get("file") and frf.get("line"):
            first_loc = f"{frf['file']}:{frf['line']}"
            break
    row = [
        run_dir_name,
        run.get("test_name", ""),
        str(run.get("hashcat_rc_signed", run.get("hashcat_rc_raw", ""))),
        str(vg.get("total_errors", "")),
        str(vg.get("host_errors", "")),
        str(vg.get("kernel_errors", "")),
        first_loc,
    ]
    is_new = not findings_path.exists()
    with open(findings_path, "a") as f:
        if is_new:
            f.write("\t".join(["run_dir", "test_name", "hc_rc", "vg_total", "host_err", "kernel_err", "first_location"]) + "\n")
        f.write("\t".join(row) + "\n")


# ---------------------------------------------------------------------------
# report subcommand
# ---------------------------------------------------------------------------

def _load_summary_json(path):
    try:
        with open(path, "r") as f:
            return json.load(f), None
    except (OSError, json.JSONDecodeError) as e:
        return None, str(e)


def iter_run_dirs(results_dir):
    p = Path(results_dir)
    if not p.is_dir():
        return
    for entry in sorted(p.iterdir()):
        if entry.is_dir() and not entry.name.startswith("."):
            yield entry


def report_rows(results_dir):
    rows = []
    for run_dir in iter_run_dirs(results_dir):
        summary_path = run_dir / "summary.json"
        if not summary_path.exists():
            rows.append({"run": run_dir.name, "hc_rc": "-", "vg": "-", "host_err": "-",
                         "kernel_err": "-", "first_location": "(in progress)", "ok": None})
            continue
        data, err = _load_summary_json(summary_path)
        if data is None:
            rows.append({"run": run_dir.name, "hc_rc": "?", "vg": "?", "host_err": "?",
                         "kernel_err": "?", "first_location": "<malformed>", "ok": False})
            continue
        try:
            run = data.get("run", {})
            vg = data.get("valgrind", {})
            errors = data.get("errors", [])
            first_loc = "-"
            for e in errors:
                frf = e.get("first_relevant_frame")
                if frf and frf.get("file") and frf.get("line"):
                    first_loc = f"{frf['file']}:{frf['line']}"
                    break
                if frf and frf.get("obj"):
                    first_loc = f"{frf['obj']} (unresolved)"
                    break
            rows.append({
                "run": run.get("timestamp", "") + "-" + run.get("test_name", run_dir.name),
                "hc_rc": run.get("hashcat_rc_signed", run.get("hashcat_rc_raw", "-")),
                "vg": vg.get("total_errors", "-"),
                "host_err": vg.get("host_errors", "-"),
                "kernel_err": vg.get("kernel_errors", "-"),
                "first_location": first_loc,
                "ok": run.get("wrapper_rc", 2) == 0,
                "test_name": run.get("test_name"),
            })
        except (AttributeError, TypeError):
            rows.append({"run": run_dir.name, "hc_rc": "?", "vg": "?", "host_err": "?",
                         "kernel_err": "?", "first_location": "<malformed>", "ok": False})
    return rows


def cmd_report(args):
    rows = report_rows(args.results_dir)

    if args.test:
        rows = [r for r in rows if r.get("test_name") == args.test]
    if args.failed:
        rows = [r for r in rows if r.get("ok") is not True]
    if args.latest is not None:
        rows = rows[-args.latest:]

    header = ("RUN", "HC_RC", "VG", "HOST_ERR", "KERNEL_ERR", "FIRST LOCATION")
    widths = [len(h) for h in header]
    str_rows = [[str(r.get(k, "-")) for k in ("run", "hc_rc", "vg", "host_err", "kernel_err", "first_location")]
                for r in rows]
    for row in str_rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def fmt(row):
        return "  ".join(c.ljust(widths[i]) for i, c in enumerate(row))

    print(fmt(header))
    for row in str_rows:
        print(fmt(row))
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_parse(args):
    repo_root = os.path.realpath(args.repo_root)
    pocl_dirs = args.pocl_kernel_dir or []
    summary = analyze(
        args.xml, repo_root, args.binary, args.modules_dir, pocl_dirs,
        test_name=args.test_name, timestamp=args.timestamp,
        command=json.loads(args.command_json) if args.command_json else [],
        hashcat_rc_raw=args.hashcat_rc,
        debug_info_detected=args.debug_info_detected,
        pocl_info=json.loads(args.pocl_info_json) if args.pocl_info_json else None,
    )

    text = write_summary(args.results_dir, summary)

    if not args.quiet:
        print(text)

    return summary["run"].get("wrapper_rc", 2)


def build_arg_parser():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    pp = sub.add_parser("parse", help="Analyze one valgrind.xml and write summary.txt/summary.json")
    pp.add_argument("--xml", required=True)
    pp.add_argument("--repo-root", required=True)
    pp.add_argument("--binary", default=None)
    pp.add_argument("--modules-dir", default=None)
    pp.add_argument("--pocl-kernel-dir", action="append", default=[])
    pp.add_argument("--test-name", default="")
    pp.add_argument("--timestamp", default=time.strftime("%Y%m%d-%H%M%S"))
    pp.add_argument("--command-json", default=None)
    pp.add_argument("--hashcat-rc", type=int, default=None)
    pp.add_argument("--debug-info-detected", action="store_true", default=None)
    pp.add_argument("--pocl-info-json", default=None)
    pp.add_argument("--results-dir", required=True)
    pp.add_argument("--quiet", action="store_true")
    pp.set_defaults(func=cmd_parse)

    rp = sub.add_parser("report", help="Aggregate past runs into a table")
    rp.add_argument("results_dir")
    rp.add_argument("--test", default=None)
    rp.add_argument("--failed", action="store_true")
    rp.add_argument("--latest", type=int, default=None)
    rp.set_defaults(func=cmd_report)

    return p


def main(argv=None):
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
