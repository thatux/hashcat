#!/usr/bin/env python3
"""Aggregate tools/valgrind run results into a table.

Thin CLI over triage.py's report_rows()/cmd_report() -- all XML/JSON parsing
logic lives in triage.py so this and run.py never duplicate it.

Usage:
    report.py                       # tools/valgrind/results/, all runs
    report.py --test success        # only that test-name
    report.py --failed              # only wrapper_rc != 0
    report.py --latest 5            # last 5 (after other filters)
    report.py --dir <sweep-dir>     # a test.sh/test_edge.sh sweep's nested results dir
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import triage  # noqa: E402

DEFAULT_RESULTS_DIR = Path(__file__).resolve().parent / "results"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dir", default=None, help="results directory to scan (default: tools/valgrind/results)")
    p.add_argument("--test", default=None, help="filter by test_name")
    p.add_argument("--failed", action="store_true", help="only runs with wrapper_rc != 0")
    p.add_argument("--latest", type=int, default=None, help="only the N most recent (after other filters)")
    args = p.parse_args(argv)

    results_dir = args.dir or str(DEFAULT_RESULTS_DIR)

    ns = argparse.Namespace(results_dir=results_dir, test=args.test, failed=args.failed, latest=args.latest)
    return triage.cmd_report(ns)


if __name__ == "__main__":
    sys.exit(main())
