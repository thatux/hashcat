##
## Author......: See docs/credits.txt
## License.....: MIT
##

import os
from pathlib import Path

ROOT = str(Path(__file__).resolve().parents[2])
TDIR = os.path.join(ROOT, "tools")
RUNNER = os.path.join(TDIR, "test_module_runner.py")
BIN = os.path.join(ROOT, "hashcat")
METADATA_BIN = BIN
ISOLATION = []
LAST_CMD = None
RUNTIME = 400
SELFTEST_RUNTIME = 60
EDGE_RUNTIME = 270
CPU_BACKEND_ID = -1
MULTI_CACHE = {}
EDGE_HH_CACHE = {}
MODULE_OPTS_CACHE = {}
ORACLE_CACHE = {}
ACTIVE = None
ENV = {}
GEN_PURE = False
GEN_LOCALE = os.environ.get("UTF8_LOCALE", "C.UTF-8")
GEN_SKIPS = []
CONTAINER_PASSWORD = b"hashcat"
TC_TESTS_DIR = os.path.join(TDIR, "tc_tests")
VC_TESTS_DIR = os.path.join(TDIR, "vc_tests")
LUKS_TESTS_DIR = os.path.join(TDIR, "luks_tests")
LUKS2_TESTS_DIR = os.path.join(TDIR, "luks2_tests")
CL_TESTS_DIR = os.path.join(TDIR, "cl_tests")

UNCAPPED = False

PASS_FDS = ()
