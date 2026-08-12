# Builds the ground-truth self-test fixtures used by `run.py selftest`.
# -g -Og -fPIE mirrors hashcat's own DEBUG=1 flags as closely as a small
# standalone program can (see tools/valgrind/README.md).

CC ?= gcc
CFLAGS = -g -Og -fPIE -Wall -Wextra
LDFLAGS = -pie

REPO_ROOT := $(abspath ../../..)
CL_HEADERS := $(REPO_ROOT)/deps/OpenCL-Headers

HOST_FIXTURES := double_free use_after_free invalid_read invalid_write leak_definite uninit_value

.PHONY: all clean
all: $(HOST_FIXTURES) cl_harness

$(HOST_FIXTURES): %: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Kernel-fixture loader: needs the OpenCL headers hashcat already vendors
# and links directly against the ICD loader's soname (there is no
# unversioned libOpenCL.so symlink in this environment's default linker
# search path).
cl_harness: cl_harness.c
	$(CC) $(CFLAGS) -I$(CL_HEADERS) -DCL_TARGET_OPENCL_VERSION=120 -o $@ $< -l:libOpenCL.so.1 $(LDFLAGS)

clean:
	rm -f $(HOST_FIXTURES) cl_harness
