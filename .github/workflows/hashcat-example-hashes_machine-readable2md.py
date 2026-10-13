#!/usr/bin/env python3

# this script is ran automatically; there should be no need to run this manually
#  used in .github/workflows/build.yml to generate docs/hashcat-example-hashes.md on every commit to master
# example usage: ./hashcat --example-hashes --machine-readable --quiet | python3 hashcat-example-hashes_machine-readable2md.py >> docs/hashcat-example_hashes.md


import sys
import json
import os
import re
import subprocess

# Replace LUKS v1 and v2 hashes, they're too big: Github no longer shows the .md "(Sorry about that, but we can't show files that are this big right now.)"
EXAMPLE_HASH_REPLACEMENTS = {
    "14600": "https://hashcat.net/misc/example_hashes/hashcat_luks_testfiles.7z",
    "29511": "https://hashcat.net/misc/example_hashes/hashcat_luks_sha1_aes_cbc-essiv_128.txt",
    "29512": "https://hashcat.net/misc/example_hashes/hashcat_luks_sha1_serpent_cbc-plain64_256.txt",
    "29513": "https://hashcat.net/misc/example_hashes/hashcat_luks_sha1_twofish_xts-plain64_256.txt",
    "29521": "https://hashcat.net/misc/example_hashes/hashcat_luks_sha256_aes_cbc-plain64_128.txt",
    "29522": "https://hashcat.net/misc/example_hashes/hashcat_luks_sha256_serpent_xts-plain64_512.txt",
    "29523": "https://hashcat.net/misc/example_hashes/hashcat_luks_sha256_twofish_cbc-essiv_256.txt",
    "29531": "https://hashcat.net/misc/example_hashes/hashcat_luks_sha512_aes_cbc-plain64_256.txt",
    "29532": "https://hashcat.net/misc/example_hashes/hashcat_luks_sha512_serpent_cbc-essiv_128.txt",
    "29533": "https://hashcat.net/misc/example_hashes/hashcat_luks_sha512_twofish_cbc-plain64_256.txt",
    "29541": "https://hashcat.net/misc/example_hashes/hashcat_luks_ripemd160_aes_cbc-essiv_256.txt",
    "29542": "https://hashcat.net/misc/example_hashes/hashcat_luks_ripemd160_serpent_xts-plain64_256.txt",
    "29543": "https://hashcat.net/misc/example_hashes/hashcat_luks_ripemd160_twofish_cbc-plain64_128.txt",
    "34100": "https://hashcat.net/misc/example_hashes/hashcat_luks2_argon2id_sha256_aes_xts-plain64_512.txt",
}

OPENCL_DIR = "../../OpenCL"
MODULES_DIR = "../../src/modules"
TESTS_DIR = "../../tools/test_modules"
TESTPY = "../../tools/test.py"

# The Test column shows three dots per mode, one for each kind of test input: a synthetic oracle
# (the hash is computed from a password), a static container shipped in the repo, and a container
# that tools/test.py -g builds on the fly and cracks end to end. A kind the mode has is green; a kind
# that is relevant to the mode's format but missing is red (a coverage gap); a kind that does not
# apply to the mode is a dash. Relevance follows the format: a container or archive mode (one that
# has a static or generated input) can carry all three kinds, a plain hash mode can only carry the
# oracle. test.py owns the descriptors, so query it for the kinds rather than scanning the tree here.
KIND_DOTS = [
    ("synthetic", "synthetic"),
    ("static",    "static"),
    ("generated", "dynamic"),
]
NA_DOT = "-"

OPENCL_ABBREV = {
    "_a0-pure": "a0p",
    "_a0-optimized": "a0o",
    "_a1-pure": "a1p",
    "_a1-optimized": "a1o",
    "_a3-pure": "a3p",
    "_a3-optimized": "a3o",
    "pure": "p",
    "optimized": "o",
}
OPENCL_ABBREV_SORT_ORDER = ["p", "o", "a0p", "a0o", "a1p", "a1o", "a3p", "a3o"]
order_map = {v: i for i, v in enumerate(OPENCL_ABBREV_SORT_ORDER)}

def md_remove_backticks_and_pipes(msg):
    return msg.replace('`', '').replace('|', '')

def sort_abbrevs(links):
    """Sort markdown links by their abbreviation order."""
    return sorted(links, key=lambda link: order_map.get(link.split("]")[0][1:], 999))

def find_opencl(zfilled_key, visited=None):
    """Return markdown links for OpenCL kernels, following redirect if needed."""
    if visited is None:
        visited = set()
    if zfilled_key in visited:
        return ""  # Avoid infinite loops
    visited.add(zfilled_key)

    kernels = []
    if os.path.isdir(OPENCL_DIR):
        for filename in sorted(os.listdir(OPENCL_DIR)):
            if zfilled_key in filename:
                for key, abbr in OPENCL_ABBREV.items():
                    if key in filename:
                        link = f"[{abbr}](/{OPENCL_DIR}/{filename})"
                        kernels.append(link)
                        break
    if kernels:
        return " " + ",&nbsp;".join(sort_abbrevs(kernels))

    # No kernels found -> check module file for redirect
    module_file = os.path.join(MODULES_DIR, f"module_{zfilled_key}.c")
    if os.path.isfile(module_file):
        with open(module_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                m = re.search(r"static\s+const\s+u64\s+KERN_TYPE\s*=\s*(\d+);", line)
                if m:
                    redirect_key = str(m.group(1)).zfill(5)
                    return find_opencl(redirect_key, visited)
    return ""

def uses_hash_recipe(zfilled_key):
    """True when the module runs its pure kernels through the mode 4000 hash-recipe engine.

    Such a module sets module_ctx->module_hash_recipe to module_hash_recipe (the default is
    MODULE_DEFAULT), so its own pure kernel files were removed and the pure path is built from a
    recipe into OpenCL/m04000_*.cl instead. Only the optimized kernels, if any, stay mode specific.
    """
    module_file = os.path.join(MODULES_DIR, f"module_{zfilled_key}.c")
    if not os.path.isfile(module_file):
        return False
    with open(module_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "module_ctx->module_hash_recipe" not in line:
                continue
            value = line.split("=", 1)[1].strip() if "=" in line else ""
            return value == "module_hash_recipe;"
    return False

def load_input_kinds():
    """Ask test.py which test-input kinds each mode has, as {mode_str: [kinds]}. test.py reads the
    per-mode descriptors, so it is the one place that knows which modes have a synthetic oracle, a
    static container or a generated container; scanning the tree here would duplicate that."""
    out = subprocess.run([sys.executable, TESTPY, "--input-kinds"],
                         stdout=subprocess.PIPE, check=True).stdout
    return json.loads(out)

def test_dots(key, zfilled_key, kinds):
    """Render the mode's test coverage as three dots, one per kind in KIND_DOTS order. A kind the
    mode has is a green dot linked to its descriptor; a kind that is relevant to the mode's format
    but absent is a red dot (a gap); a kind that does not apply is a dash. A container or archive
    mode (it has a static or generated input) can carry all three kinds; a plain hash mode can only
    carry the synthetic oracle, so its container kinds read as dashes rather than gaps."""
    present = set(kinds.get(key, []))
    container_or_archive = bool(present & {"static", "generated"})
    cells = []

    for kind, sub in KIND_DOTS:
        if kind in present:
            cells.append(f"[:green_circle:](/{TESTS_DIR}/{sub}/m{zfilled_key}.py)")
        else:
            relevant = (not container_or_archive) if kind == "synthetic" else container_or_archive
            cells.append(":red_circle:" if relevant else NA_DOT)

    return " ".join(cells)

def main():
    input_data = sys.stdin.read()
    try:
        data = json.loads(input_data)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"Invalid JSON input: {e}\n")
        sys.exit(1)

    kinds = load_input_kinds()

    footnote_map = {}
    footnote_counter = 1
    table_rows = []

    for key, value in data.items():
        name = value["name"]
        example_hash = value["example_hash"]
        example_pass = value["example_pass"]
        usage_notice = value["usage_notice"]
        advice_notice = value["advice_notice"]

        # Replace example_hash if key is in the replacement map
        if key in EXAMPLE_HASH_REPLACEMENTS:
            example_hash = EXAMPLE_HASH_REPLACEMENTS[key]

        footnote = ""
        if example_pass != "hashcat":
            footnote_val = f"Example password: `{example_pass}`"
            if footnote_val not in footnote_map:
                footnote_map[footnote_val] = footnote_counter
                footnote_counter += 1
            footnote += f"[^{footnote_map[footnote_val]}]"

        if usage_notice != "N/A":
            usage_notice = md_remove_backticks_and_pipes(usage_notice)
            footnote_val = f"Module usage notice: `{usage_notice}`"
            if footnote_val not in footnote_map:
                footnote_map[footnote_val] = footnote_counter
                footnote_counter += 1
            footnote += f"[^{footnote_map[footnote_val]}]"

        if advice_notice != "N/A":
            advice_notice = md_remove_backticks_and_pipes(advice_notice)
            footnote_val = f"Module advice notice: `{advice_notice}`"
            if footnote_val not in footnote_map:
                footnote_map[footnote_val] = footnote_counter
                footnote_counter += 1
            footnote += f"[^{footnote_map[footnote_val]}]"

        zfilled_key = key.zfill(5)
        opencl_links = find_opencl(zfilled_key)
        test_link = test_dots(key, zfilled_key, kinds)

        # A recipe mode has no pure kernel files of its own: the pure path is compiled from a recipe
        # into the mode 4000 kernels, so find_opencl only sees the optimized kernels, or none. Add a
        # "recipe" link to the kernel column so the pure path is visible and points at its documentation
        # (the mode's own recipe is the HASH_RECIPE in its module, which the mode number already links).
        if uses_hash_recipe(zfilled_key):
            recipe_link = "[recipe](/docs/hashcat-hash-recipe.md)"
            opencl_links = f"{opencl_links},&nbsp;{recipe_link}" if opencl_links else f" {recipe_link}"

        # Make sure we refer to root for display
        opencl_links = opencl_links.replace('/../../', '/')
        test_link = test_link.replace('/../../', '/')

        name = md_remove_backticks_and_pipes(name)
        example_hash = md_remove_backticks_and_pipes(example_hash)

        row = f"| [`{key}`](/src/modules/module_{zfilled_key}.c) | `{name}`{footnote} | <sup> {opencl_links} </sup> | {test_link} | `{example_hash}` |"
        table_rows.append(row)

    # Print the table
    print("\n".join(table_rows))

    # Print footnotes
    if footnote_map:
        print()
        for val, num in footnote_map.items():
            print(f"[^{num}]: {val}")

if __name__ == "__main__":
    main()
