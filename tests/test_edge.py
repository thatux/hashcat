##
## Author......: See docs/credits.txt
## License.....: MIT
##

from pathlib import Path

from hashcat_pytest import catalog, edge, execution, oracles

SUITE = "edge"


def test_edge(case, run_case):
  def crack(args, directory, result):
    metadata = catalog.edge_hh(case.mode)
    assert case.kernel in metadata["kernel_types"], "source/runtime kernel capabilities disagree"
    vectors, code = oracles.edge_oracle(case.mode, case.attack, case.kernel == "optimized")
    assert code == 0 and vectors and all(vector["hash"] for vector in vectors), "edge oracle returned empty or invalid vectors"
    context = edge.EdgeCtx(case.mode, case.attack, case.kernel, case.kernel == "optimized", metadata,
                          metadata["slow"], catalog.edge_binary_hashfile(case.mode), metadata["pw_type"] == "HEX",
                          metadata["pw_type"] == "BASE58" or case.mode in (31500, 31600),
                          catalog.edge_hexify_plain(case.mode),
                          metadata["salt_present"] == False or metadata["salt_virtual"], metadata["keep_guessing"])
    outfile = str(Path(directory, "cracks.out"))
    options = execution.edge_opts(args, context.optimized, case.width, context.pt_hex, outfile)
    if case.target == "single":
      errors, cells = edge.edge_single(context, case.width, options, outfile, vectors, directory)
    else:
      errors, cells, stop = edge.edge_multi(context, case.width, options, outfile, vectors, directory)
    assert errors == 0, "%d edge verification errors across %d invocations" % (errors, cells)
    assert cells > 0, "no applicable edge vectors"
  run_case(crack)
