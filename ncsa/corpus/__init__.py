"""The golden corpus -- the only thing that makes an accuracy claim falsifiable.

TWO ARTIFACTS, TWO DIFFERENT CLAIMS. Conflating them is how a project ends up
believing its own output.

  golden/*.yaml           CORRECTNESS. A human read the configuration, found
                          the line, and asserted the expected result. Each
                          expectation carries the line that justifies it, so a
                          reviewer can re-check the claim without re-running
                          anything. These are the cases the RegressionGuard
                          protects.

  mapping_snapshots.json  CHANGE DETECTION, and nothing more. What each pack
                          mapping currently produces against the sample set. It
                          does NOT prove a mapping is right -- it proves that
                          what it does today is what it did yesterday, and
                          makes any drift visible in a diff instead of
                          silently changing a customer's report.

The distinction matters because this project has produced confident-looking
output with nothing under it five separate times: 225 fabricated SonicWall
findings, `AC-1` returned for every RAG query, six-character ISO documents,
12,088 settings parsed out of an encrypted file, and a high-severity control
that could never fail. Every one of them would have been caught on the day it
appeared by a corpus with hand-verified expectations. None of them would have
been caught by a snapshot alone.
"""
from .golden import (GOLDEN_DIR, load_golden, run_case, verify_corpus,
                     write_snapshot, load_snapshot, snapshot_mappings)

__all__ = ["GOLDEN_DIR", "load_golden", "run_case", "verify_corpus",
           "write_snapshot", "load_snapshot", "snapshot_mappings"]
