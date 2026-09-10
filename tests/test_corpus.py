"""The golden corpus, run as a test.

Every accuracy claim NCSA makes is unfalsifiable without this file. It is not
a unit test of a function -- it is the assertion that the whole pipeline still
produces the answers a human verified against the configuration by hand.

When one of these fails, the question is NOT "how do I make it pass". It is
"which is wrong, the tool or the expectation?" -- and the answer has gone both
ways in a single run: `contains_none` was giving partial credit to a
telnet-reachable device, while `min_count` was right and the expectation was
too harsh.
"""
import json
from pathlib import Path

import pytest

from ncsa.corpus import load_golden, verify_corpus
from ncsa.corpus.golden import SNAPSHOT_PATH, diff_snapshot, snapshot_mappings


def test_corpus_exists_and_is_not_trivial():
    cases = load_golden()
    assert len(cases) >= 4, "a corpus of one config proves very little"
    total = sum(len(c.get("controls") or {}) for c in cases)
    assert total >= 25, f"only {total} verified expectations"


def test_every_expectation_states_why():
    """An expectation without a reason cannot be re-checked by anyone but its
    author, which makes it indistinguishable from a snapshot of whatever the
    tool printed that day."""
    missing = []
    for case in load_golden():
        for cid, spec in (case.get("controls") or {}).items():
            if not isinstance(spec, dict) or not spec.get("because", "").strip():
                missing.append(f"{case['name']}:{cid}")
    assert not missing, f"expectations with no stated reason: {missing}"


def test_corpus_has_negative_controls():
    """A positive case with no negative twin only proves the tool agrees with
    its author. Each platform needs a config that must SCORE BADLY."""
    cases = load_golden()
    has_fail = {c["name"] for c in cases
                if any((s.get("expect") if isinstance(s, dict) else s) == "FAIL"
                       for s in (c.get("controls") or {}).values())}
    has_pass = {c["name"] for c in cases
                if any((s.get("expect") if isinstance(s, dict) else s) == "PASS"
                       for s in (c.get("controls") or {}).values())}
    assert has_fail and has_pass
    assert len(has_fail) >= 2 and len(has_pass) >= 2


def test_golden_corpus_still_holds():
    """THE test. Every hand-verified outcome, re-checked end to end."""
    r = verify_corpus()
    if r["no_config"]:
        pytest.skip(f"configs not on this machine: {r['no_config']}")
    assert not r["missing"], "\n".join(r["missing"])
    assert not r["mismatch"], (
        f"\n{len(r['mismatch'])} verified expectation(s) no longer hold.\n"
        "Decide which is wrong -- the tool or the expectation -- and say so "
        "in the case file.\n\n" + "\n\n".join(r["mismatch"]))
    assert r["ok"] >= 25


# ------------------------------------------------------------- snapshots
def test_snapshot_detects_change_not_correctness():
    """The snapshot cannot tell a right mapping from a wrong one. It tells a
    CHANGED one from an unchanged one, so a pack edit cannot silently alter a
    customer's findings."""
    if not Path(SNAPSHOT_PATH).exists():
        pytest.skip("no snapshot recorded yet -- run tools/snapshot.py")
    diffs = diff_snapshot()
    assert not diffs, (
        f"\n{len(diffs)} behaviour change(s) since the recorded snapshot:\n  "
        + "\n  ".join(diffs[:25])
        + "\n\nIf these are intended, re-record with: python -m tools.snapshot")


def test_snapshot_covers_every_sample_platform():
    if not Path(SNAPSHOT_PATH).exists():
        pytest.skip("no snapshot recorded yet")
    snap = json.loads(Path(SNAPSHOT_PATH).read_text(encoding="utf-8"))
    platforms = {v.get("platform") for v in snap.values() if isinstance(v, dict)}
    platforms.discard(None)
    assert len(platforms) >= 3, f"snapshot covers only {platforms}"
