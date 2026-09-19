"""Expensive answers are held, but only until their sources change.

Two routes were rebuilding their answer on every request: /frameworks loads the
framework registry (~2 minutes even from its own cache) and /attack-coverage
recomputes over every rule. A dashboard page that opens several panels paid
that cost each time, and paid it again on the next visit.

Caching is easy; caching honestly is the part worth testing. A cache nobody can
invalidate would keep answering from yesterday's catalogue after a rebuild and
never say so -- in a compliance tool that is a wrong answer delivered with
confidence. So the stamp, not just the hit, is what these tests hold.

The helpers are exercised directly: driving them through the routes would add
minutes to the suite and prove less.
"""
import os
from pathlib import Path

from ncsa.api.app import _memoised, _stamp


def test_a_held_answer_is_returned_without_rebuilding(tmp_path):
    src = tmp_path / "source.yaml"
    src.write_text("a: 1", encoding="utf-8")
    calls = []

    def build():
        calls.append(1)
        return {"value": len(calls)}

    first = _memoised("t-hold", _stamp(src), build)
    second = _memoised("t-hold", _stamp(src), build)

    assert first == second
    assert first is second, "the held object itself should come back"
    assert len(calls) == 1, "an unchanged source must not rebuild"


def test_a_changed_source_rebuilds(tmp_path):
    """The point of the stamp: a rebuilt catalogue must not be served stale."""
    src = tmp_path / "source.yaml"
    src.write_text("a: 1", encoding="utf-8")
    calls = []

    def build():
        calls.append(1)
        return len(calls)

    assert _memoised("t-change", _stamp(src), build) == 1

    # A real rebuild lands a later mtime. Set it explicitly rather than trusting
    # the clock: two writes inside one filesystem tick share a timestamp, which
    # is the documented limit of this stamp, not the behaviour under test.
    src.write_text("a: 2", encoding="utf-8")
    st = src.stat()
    os.utime(src, ns=(st.st_atime_ns, st.st_mtime_ns + 2_000_000_000))

    assert _memoised("t-change", _stamp(src), build) == 2
    assert len(calls) == 2


def test_a_same_size_rewrite_inside_one_clock_tick_is_not_detected(tmp_path):
    """The known limit, recorded so it is a decision and not a surprise.

    Size plus mtime cannot see a same-length rewrite that lands within the
    filesystem's timestamp resolution. Nothing the engine stamps changes that
    fast, so this is accepted -- but it is written down here, and in _stamp,
    rather than discovered later by someone debugging a stale catalogue.
    """
    src = tmp_path / "source.yaml"
    src.write_text("a: 1", encoding="utf-8")
    first = _stamp(src)

    st = src.stat()
    src.write_text("a: 2", encoding="utf-8")          # same length
    os.utime(src, ns=(st.st_atime_ns, st.st_mtime_ns))  # same tick

    assert _stamp(src) == first, (
        "if this now differs, the stamp got stronger -- update _stamp's "
        "docstring and delete this test rather than leaving it asserting a "
        "weakness that no longer exists")


def test_a_directory_stamp_follows_files_appearing_and_disappearing(tmp_path):
    """Rules are a directory, so add and delete are the changes that matter.

    Both are caught by the file count, which is why the count is in the stamp:
    two files written in the same clock tick share an mtime, and a deletion can
    leave the newest mtime untouched entirely.
    """
    d = tmp_path / "rules"
    d.mkdir()
    (d / "one.yaml").write_text("id: A", encoding="utf-8")
    one_file = _stamp(d)

    (d / "two.yaml").write_text("id: B", encoding="utf-8")
    two_files = _stamp(d)
    assert two_files != one_file, "a new rule file must invalidate the answer"

    (d / "two.yaml").unlink()
    assert _stamp(d) != two_files, "a deleted rule file must invalidate it too"
    assert _stamp(d) == one_file, "and land back on the earlier stamp"


def test_a_missing_source_is_a_stable_stamp(tmp_path):
    """Absent is a state too. It must not raise, and must not churn."""
    missing = tmp_path / "not-there.json"
    assert _stamp(missing) == _stamp(missing)

    calls = []
    _memoised("t-missing", _stamp(missing), lambda: calls.append(1))
    _memoised("t-missing", _stamp(missing), lambda: calls.append(1))
    assert len(calls) == 1


def test_keys_do_not_collide(tmp_path):
    src = tmp_path / "s.yaml"
    src.write_text("x", encoding="utf-8")
    a = _memoised("t-key-a", _stamp(src), lambda: "A")
    b = _memoised("t-key-b", _stamp(src), lambda: "B")
    assert (a, b) == ("A", "B")


def test_the_real_stamps_resolve(tmp_path):
    """The paths the routes actually stamp must exist in this checkout."""
    from ncsa.frameworks.attack import BUNDLE
    from ncsa.frameworks.registry import CACHE_PATH

    assert Path("rules").is_dir(), "rules/ is stamped by /attack-coverage"
    # The catalogue cache and the ATT&CK bundle are both gitignored artefacts,
    # so their absence is legitimate -- the stamp only has to survive it.
    assert isinstance(_stamp(CACHE_PATH, Path(BUNDLE)), tuple)
