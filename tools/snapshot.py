"""Record what every pack mapping currently produces.

    python -m tools.snapshot          # re-record
    python -m tools.snapshot --diff   # show changes without recording

CHANGE DETECTION, not correctness -- see ncsa/corpus/__init__.py. Re-record
deliberately, after reading the diff, never to make a red test go green.
"""
import argparse
import sys

from ncsa.corpus.golden import SNAPSHOT_PATH, diff_snapshot, write_snapshot


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--diff", action="store_true")
    a = ap.parse_args()

    if a.diff:
        d = diff_snapshot()
        print(f"{len(d)} change(s)")
        for line in d:
            print("  ", line)
        return 1 if d else 0

    d = diff_snapshot()
    if d:
        print(f"recording {len(d)} change(s):")
        for line in d[:20]:
            print("  ", line)
    snap = write_snapshot()
    print(f"snapshot: {len(snap)} samples -> {SNAPSHOT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
