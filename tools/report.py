"""Produce a formal assessment report for one or more configuration files.

    python -m tools.report "E:\\sonicwall config file.txt"
    python -m tools.report config.conf --out reports/ --format html
    python -m tools.report *.conf --no-redact

Redaction is ON by default. A decoded device export carries password hashes
and real addressing, and a report is a document that gets emailed.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="tools.report",
        description="Formal compliance assessment report (PDF or HTML).")
    ap.add_argument("configs", nargs="+", help="configuration file(s)")
    ap.add_argument("--out", default="reports",
                    help="output directory (default: reports/)")
    ap.add_argument("--format", choices=("pdf", "html", "json"), default="pdf",
                    help="json exports the Security Baseline Model -- the "
                         "machine-readable form of the same assessment")
    ap.add_argument("--no-redact", action="store_true",
                    help="keep addresses and secrets in the report. Only for "
                         "configurations you are permitted to handle in full.")
    args = ap.parse_args(argv)

    from ncsa.pipeline import assess
    from ncsa.report import write_html, write_pdf
    from ncsa.schema.export import write_baseline

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    failures = 0

    for raw in args.configs:
        src = Path(raw)
        if not src.exists():
            print(f"  SKIP  {src}: no such file", file=sys.stderr)
            failures += 1
            continue

        aid = f"NCSA-{src.stem[:24]}"
        try:
            da = assess(src, redact=not args.no_redact, assessment_id=aid)
        except Exception as exc:                           # noqa: BLE001
            print(f"  FAIL  {src.name}: {type(exc).__name__}: {exc}",
                  file=sys.stderr)
            failures += 1
            continue

        device = da.identity.hostname or src.stem
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in device)
        dest = out_dir / f"NCSA_Report_{safe}.{args.format}"

        try:
            writer = {"html": write_html, "json": write_baseline}.get(
                args.format, write_pdf)
            path = writer(da, dest, aid)
        except RuntimeError as exc:
            print(f"  FAIL  {src.name}: {exc}", file=sys.stderr)
            failures += 1
            continue

        cov = da.coverage()
        score = "n/a" if cov["score_pct"] is None else f"{cov['score_pct']}%"
        print(f"  {device:<24} {score:>6} on {cov['assessed_pct']:>5}% coverage"
              f"   -> {path}")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
