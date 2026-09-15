"""Formal assessment reports.

A report is the deliverable an auditor actually reads and signs against, so it
carries two obligations the console does not:

  * EVERY figure is computed from the assessment at render time. Nothing is
    passed in, cached or written by hand -- a report that quotes a number the
    engine no longer produces is worse than no report.

  * Every claim is traceable. Findings carry the file and line; exclusions
    carry their justification; and the coverage the report was written under
    is stated on the front page rather than buried.
"""
from .render import build_report, write_html, write_pdf

__all__ = ["build_report", "write_html", "write_pdf"]
