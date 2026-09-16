"""Sanitise a real device configuration before it is shared or committed.

    python -m tools.sanitise_config <input> <output> [--words site_words.txt]

A thin wrapper around netconan (already a project dependency) with the
settings an AUDIT needs, not only the settings privacy needs:

  * IP addresses and passwords/secrets are anonymised (-a -p).
  * Default SNMP community strings are PRESERVED (-r public,private,...).
    netconan's -p also rewrites community lines; without this, a device still
    using "public" would look compliant after sanitising -- SNMP-002 exists to
    catch exactly that.
  * Site names, hostnames and serials go in a words file you keep OUT of git
    (-w). One word per line.
  * Private address ranges are preserved (--preserve-private-addresses), so
    "is this interface on an internal network" still reads correctly.

The salt is random per run and printed ONCE: keep it only if you may need to
reverse the IP anonymisation later (netconan -u).
"""
from __future__ import annotations

import argparse
import secrets
import subprocess
import sys
from pathlib import Path

# Weak community strings the controls must still be able to see.
AUDIT_RESERVED = ["public", "private", "cisco", "admin", "default"]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("input")
    ap.add_argument("output")
    ap.add_argument("--words", help="file of sensitive words (sites, hostnames, serials)")
    args = ap.parse_args(argv)

    salt = secrets.token_hex(8)
    cmd = [sys.executable, "-m", "netconan", "-i", args.input, "-o", args.output,
           "-a", "-p", "--preserve-private-addresses",
           "-r", ",".join(AUDIT_RESERVED), "-s", salt]
    if args.words:
        words = [w.strip() for w in Path(args.words).read_text(encoding="utf-8").splitlines()
                 if w.strip() and not w.startswith("#")]
        if words:
            cmd += ["-w", ",".join(words)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write(r.stderr)
        return r.returncode
    print(f"sanitised -> {args.output}")
    print(f"salt (keep only to reverse IP anonymisation): {salt}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
