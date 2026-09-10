"""Download the vendor documentation named in the parser-architecture PDF.

Plan gap this closes: every pack regex and path so far was written from recall.
Section 2 of that document is explicit -- "Use official vendor documentation as
the primary grammar and semantics reference" -- and reading ONE guide (Junos)
immediately found four defects including a false PASS on a high-severity
control. This fetches the rest so the other packs can be grounded the same way.

Each source is recorded with its URL and retrieval date so a pack rule can cite
where its grammar came from, rather than asserting it.
"""
from __future__ import annotations

import re
import sys
import time
import urllib.request
from pathlib import Path

OUT = Path(r"E:\NCSA\reference\vendor_docs")
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128 Safari/537.36"

SOURCES = [
    # (vendor key, filename, url)
    ("cisco_asa",   "cisco-asa-923-access-acls.html",
     "https://www.cisco.com/c/en/us/td/docs/security/asa/asa923/configuration/firewall/asa-923-firewall-config/access-acls.html"),
    ("fortios",     "fortios-76-cli-config-firewall-policy.html",
     "https://docs.fortinet.com/document/fortigate/7.6.2/cli-reference/333889629/config-firewall-policy"),
    ("fortios",     "fortigate-76-admin-firewall-policy.html",
     "https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/656084/firewall-policy"),
    ("panos",       "panos-111-security-policy.html",
     "https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/policy/security-policy"),
    ("panos",       "panos-111-security-policy-rule-components.html",
     "https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/policy/security-policy/components-of-a-security-policy-rule"),
    ("panos",       "panos-111-policy-objects.html",
     "https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/policy/policy-objects"),
    ("junos",       "junos-security-edit-policies.html",
     "https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-policies.html"),
    ("junos",       "junos-security-edit-policy-security.html",
     "https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-policy-security.html"),
    ("checkpoint",  "checkpoint-r8120-cli-reference.pdf",
     "https://sc1.checkpoint.com/documents/R81.20/WebAdminGuides/EN/CP_R81.20_CLI_ReferenceGuide/CP_R81.20_CLI_ReferenceGuide.pdf"),
    ("f5",          "f5-techdocs.html",          "https://techdocs.f5.com/"),
    ("arista",      "arista-eos-toi.html",       "https://www.arista.com/en/support/toi/eos"),
    ("a10",         "a10-documentation.html",    "https://documentation.a10networks.com/"),
    ("cumulus",     "nvidia-cumulus-docs.html",  "https://docs.nvidia.com/networking-ethernet-software/"),
    ("sonic",       "sonic-wiki.html",           "https://github.com/sonic-net/SONiC/wiki"),
]


def fetch(url: str, dest: Path) -> tuple[bool, int, str]:
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/pdf,*/*",
        "Accept-Language": "en-US,en;q=0.9",
    })
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            data = r.read()
            ctype = r.headers.get("Content-Type", "")
        dest.write_bytes(data)
        return True, len(data), ctype
    except Exception as exc:
        return False, 0, f"{type(exc).__name__}: {exc}"[:70]


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    manifest = []
    for vendor, fname, url in SOURCES:
        dest = OUT / fname
        if dest.exists() and dest.stat().st_size > 2000:
            print(f"  have    {vendor:<11} {fname[:44]:<46} {dest.stat().st_size:>8}")
            manifest.append((vendor, fname, url, dest.stat().st_size, "cached"))
            continue
        ok, n, info = fetch(url, dest)
        status = "ok" if ok else "FAIL"
        print(f"  {status:<7} {vendor:<11} {fname[:44]:<46} {n:>8}  {info[:34]}")
        manifest.append((vendor, fname, url, n, info[:40]))
        time.sleep(1.0)          # be polite to vendor doc sites

    with (OUT / "SOURCES.md").open("w", encoding="utf-8") as fh:
        fh.write("# Vendor documentation sources\n\n")
        fh.write("Retrieved for grammar grounding. Every pack rule derived from one of\n")
        fh.write("these should cite the vendor + file, not rely on recall.\n\n")
        fh.write(f"Retrieved: {time.strftime('%Y-%m-%d')}\n\n")
        fh.write("| vendor | file | bytes | url |\n|---|---|---|---|\n")
        for v, f, u, n, s in manifest:
            fh.write(f"| {v} | `{f}` | {n} | {u} |\n")
    print(f"\nmanifest written: {OUT / 'SOURCES.md'}")


if __name__ == "__main__":
    main()
