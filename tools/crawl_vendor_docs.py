"""Render vendor documentation with a real browser and extract grammar section-wise.

WHY A BROWSER IS NEEDED
-----------------------
Most vendor documentation is a JavaScript application. A plain HTTP fetch of
F5's techdocs returns 382 KB of HTML containing 51 characters of readable text;
Palo Alto returns a 228 KB shell with the actual rule model absent. The syntax
and the semantic tables ARE published on the site -- they are simply rendered
client-side, section by section.

WHAT IS EXTRACTED
-----------------
Two things, because vendors document grammar in two different shapes:

  * CLI statements  -- code blocks and `set`/`config` lines (Fortinet, Junos,
    Arista, SONiC style)
  * SEMANTIC TABLES -- field/description grids (Palo Alto, Check Point style),
    which are the authoritative object model even where no CLI is shown

Each page is saved with its URL so a pack rule can cite the section it came
from rather than resting on recall.
"""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

OUT = Path(r"E:\NCSA\reference\vendor_docs\rendered")

# Section-wise entry points. These are documentation *sections*, not landing
# pages -- the earlier fetch failed partly because it grabbed one page per
# vendor instead of the tree.
TARGETS: dict[str, list[str]] = {
    "panos": [
        "https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/policy/security-policy",
        "https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/policy/security-policy/components-of-a-security-policy-rule",
        "https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/policy/policy-objects",
    ],
    "arista": [
        "https://www.arista.com/en/um-eos/eos-section-19-1-acls-and-route-maps",
        "https://www.arista.com/en/um-eos/eos-section-5-3-aaa-configuration",
    ],
    "cumulus": [
        "https://docs.nvidia.com/networking/cumulus-linux-59/System-Configuration/Authentication-Authorization-and-Accounting/",
        "https://docs.nvidia.com/networking/cumulus-linux-59/Layer-3/Access-Control-Lists/",
    ],
    "f5": [
        "https://techdocs.f5.com/en-us/bigip-17-1-0/big-ip-systems-configuring-for-security.html",
    ],
    "a10": [
        "https://documentation.a10networks.com/docs/IN/ACOS/6_0_x/",
    ],
    "sonic": [
        "https://github.com/sonic-net/SONiC/wiki/Configuration",
    ],
    "checkpoint": [
        "https://sc1.checkpoint.com/documents/R81.20/WebAdminGuides/EN/CP_R81.20_SecurityManagement_AdminGuide/Content/Topics-SECMG/Access-Control-Policy.htm",
        "https://sc1.checkpoint.com/documents/R81.20/WebAdminGuides/EN/CP_R81.20_SecurityManagement_AdminGuide/Content/Topics-SECMG/Creating-an-Access-Control-Policy.htm",
    ],
}

CLI_RE = re.compile(
    r"^\s*(?:config|set|edit|next|end|unset|show|nv set|net add|ip |no |aaa |"
    r"snmp-server|logging|ntp|line |username |access-list|permit |deny |"
    r"management|tmsh|modify|create|add |delete )\S.*", re.I)


def extract(page) -> dict:
    return page.evaluate("""() => {
        // Pick the container with the MOST text rather than the first match --
        // a wrong selector returned 122 characters on Palo Alto while the real
        // content sat in a sibling node.
        const cands = Array.from(document.querySelectorAll(
            'main, article, [role=main], .content, #content, .body, #main-content, body'));
        let main = document.body;
        for (const c of cands) {
            if ((c.innerText || '').length > (main.innerText || '').length) main = c;
        }
        const text = main.innerText || '';
        const code = Array.from(document.querySelectorAll('pre, code, .code, .programlisting'))
                          .map(e => e.innerText.trim()).filter(t => t.length > 4);
        const tables = Array.from(document.querySelectorAll('table')).map(t =>
            Array.from(t.querySelectorAll('tr')).map(r =>
                Array.from(r.querySelectorAll('th,td'))
                     .map(c => c.innerText.trim().replace(/\\s+/g,' ')).join(' | ')
            ).filter(Boolean).join('\\n')
        ).filter(t => t.length > 40);
        return {text, code, tables};
    }""")


def main() -> None:
    from playwright.sync_api import sync_playwright

    OUT.mkdir(parents=True, exist_ok=True)
    only = sys.argv[1:] or list(TARGETS)
    summary = []

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        ctx = browser.new_context(
            user_agent=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 Chrome/128 Safari/537.36"),
            viewport={"width": 1400, "height": 1000})
        page = ctx.new_page()

        for vendor in only:
            for i, url in enumerate(TARGETS.get(vendor, [])):
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=45000)
                    # networkidle never fires on sites that hold connections
                    # open (analytics sockets, chat widgets) -- Arista and F5
                    # both timed out on it. Wait for CONTENT instead of silence.
                    try:
                        page.wait_for_selector("table, pre, code, article, .content",
                                               timeout=20000)
                    except Exception:
                        pass
                    time.sleep(3)
                    d = extract(page)
                except Exception as exc:
                    print(f"  FAIL  {vendor:<11} {url[:58]:<60} {type(exc).__name__}")
                    summary.append((vendor, url, 0, 0, 0)); continue

                cli = sorted({l.strip() for blk in d["code"] for l in blk.splitlines()
                              if CLI_RE.match(l)})
                stem = f"{vendor}-{i}"
                (OUT / f"{stem}.txt").write_text(d["text"], encoding="utf-8")
                (OUT / f"{stem}.cli.txt").write_text("\n".join(cli), encoding="utf-8")
                (OUT / f"{stem}.tables.txt").write_text("\n\n".join(d["tables"]), encoding="utf-8")
                (OUT / f"{stem}.url.txt").write_text(url, encoding="utf-8")
                print(f"  ok    {vendor:<11} {len(d['text']):>7} chars  "
                      f"{len(cli):>4} CLI  {len(d['tables']):>3} tables  {url[:44]}")
                summary.append((vendor, url, len(d["text"]), len(cli), len(d["tables"])))

        browser.close()

    (OUT / "summary.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
    print(f"\ntotal: {sum(s[3] for s in summary)} CLI statements, "
          f"{sum(s[4] for s in summary)} tables across {len(summary)} pages")


if __name__ == "__main__":
    main()
