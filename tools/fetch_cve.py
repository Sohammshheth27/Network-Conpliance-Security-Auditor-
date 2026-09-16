"""Refresh the local CVE snapshot that the extended CVE check reads.

    python -m tools.fetch_cve

For every platform in PRODUCTS this fetches the NVD CVE 2.0 records whose
configurations name that product's CPE, plus the CISA Known Exploited
Vulnerabilities catalogue, and writes compacted copies under reference/cve/
stamped with the fetch time.

The check itself never touches the network. That keeps assessments
reproducible and air-gap friendly -- and it is why every CVE result states the
date of the data it was matched against. A snapshot is a claim about the past.
"""
from __future__ import annotations

import argparse
import json
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV = ("https://www.cisa.gov/sites/default/files/feeds/"
       "known_exploited_vulnerabilities.json")
OUT = Path("reference/cve")

#: platform -> CPE prefix (part:vendor:product). Only platforms whose version
#: string can be matched precisely belong here; see ncsa/extended/cve.py.
PRODUCTS = {
    "sonicwall_sonicos": "cpe:2.3:o:sonicwall:sonicos",
}

#: NVD asks unauthenticated clients to stay under 5 requests per 30 seconds.
PAGE_PAUSE_S = 6.5


def _get(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "NCSA-cve-snapshot/1.0"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.load(r)


def _best_metric(metrics: dict) -> dict | None:
    """Prefer the newest CVSS version NVD provides, primary source first."""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key) or []
        rows = sorted(rows, key=lambda m: m.get("type") != "Primary")
        for m in rows:
            d = m.get("cvssData", {})
            return {"cvss_version": d.get("version"),
                    "base_score": d.get("baseScore"),
                    "base_severity": d.get("baseSeverity") or m.get("baseSeverity"),
                    "vector": d.get("vectorString"),
                    "source": m.get("source")}
    return None


def _compact(vuln: dict) -> dict:
    c = vuln["cve"]
    desc = next((d["value"] for d in c.get("descriptions", [])
                 if d.get("lang") == "en"), "")
    configs = []
    for cfg in c.get("configurations", []) or []:
        configs.append({
            "operator": cfg.get("operator", "OR"),
            "negate": cfg.get("negate", False),
            "nodes": [{
                "operator": n.get("operator", "OR"),
                "negate": n.get("negate", False),
                "cpeMatch": [{k: m[k] for k in m
                              if k in ("criteria", "vulnerable",
                                       "versionStartIncluding",
                                       "versionStartExcluding",
                                       "versionEndIncluding",
                                       "versionEndExcluding")}
                             for m in n.get("cpeMatch", [])],
            } for n in cfg.get("nodes", [])],
        })
    return {
        "id": c["id"],
        "published": c.get("published"),
        "last_modified": c.get("lastModified"),
        "status": c.get("vulnStatus"),
        "description": desc,
        "metric": _best_metric(c.get("metrics", {})),
        "cwe": sorted({d["value"] for w in c.get("weaknesses", [])
                       for d in w.get("description", [])
                       if d.get("value", "").startswith("CWE-")}),
        "references": [r["url"] for r in c.get("references", [])][:5],
        "configurations": configs,
    }


def fetch_nvd(cpe_prefix: str) -> list[dict]:
    out, start = [], 0
    while True:
        q = urllib.parse.urlencode({"virtualMatchString": cpe_prefix,
                                    "resultsPerPage": 2000,
                                    "startIndex": start})
        page = _get(f"{NVD}?{q}")
        out.extend(_compact(v) for v in page.get("vulnerabilities", []))
        start += page.get("resultsPerPage", 0)
        if start >= page.get("totalResults", 0) or not page.get("resultsPerPage"):
            return out
        time.sleep(PAGE_PAUSE_S)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="tools.fetch_cve")
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")

    for platform, cpe in PRODUCTS.items():
        cves = fetch_nvd(cpe)
        doc = {"source": NVD, "cpe_prefix": cpe, "platform": platform,
               "fetched_at": stamp, "total": len(cves), "cves": cves}
        path = out / f"nvd-{platform}.json"
        path.write_text(json.dumps(doc, indent=1), encoding="utf-8")
        print(f"  {platform:<22} {len(cves):>4} CVE records -> {path}")
        time.sleep(PAGE_PAUSE_S)

    kev = _get(KEV)
    kev["fetched_at"] = stamp
    (out / "kev.json").write_text(json.dumps(kev), encoding="utf-8")
    print(f"  CISA KEV catalogue {kev.get('catalogVersion')}: "
          f"{kev.get('count')} entries -> {out / 'kev.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
