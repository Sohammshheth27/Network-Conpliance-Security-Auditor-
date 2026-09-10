"""DISA STIG loader (XCCDF 1.1 manual benchmarks).

Plan 6.2: public domain -- we embed the full check and fix text.

The fix text matters more than it looks: it contains the literal correct
command for the platform, which makes it simultaneously rule content *and*
free training examples for the RAG (plan 5.2 Tier 3), *and* the authoritative
source for remediation templates (plan 8.1).

v1.4 6.4 caveat, learned from the real files: our controls do NOT map 1:1 onto
Vuln IDs. There is no rule titled "SSH must use version 2" in the Cisco NDM
STIG -- `ip ssh version 2` lives inside the fix text of V-215844 (FIPS HMAC,
CAT I). Four separate rules touch SSH. Hence: mine the fix text, and let a
control reference a *list* of Vuln IDs.
"""
import re
import zipfile
from pathlib import Path

from ..schema.enums import Severity
from .models import Automatability, Catalog, CatalogEntry, Framework, License

NS = {"x": "http://checklists.nist.gov/xccdf/1.1"}

# A STIG rule is procedural when its check asks a human to inspect policy or
# interview staff rather than read the configuration.
_PROCEDURAL_RE = re.compile(
    r"\b(interview|written policy|documented procedure|site security plan|"
    r"ISSO|ISSM|physically inspect|visually inspect|organizational policy)\b",
    re.I,
)

# Commands that appear in fix text, used to detect config-decidable rules and
# to seed the remediation knowledge base.
_CMD_RE = re.compile(
    # a device prompt anywhere on the line: R4(config)# / switch# / [edit] / >
    r"(?:^|\s)[A-Za-z0-9_\-]{1,24}(?:\([a-z0-9\-]+\))?\s*[#>]\s*\S"
    r"|^\s*\[edit"                       # Junos configuration mode
    r"|^\s*(?:set|delete) \S+ \S+"        # Junos / FortiOS / PAN-OS set-lines
    r"|^\s*(?:no\s+)?(?:ip|ipv6|aaa|snmp-server|logging|ntp|line|username|"
    r"crypto|service|banner|transport|enable|password|login|exec-timeout)\s+\S+",
    re.M | re.I,
)


def _text(node) -> str:
    """Collapse to a single line. For titles and descriptions."""
    return re.sub(r"[ \t]*\n[ \t\n]*", " ", "".join(node.itertext())).strip() if node is not None else ""


def _text_lines(node) -> str:
    """Preserve line structure. Mandatory for check and fix text.

    The fix text is where the literal platform command lives, and commands are
    line-oriented. Collapsing newlines here made every rule look non-automatable
    (0 of 553 triaged as CONFIG) because the line-anchored command regex could
    only ever match at position 0.
    """
    if node is None:
        return ""
    raw = "".join(node.itertext())
    raw = re.sub(r"[ \t]+", " ", raw)
    return re.sub(r"\n{3,}", "\n\n", raw).strip()


def _parse_xccdf(data: bytes, source_file: str) -> list[CatalogEntry]:
    import xml.etree.ElementTree as ET

    root = ET.fromstring(data)
    bench_title = _text(root.find("x:title", NS)) or root.get("id", "")
    ver = _text(root.find("x:version", NS))
    rel = ""
    for pt in root.findall("x:plain-text", NS):
        m = re.search(r"Release:\s*(\d+)", pt.text or "")
        if m:
            rel = m.group(1)
            break
    source_doc = f"{bench_title} V{ver}R{rel}" if ver else bench_title

    # NDM / RTR / L2S / ALG / IDPS / VPN -- plan 6.3. NDM is our MVP territory.
    part = None
    m = re.search(r"_(NDM|RTR|L2S|ALG|IDPS|VPN)_", source_file)
    if m:
        part = m.group(1)

    entries: list[CatalogEntry] = []
    for group in root.findall("x:Group", NS):
        vuln_id = group.get("id", "")
        for rule in group.findall("x:Rule", NS):
            title = _text(rule.find("x:title", NS))
            desc = _text(rule.find("x:description", NS))
            check = _text_lines(rule.find(".//x:check-content", NS))
            fix = _text_lines(rule.find("x:fixtext", NS))

            if _PROCEDURAL_RE.search(check) or _PROCEDURAL_RE.search(title):
                auto = Automatability.PROCEDURAL
            elif _CMD_RE.search(fix or ""):
                auto = Automatability.CONFIG
            else:
                auto = Automatability.UNKNOWN

            entries.append(
                CatalogEntry(
                    framework=Framework.DISA_STIG,
                    id=vuln_id,
                    title=title,
                    description=desc or None,
                    check=check or None,
                    fix=fix or None,          # public domain: keep it, it is gold
                    severity=Severity.from_xccdf(rule.get("severity", "")),
                    license=License.PUBLIC_DOMAIN,
                    automatable=auto,
                    source_document=source_doc,
                    source_file=source_file,
                    platform=_platform_of(source_file),
                    # CCIs are how a STIG rule states which 800-53 control it
                    # implements. Kept so the NIST label can be DERIVED from the
                    # STIG hit rather than retrieved -- see frameworks/cci.py.
                    extra={"rule_id": rule.get("id", ""), "part": part or "",
                           "ccis": _ccis(rule)},
                )
            )
    return entries


def _ccis(rule) -> list:
    """CCI identifiers cited by one XCCDF Rule."""
    out = []
    for el in rule.iter():
        if el.tag.endswith("ident") and "cci" in (el.get("system") or ""):
            if el.text and el.text.startswith("CCI-"):
                out.append(el.text.strip())
    return out


def _platform_of(filename: str) -> str | None:
    f = filename.lower()
    if "cisco_ios-xe_router" in f:
        return "cisco_iosxe_router"
    if "cisco_ios-xe_switch" in f:
        return "cisco_iosxe_switch"
    if "juniper_srx" in f:
        return "juniper_srx"
    if f.startswith("u_pan_") or "_pan_" in f:
        return "paloalto_panos"
    return None


def load(stig_dir: str | Path) -> Catalog:
    """Load every XCCDF found in the STIG directory, including inside zips."""
    d = Path(stig_dir)
    entries: list[CatalogEntry] = []
    sources: list[str] = []

    for xml in sorted(d.rglob("*.xml")):
        if "xccdf" not in xml.name.lower():
            continue
        entries += _parse_xccdf(xml.read_bytes(), xml.name)
        sources.append(str(xml))

    seen = {Path(s).name for s in sources}
    for z in sorted(d.rglob("*.zip")):
        with zipfile.ZipFile(z) as zf:
            for nm in zf.namelist():
                base = nm.split("/")[-1]
                if not (nm.lower().endswith(".xml") and "xccdf" in nm.lower()):
                    continue
                if base in seen:          # already loaded from the extracted copy
                    continue
                entries += _parse_xccdf(zf.read(nm), base)
                sources.append(f"{z.name}!{base}")
                seen.add(base)

    return Catalog(framework=Framework.DISA_STIG, entries=entries, sources=sources)
