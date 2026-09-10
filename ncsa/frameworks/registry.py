"""Load every framework, and report coverage honestly.

Plan 6.6: load 100% of every framework, automate a subset, and say plainly
which is which. A tool claiming 100% automation of ISO 27001 would be lying --
half of ISO 27001 is about policies and people.
"""
from pathlib import Path

from pydantic import BaseModel, Field

from . import ai_security, cis, derived, iso, nist, nist_171, pci, stig
from .ai_security import AiSecurityKB
from .models import Automatability, Catalog, Framework

DEFAULT_ROOT = Path(r"E:\NCSA\reference")

PATHS = {
    "nist": "nist/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
    "stig": "stig_xccdf",
    "cis": "cis_benchmarks",
    "iso": "iso/sp800-53r5-to-iso27001-2022-OLIR.xlsx",
    "atlas": "ai_security/stix-atlas.json",
    "nist171": "nist/nist.gov/SP800-171/rev3/json/NIST_SP800-171_rev3_catalog.json",
    "cmmc": "nist/nist.gov/SP800-171/rev2/json/NIST_SP-800-171_rev2_catalog.json",
    "pci": "pci_dss/PCI-DSS-v4_0_1-Requirements.pdf",
    "nerc": "nerc_cip/nerc_cip_controls.json",
}


class FrameworkRegistry(BaseModel):
    """Every framework, loaded. The single source the rule engine reads."""

    catalogs: dict[Framework, Catalog] = Field(default_factory=dict)
    nist_to_iso: dict[str, list[str]] = Field(default_factory=dict)
    #: 800-53 id -> 800-171 requirement ids, extracted from NIST's own
    #: catalogue. Lets a rule that already cites 800-53 reach 800-171 free.
    nist_to_171: dict[str, list[str]] = Field(default_factory=dict)
    ai_kb: AiSecurityKB | None = None

    # ------------------------------------------------------------------ query
    def iso_clauses_for(self, nist_ids: list[str]) -> list[str]:
        """Plan 6.2's ISO shortcut: NIST ID -> official crosswalk -> ISO clause.

        Control enhancements inherit from their base control when the crosswalk
        has no direct entry. NIST maps 220 IDs, only 48 of them enhancements, so
        a rule citing AC-17(2) would otherwise return no ISO clauses at all --
        a hole in the "NIST and ISO are complete for every vendor" claim in 6.4.
        An enhancement refines its base control, so the base control's ISO
        clauses are the correct answer, not an approximation.
        """
        import re

        out: list[str] = []
        for nid in nist_ids:
            key = nid.upper()
            clauses = self.nist_to_iso.get(key)
            if clauses is None:
                base = re.sub(r"[.(]\d+\)?$", "", key)     # AC-17.2 / AC-17(2) -> AC-17
                clauses = self.nist_to_iso.get(base, [])
            for clause in clauses:
                if clause not in out:
                    out.append(clause)
        return sorted(out, key=lambda c: (c.startswith("A."), c))

    def nist171_for(self, nist_ids: list[str]) -> list[str]:
        """800-53 ids -> 800-171 requirement ids, via NIST's own crosswalk.

        Enhancements inherit from their base control for the same reason they
        do in `iso_clauses_for`: a rule citing AC-17(2) should not silently
        return nothing just because the crosswalk indexes AC-17.
        """
        import re

        out: list[str] = []
        for nid in nist_ids:
            key = nid.upper()
            reqs = self.nist_to_171.get(key)
            if reqs is None:
                base = re.sub(r"[.(]\d+\)?$", "", key)
                reqs = self.nist_to_171.get(base, [])
            for r in reqs:
                if r not in out:
                    out.append(r)
        return sorted(out)

    def unpopulated(self) -> dict[str, str]:
        """Frameworks that loaded zero entries, and why.

        A zero with no explanation is indistinguishable from a bug.
        """
        out = {}
        for fw, cat in self.catalogs.items():
            if len(cat) == 0 and fw in derived.UNPOPULATED_REASONS:
                out[fw.value] = derived.UNPOPULATED_REASONS[fw]
        return out

    def iso_coverage(self, nist_ids: list[str]) -> dict:
        """Which NIST ids resolved directly, by inheritance, or not at all."""
        import re

        direct, inherited, missing = [], [], []
        for nid in nist_ids:
            key = nid.upper()
            if key in self.nist_to_iso:
                direct.append(key)
            elif re.sub(r"[.(]\d+\)?$", "", key) in self.nist_to_iso:
                inherited.append(key)
            else:
                missing.append(key)
        return {"direct": direct, "inherited": inherited, "missing": missing}

    def total_loaded(self) -> int:
        return sum(len(c) for c in self.catalogs.values())

    def coverage_report(self) -> str:
        """The honest picture -- plan 6.6 and 14.2."""
        lines = ["FRAMEWORK COVERAGE", ""]
        lines.append(f"{'Framework':<22}{'Loaded':>8}{'Config':>9}{'Procedural':>12}{'Untriaged':>11}")
        lines.append("-" * 62)
        for fw, cat in self.catalogs.items():
            c = cat.counts_by_automatability()
            lines.append(
                f"{fw.value:<22}{len(cat):>8}{c['config']:>9}"
                f"{c['procedural']:>12}{c['unknown']:>11}"
            )
        lines.append("-" * 62)
        lines.append(f"{'TOTAL':<22}{self.total_loaded():>8}")
        lines.append("")
        lines.append("'Config' = decidable from a configuration file, therefore automatable.")
        lines.append("'Procedural' = policy/people/physical; reports as MANUAL_REVIEW by design.")
        return "\n".join(lines)


CACHE_PATH = Path(r"E:\NCSA\reference\.framework_cache.json")


def load_all(
    root: str | Path = DEFAULT_ROOT,
    *,
    cis_latest_only: bool = True,
    use_cache: bool = True,
    rebuild: bool = False,
) -> FrameworkRegistry:
    """Load every framework, using a JSON cache when one is current.

    Parsing ~30 CIS PDFs takes ~10 minutes, which is far too slow to sit in
    front of every scan or test run. The cache is keyed on the source files'
    (path, size, mtime), so editing or re-downloading any source invalidates it
    automatically -- no manual cache-busting, and no risk of a stale catalogue
    silently backing a compliance verdict.
    """
    root = Path(root)

    if use_cache and not rebuild and CACHE_PATH.exists():
        cached = _load_cache(root)
        if cached is not None:
            return cached

    reg = _load_fresh(root, cis_latest_only)
    if use_cache:
        _write_cache(root, reg)
    return reg


def _fingerprint(root: Path) -> list[list]:
    """(relative path, size, mtime) for every framework source file."""
    fp: list[list] = []
    for pat in ("nist/**/*catalog.json", "stig_xccdf/**/*.xml", "stig_xccdf/*.zip",
                "cis_benchmarks/**/*.pdf", "iso/*.xlsx", "ai_security/*.json",
                "nist/**/SP800-171/**/*.json", "pci_dss/*.pdf",
                "nerc_cip/*.json"):
        for f in sorted(root.glob(pat)):
            st = f.stat()
            fp.append([str(f.relative_to(root)), st.st_size, int(st.st_mtime)])

    # Loader code is part of the fingerprint too. Without this, editing a
    # parser leaves a stale catalogue in place and the next scan silently
    # evaluates against yesterday's interpretation of the same files.
    pkg = Path(__file__).parent
    for f in sorted(pkg.glob("*.py")):
        st = f.stat()
        fp.append(["code/" + f.name, st.st_size, int(st.st_mtime)])
    return fp


def _write_cache(root: Path, reg: FrameworkRegistry) -> None:
    import json

    payload = {
        "fingerprint": _fingerprint(root),
        "registry": reg.model_dump(mode="json"),
    }
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with CACHE_PATH.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh)


def _load_cache(root: Path) -> "FrameworkRegistry | None":
    import json

    try:
        with CACHE_PATH.open(encoding="utf-8") as fh:
            payload = json.load(fh)
    except Exception:
        return None
    if payload.get("fingerprint") != _fingerprint(root):
        return None          # a source changed -- reparse rather than trust it
    try:
        return FrameworkRegistry.model_validate(payload["registry"])
    except Exception:
        return None


def _load_fresh(root: Path, cis_latest_only: bool) -> FrameworkRegistry:
    reg = FrameworkRegistry()

    nist_path = root / PATHS["nist"]
    if nist_path.exists():
        reg.catalogs[Framework.NIST_800_53] = nist.load(nist_path)

    stig_dir = root / PATHS["stig"]
    if stig_dir.exists():
        reg.catalogs[Framework.DISA_STIG] = stig.load(stig_dir)

    cis_dir = root / PATHS["cis"]
    if cis_dir.exists():
        reg.catalogs[Framework.CIS] = cis.load(cis_dir, latest_only=cis_latest_only)

    iso_path = root / PATHS["iso"]
    if iso_path.exists():
        cat, mapping = iso.load(iso_path)
        reg.catalogs[Framework.ISO_27001] = cat
        reg.nist_to_iso = mapping

    n171_path = root / PATHS["nist171"]
    if n171_path.exists():
        cat, mapping = nist_171.load(n171_path)
        reg.catalogs[Framework.NIST_800_171] = cat
        reg.nist_to_171 = mapping

    # PCI loads its twelve requirements even without the source document, so
    # the framework stays citable at requirement level either way.
    reg.catalogs[Framework.PCI_DSS] = pci.load(root / PATHS["pci"])

    # These two stay empty unless their source is present. `unpopulated()`
    # reports why, rather than leaving a bare zero to be misread.
    reg.catalogs[Framework.CMMC] = derived.load_cmmc(root / PATHS["cmmc"])
    reg.catalogs[Framework.NERC_CIP] = derived.load_nerc(root / PATHS["nerc"])

    atlas_path = root / PATHS["atlas"]
    if atlas_path.exists():
        reg.ai_kb = ai_security.load_atlas(atlas_path)

    return reg
