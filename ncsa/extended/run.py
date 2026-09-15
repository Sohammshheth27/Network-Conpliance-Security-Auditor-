"""Run every extended check against one assessed device.

Each domain is isolated: one adapter failing becomes that domain's ERROR, not
an exception that loses the others -- the same rule bulk ingestion follows for
files.
"""
from __future__ import annotations

from .cve import assess_cve
from .model import DomainResult
from .vpn import assess_vpn
from .wireless import assess_wireless

DOMAINS = {
    "vpn": assess_vpn,
    "wireless": assess_wireless,
    "cve": assess_cve,
}


def run_extended(da) -> dict:
    out = {}
    for name, fn in DOMAINS.items():
        try:
            out[name] = fn(da).to_json()
        except Exception as exc:                        # noqa: BLE001
            out[name] = DomainResult(
                name, None,
                f"The {name} adapter failed on this device: "
                f"{type(exc).__name__}: {exc}. This is a defect in the tool.",
                validated_on="n/a").to_json()
            out[name]["error"] = True
    # ATT&CK tags, resolved against the bundle on disk. A missing bundle means
    # no tags, never unresolved ones.
    from ..frameworks.attack import tags_for

    for dom in out.values():
        for f in dom.get("findings", []):
            f["attack"] = tags_for(f["check_id"])
    return {
        "scope": "Extended checks are reported beside the 88-control "
                 "compliance score and never change it.",
        "domains": out,
    }
