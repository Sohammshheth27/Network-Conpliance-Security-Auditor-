"""The remediation catalogue: every step must be runnable where it claims.

A remediation keyed by a misspelt platform is silently never offered -- the
plan just reports "unavailable" -- so the key is checked against the platforms
the packs actually declare.
"""
import glob

import yaml

from ncsa.engine.remediate import ROLLBACK, _IMPACT_FIELD, IMPACT_RESTRICTS_SOURCE
from ncsa.engine.rules import load_rules


def _platforms() -> set[str]:
    out = set()
    for p in glob.glob("packs/*.yaml"):
        if p.endswith(".learned.yaml"):
            continue
        d = yaml.safe_load(open(p, encoding="utf-8")) or {}
        if d.get("platform"):
            out.add(d["platform"])
    return out


def test_every_remediation_targets_a_real_platform():
    known = _platforms() | {"default"}
    allowed_impacts = set(_IMPACT_FIELD) | {IMPACT_RESTRICTS_SOURCE, "none"}
    for c in load_rules("rules"):
        for platform, spec in (c.remediation or {}).items():
            assert platform in known, f"{c.id}: unknown platform {platform!r}"
            assert spec.get("commands"), f"{c.id}/{platform}: no commands"
            assert spec.get("verify"), f"{c.id}/{platform}: no verify command"
            impact = spec.get("management_impact", "none")
            assert impact in allowed_impacts, f"{c.id}/{platform}: {impact!r}"


def test_disabling_a_transport_runs_last():
    """Enable-then-disable: a step that removes a management transport must
    sort after the steps that build its replacement."""
    for c in load_rules("rules"):
        for platform, spec in (c.remediation or {}).items():
            if spec.get("management_impact") in _IMPACT_FIELD:
                assert int(spec.get("phase", 0)) == 40, f"{c.id}/{platform}"


def test_the_firewall_vendors_now_have_remediation():
    have = {pl for c in load_rules("rules") for pl in (c.remediation or {})}
    assert {"cisco_asa", "fortios", "panos"} <= have


def test_asa_gets_its_own_rollback_not_the_ios_wording():
    rb = next(v for k, v in ROLLBACK.items() if "cisco_asa".startswith(k))
    assert "ASA" in rb[1]
