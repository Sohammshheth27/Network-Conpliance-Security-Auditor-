"""IPsec VPN checks, validated against the real NSA 3700's 15 tunnels.

The checks judge only settings whose encoding is self-evident (on/off switches
and lifetimes in seconds). The algorithm codes are vendor-private and stay
UNKNOWN -- and one test below exists purely to stop a future change from
"helpfully" guessing them.

The expectations are re-derived from the raw export independently of the
reader, so a reader bug cannot make its own test pass.
"""
import os
import re
from urllib.parse import unquote_plus

import pytest

from ncsa.extended.model import ExtendedFinding
from ncsa.extended.vpn import VpnTunnel, assess_vpn, check_tunnel
from ncsa.pipeline import assess
from ncsa.schema.evidence import EvidenceRef

SW = r"E:\sonicwall config file.txt"
sw_only = pytest.mark.skipif(not os.path.exists(SW), reason="SonicWall sample absent")


@pytest.fixture(scope="module")
def sw():
    da = assess(SW, redact=False, assessment_id="TEST-VPN")
    return da, assess_vpn(da)


def _raw_settings() -> list[str]:
    return open(SW, encoding="utf-8", errors="replace").read().split("&")


def _raw_by_index(prefix: str) -> dict[int, str]:
    """`prefix_N=value` straight from the file, bypassing the reader."""
    out = {}
    for tok in _raw_settings():
        k, _, v = tok.partition("=")
        m = re.match(rf"^{prefix}_(\d+)$", unquote_plus(k).strip())
        if m:
            out[int(m.group(1))] = unquote_plus(v).strip()
    return out


# ------------------------------------------------------------ the real device

@sw_only
def test_every_tunnel_in_the_file_is_found(sw):
    _da, res = sw
    names = {v for v in _raw_by_index("ipsecName").values() if v}
    assert {t["name"] for t in res.inventory} == names
    assert len(names) == 15


@sw_only
def test_enabled_state_matches_the_raw_file(sw):
    """`ipsecSaDisabled=on` switches a tunnel off."""
    _da, res = sw
    names = _raw_by_index("ipsecName")
    disabled = _raw_by_index("ipsecSaDisabled")
    expected = {names[i]: disabled[i] == "off" for i in names if names[i]}
    got = {t["name"]: t["enabled"] for t in res.inventory}
    assert got == expected


@sw_only
def test_pfs_failures_are_the_tunnels_the_file_says(sw):
    _da, res = sw
    names = _raw_by_index("ipsecName")
    pfs = _raw_by_index("ipsecPFSEnablePFS")
    disabled = _raw_by_index("ipsecSaDisabled")
    expected = sorted(names[i] for i in names
                      if names[i] and disabled[i] == "off" and pfs[i] == "off")
    got = sorted(f.scope for f in res.findings
                 if f.check_id == "NCSA-X-VPN-001" and f.state == "FAIL")
    assert got == expected
    # Tunnel names are not asserted literally: they are a real customer's
    # site names and this file is published.
    assert len(got) >= 2


@sw_only
def test_anti_replay_is_read_with_its_inverted_polarity(sw):
    """`ipsecAntiReplayDisabled=on` means anti-replay is OFF.

    A reader that took the value at face value would pass exactly the tunnels
    that should fail.
    """
    _da, res = sw
    names = _raw_by_index("ipsecName")
    ar_disabled = _raw_by_index("ipsecAntiReplayDisabled")
    sa_disabled = _raw_by_index("ipsecSaDisabled")
    expected = sorted(names[i] for i in names
                      if names[i] and sa_disabled[i] == "off"
                      and ar_disabled[i] == "on")
    got = sorted(f.scope for f in res.findings
                 if f.check_id == "NCSA-X-VPN-002" and f.state == "FAIL")
    assert got == expected


@sw_only
def test_every_cited_setting_is_the_one_quoted(sw):
    """`setting[n]` must hold the text the finding quotes."""
    _da, res = sw
    settings = _raw_settings()
    for f in res.findings:
        for e in f.evidence:
            n = int(e.record_id[len("setting["):-1])
            key = unquote_plus(settings[n - 1].partition("=")[0]).strip()
            assert e.raw.startswith(key + "="), (
                f"{f.check_id} [{f.scope}] cites setting {n} as {e.raw!r}, "
                f"which holds {key!r}")


@sw_only
def test_disabled_tunnels_are_not_applicable_with_a_reason(sw):
    _da, res = sw
    off = {t["name"] for t in res.inventory if t["enabled"] is False}
    assert off, "expected disabled tunnels on this device"
    for f in res.findings:
        if f.scope in off:
            assert f.state == "NOT_APPLICABLE"
            assert "disabled" in f.reason


@sw_only
def test_algorithm_strength_is_never_guessed(sw):
    """The guard against the most tempting mistake in this module.

    SonicOS stores algorithms as private codes (250 is in IANA's private-use
    range). No verified decoding is held, so this check must never PASS or
    FAIL -- and must show the codes and how to calibrate them.
    """
    _da, res = sw
    alg = [f for f in res.findings if f.check_id == "NCSA-X-VPN-005"]
    assert alg
    for f in alg:
        assert f.state in ("UNKNOWN", "NOT_APPLICABLE"), (
            f"{f.scope}: algorithm strength was decided ({f.state}) from "
            "undecoded vendor codes")
        if f.state == "UNKNOWN":
            assert "Proposals" in f.reason, "say how to calibrate"
            assert f.observed, "show the raw codes"


@sw_only
def test_the_compliance_result_is_untouched(sw):
    """Extended checks sit beside the score, never inside it.

    Running them must change neither the score, the coverage, nor the parse
    accounting of an assessment already reported.
    """
    da = assess(SW, redact=False, assessment_id="TEST-VPN-ISO")
    cov, records = dict(da.coverage()), dict(da.records)
    consumed_before = set(da.document._consumed)

    assess_vpn(da)

    assert da.coverage() == cov
    assert da.coverage()["score_pct"] == 36.2
    assert da.coverage()["assessed_pct"] == 53.4
    assert da.records == records
    assert da.document._consumed == consumed_before, (
        "the VPN adapter marked settings consumed, which changes the parse "
        "accounting of the compliance assessment")


# ---------------------------------------------------------------- unit level

def _ev(raw="x=1"):
    return EvidenceRef(file="t", line=1, raw=raw)


def _tunnel(**kw):
    base = dict(name="t1", enabled=True, pfs=True, anti_replay=True,
                ike_lifetime_s=28800, ipsec_lifetime_s=28800,
                management={"ssh": False}, algorithms_raw={"a": "1"})
    base.update(kw)
    t = VpnTunnel(**base)
    t.evidence = {k: _ev(f"{k}=v") for k in
                  ("enabled", "pfs", "anti_replay", "ike_lifetime_s",
                   "ipsec_lifetime_s", "management.ssh", "alg.a")}
    return t


def _state(findings, cid):
    return next(f.state for f in findings if f.check_id == cid)


def test_lifetime_bounds():
    ok = check_tunnel(_tunnel())
    assert _state(ok, "NCSA-X-VPN-003") == "PASS"
    long_ike = check_tunnel(_tunnel(ike_lifetime_s=86_401))
    assert _state(long_ike, "NCSA-X-VPN-003") == "FAIL"
    unbounded = check_tunnel(_tunnel(ipsec_lifetime_s=0))
    assert _state(unbounded, "NCSA-X-VPN-003") == "FAIL", "0 means no limit"


def test_management_over_a_tunnel_goes_to_a_person_not_a_verdict():
    """Hub-and-spoke management is usually intended; only the owner knows."""
    t = _tunnel(management={"ssh": True})
    assert _state(check_tunnel(t), "NCSA-X-VPN-004") == "MANUAL_REVIEW"


def test_missing_settings_are_unknown_not_pass():
    t = _tunnel(pfs=None, anti_replay=None)
    out = check_tunnel(t)
    assert _state(out, "NCSA-X-VPN-001") == "UNKNOWN"
    assert _state(out, "NCSA-X-VPN-002") == "UNKNOWN"


def test_a_failure_without_evidence_is_refused():
    with pytest.raises(ValueError, match="must carry evidence"):
        ExtendedFinding("X", "t", "vpn", "FAIL", "high", "s", "r")


def test_an_unsupported_platform_is_a_gap_in_the_tool_not_the_device():
    class _Id:
        platform = "cisco_asa"

    class _Da:
        identity = _Id()
        document = None

    res = assess_vpn(_Da())
    assert res.present is None
    assert "gap in the tool" in res.summary


@sw_only
def test_every_nist_id_cited_exists_in_the_catalogue(sw):
    from ncsa.frameworks.models import Framework
    from ncsa.frameworks.registry import load_all

    cat = load_all().catalogs[Framework.NIST_800_53]
    _da, res = sw
    cited = {i for f in res.findings for i in f.nist_800_53}
    # The catalogue writes enhancements as SC-8.1; the rules write SC-8(1).
    missing = sorted(i for i in cited
                     if cat.by_id(re.sub(r"\((\d+)\)", r".\1", i)) is None)
    assert not missing, f"cited NIST ids not in the catalogue: {missing}"
