"""The 2-D topology figure.

Validated on the real NSA 3700. The figure is only useful if it is true, so
the tests pin what it shows against the configuration -- and pin the two
honesty properties: it never presents configured structure as live discovery,
and it never publishes a public IP or a site name unless asked to.
"""
import ipaddress
import os
import re
import xml.etree.ElementTree as ET

import pytest

from ncsa.pipeline import assess
from ncsa.topology.map import build_map, render_svg

SW = r"E:\sonicwall config file.txt"
sw_only = pytest.mark.skipif(not os.path.exists(SW), reason="SonicWall sample absent")
def _real_tunnel_names(da) -> set[str]:
    """Read from the device at test time.

    Never written into this file: it is published, and a list of the names
    to check for would itself disclose them.
    """
    from ncsa.extended.vpn import tunnels_from_sonicos

    generic = {"WAN GroupVPN", "WLAN GroupVPN", "VPN ZOne GroupVPN"}
    return {t.name for t in tunnels_from_sonicos(da.document)} - generic


@pytest.fixture(scope="module")
def da():
    return assess(SW, redact=False, assessment_id="TEST-TOPO")


def _zone(m, name):
    return next(z for z in m["zones"] if z["name"] == name)


def _public_ips(text):
    out = set()
    for tok in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        try:
            if ipaddress.ip_address(tok).is_global:
                out.add(tok)
        except ValueError:
            pass
    return out


@sw_only
def test_lan_and_management_subnets_are_drawn(da):
    m = build_map(da, redact=True)
    lan = {i["network"] for i in _zone(m, "LAN")["interfaces"]}
    assert {"10.90.213.0/24", "192.168.5.0/24"} <= lan
    assert _zone(m, "MGMT")["interfaces"][0]["network"] == "192.168.1.0/24"


@sw_only
def test_every_wan_uplink_is_drawn(da):
    wan = _zone(build_map(da, redact=False), "WAN")
    assert len(wan["interfaces"]) == 7
    assert wan["trust"] == "untrusted"


@sw_only
def test_the_wlan_zone_is_shown_empty_not_live(da):
    """Policy defines WLAN; no access point and no interface populate it."""
    wlan = _zone(build_map(da), "WLAN")
    assert wlan["populated"] is False
    assert wlan["access_points"] == 0
    assert "no access point" in wlan["note"]


@sw_only
def test_the_wlan_to_dmz_any_any_flow_is_drawn(da):
    m = build_map(da, redact=False)
    f = next(f for f in m["flows"] if (f["from"], f["to"]) == ("WLAN", "DMZ"))
    assert any("#217" in r for r in f["any_any"])


@sw_only
def test_only_any_any_flows_into_more_trusted_zones_are_drawn(da):
    """SonicWall auto-creates an any/any default for most zone pairs.

    Drawing them all buried WLAN -> DMZ under a dozen normal outbound defaults.
    Only flows running UP the trust scale are drawn; the rest are counted.
    """
    m = build_map(da, redact=False)
    wlan_dmz = next(f for f in m["flows"] if (f["from"], f["to"]) == ("WLAN", "DMZ"))
    assert wlan_dmz["escalates"] and wlan_dmz["latent"]
    svg = render_svg(m)
    assert "WLAN → DMZ: any/any, latent" in svg
    assert not re.search(r"(?<!W)LAN → WAN: any/any", svg), (
        "the normal outbound default must not be drawn as a risk")
    assert "further any/any flow(s)" in svg, "undrawn flows must be counted"


@sw_only
def test_the_vpn_zone_is_live_when_tunnels_feed_it(da):
    """No interface sits in VPN, but 11 enabled tunnels deliver into it.

    Marking VPN -> LAN "latent" would understate a live exposure; the custom
    `VPN ZOne` and MPLS zones, which nothing feeds, stay latent.
    """
    m = build_map(da, redact=False)
    vpn = _zone(m, "VPN")
    assert vpn["populated"] is True and "11 enabled" in vpn["note"]
    flow = next(f for f in m["flows"] if (f["from"], f["to"]) == ("VPN", "LAN"))
    assert flow["latent"] is False
    assert _zone(m, "MPLS")["populated"] is False


@sw_only
def test_each_uplink_gets_one_pseudonym(da):
    svg = render_svg(build_map(da))
    assert not re.search(r"public-IP-\d+/", svg), "a redacted subnet was numbered separately"
    assert "public-IP-7" in svg and "public-IP-8" not in svg


@sw_only
def test_the_vendor_name_is_spelled_correctly(da):
    assert build_map(da)["device"]["name"] == "SonicWall NSA 3700"


@sw_only
def test_every_tunnel_is_drawn_with_its_state(da):
    m = build_map(da, redact=False)
    assert len(m["tunnels"]) == 15
    assert sum(1 for t in m["tunnels"] if t["enabled"]) == 11


@sw_only
def test_redaction_is_the_default_and_is_complete(da):
    m = build_map(da)
    svg = render_svg(m)
    assert m["redacted"] is True
    assert not _public_ips(svg), "a public IP reached the redacted figure"
    names = _real_tunnel_names(da)
    assert names, "expected site tunnels on this device"
    leaked = sorted(n for n in names if n in svg)
    assert not leaked, f"{len(leaked)} site name(s) reached the redacted figure"
    assert da.identity.hostname not in svg, "the hostname reached the redacted figure"
    # Private addressing is kept: it is the useful part and identifies nobody.
    assert "10.90.213.0/24" in svg


@sw_only
def test_unredacted_shows_the_real_values_when_asked(da):
    svg = render_svg(build_map(da, redact=False))
    assert _public_ips(svg)
    assert da.identity.hostname in svg


@sw_only
def test_the_figure_says_it_is_not_live(da):
    svg = render_svg(build_map(da))
    assert "Derived from configuration" in svg and "not live" in svg


@sw_only
def test_the_svg_is_well_formed(da):
    ET.fromstring(render_svg(build_map(da, redact=False)))


def test_configuration_text_is_escaped():
    """Names come from the device file, which is untrusted input."""
    m = {"device": {"name": "<script>alert(1)</script>", "model": "x", "os": "", "version": ""},
         "zones": [{"name": "A&B<", "trust": "unknown", "populated": True, "note": "",
                    "access_points": None,
                    "interfaces": [{"name": "X0\"><img>", "address": "", "network": "10.0.0.0/8",
                                    "enabled": True}]}],
         "tunnels": [], "flows": [],
         "source": {"file": "f", "sha256": "0", "derived_from": "configuration",
                    "generated_at": "now"},
         "redacted": False}
    svg = render_svg(m)
    ET.fromstring(svg)
    assert "<script>" not in svg and "<img>" not in svg


def test_a_router_without_a_policy_graph_still_draws():
    da = assess("samples/cisco/edge-rtr-01.cfg", redact=False, assessment_id="TEST-TOPO-RTR")
    m = build_map(da)
    assert m["zones"], "interfaces must still be drawn without zones"
    ET.fromstring(render_svg(m))
