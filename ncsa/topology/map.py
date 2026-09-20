"""A 2-D topology figure of one device: zones, LANs, WLANs, uplinks, tunnels.

WHAT THE FIGURE IS
------------------
A picture of what the CONFIGURATION says the network looks like: which zones
exist, which interfaces and subnets sit in each, where the internet enters,
which VPN sites hang off the device, whether any access point is provisioned
for the wireless zone, and which zone-to-zone flows the policy opens with an
any/any rule.

WHAT IT IS NOT
--------------
It is not live discovery. A configuration file does not say which hosts are
connected right now -- that needs ARP/DHCP tables, LLDP or the vendor API.
Every figure says "derived from configuration" in its footer, because a map
that looks live and is not is the kind of overstatement this project avoids.

Zones the policy defines but no interface populates are drawn DASHED and
labelled as such. On the reference NSA 3700 that is WLAN: the policy opens
WLAN -> DMZ any/any, yet nothing sits in the zone, which is exactly the
difference between a latent and a live exposure.

REDACTION IS ON BY DEFAULT
--------------------------
A WAN uplink's address is a real public IP and a tunnel's name is usually a
customer's site name. With `redact=True` (the default) public addresses become
`public-IP-n`, tunnel names `Tunnel n`, peers `peer-n`, and the hostname is
replaced by the model. Private (RFC 1918) addressing is kept: it is what makes
the figure useful and it identifies nobody.
"""
from __future__ import annotations

import ipaddress
import math
from datetime import datetime, timezone
from xml.sax.saxutils import escape

VENDOR_NAMES = {"sonicwall": "SonicWall", "cisco": "Cisco", "juniper": "Juniper",
                "paloalto": "Palo Alto", "fortinet": "Fortinet", "aws": "AWS",
                "azure": "Azure", "gcp": "Google Cloud", "arista": "Arista",
                "aruba": "Aruba"}
#: Trust order. An any/any allow is drawn only when it runs UP this scale.
TRUST_RANK = {"untrusted": 0, "unknown": 1, "semi": 2, "trusted": 3}

UNTRUSTED_NAMES = {"wan", "untrust", "internet", "public", "outside"}
TRUSTED_NAMES = {"lan", "trust", "inside", "mgmt", "management"}
SEMI_NAMES = {"dmz"}

# Zones are placed around the device in this order, starting at the top.
_ORDER = ["wan", "vpn", "sslvpn", "dmz", "wlan", "lan", "mgmt", "mpls", "multicast"]


# --------------------------------------------------------------------- model

def _is_public(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr.split("/")[0])
    except ValueError:
        return False
    return ip.is_global


class _Redactor:
    """Stable pseudonyms, so the same address reads the same everywhere."""

    def __init__(self, on: bool):
        self.on = on
        self._ip: dict = {}
        self._peer: dict = {}
        self._tun: dict = {}

    def ip(self, v: str) -> str:
        if not self.on or not v or not _is_public(v):
            return v
        base = v.split("/")[0]
        if base not in self._ip:
            self._ip[base] = f"public-IP-{len(self._ip) + 1}"
        return self._ip[base] + ("/" + v.split("/")[1] if "/" in v else "")

    def net(self, v: str) -> str:
        # A public subnet names the ISP block -- as identifying as the address.
        return self.ip(v) if v and _is_public(v.split("/")[0]) else v

    def peer(self, v: str) -> str:
        if not self.on or not v:
            return v
        self._peer.setdefault(v, f"peer-{len(self._peer) + 1}")
        return self._peer[v]

    def tunnel(self, v: str) -> str:
        if not self.on:
            return v
        self._tun.setdefault(v, f"Tunnel {len(self._tun) + 1}")
        return self._tun[v]


def _trust(zone: str, graph) -> str:
    z = zone.lower()
    if graph is not None and zone in getattr(graph, "untrusted_zones", set()):
        return "untrusted"
    if z in UNTRUSTED_NAMES or z == "wlan":
        return "untrusted"
    if z in SEMI_NAMES:
        return "semi"
    if z in TRUSTED_NAMES:
        return "trusted"
    return "unknown"


def build_map(da, *, redact: bool = True) -> dict:
    """Everything the figure shows, as data. Rendering is separate."""
    from ..extended.vpn import tunnels_from_sonicos
    from .interfaces import extract

    r = _Redactor(redact)
    i = da.identity
    graph = getattr(da, "graph", None)

    try:
        ifaces = extract(da)
    except Exception:                                   # noqa: BLE001
        ifaces = []

    zones: dict = {}

    def zone(name: str) -> dict:
        key = name or "(no zone)"
        if key not in zones:
            zones[key] = {"name": key, "trust": _trust(key, graph) if name else "unknown",
                          "interfaces": [], "populated": False,
                          "access_points": None, "note": ""}
        return zones[key]

    for itf in ifaces:
        j = itf.to_json()
        z = zone(j.get("zone") or "")
        addr = j.get("address") or ""
        net = j.get("network") or ""
        if redact and addr and _is_public(addr):
            # An uplink is named by its own pseudonym. Redacting its subnet too
            # numbered the same fact twice: public-IP-2, -4, -6...
            net = r.ip(addr)
        else:
            net = r.net(net)
        z["interfaces"].append({"name": j["name"], "address": r.ip(addr),
                                "network": net,
                                "enabled": bool(j.get("enabled", True))})
        z["populated"] = True

    # Zones the POLICY defines, even when no interface sits in them.
    if graph is not None:
        for rule in graph.rules:
            for zn in list(rule.source_zones) + list(rule.destination_zones):
                if zn:
                    zone(zn)

    platform = (i.platform or "").lower()
    doc = getattr(da, "document", None)

    # Wireless: access-point provisioning, where the platform states it.
    if platform.startswith("sonicwall") and doc is not None and hasattr(doc, "values"):
        from ..extended.wireless import sonicos_provisioning
        provisioned, reason, _ev = sonicos_provisioning(da)
        for zn, z in zones.items():
            if zn.upper() == "WLAN":
                z["access_points"] = 0 if not provisioned else None
                z["note"] = ("no access point provisioned" if not provisioned
                             else "access points provisioned")
                z["populated"] = z["populated"] or provisioned

    for z in zones.values():
        if not z["populated"] and not z["note"]:
            z["note"] = "defined in policy; no interface assigned"

    # VPN tunnels.
    tunnels = []
    if platform.startswith("sonicwall") and doc is not None and hasattr(doc, "values"):
        for t in tunnels_from_sonicos(doc):
            tunnels.append({"name": r.tunnel(t.name), "enabled": t.enabled,
                            "peer": r.peer(t.peer) if t.peer else None})

    # SonicOS delivers decrypted site-to-site traffic into the VPN zone. With
    # enabled tunnels that zone is a live source even though no interface sits
    # in it -- labelling its flows "latent" would understate a real exposure.
    live_tunnels = sum(1 for t in tunnels if t["enabled"] is not False)
    if live_tunnels:
        for zn, z in zones.items():
            if zn.upper() == "VPN":
                z["populated"] = True
                z["note"] = f"fed by {live_tunnels} enabled VPN tunnel(s)"

    # Zone-to-zone flows the policy opens.
    flows: dict = {}
    if graph is not None:
        for rule in graph.rules:
            if not rule.enabled or rule.action.lower() not in ("allow", "accept", "permit"):
                continue
            wide = (all(s.lower() in ("any", "all") for s in rule.source or ["any"])
                    and all(d.lower() in ("any", "all") for d in rule.destination or ["any"])
                    and all(s.lower() in ("any", "all") for s in rule.services or ["any"]))
            for sz in rule.source_zones or []:
                for dz in rule.destination_zones or []:
                    if not sz or not dz or sz == dz:
                        continue
                    f = flows.setdefault((sz, dz), {"from": sz, "to": dz,
                                                    "rules": 0, "any_any": []})
                    f["rules"] += 1
                    if wide:
                        f["any_any"].append(rule.name or rule.id)

    # Which flows run UP the trust scale, and which start from an empty zone.
    for f in flows.values():
        zf, zt = zones.get(f["from"]), zones.get(f["to"])
        f["escalates"] = bool(zf and zt and
                              TRUST_RANK[zf["trust"]] < TRUST_RANK[zt["trust"]])
        f["latent"] = bool(zf and not zf["populated"])

    name = i.hostname or i.source_file
    if redact:
        vendor = VENDOR_NAMES.get((i.vendor or "").lower(), (i.vendor or "").capitalize())
        name = " ".join(x for x in (vendor, i.model or "") if x) or "device"

    return {
        "device": {"name": name, "vendor": i.vendor, "model": i.model,
                   "os": i.os, "version": i.version},
        "zones": sorted(zones.values(), key=_zone_rank),
        "tunnels": tunnels,
        "flows": sorted(flows.values(), key=lambda f: (-len(f["any_any"]), -f["rules"])),
        "source": {"file": "redacted" if redact else i.source_file,
                   "sha256": i.sha256[:16] if i.sha256 else "",
                   "derived_from": "configuration",
                   "generated_at": datetime.now(timezone.utc).strftime("%d %b %Y %H:%M UTC")},
        "redacted": redact,
    }


def _zone_rank(z: dict):
    n = z["name"].lower()
    for idx, key in enumerate(_ORDER):
        if n == key or n.startswith(key):
            return (idx, n)
    return (len(_ORDER), n)


# -------------------------------------------------------------------- render

# The figure is read inside a light console and printed into a light report,
# so it is drawn light. Each trust level is a pale fill with a saturated stroke
# of the same hue: the colour still carries the meaning at a glance, and the
# labels inside the box stay legible, which they were not when a near-white
# label sat on a near-white page.
PALETTE = {
    "untrusted": ("#fff1f2", "#be123c"),   # rose
    "semi": ("#fffbeb", "#b45309"),        # amber
    "trusted": ("#ecfdf5", "#047857"),     # emerald
    "unknown": ("#f0f3f8", "#476788"),     # pebble / slate
}
BG, INK, MUTED, DEVICE = "#ffffff", "#0b3558", "#476788", "#006bff"
HAIRLINE, CANVAS, PANEL = "#d4e0ed", "#f8f9fb", "#f0f3f8"
FLOW = "#be123c"          # an any/any allow into a more trusted zone
IDLE = "#a6bbd1"          # defined in policy, nothing assigned


def _t(x, y, s, size=16, color=INK, weight="normal", anchor="start", family="Segoe UI, Arial, sans-serif"):
    return (f'<text x="{x:.0f}" y="{y:.0f}" font-family="{family}" font-size="{size}" '
            f'fill="{color}" font-weight="{weight}" text-anchor="{anchor}">{escape(str(s))}</text>')


def render_svg(m: dict, width: int = 2000, height: int = 1300) -> str:
    """Deterministic radial layout: device in the middle, zones around it."""
    # The VPN site list gets a column of its own, clear of the zone ring.
    side = 520 if m["tunnels"] else 0
    cx, cy = (width - side) / 2, height / 2 - 20
    zones = m["zones"]
    n = max(len(zones), 1)
    rx, ry = (width - side) * 0.40, height * 0.35
    boxes = {}
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
           f'viewBox="0 0 {width} {height}">',
           f'<rect width="{width}" height="{height}" fill="{BG}"/>',
           '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" '
           'markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
           '<path d="M0,0 L10,5 L0,10 z" fill="#be123c"/></marker></defs>']

    # Zone positions around an ellipse, first zone at the top.
    for k, z in enumerate(zones):
        a = -math.pi / 2 + 2 * math.pi * k / n
        zx, zy = cx + rx * math.cos(a), cy + ry * math.sin(a)
        lines = len(z["interfaces"][:8]) + 2
        w, h = 330, 58 + 23 * lines
        boxes[z["name"]] = (zx - w / 2, zy - h / 2, w, h, zx, zy)

    # Device-to-zone links first, so boxes draw over them.
    for z in zones:
        x, y, w, h, zx, zy = boxes[z["name"]]
        dash = "" if z["populated"] else ' stroke-dasharray="7 6"'
        col = PALETTE[z["trust"]][1] if z["populated"] else IDLE
        out.append(f'<line x1="{cx:.0f}" y1="{cy:.0f}" x2="{zx:.0f}" y2="{zy:.0f}" '
                   f'stroke="{col}" stroke-width="2" opacity="0.7"{dash}/>')

    # Only the flows that matter are drawn: an any/any allow from a LESS
    # trusted zone into a more trusted one. Drawing every auto-generated
    # default rule (LAN -> WAN is the normal outbound direction) buried the one
    # arrow worth seeing under a dozen that are not.
    drawn = [f for f in m["flows"] if f["any_any"] and f.get("escalates")
             and f["from"] in boxes and f["to"] in boxes][:8]
    hidden = sum(1 for f in m["flows"] if f["any_any"]) - len(drawn)
    labels: list = []
    for f in drawn:
        _, _, _, _, x1, y1 = boxes[f["from"]]
        _, _, _, _, x2, y2 = boxes[f["to"]]
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2
        dx, dy = mx - cx, my - cy
        d = math.hypot(dx, dy)
        if d < 140:
            # Zones on opposite sides: bowing away from the centre is
            # undefined and the arrow ran straight through the device. Bow
            # perpendicular to the chord instead.
            px, py = -(y2 - y1), (x2 - x1)
            pl = math.hypot(px, py) or 1
            qx, qy = mx + px / pl * 400, my + py / pl * 400
        else:
            qx, qy = mx + dx / d * 230, my + dy / d * 230
        dash = ' stroke-dasharray="9 7"' if f.get("latent") else ""
        out.append(f'<path d="M{x1:.0f},{y1:.0f} Q{qx:.0f},{qy:.0f} {x2:.0f},{y2:.0f}" '
                   f'fill="none" stroke="{FLOW}" stroke-width="3"{dash} '
                   f'marker-end="url(#arrow)" opacity="0.9"/>')
        lx, ly = (x1 + 2 * qx + x2) / 4, (y1 + 2 * qy + y2) / 4
        n_r = len(f["any_any"])
        label = (f'{f["from"]} → {f["to"]}: any/any'
                 + (", latent" if f.get("latent") else "")
                 + f' ({n_r} rule{"s" if n_r > 1 else ""})')
        # Labels are collected and drawn LAST: drawn here, the zone boxes
        # painted over them and hid the most important one (WLAN -> DMZ).
        labels.append(f'<rect x="{lx - 190:.0f}" y="{ly - 17:.0f}" width="380" height="30" rx="7" '
                      f'fill="{BG}" stroke="{FLOW}" stroke-width="1"/>')
        labels.append(_t(lx, ly + 3, label, 15, FLOW, "bold", "middle"))

    # Device.
    dw, dh = 380, 120
    out.append(f'<rect x="{cx - dw / 2:.0f}" y="{cy - dh / 2:.0f}" width="{dw}" height="{dh}" '
               f'rx="14" fill="{PANEL}" stroke="{DEVICE}" stroke-width="3"/>')
    dev = m["device"]
    out.append(_t(cx, cy - 22, dev["name"], 24, INK, "bold", "middle"))
    out.append(_t(cx, cy + 8, " · ".join(x for x in (dev.get("model"), dev.get("os"),
                                                      dev.get("version")) if x), 15, MUTED, "normal", "middle"))
    out.append(_t(cx, cy + 30, f'{len(zones)} zones · {sum(len(z["interfaces"]) for z in zones)} interfaces'
                  f' · {len(m["tunnels"])} tunnels', 15, MUTED, "normal", "middle"))

    # Zones.
    for z in zones:
        x, y, w, h, zx, zy = boxes[z["name"]]
        fill, stroke = PALETTE[z["trust"]]
        dash = "" if z["populated"] else ' stroke-dasharray="7 6"'
        if not z["populated"]:
            fill, stroke = CANVAS, IDLE
        out.append(f'<rect x="{x:.0f}" y="{y:.0f}" width="{w}" height="{h}" rx="12" '
                   f'fill="{fill}" stroke="{stroke}" stroke-width="2"{dash}/>')
        out.append(_t(x + 14, y + 24, z["name"], 19, stroke, "bold"))
        out.append(_t(x + w - 12, y + 24, z["trust"], 14, MUTED, "normal", "end"))
        ly = y + 56
        for itf in z["interfaces"][:8]:
            state = "" if itf["enabled"] else "  (down)"
            txt = f'{itf["name"]}  {itf["network"] or itf["address"] or "-"}{state}'
            out.append(_t(x + 14, ly, txt, 15, INK, family="Consolas, monospace"))
            ly += 23
        if len(z["interfaces"]) > 8:
            out.append(_t(x + 14, ly, f'+ {len(z["interfaces"]) - 8} more', 15, MUTED))
            ly += 23
        if z["note"]:
            out.append(_t(x + 14, ly, z["note"], 14,
                          "#b45309" if not z["populated"] else MUTED, "normal"))

    # Internet above the WAN zone.
    wan = next((z for z in zones if z["trust"] == "untrusted" and z["name"].lower() != "wlan"
                and z["populated"]), None)
    if wan:
        x, y, w, h, zx, zy = boxes[wan["name"]]
        ix, iy = zx, max(y - 60, 30)
        out.append(f'<line x1="{zx:.0f}" y1="{y:.0f}" x2="{ix:.0f}" y2="{iy + 18:.0f}" '
                   f'stroke="{FLOW}" stroke-width="2"/>')
        out.append(f'<ellipse cx="{ix:.0f}" cy="{iy:.0f}" rx="80" ry="22" fill="#fff1f2" '
                   f'stroke="{FLOW}" stroke-width="2"/>')
        out.append(_t(ix, iy + 5, "Internet", 17, FLOW, "bold", "middle"))

    # VPN sites beside the VPN zone.
    if m["tunnels"]:
        tx, ty = width - side + 30, 70
        out.append(f'<line x1="{tx - 12}" y1="30" x2="{tx - 12}" y2="{height - 110}" '
                   f'stroke="{HAIRLINE}" stroke-width="1"/>')
        up = sum(1 for t in m["tunnels"] if t["enabled"] is not False)
        out.append(_t(tx, ty, f'VPN sites ({up} of {len(m["tunnels"])} enabled)', 16, INK, "bold"))
        for k, t in enumerate(m["tunnels"][:18]):
            col = "#047857" if t["enabled"] is not False else IDLE
            yy = ty + 24 + k * 23
            out.append(f'<circle cx="{tx + 5:.0f}" cy="{yy - 4:.0f}" r="4" fill="{col}"/>')
            out.append(_t(tx + 16, yy, (t["name"][:26] + ("" if t["enabled"] is not False else "  (disabled)")),
                          14, INK if t["enabled"] is not False else MUTED))

    out.extend(labels)

    # Legend and provenance.
    ly = height - 64
    items = [(FLOW, "untrusted"), ("#b45309", "DMZ / semi-trusted"),
             ("#047857", "trusted"), (IDLE, "defined in policy, nothing assigned (dashed)")]
    lx = 30
    for col, label in items:
        out.append(f'<rect x="{lx}" y="{ly - 11}" width="14" height="14" rx="3" fill="{col}"/>')
        out.append(_t(lx + 22, ly, label, 15, MUTED))
        lx += 24 + 8 * len(label) + 30
    out.append(f'<line x1="{lx}" y1="{ly - 4}" x2="{lx + 40}" y2="{ly - 4}" stroke="{FLOW}" '
               f'stroke-width="3" marker-end="url(#arrow)"/>')
    out.append(_t(lx + 50, ly, "any/any allow into a more trusted zone (dashed: latent)", 12, MUTED))
    if hidden > 0:
        out.append(_t(30, height - 46,
                      f"{hidden} further any/any flow(s) run toward an equally or less "
                      "trusted zone (e.g. LAN to WAN, the normal outbound direction) "
                      "and are not drawn; every flow is in the map data.", 14, MUTED))
    src = m["source"]
    out.append(_t(30, height - 30,
                  f'Derived from configuration ({src["file"]}, sha256 {src["sha256"]}…), not live '
                  f'discovery. Generated {src["generated_at"]}.'
                  + ("  Public addresses, site names and hostname redacted." if m["redacted"] else ""),
                  14, MUTED))
    out.append("</svg>")
    return "\n".join(out)
