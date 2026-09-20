"""A topology figure of one device: zones, LANs, WLANs, uplinks, tunnels.

WHAT THE FIGURE IS
------------------
A picture of what the CONFIGURATION says the network looks like: which zones
exist, which interfaces and subnets sit in each, where the internet enters,
which VPN sites hang off the device, whether any access point is provisioned
for the wireless zone, and which zone-to-zone flows the policy opens with an
any/any rule.

HOW IT IS LAID OUT, AND WHY THAT CHANGED
----------------------------------------
Zones are stacked in TRUST TIERS -- internet-facing at the top, the device as a
full-width slab across the middle, internal zones below -- which is how every
network diagram an administrator has ever read is drawn.

It used to be a ring: the device in the centre with ten zones around it. Every
fact was present and none of it was legible. Working out whether a flow ran
toward something sensitive meant finding two boxes on a circle and judging
which was "more trusted", and the arrows between them crossed the middle at
every angle. Stacking the tiers makes the one question worth asking --
DOES THIS REACH MY INTERNAL NETWORK? -- answerable by direction alone: an
escalating flow points DOWN, and it visibly passes through the firewall slab on
its way. Position now carries meaning, so the reader does not have to.

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

That is redaction at the MAP layer, and it still applies. A redacted
ASSESSMENT is separately pseudonymised in the reader, which maps each address
to a stable stand-in inside 10/8 -- so an assessment run with `redact=True`
arrives here already carrying private-looking addressing, and the figure shows
its structure rather than a row of blanks.
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
#
# The figure is drawn on a DARK canvas. A network diagram is read on a console
# for minutes at a time, and on dark ground a saturated stroke separates from
# its background far more strongly than the same hue does on white -- so trust
# reads at a glance and the arrows stay visible over ten stacked boxes. Every
# fill, stroke and text colour below is chosen against this ground, not adapted
# from the light version: dark backgrounds punish borrowed palettes.
INK = "#e8eef8"          # primary text
MUTED = "#93a7c4"        # secondary text

# Ground.
BG = "#070d17"           # page
CANVAS = "#0c1424"       # tier band
PANEL = "#111c30"        # device / side panel
HAIRLINE = "#1e2b44"     # rules and grid
GRID = "#111a2b"

# Trust. (fill, stroke, label) -- the label is a LIGHT tint of the stroke so
# the zone name carries the same meaning as its border without dropping
# contrast against a dark fill, which a saturated stroke colour would.
PALETTE = {
    "untrusted": ("#2b0f18", "#f43f5e", "#fda4af"),   # rose
    "semi": ("#2b1d08", "#f59e0b", "#fcd34d"),        # amber
    "trusted": ("#052419", "#10b981", "#6ee7b7"),     # emerald
    "unknown": ("#141d2e", "#64748b", "#a8b8cf"),     # slate
}
DEVICE = "#38bdf8"       # the device's own stroke
DEVICE_FILL = "#0d2540"
FLOW = "#fb7185"         # an any/any allow into a more trusted zone
IDLE = "#3f5375"         # defined in policy, nothing assigned

# Tiers, top to bottom. UNKNOWN SITS ABOVE THE DEVICE, with the outside tiers:
# a zone whose trust we could not establish is not one to draw among the
# internal networks. On the reference device that is where VPN and MPLS land,
# and VPN traffic does arrive from outside, so the placement is also correct.
TIERS = [
    ("untrusted", "INTERNET-FACING", "reachable from outside your control"),
    ("semi", "PERIMETER / DMZ", "published services, partially trusted"),
    ("unknown", "TRUST NOT ESTABLISHED", "defined in policy, not classified"),
]
TRUSTED_TIER = ("trusted", "INTERNAL", "your users, servers and management plane")

MARGIN = 40
BOX_W = 366
BOX_GAP = 30
# Clearance between a tier's heading and its first row of boxes. It must
# exceed DEPTH: a solid is extruded UPWARD from its own top edge, so at 40 the
# first row's top face rode over the heading and struck a line through every
# tier's subtitle.
TIER_HEAD = 60
TIER_PAD = 22
HEADER_H = 132
DEVICE_H = 132
FOOTER_H = 132
LBL_W = 390             # a flow's label plate
LBL_H = 32


def _width(text: str, size: int, bold: bool = False) -> float:
    """Roughly how wide a run of text will be.

    SVG has no text metrics until it is rendered, so anything placed AFTER a
    string has to estimate. Under-estimating is what printed every tier's
    subtitle on top of its own heading: uppercase bold advances closer to
    0.72em than the 0.56em a mixed-case average suggests.
    """
    upper = sum(1 for c in text if c.isupper() or c.isdigit())
    ratio = 0.56 + 0.10 * (upper / max(len(text), 1)) + (0.06 if bold else 0)
    return len(text) * size * ratio


def _t(x, y, s, size=16, color=INK, weight="normal", anchor="start",
       family="Inter, Segoe UI, Arial, sans-serif", opacity=None):
    op = f' opacity="{opacity}"' if opacity is not None else ""
    return (f'<text x="{x:.0f}" y="{y:.0f}" font-family="{family}" font-size="{size}" '
            f'fill="{color}" font-weight="{weight}" text-anchor="{anchor}"{op}>'
            f'{escape(str(s))}</text>')


def _mono(x, y, s, size=15, color=INK, anchor="start", opacity=None):
    return _t(x, y, s, size, color, "normal", anchor,
              "JetBrains Mono, Consolas, monospace", opacity)


# ------------------------------------------------------------------ 3-D solid
#
# Zones are drawn as extruded slabs rather than flat rectangles. This is real
# geometry -- three painted faces per solid with a cast shadow -- not a CSS
# effect, so it renders identically in the browser and in the PDF report and
# needs no WebGL library (which the console's content-security policy would
# block anyway).
#
# The projection is a shallow cabinet oblique: the front face keeps its true
# rectangle so LABELS STAY HORIZONTAL AND FULLY LEGIBLE, and depth is added by
# offsetting a second face up and to the right. A true isometric would skew
# every label, which trades the one thing this figure exists for -- being read
# -- for the appearance of sophistication.
DEPTH = 16          # how far the solid is extruded, in pixels


def _mix(hex_colour: str, other: str, amount: float) -> str:
    """Blend toward `other`. On a dark figure the top face of a solid must be
    LIGHTER than its front, not darker: multiplying a near-black fill by 0.96
    is invisible, so the extrusion simply vanished."""
    a, b = hex_colour.lstrip("#"), other.lstrip("#")
    if len(a) != 6 or len(b) != 6:
        return hex_colour
    out = []
    for i in (0, 2, 4):
        ca, cb = int(a[i:i + 2], 16), int(b[i:i + 2], 16)
        out.append(max(0, min(255, round(ca + (cb - ca) * amount))))
    return "#%02x%02x%02x" % tuple(out)


def _shade(hex_colour: str, factor: float) -> str:
    """Same hue, darker or lighter -- kept for callers outside this module."""
    h = hex_colour.lstrip("#")
    if len(h) != 6:
        return hex_colour
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    f = lambda v: max(0, min(255, int(v * factor)))   # noqa: E731
    return f"#{f(r):02x}{f(g):02x}{f(b):02x}"


def _solid(x, y, w, h, fill, stroke, *, depth=DEPTH, dash="", radius=12) -> list[str]:
    """One extruded box: shadow, right face, top face, then the front face."""
    d = depth
    top = _mix(fill, "#ffffff", 0.16)
    side = _mix(fill, "#000000", 0.45)
    return [
        # Cast shadow, offset down-right. Black on a dark ground, not navy.
        f'<rect x="{x + 7:.0f}" y="{y + 9:.0f}" width="{w}" height="{h}" rx="{radius}" '
        f'fill="#000000" opacity="0.38"/>',
        # Right face.
        f'<path d="M{x + w:.0f},{y:.0f} L{x + w + d:.0f},{y - d:.0f} '
        f'L{x + w + d:.0f},{y + h - d:.0f} L{x + w:.0f},{y + h:.0f} Z" '
        f'fill="{side}" stroke="{stroke}" stroke-width="1" stroke-opacity="0.55"/>',
        # Top face.
        f'<path d="M{x:.0f},{y:.0f} L{x + d:.0f},{y - d:.0f} '
        f'L{x + w + d:.0f},{y - d:.0f} L{x + w:.0f},{y:.0f} Z" '
        f'fill="{top}" stroke="{stroke}" stroke-width="1" stroke-opacity="0.55"/>',
        # Front face, drawn last so its border is unbroken.
        f'<rect x="{x:.0f}" y="{y:.0f}" width="{w}" height="{h}" rx="{radius}" '
        f'fill="{fill}" stroke="{stroke}" stroke-width="2"{dash}/>',
    ]


def _box_h(z: dict) -> int:
    """Tall enough for the zone's name, its addressing and its note."""
    lines = len(z["interfaces"][:9])
    if len(z["interfaces"]) > 9:
        lines += 1
    if z.get("note"):
        lines += 1
    return 62 + 23 * max(lines, 1)


def _rows(zones: list, per_row: int) -> list[list]:
    return [zones[i:i + per_row] for i in range(0, len(zones), per_row)] or []


def render_svg(m: dict, width: int = 2000, height: int = 1300,
               *, solid: bool = True) -> str:
    """Trust-tiered layout: outside at the top, the device across the middle.

    `height` is a MINIMUM. The figure grows to fit however many zones the
    device has rather than compressing them into a fixed box, because a zone
    whose addressing is clipped is a zone the reader cannot check.

    `solid` draws every zone and the device as an extruded 3-D slab. It is the
    default because depth separates the boxes from the lines crossing between
    them; `solid=False` keeps the flat figure, which reproduces better on a
    monochrome printer.
    """
    zones = m["zones"]
    side = 560 if m["tunnels"] else 0
    usable = width - side - 2 * MARGIN
    per_row = max(1, int(usable // (BOX_W + BOX_GAP)))

    # ---------------------------------------------------------------- layout
    # Measured first, drawn second: the canvas height depends on how many rows
    # each tier needs, and the device band has to sit between the outside tiers
    # and the internal one wherever that falls.
    plan: list = []          # (kind, payload, y, h)
    y = HEADER_H
    for key, title, subtitle in TIERS:
        members = [z for z in zones if z["trust"] == key]
        if not members:
            continue
        rows = _rows(members, per_row)
        h = TIER_HEAD + sum(max(_box_h(z) for z in r) + BOX_GAP for r in rows) + TIER_PAD
        plan.append(("tier", (key, title, subtitle, rows), y, h))
        y += h
    device_y = y
    y += DEVICE_H
    trusted = [z for z in zones if z["trust"] == "trusted"]
    if trusted:
        rows = _rows(trusted, per_row)
        key, title, subtitle = TRUSTED_TIER
        h = TIER_HEAD + sum(max(_box_h(z) for z in r) + BOX_GAP for r in rows) + TIER_PAD
        plan.append(("tier", (key, title, subtitle, rows), y, h))
        y += h
    height = max(height, int(y + FOOTER_H))

    # Place every zone box, so flows can be routed before anything is painted.
    boxes: dict = {}
    for kind, payload, ty, th in plan:
        _key, _title, _sub, rows = payload
        ry = ty + TIER_HEAD
        for row in rows:
            rh = max(_box_h(z) for z in row)
            total = len(row) * BOX_W + (len(row) - 1) * BOX_GAP
            rx = MARGIN + max((usable - total) / 2, 0)
            for z in row:
                bh = _box_h(z)
                boxes[z["name"]] = (rx, ry + (rh - bh) / 2, BOX_W, bh,
                                    rx + BOX_W / 2, ry + (rh - bh) / 2 + bh / 2)
                rx += BOX_W + BOX_GAP
            ry += rh + BOX_GAP

    cx = MARGIN + usable / 2
    dev_cy = device_y + DEVICE_H / 2

    # ------------------------------------------------------------------ paint
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
           f'viewBox="0 0 {width} {height}">',
           '<defs>',
           f'<marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" '
           f'markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
           f'<path d="M0,0 L10,5 L0,10 z" fill="{FLOW}"/></marker>',
           f'<marker id="idle" viewBox="0 0 10 10" refX="9" refY="5" '
           f'markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
           f'<path d="M0,0 L10,5 L0,10 z" fill="{IDLE}"/></marker>',
           f'<pattern id="grid" width="48" height="48" patternUnits="userSpaceOnUse">'
           f'<path d="M48,0 L0,0 0,48" fill="none" stroke="{GRID}" stroke-width="1"/>'
           f'</pattern>',
           f'<linearGradient id="devglow" x1="0" y1="0" x2="0" y2="1">'
           f'<stop offset="0%" stop-color="{_mix(DEVICE_FILL, "#38bdf8", 0.22)}"/>'
           f'<stop offset="100%" stop-color="{DEVICE_FILL}"/></linearGradient>',
           '</defs>',
           f'<rect width="{width}" height="{height}" fill="{BG}"/>',
           f'<rect width="{width}" height="{height}" fill="url(#grid)" opacity="0.6"/>']

    # Header.
    dev = m["device"]
    out.append(_t(MARGIN, 58, dev["name"], 30, INK, "bold"))
    meta = " · ".join(x for x in (dev.get("model"), dev.get("os"), dev.get("version")) if x)
    if meta:
        out.append(_t(MARGIN, 86, meta, 16, MUTED))
    n_if = sum(len(z["interfaces"]) for z in zones)
    chips = [f'{len(zones)} zones', f'{n_if} interfaces', f'{len(m["tunnels"])} VPN tunnels']
    chx = MARGIN
    for c in chips:
        w = 16 + 8 * len(c)
        out.append(f'<rect x="{chx:.0f}" y="102" width="{w}" height="26" rx="13" '
                   f'fill="{PANEL}" stroke="{HAIRLINE}" stroke-width="1"/>')
        out.append(_t(chx + w / 2, 120, c, 14, MUTED, "normal", "middle"))
        chx += w + 10
    out.append(_t(width - side - MARGIN, 58, "TRUST TIERS", 14, MUTED, "bold", "end"))
    out.append(_t(width - side - MARGIN, 82,
                  "outside at the top · your network at the bottom", 14, MUTED,
                  "normal", "end"))
    out.append(_t(width - side - MARGIN, 104,
                  "an arrow pointing DOWN crosses the firewall inward", 14, FLOW,
                  "normal", "end"))

    # Tier bands and their labels.
    for kind, payload, ty, th in plan:
        key, title, subtitle, rows = payload
        stroke = PALETTE[key][1]
        out.append(f'<rect x="{MARGIN - 14:.0f}" y="{ty:.0f}" width="{usable + 28:.0f}" '
                   f'height="{th:.0f}" rx="18" fill="{CANVAS}" stroke="{HAIRLINE}" '
                   f'stroke-width="1"/>')
        out.append(f'<rect x="{MARGIN - 14:.0f}" y="{ty:.0f}" width="6" '
                   f'height="{th:.0f}" rx="3" fill="{stroke}" opacity="0.85"/>')
        out.append(_t(MARGIN + 4, ty + 27, title, 16, stroke, "bold"))
        out.append(_t(MARGIN + 4 + _width(title, 16, bold=True) + 22, ty + 27,
                      subtitle, 14, MUTED))

    # --------------------------------------------------------------- the flows
    # Only the flows that matter are drawn: an any/any allow from a LESS
    # trusted zone into a more trusted one. Drawing every auto-generated
    # default rule (LAN -> WAN is the normal outbound direction) buried the one
    # arrow worth seeing under a dozen that are not.
    drawn = [f for f in m["flows"] if f["any_any"] and f.get("escalates")
             and f["from"] in boxes and f["to"] in boxes][:8]
    hidden = sum(1 for f in m["flows"] if f["any_any"]) - len(drawn)
    labels: list = []
    # A plate must clear the zone boxes AND every plate already placed.
    # Avoiding only the boxes printed "VPN ZOne -> DMZ" directly on top of
    # "MPLS -> DMZ", which is exactly as unreadable as printing either on a box.
    # The device slab counts as an obstacle too. Left out, "MPLS -> LAN" was
    # printed straight across the device's own name.
    obstacles = [(b[0], b[1], b[2], b[3]) for b in boxes.values()]
    obstacles.append((MARGIN, device_y + 18, usable, DEVICE_H - 42))
    # So does each tier's heading: it is text, and a plate settling on it is no
    # more readable than one settling on a box. "MPLS -> DMZ" came to rest
    # across "TRUST NOT ESTABLISHED", and "VPN -> LAN" across "INTERNAL".
    obstacles += [(MARGIN - 14, ty + 4, usable + 28, 34) for _k, _p, ty, _h in plan]
    for idx, f in enumerate(drawn):
        sx0, sy0, sw, sh, scx, scy = boxes[f["from"]]
        ex0, ey0, ew, eh, ecx, ecy = boxes[f["to"]]
        if ecy > scy + 40:                       # destination is lower: go down
            x1, y1, x2, y2 = scx, sy0 + sh, ecx, ey0
        elif ecy < scy - 40:
            x1, y1, x2, y2 = scx, sy0, ecx, ey0 + eh
        else:                                    # same row: leave by the side
            right = ecx > scx
            x1, y1 = (sx0 + sw, scy) if right else (sx0, scy)
            x2, y2 = (ex0, ecy) if right else (ex0 + ew, ecy)
        # A vertical S-curve. Every escalating flow therefore enters the device
        # band from above and leaves below it, which is the fact the figure is
        # for: this traffic crosses the firewall.
        my = (y1 + y2) / 2
        bow = (idx - (len(drawn) - 1) / 2) * 26      # fan them out, no overlap
        dash = ' stroke-dasharray="9 7"' if f.get("latent") else ""
        out.append(f'<path d="M{x1:.0f},{y1:.0f} C{x1 + bow:.0f},{my:.0f} '
                   f'{x2 + bow:.0f},{my:.0f} {x2:.0f},{y2:.0f}" fill="none" '
                   f'stroke="{FLOW}" stroke-width="3"{dash} '
                   f'marker-end="url(#arrow)" opacity="0.95"/>')
        # Search outward from the arrow's midpoint for a position clear of
        # everything already on the canvas, preferring small moves so the plate
        # stays near its own arrow. A deterministic scan over candidates, not a
        # nudge loop: two obstacles facing each other bounce a nudge forever.
        #
        # SCORED, because the search can genuinely run out of room. An earlier
        # version took the first free candidate and otherwise fell back to the
        # arrow's midpoint -- so the one flow that found nothing (VPN ZOne ->
        # DMZ, 0 of 65 candidates free once tier headings became obstacles) was
        # dumped at the exact spot it had just proved was occupied, landing on
        # both a neighbouring plate and a tier subtitle. Failing into the WORST
        # position is worse than not searching. When nothing is free the least
        # overlapped candidate wins instead.
        lo = MARGIN + LBL_W / 2
        hi = MARGIN + usable - LBL_W / 2
        top, bot = HEADER_H + LBL_H, height - FOOTER_H - LBL_H
        base_x = min(max((x1 + x2) / 2 + bow * 0.75, lo), hi)
        cands = []
        for dy in range(0, 361, 36):
            for sy in ((0,) if dy == 0 else (-1, 1)):
                for dx in range(0, 561, 70):
                    for sx in ((0,) if dx == 0 else (-1, 1)):
                        cands.append((dy * sy, dx * sx))
        # Vertical first: a plate above or below its arrow still reads as
        # belonging to it, one shifted sideways is easily misattributed.
        cands.sort(key=lambda c: (abs(c[0]) + abs(c[1]) * 0.55, abs(c[1]), c))
        best, best_cost = (base_x, my), None
        for dy, dx in cands:
            px = min(max(base_x + dx, lo), hi)
            py = min(max(my + dy, top), bot)
            cost = 0.0
            for o in obstacles:
                ox = min(px + LBL_W / 2, o[0] + o[2]) - max(px - LBL_W / 2, o[0])
                oy = (min(py + LBL_H / 2 + 5, o[1] + o[3])
                      - max(py - LBL_H / 2 - 5, o[1]))
                if ox > 0 and oy > 0:
                    cost += ox * oy
            if cost == 0:
                best = (px, py)
                break
            if best_cost is None or cost < best_cost:
                best, best_cost = (px, py), cost
        lx, ly = best
        obstacles.append((lx - LBL_W / 2, ly - LBL_H / 2, LBL_W, LBL_H))
        n_r = len(f["any_any"])
        label = (f'{f["from"]} → {f["to"]}: any/any'
                 + (", latent" if f.get("latent") else "")
                 + f' ({n_r} rule{"s" if n_r > 1 else ""})')
        # Labels are collected and drawn LAST: drawn here, the zone boxes
        # painted over them and hid the most important one (WLAN -> DMZ).
        labels.append(f'<rect x="{lx - LBL_W / 2:.0f}" y="{ly - LBL_H / 2:.0f}" '
                      f'width="{LBL_W}" height="{LBL_H}" '
                      f'rx="8" fill="{BG}" stroke="{FLOW}" stroke-width="1" '
                      f'fill-opacity="0.94"/>')
        labels.append(_t(lx, ly + 5, label, 15, FLOW, "bold", "middle"))

    # --------------------------------------------------------------- the zones
    for z in zones:
        if z["name"] not in boxes:
            continue
        x, yy, w, h, zcx, zcy = boxes[z["name"]]
        fill, stroke, text = PALETTE[z["trust"]]
        dash = "" if z["populated"] else ' stroke-dasharray="7 6"'
        if not z["populated"]:
            fill, stroke, text = "#0f1726", IDLE, MUTED
        if solid:
            out.extend(_solid(x, yy, w, h, fill, stroke, dash=dash))
        else:
            out.append(f'<rect x="{x:.0f}" y="{yy:.0f}" width="{w}" height="{h}" rx="12" '
                       f'fill="{fill}" stroke="{stroke}" stroke-width="2"{dash}/>')
        out.append(_t(x + 16, yy + 30, z["name"], 20, text, "bold"))
        n = len(z["interfaces"])
        out.append(_t(x + w - 14, yy + 30, f'{n} interface{"" if n == 1 else "s"}',
                      14, MUTED, "normal", "end"))
        out.append(f'<line x1="{x + 16:.0f}" y1="{yy + 42:.0f}" x2="{x + w - 14:.0f}" '
                   f'y2="{yy + 42:.0f}" stroke="{stroke}" stroke-width="1" '
                   f'stroke-opacity="0.35"/>')
        ly = yy + 66
        for itf in z["interfaces"][:9]:
            state = "" if itf["enabled"] else "  (down)"
            out.append(_mono(x + 16, ly, f'{itf["name"]:<5} '
                             f'{itf["network"] or itf["address"] or "-"}{state}', 15,
                             INK if itf["enabled"] else MUTED))
            ly += 23
        if n > 9:
            out.append(_t(x + 16, ly, f'+ {n - 9} more', 15, MUTED))
            ly += 23
        if z["note"]:
            out.append(_t(x + 16, ly, z["note"], 14,
                          "#fcd34d" if not z["populated"] else MUTED))

    # -------------------------------------------------------------- the device
    dw = usable
    if solid:
        out.extend(_solid(MARGIN, device_y + 18, dw, DEVICE_H - 42, DEVICE_FILL,
                          DEVICE, depth=DEPTH + 6, radius=16))
    else:
        out.append(f'<rect x="{MARGIN}" y="{device_y + 18:.0f}" width="{dw:.0f}" '
                   f'height="{DEVICE_H - 42}" rx="16" fill="{DEVICE_FILL}" '
                   f'stroke="{DEVICE}" stroke-width="3"/>')
    out.append(_t(MARGIN + 24, dev_cy + 2, dev["name"], 22, INK, "bold"))
    out.append(_t(MARGIN + 24, dev_cy + 26, "every flow between the tiers above and "
                  "below is enforced here", 15, MUTED))
    out.append(_t(MARGIN + dw - 24, dev_cy + 2,
                  f'{len(drawn)} any/any flow(s) drawn', 16, FLOW, "bold", "end"))
    out.append(_t(MARGIN + dw - 24, dev_cy + 26, "policy enforcement point", 14,
                  MUTED, "normal", "end"))

    # Internet, above the top tier.
    top_tier = plan[0] if plan else None
    if top_tier and top_tier[1][0] == "untrusted":
        iy = top_tier[2] - 26
        out.append(f'<rect x="{cx - 96:.0f}" y="{iy - 20:.0f}" width="192" height="38" '
                   f'rx="19" fill="{PALETTE["untrusted"][0]}" stroke="{FLOW}" '
                   f'stroke-width="2"/>')
        out.append(_t(cx, iy + 5, "INTERNET", 17, "#fda4af", "bold", "middle"))

    # ----------------------------------------------------------- VPN side list
    if m["tunnels"]:
        tx = width - side + 24
        out.append(f'<rect x="{tx - 16:.0f}" y="{MARGIN:.0f}" width="{side - 44:.0f}" '
                   f'height="{height - FOOTER_H - MARGIN:.0f}" rx="18" fill="{CANVAS}" '
                   f'stroke="{HAIRLINE}" stroke-width="1"/>')
        up = sum(1 for t in m["tunnels"] if t["enabled"] is not False)
        out.append(_t(tx, MARGIN + 34, "VPN SITES", 16, INK, "bold"))
        out.append(_t(tx, MARGIN + 56, f'{up} of {len(m["tunnels"])} enabled', 14, MUTED))
        ty = MARGIN + 88
        for t in m["tunnels"][:22]:
            live = t["enabled"] is not False
            col = "#10b981" if live else IDLE
            out.append(f'<circle cx="{tx + 6:.0f}" cy="{ty - 5:.0f}" r="4" fill="{col}"/>')
            out.append(_t(tx + 20, ty, t["name"][:30] + ("" if live else "  (disabled)"),
                          14, INK if live else MUTED))
            ty += 23
        if len(m["tunnels"]) > 22:
            out.append(_t(tx + 20, ty, f'+ {len(m["tunnels"]) - 22} more', 14, MUTED))

    out.extend(labels)

    # ------------------------------------------------------- legend, provenance
    ly = height - 78
    out.append(f'<line x1="{MARGIN}" y1="{ly - 30:.0f}" x2="{width - MARGIN}" '
               f'y2="{ly - 30:.0f}" stroke="{HAIRLINE}" stroke-width="1"/>')
    items = [(PALETTE["untrusted"][1], "internet-facing"),
             (PALETTE["semi"][1], "DMZ / semi-trusted"),
             (PALETTE["trusted"][1], "internal"),
             (IDLE, "defined in policy, nothing assigned (dashed)")]
    lx = MARGIN
    for col, label in items:
        out.append(f'<rect x="{lx}" y="{ly - 11}" width="14" height="14" rx="4" fill="{col}"/>')
        out.append(_t(lx + 22, ly, label, 15, MUTED))
        lx += 24 + 8 * len(label) + 26
    out.append(f'<line x1="{lx}" y1="{ly - 4}" x2="{lx + 40}" y2="{ly - 4}" '
               f'stroke="{FLOW}" stroke-width="3" marker-end="url(#arrow)"/>')
    out.append(_t(lx + 50, ly, "any/any allow into a more trusted zone (dashed: latent)",
                  14, MUTED))
    if hidden > 0:
        out.append(_t(MARGIN, height - 52,
                      f"{hidden} further any/any flow(s) run toward an equally or less "
                      "trusted zone (e.g. LAN to WAN, the normal outbound direction) "
                      "and are not drawn; every flow is in the map data.", 14, MUTED))
    src = m["source"]
    out.append(_t(MARGIN, height - 30,
                  f'Derived from configuration ({src["file"]}, sha256 {src["sha256"]}…), not live '
                  f'discovery. Generated {src["generated_at"]}.'
                  + ("  Public addresses, site names and hostname redacted." if m["redacted"] else ""),
                  14, MUTED))
    out.append("</svg>")
    return "\n".join(out)
