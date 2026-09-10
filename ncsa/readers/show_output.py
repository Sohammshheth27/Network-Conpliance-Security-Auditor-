"""Reader 6: `show` command output, via TextFSM and the ntc-templates library.

WHY THIS EXISTS, stated precisely, because it is easy to oversell.

ntc-templates does NOT parse configuration files. It parses the output of
operational `show` commands, and its 979 templates are overwhelmingly for
`show version`, `show interfaces`, `show inventory` and friends. So this is not
a replacement for our config readers -- it answers a different question.

It answers one we could not answer at all. Deliverable 4 asks for "device
identification: including serial numbers and hardware details", and a running
config does not contain them. `show version` does, and NCSA reported
`serial=None` for every Cisco and Juniper device precisely because we were
looking in the only place the answer could never be.

There is a second reason to take the dependency, and it is the more important
one architecturally: 979 templates covering 35 vendors are maintained by people
who are not us, tested against real device output, and updated when firmware
changes their spelling. Every parser we do not own is a parser we cannot get
wrong. Our packs keep doing the thing only we can do -- deciding what a setting
MEANS for security -- and stop doing text extraction wherever a maintained
template already does it.

The honest limits, since they belong next to the claim:

  * `show` output is a point-in-time snapshot of OPERATIONAL state. A config
    is declared intent. They can disagree, and when they do that disagreement
    is a finding in its own right, not an error.
  * Coverage is uneven. 21 vendors have a `show version` template; the rest do
    not. A missing template is reported, never guessed around.
"""
from __future__ import annotations

import re
from pathlib import Path

# Where the cloned library lives. Kept configurable because a deployment may
# prefer the pip-installed `ntc_templates` package.
DEFAULT_TEMPLATE_DIRS = (
    Path("downloads/ntc-templates/ntc_templates/templates"),
    Path("ntc_templates/templates"),
)

# Fields worth lifting into DeviceIdentity, in the order we prefer them.
# Vendors disagree on the spelling, which is exactly what the templates
# normalise for us.
# Read off the templates themselves, not assumed: Arista writes MODEL and
# IMAGE, Junos writes JUNOS_VERSION, NX-OS writes PLATFORM and OS. Guessing a
# single spelling is how a field silently comes back None on four vendors out
# of five while the parse itself succeeded.
IDENTITY_FIELDS = {
    "serial": ("SERIAL", "SERIAL_NUMBER", "SYSTEM_SERIAL_NUMBER", "SN",
               "CHASSIS_SERIAL", "SERIAL_NUM"),
    "model": ("HARDWARE", "MODEL", "PID", "PLATFORM", "CHASSIS",
              "HARDWARE_MODEL"),
    "version": ("VERSION", "JUNOS_VERSION", "OS_VERSION", "SOFTWARE_VERSION",
                "OS", "IMAGE", "RELEASE", "SW_VERSION"),
    "hostname": ("HOSTNAME", "DEVICE_NAME", "NAME"),
    "os": ("SOFTWARE_IMAGE", "BOOT_IMAGE"),
}


def template_dir(explicit=None) -> Path | None:
    for d in ([Path(explicit)] if explicit else []) + list(DEFAULT_TEMPLATE_DIRS):
        if d.is_dir():
            return d
    return None


def available_platforms(explicit=None) -> list:
    """Every platform with at least one template on disk."""
    d = template_dir(explicit)
    if d is None:
        return []
    seen = set()
    for f in d.glob("*.textfsm"):
        # `cisco_ios_show_version.textfsm` -> `cisco_ios`
        m = re.match(r"([a-z0-9]+_[a-z0-9]+)_show", f.name)
        if m:
            seen.add(m.group(1))
    return sorted(seen)


def parse(text: str, platform: str, command: str = "show version",
          *, templates=None) -> list:
    """Parse `show` output. Returns a list of row dicts, [] if no template.

    A missing template returns an empty list rather than raising: an
    unsupported platform is a coverage gap to report, not a crash.
    """
    d = template_dir(templates)
    if d is None:
        return []
    name = f"{platform}_{command.strip().replace(' ', '_').replace('/', '_')}"
    path = d / f"{name}.textfsm"
    if not path.exists():
        return []

    import textfsm
    with path.open(encoding="utf-8") as fh:
        fsm = textfsm.TextFSM(fh)
        rows = fsm.ParseText(text)
    return [dict(zip(fsm.header, r)) for r in rows]


def _first(value):
    """Templates return a list for repeatable fields (a stacked switch has
    several serials). The first is the chassis; the rest are recorded but the
    identity takes one."""
    if isinstance(value, list):
        return value[0] if value else None
    return value or None


def identity_from(rows) -> dict:
    """Lift DeviceIdentity fields out of parsed `show version` rows."""
    if not rows:
        return {}
    row = rows[0]
    out = {}
    for target, candidates in IDENTITY_FIELDS.items():
        for key in candidates:
            if key in row and row[key]:
                v = _first(row[key])
                if v:
                    out[target] = v
                    break
    # A stacked or chassis device reports several serials; keep them all so a
    # report can list every member rather than silently naming one.
    for key in ("SERIAL", "SERIAL_NUMBER"):
        if isinstance(row.get(key), list) and len(row[key]) > 1:
            out["serial_all"] = list(row[key])
    return out


# --------------------------------------------------------------- detection
_SHOW_MARKERS = (
    re.compile(r"^\s*(Cisco IOS Software|Cisco Adaptive Security Appliance)", re.M),
    re.compile(r"^\s*Hostname:\s", re.M),
    re.compile(r"^\s*System image file is", re.M),
    re.compile(r"^\s*Model number\s*:", re.M),
    re.compile(r"^\s*(Arista|Juniper) \S+", re.M),
    re.compile(r"^\s*JUNOS \S+ \[", re.M),
    re.compile(r"uptime is \d", re.I),
)


def looks_like_show_output(text: str) -> bool:
    """Is this operational output rather than a configuration?

    Deliberately conservative. A file misread as `show` output would be handed
    to a template instead of a config reader and silently produce nothing;
    guessing wrong in this direction costs a whole assessment.
    """
    head = "\n".join(text.splitlines()[:60])
    if re.search(r"^\s*(version \d|hostname |interface |set system |config )",
                 head, re.M | re.I):
        return False                      # reads like a config
    return any(rx.search(head) for rx in _SHOW_MARKERS)


PLATFORM_ALIASES = {
    "cisco_iosxe_router": "cisco_ios",
    "cisco_iosxe_switch": "cisco_ios",
    "cisco_asa": "cisco_asa",
    "juniper_srx": "juniper_junos",
    "juniper_srx_xml": "juniper_junos",
    "arista_eos": "arista_eos",
    "fortinet_fortios": "fortinet",
    "paloalto_panos": "paloalto_panos",
    "aruba_aoscx": "aruba_oscx",
}


def ntc_platform(platform: str) -> str:
    """Our platform key -> ntc-templates' naming."""
    return PLATFORM_ALIASES.get(platform, platform)
