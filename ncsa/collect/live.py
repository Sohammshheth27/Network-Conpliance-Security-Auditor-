"""Live collection: pull a running configuration over SSH, then assess it.

The file-upload path stays the primary one. This exists for the operator who
would rather point NCSA at a device than export a file by hand -- and it is
held to a stricter standard than upload, because it touches a live device.

What it guarantees
------------------
* READ-ONLY. Each platform has a fixed list of show commands and nothing else
  is ever sent: no configuration mode, no free-form command from the request.
  A collector that could be talked into `configure terminal` is a remote
  administration tool, not an auditor.
* CREDENTIALS ARE NOT KEPT. They are used for one session and dropped. Any
  error text is scrubbed of them before it reaches a log or a response --
  some SSH libraries echo the failing login back in the exception.
* THE FINGERPRINT DECIDES, NOT THE USER. The requested platform picks the SSH
  driver. Which mapping pack applies is still decided by fingerprinting what
  came back; a mismatch is reported, never silently trusted.

Deliberately NOT supported: SonicWall (its CLI prints a different format from
the .exp export our pack is verified against) and Aruba AOS-CX (no command
output verified). Adding one is a PROFILES entry once its output is verified.

netmiko and napalm are optional dependencies, imported only when used.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class Profile:
    netmiko: str                 # netmiko device_type
    commands: tuple              # read-only; the LAST one's output is the config
    suffix: str                  # file extension the readers expect
    napalm: str | None = None    # napalm driver, where one exists


PROFILES: dict[str, Profile] = {
    "cisco_iosxe_router": Profile("cisco_ios", ("show running-config",), ".cfg", "ios"),
    "cisco_asa": Profile("cisco_asa", ("show running-config",), ".cfg"),
    "juniper_srx": Profile("juniper_junos", ("show configuration",), ".conf", "junos"),
    "arista_eos": Profile("arista_eos", ("show running-config",), ".cfg", "eos"),
    # `show` at the top level prints the whole FortiOS configuration.
    "fortios": Profile("fortinet", ("show",), ".conf"),
    # The PAN-OS pack reads XML. The first command is a CLI session preference,
    # not a configuration change.
    "panos": Profile("paloalto_panos",
                     ("set cli config-output-format xml", "show config running"),
                     ".xml"),
}

#: Every command the collector may ever send, across all platforms.
ALLOWED_COMMANDS = frozenset(c for p in PROFILES.values() for c in p.commands)

_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-:]{0,252}$")


class CollectorUnavailable(RuntimeError):
    """The SSH library is not installed."""


class CollectionError(RuntimeError):
    """The device could not be reached, refused the login, or returned nothing."""


@dataclass
class Collected:
    host: str
    platform: str
    driver: str
    text: str
    commands: list = field(default_factory=list)
    collected_at: str = ""

    def note(self) -> str:
        return (f"Collected live from {self.host} over SSH ({self.driver}) at "
                f"{self.collected_at} using read-only commands: "
                + "; ".join(self.commands) + ".")


def validate_target(host: str, port: int) -> None:
    if not isinstance(host, str) or not _HOST_RE.fullmatch(host.strip()):
        raise ValueError("host must be an IP address or DNS name")
    if not (isinstance(port, int) and 1 <= port <= 65535):
        raise ValueError("port must be between 1 and 65535")


def profile_for(platform: str) -> Profile:
    try:
        return PROFILES[platform]
    except KeyError:
        raise ValueError(
            f"live collection does not support {platform!r}; supported: "
            + ", ".join(sorted(PROFILES))) from None


def _scrub(text: str, *secrets: str | None) -> str:
    for s in secrets:
        if s:
            text = text.replace(s, "********")
    return text


# --- connection seams (tests replace these) -------------------------------
def _netmiko_connect(**params):
    try:
        from netmiko import ConnectHandler
    except ImportError as exc:
        raise CollectorUnavailable(
            "netmiko is not installed. Install it with: pip install netmiko") from exc
    return ConnectHandler(**params)


def _napalm_open(driver: str, host: str, username: str, password: str, port: int):
    try:
        from napalm import get_network_driver
    except ImportError as exc:
        raise CollectorUnavailable(
            "napalm is not installed. Install it with: pip install napalm") from exc
    dev = get_network_driver(driver)(hostname=host, username=username,
                                     password=password, optional_args={"port": port})
    dev.open()
    return dev


def collect(host: str, platform: str, username: str, password: str, *,
            port: int = 22, driver: str = "netmiko",
            secret: str | None = None) -> Collected:
    """Fetch the running configuration. Sends only the platform's show commands."""
    validate_target(host, port)
    prof = profile_for(platform)
    host = host.strip()
    when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    try:
        if driver == "napalm":
            if not prof.napalm:
                raise ValueError(f"napalm has no driver for {platform!r}; use netmiko")
            dev = _napalm_open(prof.napalm, host, username, password, port)
            try:
                text = dev.get_config(retrieve="running").get("running") or ""
            finally:
                dev.close()
            sent = [f"napalm get_config(retrieve='running') [{prof.napalm}]"]
        elif driver == "netmiko":
            conn = _netmiko_connect(device_type=prof.netmiko, host=host,
                                    username=username, password=password,
                                    port=port, secret=secret or "",
                                    conn_timeout=15)
            try:
                if secret and prof.netmiko.startswith("cisco"):
                    conn.enable()
                out = ""
                sent = []
                for cmd in prof.commands:
                    # Belt and braces: the allow-list is checked at the point
                    # of sending, not only where the profile is defined.
                    if cmd not in ALLOWED_COMMANDS:
                        raise CollectionError(f"refusing non-allow-listed command {cmd!r}")
                    out = conn.send_command(cmd, read_timeout=120)
                    sent.append(cmd)
                text = out
            finally:
                conn.disconnect()
        else:
            raise ValueError("driver must be 'netmiko' or 'napalm'")
    except (CollectorUnavailable, ValueError, CollectionError):
        raise
    except Exception as exc:                            # noqa: BLE001
        raise CollectionError(
            _scrub(f"{type(exc).__name__}: {exc}", password, secret, username)) from None

    if not text or not text.strip():
        raise CollectionError(f"{host} returned an empty configuration")
    return Collected(host=host, platform=platform, driver=driver, text=text,
                     commands=sent, collected_at=when)


def write_collected(c: Collected, dest_dir: Path) -> Path:
    """Write the configuration exactly as received -- no header, because a
    comment line in front of XML or a Junos block changes how it parses."""
    safe = re.sub(r"[^A-Za-z0-9.\-]", "_", c.host)
    dest = Path(dest_dir) / f"{uuid.uuid4().hex}_{safe}{PROFILES[c.platform].suffix}"
    dest.write_text(c.text, encoding="utf-8")
    return dest
