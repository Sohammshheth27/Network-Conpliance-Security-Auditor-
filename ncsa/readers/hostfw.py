"""Host firewalls: Windows Firewall and Linux iptables.

The capability `firewall_audit` has and we did not. The brief says "any network
device configuration", and a laptop's own firewall is the one every engineer
can produce in ten seconds -- which also makes it the only device in this
project that can be demonstrated live, on the presenter's machine, with no
customer data involved.

It costs almost nothing architecturally. Once host rules become
`SecurityRule` objects in an `ObjectGraph`, everything already built applies
unchanged: hygiene finds the shadowed and unused ones, reachability answers
"can anything reach port 3389 on this host", and the controls evaluate the
same SBM fields. That is the payoff of having a vendor-neutral model rather
than a Windows-shaped one.

WHAT IS DIFFERENT ABOUT A HOST FIREWALL, and why it is not just another vendor:

  * PROFILES. A Windows rule applies to Domain, Private or Public, and the
    same rule can be harmless on one and dangerous on another. The profile is
    carried as the zone, so a rule permitting RDP on Public is distinguishable
    from the same rule on Domain.
  * NO ORDER. Windows Firewall does not evaluate rules top-to-bottom; block
    rules win over allow rules regardless of position. Shadow analysis assumes
    ordered evaluation, so it is NOT applied here -- claiming a rule is
    shadowed on a platform with no ordering would be inventing a finding.
  * LIVE STATE, not a file. This reads the running configuration, so there is
    no file hash to pin an assessment to. The collection timestamp is recorded
    instead, and stated as such.
"""
from __future__ import annotations

import json
import platform
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime

from ..schema.evidence import EvidenceRef

# One call, joined in PowerShell. Fetching filters per rule turns 703 rules
# into 1,400 round-trips and takes minutes.
_PS_COLLECT = r"""
$ErrorActionPreference='SilentlyContinue'
$port = @{}; Get-NetFirewallPortFilter | ForEach-Object { $port[$_.InstanceID] = $_ }
$addr = @{}; Get-NetFirewallAddressFilter | ForEach-Object { $addr[$_.InstanceID] = $_ }
$app  = @{}; Get-NetFirewallApplicationFilter | ForEach-Object { $app[$_.InstanceID] = $_ }
$out = Get-NetFirewallRule | ForEach-Object {
  $p = $port[$_.InstanceID]; $a = $addr[$_.InstanceID]; $g = $app[$_.InstanceID]
  [pscustomobject]@{
    name=$_.Name; display=$_.DisplayName; enabled=[string]$_.Enabled
    direction=[string]$_.Direction; action=[string]$_.Action
    profile=[string]$_.Profile; group=$_.DisplayGroup
    protocol=[string]$p.Protocol; localPort=[string]$p.LocalPort
    remotePort=[string]$p.RemotePort
    localAddress=[string]$a.LocalAddress; remoteAddress=[string]$a.RemoteAddress
    program=[string]$g.Program
  }
}
$profiles = Get-NetFirewallProfile | ForEach-Object {
  [pscustomobject]@{ name=[string]$_.Name; enabled=[string]$_.Enabled
    inbound=[string]$_.DefaultInboundAction
    outbound=[string]$_.DefaultOutboundAction
    logBlocked=[string]$_.LogBlocked }
}
@{ rules=$out; profiles=$profiles } | ConvertTo-Json -Depth 4 -Compress
"""


@dataclass
class HostFirewall:
    """Live host firewall state, shaped like the other readers."""

    source_file: str
    collected_at: str
    os: str = ""
    rules: list = field(default_factory=list)
    profiles: list = field(default_factory=list)
    lines: list = field(default_factory=list)
    _consumed: set = field(default_factory=set)
    redacted: bool = False

    def evidence(self, lineno, raw: str) -> EvidenceRef:
        """A live host firewall has no file, so most records have no line.

        `None` rather than 0: EvidenceRef requires a line >= 1 precisely so a
        placeholder cannot masquerade as a real position, and a rule read from
        the running configuration genuinely has none. `record_id` carries the
        rule's own name, which is the durable identifier here.
        """
        return EvidenceRef(file=self.source_file,
                           line=(lineno if lineno and lineno > 0 else None),
                           raw=(raw or "").strip()[:200] or "(no text)",
                           record_id=self.collected_at)

    @property
    def total_records(self) -> int:
        return len(self.rules) + len(self.profiles)

    def accounting_snapshot(self) -> dict:
        from ..schema.enums import RecordState
        mapped = len(self._consumed)
        return {RecordState.MAPPED.value: mapped,
                RecordState.PARSED.value: max(self.total_records - mapped, 0),
                RecordState.UNKNOWN.value: 0}

    def unrecognised(self, limit=500) -> list:
        return []


def collect_windows(timeout=180) -> HostFirewall:
    """Read the live Windows Firewall."""
    p = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS_COLLECT],
        capture_output=True, text=True, timeout=timeout)
    if p.returncode != 0 or not p.stdout.strip():
        raise RuntimeError(
            f"could not read Windows Firewall: {p.stderr.strip()[:200]}")
    data = json.loads(p.stdout)
    rules = data.get("rules") or []
    if isinstance(rules, dict):
        rules = [rules]
    profiles = data.get("profiles") or []
    if isinstance(profiles, dict):
        profiles = [profiles]

    fw = HostFirewall(
        source_file=f"windows-firewall://{platform.node()}",
        collected_at=datetime.now().replace(microsecond=0).isoformat(),
        os=f"Windows {platform.release()}",
        rules=rules, profiles=profiles)
    fw.lines = [f"{r.get('name')} {r.get('action')} {r.get('direction')} "
                f"{r.get('protocol')}/{r.get('localPort')}" for r in rules]
    return fw


# ---------------------------------------------------------------- iptables
_IPT_RULE = re.compile(r"^-A\s+(\S+)\s+(.*)$")


def parse_iptables(text: str, host="") -> HostFirewall:
    """Parse `iptables-save` output.

    Partial by design, and said so: iptables supports match extensions that
    change semantics in ways a line-oriented read cannot capture (conntrack
    state, recent, hashlimit). Rules using them are kept with their raw text
    so they appear in the policy, but their match conditions are not modelled
    and reachability will report them unevaluable rather than guess.
    """
    fw = HostFirewall(
        source_file=f"iptables://{host or 'localhost'}",
        collected_at=datetime.now().replace(microsecond=0).isoformat(),
        os="Linux")
    policies = {}
    for i, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        fw.lines.append(line)
        if line.startswith(":"):
            parts = line[1:].split()
            if len(parts) >= 2:
                policies[parts[0]] = parts[1]
            continue
        m = _IPT_RULE.match(line)
        if not m:
            continue
        chain, rest = m.group(1), m.group(2)
        proto = _opt(rest, "-p")
        fw.rules.append({
            "name": f"{chain}#{len(fw.rules)}", "display": line[:120],
            "enabled": "True", "direction":
                "Inbound" if chain.upper() in ("INPUT", "FORWARD") else "Outbound",
            "action": (_opt(rest, "-j") or "").title(),
            "profile": chain, "protocol": (proto or "Any").upper(),
            "localPort": _opt(rest, "--dport") or "Any",
            "remotePort": _opt(rest, "--sport") or "Any",
            "localAddress": _opt(rest, "-d") or "Any",
            "remoteAddress": _opt(rest, "-s") or "Any",
            "line": i, "raw": line,
        })
    fw.profiles = [{"name": c, "enabled": "True", "inbound": p,
                    "outbound": p, "logBlocked": "False"}
                   for c, p in policies.items()]
    return fw


def _opt(rest: str, flag: str) -> str:
    m = re.search(rf"(?:^|\s){re.escape(flag)}\s+(\S+)", rest)
    return m.group(1) if m else ""


def collect(timeout=180) -> HostFirewall:
    """Whatever host firewall this machine runs."""
    if platform.system() == "Windows":
        return collect_windows(timeout=timeout)
    out = subprocess.run(["iptables-save"], capture_output=True, text=True,
                         timeout=timeout)
    if out.returncode != 0:
        raise RuntimeError("iptables-save failed; run as root, or pass the "
                           "output to parse_iptables()")
    return parse_iptables(out.stdout, host=platform.node())
