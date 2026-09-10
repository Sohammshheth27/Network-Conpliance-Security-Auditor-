"""Batfish as an independent second opinion -- not as a parser we depend on.

WHAT THIS IS FOR, because the obvious assumption is wrong.

Batfish is not a way to support more vendors. Measured against the 37 vendors
named in the NCSA brief it covers 10 of them -- 27% -- and it does NOT support
SonicWall, which is the appliance this project was actually built against. Its
supported list (A10, Arista, AWS, Check Point, Cisco, Cumulus, F5, Fortinet,
FRR, iptables, Juniper, Palo Alto, SONiC) overlaps heavily with the vendors we
already parse rather than extending past them.

What it IS: a mature, independently-written implementation of the same
questions we answer, by people who have spent years on the data plane. Where
both tools can read a device, agreement raises confidence and DISAGREEMENT IS
THE POINT -- it means one of us is wrong about a real device, and that is worth
more than either tool's unchallenged opinion. This is the same n-version
reasoning as the pack-versus-detector consensus, applied to a second codebase
instead of a second method.

Three rules keep the dependency honest:

  * OPTIONAL, ALWAYS. Batfish runs in Docker. If it is not reachable, every
    function here degrades to "not consulted" and no assessment changes. A
    compliance tool that stops working when a container is down is not a
    compliance tool.
  * NEVER AUTHORITATIVE. Batfish findings are recorded alongside ours with
    their source named, never merged in as if we had found them. Its model and
    ours disagree about what a "rule" is in places, and silently adopting its
    answers would make our evidence trail wrong.
  * SCOPE CHECKED FIRST. Handing it a SonicWall export produces a parse error
    that looks like a finding. Unsupported platforms are declined up front.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

# Batfish's own supported list, as published. Anything not here is declined
# rather than sent and misparsed.
SUPPORTED = {
    "cisco_asa": "cisco", "cisco_iosxe_router": "cisco",
    "cisco_iosxe_switch": "cisco", "cisco_nxos": "cisco",
    "arista_eos": "arista", "juniper_srx": "juniper",
    "juniper_srx_xml": "juniper", "paloalto_panos": "paloalto",
    "fortinet_fortios": "fortinet", "security_groups": "aws",
    "sonic": "sonic", "cumulus": "cumulus", "f5": "f5",
    "checkpoint": "checkpoint", "a10": "a10", "iptables": "iptables",
}

IMAGE = "batfish/allinone"
CONTAINER = "ncsa-batfish"


@dataclass
class BatfishStatus:
    available: bool
    detail: str = ""
    version: str = ""

    def __bool__(self) -> bool:
        return self.available


def _docker(*args, timeout=60, wsl=True):
    """Run docker, in WSL where that is where it lives on this machine."""
    cmd = (["wsl", "-d", "Ubuntu", "-u", "root", "docker", *args] if wsl
           else ["docker", *args])
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def status(timeout=30) -> BatfishStatus:
    """Is Batfish reachable? Never raises -- absence is a normal state."""
    try:
        import pybatfish  # noqa: F401
    except ImportError:
        return BatfishStatus(False, "pybatfish is not installed "
                                    "(pip install pybatfish)")
    try:
        p = _docker("ps", "--filter", f"name={CONTAINER}",
                    "--format", "{{.Names}} {{.Status}}", timeout=timeout)
    except Exception as exc:                           # noqa: BLE001
        return BatfishStatus(False, f"docker unreachable: {type(exc).__name__}")
    if p.returncode != 0:
        return BatfishStatus(False, f"docker error: {p.stderr.strip()[:120]}")
    if CONTAINER not in p.stdout:
        return BatfishStatus(False, f"container {CONTAINER!r} is not running")
    return BatfishStatus(True, p.stdout.strip())


def start(timeout=600) -> BatfishStatus:
    """Start the Batfish service. Idempotent."""
    s = status()
    if s.available:
        return s
    try:
        _docker("rm", "-f", CONTAINER, timeout=60)
        p = _docker("run", "-d", "--name", CONTAINER,
                    "-p", "9997:9997", "-p", "9996:9996", IMAGE,
                    timeout=timeout)
        if p.returncode != 0:
            return BatfishStatus(False, p.stderr.strip()[:200])
    except Exception as exc:                           # noqa: BLE001
        return BatfishStatus(False, f"{type(exc).__name__}: {exc}")
    return status()


def supports(platform: str) -> bool:
    return platform in SUPPORTED


def wait_ready(timeout=120, poll=2) -> BatfishStatus:
    """Block until the API answers, or give up and say so.

    The allinone container on this machine exits with code 0 after serving a
    batch of questions and is brought back by its restart policy, so
    "the container was up a moment ago" is not a usable precondition. Checking
    `docker ps` alone reported available while the API refused connections.
    The port is what callers actually need, so the port is what is polled.
    """
    import socket
    import time

    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        s = socket.socket()
        s.settimeout(2)
        try:
            s.connect(("localhost", 9996))
            return BatfishStatus(True, "API answering on :9996")
        except Exception as exc:                       # noqa: BLE001
            last = type(exc).__name__
        finally:
            s.close()
        time.sleep(poll)
    return BatfishStatus(False, f"API did not become ready in {timeout}s ({last})")


def ensure_running(timeout=180) -> BatfishStatus:
    """Start Batfish if needed and wait for it to actually answer."""
    ready = wait_ready(timeout=5, poll=1)
    if ready:
        return ready
    start()
    return wait_ready(timeout=timeout)


# ---------------------------------------------------------------- analysis
@dataclass
class BatfishFinding:
    kind: str
    detail: str
    node: str = ""
    source: str = "batfish"
    raw: dict = field(default_factory=dict)

    def to_json(self) -> dict:
        return {"kind": self.kind, "detail": self.detail, "node": self.node,
                "source": self.source}


@dataclass
class BatfishReport:
    consulted: bool = False
    reason: str = ""
    nodes: int = 0
    findings: list = field(default_factory=list)
    parse_warnings: list = field(default_factory=list)

    def by_kind(self, kind) -> list:
        return [f for f in self.findings if f.kind == kind]

    def summary(self) -> dict:
        kinds: dict = {}
        for f in self.findings:
            kinds[f.kind] = kinds.get(f.kind, 0) + 1
        return {"consulted": self.consulted, "nodes_parsed": self.nodes,
                "reason": self.reason, "findings": len(self.findings),
                "by_kind": kinds, "parse_warnings": len(self.parse_warnings)}


def analyse(config_path, platform: str, *, snapshot_dir=None,
            name="ncsa") -> BatfishReport:
    """Send one config to Batfish and collect its own findings.

    Returns a report whose `consulted` flag says whether Batfish actually ran.
    A report with consulted=False is not an error and not a clean result -- it
    is the absence of a second opinion, and callers must not read it as
    agreement.
    """
    rep = BatfishReport()
    if not supports(platform):
        rep.reason = (f"Batfish does not support {platform!r}. Its published "
                      "list covers 10 of the 37 vendors in this brief and "
                      "excludes SonicWall; sending an unsupported config "
                      "produces parse errors that look like findings.")
        return rep

    s = ensure_running()
    if not s:
        rep.reason = f"Batfish not consulted: {s.detail}"
        return rep

    try:
        from pybatfish.client.session import Session
    except ImportError:
        rep.reason = "pybatfish is not installed"
        return rep

    # Batfish reads a directory laid out as snapshot/configs/<file>.
    import tempfile
    root = Path(snapshot_dir or tempfile.mkdtemp(prefix="ncsa-bf-"))
    cfg = root / "configs"
    cfg.mkdir(parents=True, exist_ok=True)
    shutil.copy(config_path, cfg / Path(config_path).name)

    try:
        bf = Session(host="localhost")
        bf.set_network(name)
        bf.init_snapshot(str(root), name="snap", overwrite=True)

        # Did Batfish actually RECOGNISE a device? Zero findings from a tool
        # that never parsed the file is not a clean result, and the two are
        # indistinguishable without asking. This check is the difference
        # between "Batfish agrees" and "Batfish was not looking".
        nodes = bf.q.nodeProperties().answer().frame()
        rep.nodes = int(len(nodes))
        if rep.nodes == 0:
            rep.reason = ("Batfish parsed no device from this file, so its "
                          "empty answer means nothing. Not treated as "
                          "agreement.")
            return rep

        init = bf.q.initIssues().answer().frame()
        for _, row in init.iterrows():
            rep.parse_warnings.append(str(row.to_dict())[:200])

        for question, kind in (
            ("unusedStructures", "unused_structure"),
            ("filterLineReachability", "unreachable_filter_line"),
            ("undefinedReferences", "undefined_reference"),
        ):
            try:
                df = getattr(bf.q, question)().answer().frame()
            except Exception as exc:                   # noqa: BLE001
                rep.parse_warnings.append(f"{question}: {exc}")
                continue
            for _, row in df.iterrows():
                d = row.to_dict()
                rep.findings.append(BatfishFinding(
                    kind=kind, node=str(d.get("Sources") or d.get("Node") or ""),
                    detail=str(d)[:300], raw={k: str(v)[:120]
                                              for k, v in d.items()}))
        rep.consulted = True
    except Exception as exc:                           # noqa: BLE001
        rep.reason = f"Batfish call failed: {type(exc).__name__}: {exc}"
    return rep


# --------------------------------------------------------------- consensus
@dataclass
class CrossCheck:
    agreed: list = field(default_factory=list)
    only_ncsa: list = field(default_factory=list)
    only_batfish: list = field(default_factory=list)
    consulted: bool = False

    def summary(self) -> dict:
        return {"consulted": self.consulted, "agreed": len(self.agreed),
                "only_ncsa": len(self.only_ncsa),
                "only_batfish": len(self.only_batfish)}


def cross_check(hygiene_report, batfish_report) -> CrossCheck:
    """Compare our rule hygiene against Batfish's own view.

    Deliberately reports what only ONE tool found in both directions.
    "Only NCSA" may be a false positive of ours; "only Batfish" is a gap in
    our analysis. Both are information, and a comparison that showed only
    agreement would be measuring nothing.
    """
    out = CrossCheck(consulted=batfish_report.consulted)
    if not batfish_report.consulted:
        return out

    ours = {f.rule.lower() for f in hygiene_report.findings}
    theirs = set()
    for f in batfish_report.findings:
        theirs.update(w.strip().lower() for w in f.node.split(",") if w.strip())

    out.agreed = sorted(ours & theirs)
    out.only_ncsa = sorted(ours - theirs)[:50]
    out.only_batfish = sorted(theirs - ours)[:50]
    return out
