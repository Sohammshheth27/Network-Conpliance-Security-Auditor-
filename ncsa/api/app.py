"""HTTP surface for NCSA.

    uvicorn ncsa.api.app:app --reload --port 8000
    http://localhost:8000/docs        interactive schema for UI work

Deliberately thin. Every route is a call into functions that already exist and
are already tested; the engine must never gain behaviour that only the web
layer knows about, or the CLI and the API start disagreeing about the same
device.

UPLOADS ARE UNTRUSTED. A configuration file arrives from whoever runs the
device, and this project has already found injection-shaped content inside real
device data. Files are written to a temp directory, never executed, never
interpolated into a prompt, and redaction is ON by default -- a decoded
SonicOS export carries password hashes and real addressing.
"""
from __future__ import annotations

import shutil
import tempfile
import uuid
from pathlib import Path

from pydantic import BaseModel
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .convert import assessment_out, candidate_out, remediation_out
from .schemas import (ApprovalIn, ApprovalOut, AssessmentOut, CollectIn,
                      MonitorIn, ReachQueryIn, RemediationOut, TopologyIn,
                      TrainingCandidateOut)

app = FastAPI(
    title="NCSA -- Network Compliance & Security Auditor",
    version="0.1.0",
    description="Vendor-agnostic configuration compliance. Every finding "
                "carries the file and line it came from.")

# --------------------------------------------------------------- security
# The API used to answer anyone, from any origin. Since /collect carries
# device credentials and every upload is a customer configuration, access is
# now explicit:
#
#   NCSA_API_TOKEN set    -> every API call must carry
#                            `Authorization: Bearer <token>`.
#   NCSA_API_TOKEN unset  -> the API answers THIS machine only (loopback), so
#                            a demo still needs no setup but is not exposed
#                            to the network by default.
#   NCSA_CORS_ORIGINS     -> comma-separated browser origins allowed to call
#                            the API; defaults to the local Vite dev server.
#
# The landing page, the static console and /health stay public: they carry
# no customer data.
import hmac as _hmac

from fastapi import Request
from fastapi.responses import JSONResponse

_PUBLIC = ("/", "/app", "/health", "/docs", "/openapi.json", "/redoc",
           "/report-signing-key")
_LOOPBACK = {"127.0.0.1", "::1", "localhost",
             # Starlette's in-process TestClient; no network peer can present
             # this as its address.
             "testclient"}


def _origins() -> list[str]:
    raw = _os_env("NCSA_CORS_ORIGINS")
    return [o.strip() for o in raw.split(",") if o.strip()] if raw else [
        "http://localhost:5173", "http://127.0.0.1:5173"]


def _os_env(name: str) -> str:
    import os
    return os.environ.get(name, "")


@app.middleware("http")
async def _require_access(request: Request, call_next):
    path = request.url.path
    if (request.method == "OPTIONS" or path in _PUBLIC
            or path.startswith("/static/")
            # The dashboard shell and its assets carry no customer data; every
            # call the page then makes goes through the checks below.
            or path.startswith("/dashboard")):
        return await call_next(request)
    token = _os_env("NCSA_API_TOKEN")
    if token:
        sent = request.headers.get("authorization", "")
        if not (sent.startswith("Bearer ")
                and _hmac.compare_digest(sent[7:].strip(), token)):
            return JSONResponse({"detail": "missing or invalid API token"},
                                status_code=401,
                                headers={"WWW-Authenticate": "Bearer"})
    else:
        host = request.client.host if request.client else ""
        if host not in _LOOPBACK:
            return JSONResponse(
                {"detail": "this NCSA instance answers the local machine only; "
                           "set NCSA_API_TOKEN to allow remote clients"},
                status_code=403)
    return await call_next(request)


app.add_middleware(CORSMiddleware, allow_origins=_origins(),
                   allow_methods=["GET", "POST"],
                   allow_headers=["Authorization", "Content-Type"])


# The dashboard calls the engine as /api/<route>. In development Vite proxies
# that prefix away; this does the same in production, so ONE copy of the client
# code works in both places and the page never needs to know which it is in.
# Registered after the CORS middleware, therefore outermost: the path is
# normalised before the access check and before routing, so /api/assessments is
# the same request as /assessments -- same auth, same handler, no duplicate
# route table to keep in step.
@app.middleware("http")
async def _strip_api_prefix(request: Request, call_next):
    path = request.url.path
    if path == "/api" or path.startswith("/api/"):
        request.scope["path"] = path[4:] or "/"
        raw = request.scope.get("raw_path")
        if raw:
            request.scope["raw_path"] = raw.replace(b"/api", b"", 1)
    return await call_next(request)

_STATIC = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")


@app.get("/", include_in_schema=False)
def landing():
    """The public page. Same process, same origin, no build step.

    It reads its figures from /frameworks and /platforms rather than carrying
    its own copy, so the landing page and the console cannot drift apart into
    quoting different numbers for the same engine.
    """
    return FileResponse(str(_STATIC / "landing.html"))


@app.get("/app", include_in_schema=False)
def console():
    """The operator console. Served by the same process as the API so a demo
    needs one command and no build step."""
    return FileResponse(str(_STATIC / "index.html"))


# The React dashboard (frontend/), built into this package by
# `npm run build` -- see frontend/vite.config.ts for the output path. Built
# assets are committed so the engine still needs one command at demo time.
_DASHBOARD = _STATIC / "dashboard"


@app.get("/dashboard", include_in_schema=False)
@app.get("/dashboard/{rest:path}", include_in_schema=False)
def dashboard(rest: str = ""):
    """A built file when the path names one, otherwise the app shell.

    The dashboard uses real URLs (/dashboard/assessments/<id>), so a deep link
    or a plain refresh asks the engine for a path that is not a file on disk.
    Returning the shell lets the client router resolve it; returning 404 would
    make every refresh look like a broken link.
    """
    index = _DASHBOARD / "index.html"
    if not index.exists():
        return JSONResponse(
            {"detail": "the dashboard is not built -- run `npm install && "
                       "npm run build` in frontend/, which writes "
                       "ncsa/api/static/dashboard"},
            status_code=503)
    if rest:
        target = (_DASHBOARD / rest).resolve()
        # Only inside the build directory: `rest` comes from the URL.
        if target.is_file() and _DASHBOARD.resolve() in target.parents:
            return FileResponse(str(target))
    return FileResponse(str(index))


# Assessments survive a restart: SQLite records each one with the file and the
# options it was made with, and it is rebuilt on first access afterwards (see
# store.py). NCSA_DATA_DIR moves the data directory; it defaults to ./data,
# which is git-ignored because it holds customer configurations.
import os as _os

from .store import AssessmentStore

_DATA_DIR = Path(_os.environ.get("NCSA_DATA_DIR")
                 or Path(__file__).resolve().parents[2] / "data")
_STORE = AssessmentStore(_DATA_DIR)
_UPLOADS = _STORE.uploads

#: The hash-chained log of every approved mapping -- the product's audit trail.
#: A module constant so tests can point it elsewhere: a test approval written
#: here is a fabricated entry in a record auditors are told to trust.
APPROVALS_LOG = Path("reference/approved_mappings.jsonl")

MAX_UPLOAD_MB = 64


# --------------------------------------------------------------- ingestion
@app.post("/assess", response_model=list[AssessmentOut], tags=["assess"])
async def assess_upload(files: list[UploadFile] = File(...),
                        redact: bool = Query(True),
                        frameworks: list[str] | None = Query(None)):
    """Deliverable 1: single or bulk ingestion.

    One unreadable file must never abort a batch -- an administrator uploading
    forty devices should get thirty-nine assessments and one clear error, not
    a stack trace.
    """
    from ..frameworks.selection import normalise

    try:
        fws = normalise(frameworks)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc

    out = []
    for f in files:
        dest = _STORE.new_upload_path(f.filename or "config", uuid.uuid4().hex)
        size = 0
        with dest.open("wb") as fh:
            while chunk := await f.read(1 << 20):
                size += len(chunk)
                if size > MAX_UPLOAD_MB * 1024 * 1024:
                    dest.unlink(missing_ok=True)
                    raise HTTPException(413, f"{f.filename} exceeds "
                                             f"{MAX_UPLOAD_MB} MB")
                fh.write(chunk)
        aid, da = _ingest(dest, f.filename or dest.name, redact, fws)
        out.append(assessment_out(da, aid))
    return out


def _ingest(dest: Path, name: str, redact: bool, fws, notes: list | None = None):
    """Assess one stored configuration and keep it for the session.

    Shared by upload and live collection, so the two ingest paths cannot
    drift into assessing the same device differently.
    """
    from ..pipeline import DeviceAssessment, DeviceIdentity, assess

    aid = uuid.uuid4().hex[:12]
    try:
        da = assess(dest, redact=redact, assessment_id=aid, frameworks=fws)
    except Exception as exc:                       # noqa: BLE001
        # A refusal is a RESULT, not a failure: the tool declining an
        # encrypted backup is the behaviour we want to surface, with the
        # reason attached.
        da = DeviceAssessment(identity=DeviceIdentity(source_file=name),
                              supported=False,
                              notes=[f"{type(exc).__name__}: {exc}"])
    if notes and isinstance(da.notes, list):
        da.notes[0:0] = list(notes)
    _STORE.put(aid, da, dest, name=name, redact=redact, frameworks=fws)
    return aid, da


# --------------------------------------------------------- live collection
@app.get("/collect/profiles", tags=["assess"])
def collect_profiles():
    """Platforms live collection supports, and exactly what it will send."""
    from ..collect.live import PROFILES

    return [{"platform": k, "netmiko": p.netmiko, "napalm": p.napalm,
             "commands": list(p.commands)} for k, p in PROFILES.items()]


@app.post("/collect", response_model=list[AssessmentOut], tags=["assess"])
def collect_live(body: CollectIn):
    """Pull a running configuration over SSH with read-only commands, then
    assess it exactly as an upload. Credentials are used once, never stored.

    422 bad request or unsupported platform; 503 SSH library not installed;
    502 the device could not be reached, refused the login, or sent nothing.
    """
    from ..collect import live
    from ..frameworks.selection import normalise

    # `from None` throughout: a chained traceback is one more place a
    # credential could surface.
    try:
        fws = normalise(body.frameworks)
        c = live.collect(
            body.host, body.platform, body.username,
            body.password.get_secret_value(), port=body.port, driver=body.driver,
            secret=body.secret.get_secret_value() if body.secret else None)
    except live.CollectorUnavailable as exc:
        raise HTTPException(503, str(exc)) from None
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    except live.CollectionError as exc:
        raise HTTPException(502, str(exc)) from None

    dest = live.write_collected(c, _UPLOADS)
    aid, da = _ingest(dest, f"{c.host} (live)", body.redact, fws, notes=[c.note()])
    got = da.identity.platform
    if got and got != body.platform and isinstance(da.notes, list):
        da.notes.append(
            f"Requested platform {body.platform!r}, but the configuration "
            f"fingerprints as {got!r}; it was assessed as {got!r}.")
    return [assessment_out(da, aid)]


# ------------------------------------------------------------ monitoring
_MONITORS: dict = {}


def _monitor():
    """One monitor per data directory, so tests never touch real jobs."""
    from ..collect.monitor import Monitor

    d = str(_STORE.data_dir)
    if d not in _MONITORS:
        _MONITORS[d] = Monitor(d)
    return _MONITORS[d]


def _monitor_ingest(dest, name, redact, fws, notes):
    return _ingest(dest, name, redact, fws, notes=notes)


@app.on_event("startup")
def _start_monitor():
    # Opt-in: a scheduler is a background thread that logs in to devices.
    if _os_env("NCSA_MONITOR") == "1":
        _monitor().start(_monitor_ingest, _UPLOADS)


@app.on_event("startup")
def _warm_imports():
    """Import the heavy modules once, here, in the main thread.

    Endpoints declared with `def` run in a threadpool, and a dashboard page
    calls several of them at once -- the Frameworks page opens with five. Two
    threads importing the same module for the FIRST time is a real deadlock in
    CPython's per-module import lock, and it surfaced as `_DeadlockError` and a
    500 on a page that answered perfectly when called one request at a time.
    The concurrency was always allowed; nothing had exercised it before.

    Importing them here means no request is ever the first, so the race cannot
    happen. This is import cost only -- no catalogue is parsed and no file is
    read; `load_all()` still decides that when a route asks for it.
    """
    from ..engine import rules  # noqa: F401
    from ..extended import cve, wireless  # noqa: F401
    from ..frameworks import ai_security, attack, selection  # noqa: F401
    from ..frameworks.registry import load_all  # noqa: F401


@app.post("/monitor", tags=["monitor"])
def create_monitor(body: MonitorIn):
    """Re-collect a device every N minutes (>= 15) and alert on drift."""
    from ..frameworks.selection import normalise

    try:
        job = _monitor().add_job(
            host=body.host, platform=body.platform, username=body.username,
            password=body.password.get_secret_value(),
            secret=body.secret.get_secret_value() if body.secret else None,
            port=body.port, driver=body.driver,
            interval_minutes=body.interval_minutes,
            frameworks=normalise(body.frameworks), redact=body.redact)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    return job


@app.get("/monitor", tags=["monitor"])
def list_monitors():
    """Monitoring jobs (never their credentials) and the latest alerts."""
    m = _monitor()
    return {"jobs": m.jobs(), "alerts": m.alerts()}


@app.post("/monitor/{job_id}/run", tags=["monitor"])
def run_monitor(job_id: str):
    """Run a monitoring job now: collect, assess, compare, alert."""
    from ..collect.live import CollectorUnavailable

    try:
        return _monitor().run(job_id, _monitor_ingest, _UPLOADS)
    except KeyError:
        raise HTTPException(404, f"no monitoring job {job_id!r}") from None
    except CollectorUnavailable as exc:
        raise HTTPException(503, str(exc)) from None


@app.delete("/monitor/{job_id}", tags=["monitor"])
def delete_monitor(job_id: str):
    if not _monitor().delete(job_id):
        raise HTTPException(404, f"no monitoring job {job_id!r}")
    return {"deleted": job_id}


@app.get("/assessment/{aid}", response_model=AssessmentOut, tags=["assess"])
def get_assessment(aid: str):
    da, _ = _get(aid)
    return assessment_out(da, aid)


@app.get("/assessments", tags=["assess"])
def list_assessments():
    # From the database, so assessments from before a restart are listed
    # without re-running any of them. Each carries its framework scores, so
    # this is also the fleet view.
    return _STORE.summaries()


@app.get("/fleet.csv", tags=["assess"])
def fleet_csv():
    """Every assessed device with its overall and per-framework scores."""
    import csv
    import io

    from fastapi.responses import Response

    buf = io.StringIO()
    w = csv.writer(buf)
    fws = ["nist_800_53", "iso_27001", "stig", "cis"]
    w.writerow(["assessment_id", "device", "vendor", "platform", "assessed_at",
                "score_pct", "coverage_pct"] + [f"{k}_score_pct" for k in fws])
    for s in _STORE.summaries():
        if not s.get("supported", True):
            continue
        f = s.get("frameworks") or {}
        w.writerow([s["assessment_id"], s["device"], s["vendor"], s["platform"],
                    s["assessed_at"], s["score_pct"], s["assessed_pct"]]
                   + ["" if f.get(k) is None else f[k] for k in fws])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition":
                             'attachment; filename="ncsa_fleet.csv"'})


# ------------------------------------------------------------- remediation
@app.get("/assessment/{aid}/remediation", response_model=RemediationOut,
         tags=["remediate"])
def get_remediation(aid: str):
    """Ordered, lockout-checked CLI steps. Steps that would sever the only
    management path are returned in `deferred`, never in the script."""
    from ..engine.remediate import build_plan
    from ..engine.rules import load_rules

    da, _ = _get(aid)
    controls = {c.id: c for c in load_rules(
        "rules", platform=da.identity.platform)}
    sbm = _sbm_for(da)
    return remediation_out(build_plan(da, controls_by_id=controls, sbm=sbm))


@app.get("/assessment/{aid}/baseline", tags=["report"])
def get_baseline(aid: str):
    """The device's Security Baseline Model as JSON.

    The machine-readable counterpart to the PDF report: the same assessment,
    shaped for a pipeline. Every field carries its observation state, so a
    consumer can tell a value we READ from one we assumed.
    """
    from ..schema.export import baseline

    da, _ = _get(aid)
    return baseline(da, aid)


@app.get("/assessment/{aid}/report", tags=["report"])
def get_report(aid: str, format: str = Query("pdf", pattern="^(pdf|html)$"),
               framework: str | None = Query(None)):
    """The formal assessment report: device details and every result.

    Monochrome and typeset for print, because this is the artefact an auditor
    signs against. Every figure is computed from the assessment when the
    report is rendered -- nothing is cached, and nothing is written by hand.

    `framework` (cis, nist_800_53, stig, iso_27001) produces the report for
    ONE framework: the same configuration re-assessed with only that
    framework selected -- exactly what selecting it at upload does, so the
    scoped report cannot disagree with a scoped assessment.
    """
    from fastapi.responses import HTMLResponse

    from ..frameworks.selection import normalise
    from ..report import build_report, write_pdf

    da, path = _get(aid)
    suffix, fw_key = "", None
    if framework:
        try:
            key = normalise([framework])[0]
        except (ValueError, TypeError, IndexError) as exc:
            raise HTTPException(422, str(exc) or "unknown framework") from None
        from ..pipeline import assess

        meta = _STORE.meta(aid) or {}
        da = assess(path, redact=meta.get("redact", True), assessment_id=aid,
                    frameworks=[key])
        suffix, fw_key = f"_{key}", key
    device = (da.identity.hostname or da.identity.source_file or aid)
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in device)

    if format == "html":
        return HTMLResponse(build_report(da, aid))

    out = _UPLOADS / f"NCSA_Report_{safe}_{aid}{suffix}.pdf"
    try:
        write_pdf(da, out, aid)
    except RuntimeError as exc:
        # PDF rendering needs a Chromium binary. Saying so beats a 500, and
        # the HTML form of the same report is always available.
        raise HTTPException(503, {
            "error": str(exc),
            "alternative": f"/assessment/{aid}/report?format=html",
        }) from exc
    # Tamper evidence: the exact bytes issued are hashed and signed, and the
    # record lets /verify-report say later whether a PDF is still this one.
    signed = _signer().sign(out.read_bytes(), aid=aid, framework=fw_key)
    return FileResponse(str(out), media_type="application/pdf",
                        filename=out.name,
                        headers={"X-NCSA-Report-SHA256": signed["sha256"],
                                 "X-NCSA-Signature": signed["signature"]})


_SIGNERS: dict = {}


def _signer():
    """One signer per data directory, created on first use -- so a test
    suite pointed at a temporary store never touches the real signing key."""
    from ..report.signing import ReportSigner

    d = str(_STORE.data_dir)
    if d not in _SIGNERS:
        _SIGNERS[d] = ReportSigner(d)
    return _SIGNERS[d]


@app.get("/report-signing-key", tags=["report"])
def report_signing_key():
    """The PUBLIC key reports are signed with. Anyone can verify a report
    offline with this and the X-NCSA-Signature header; no secret needed."""
    return {"algorithm": "Ed25519 over the hex SHA-256 of the PDF",
            "public_key_pem": _signer().public_pem}


@app.post("/verify-report", tags=["report"])
async def verify_report(file: UploadFile = File(...)):
    """Is this PDF a report this engine issued, byte for byte?"""
    data = await file.read()
    if len(data) > MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(413, "file too large")
    return _signer().verify(data)


@app.post("/assessment/{aid}/blast-radius", tags=["analyse"])
def get_blast_radius(aid: str, origin_zone: str = Query(""),
                     origin_address: str = Query("any")):
    """If this segment is compromised, what else can be reached?

    Walks the policy outward from a foothold and names the rule permitting
    each step. Exposure only -- policy permitting a packet says nothing about
    whether a service is listening, patched or authenticated.
    """
    from ..topology.blast import blast_radius

    da, _ = _get(aid)
    _require_graph(da, "blast radius")
    out = blast_radius(da.graph, origin_zone=origin_zone,
                       origin_address=origin_address,
                       origin_members=_zone_members(da, origin_zone)).to_json()

    # Name the techniques from the bundle rather than from the engine's map:
    # blast.py carries ids only, so a technique cannot be described here from
    # memory and drift from what MITRE publishes. An id the bundle does not
    # know is dropped, not guessed.
    from ..frameworks.attack import load_techniques

    try:
        known = load_techniques()
    except Exception:            # noqa: BLE001 -- bundle absent is not a finding
        known = {}
    for step in out.get("reachable", []):
        tags = []
        for tid in step.pop("attack_ids", []):
            entry = known.get(tid)
            name = entry.get("name") if isinstance(entry, dict) else entry
            if name:
                tags.append({"id": tid, "name": name})
        step["attack"] = tags
    return out


def _zone_members(da, zone: str):
    """What sits in a zone today: interfaces, plus access points for WLAN.

    None when the device model is unavailable -- "could not tell" must not
    be reported as "empty", or every path would be mislabelled latent.
    """
    from ..topology.blast import zone_members
    return zone_members(da, zone)


@app.get("/assessment/{aid}/zones", tags=["analyse"])
def get_zones(aid: str):
    """Zones a blast radius can start from, read from the policy itself."""
    da, _ = _get(aid)
    _require_graph(da, "zone listing")
    g = da.graph
    src = sorted({z for r in g.rules for z in r.source_zones if z})
    dst = sorted({z for r in g.rules for z in r.destination_zones if z})
    return {"source_zones": src, "destination_zones": dst,
            "untrusted": sorted(g.untrusted_zones)}


@app.get("/assessment/{aid}/extended", tags=["analyse"])
def get_extended(aid: str):
    """VPN and wireless checks, reported beside the compliance score.

    They never change the score or coverage of the assessment: see
    ncsa/extended/model.py for why.
    """
    from ..extended.run import run_extended

    da, _ = _get(aid)
    return run_extended(da)


class WhatIfRequest(BaseModel):
    fix_controls: list[str] = []
    disable_rules: list[str] = []
    origin_zone: str = ""


@app.post("/assessment/{aid}/what-if", tags=["analyse"])
def what_if(aid: str, req: WhatIfRequest):
    """Re-score a COPY of the assessment with the requested changes applied.

    The stored assessment and the device are untouched; every response carries
    that label. Requests that cannot be simulated honestly come back under
    `rejected` with the reason; changes that did not close what they appear to
    close (an IPv6 twin still open) come back under `warnings`.
    """
    from ..whatif import simulate

    da, _ = _get(aid)
    try:
        return simulate(da, fix_controls=req.fix_controls,
                        disable_rules=req.disable_rules,
                        origin_zone=req.origin_zone,
                        origin_members=(_zone_members(da, req.origin_zone)
                                        if req.origin_zone else None))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@app.get("/assessment/{aid}/topology-map", tags=["analyse"])
def get_topology_map(aid: str, redact: bool = Query(True)):
    """Zones, LANs, WLANs, uplinks and tunnels as data for a 2-D figure.

    Derived from the configuration, not live discovery. Public addresses, site
    names and the hostname are redacted unless `redact=false`.
    """
    from ..topology.map import build_map

    da, _ = _get(aid)
    return build_map(da, redact=redact)


@app.get("/assessment/{aid}/topology-map.svg", tags=["analyse"])
def get_topology_svg(aid: str, redact: bool = Query(True),
                     solid: bool = Query(True)):
    """The same figure, rendered. One layout serves the UI and the export.

    `solid` extrudes every zone and the device into a 3-D slab. Flat is kept
    for print: the shading that separates boxes on screen turns to mud on a
    monochrome printer.
    """
    from fastapi.responses import Response

    from ..topology.map import build_map, render_svg

    da, _ = _get(aid)
    return Response(render_svg(build_map(da, redact=redact), solid=solid),
                    media_type="image/svg+xml")


@app.get("/assessment/{aid}/graph", tags=["analyse"])
def get_graph(aid: str, limit: int = Query(500, le=5000)):
    """The policy object graph itself -- objects, rules and how they resolve.

    Everything else in the analyse group is a CONCLUSION drawn from this graph:
    rule hygiene, reachability and recertification all read it. Until now it
    was computed on every assessment and visible nowhere, so a reviewer could
    see the verdicts but not the reconstruction they came from -- and the
    number of objects was the only evidence it existed at all.

    Each rule is returned with its references RESOLVED, so a reader can check
    `LAN Subnets -> 10.10.0.0/24` rather than take the verdict on trust. A
    reference that did not resolve is marked, not omitted: an unresolved group
    silently rendered as an empty list is how a policy reads as tidier than it
    is.
    """
    from ..graph.model import NodeKind
    from ..graph.resolve import Resolver

    da, _ = _get(aid)
    _require_graph(da, "the policy object graph")
    g = da.graph
    r = Resolver(g)

    def resolve_side(names):
        out = []
        for res in (r.resolve(n) for n in names):
            out.append({"name": res.name, "state": res.state.value,
                        "values": res.values, "path": res.path,
                        "detail": res.detail})
        return out

    rules = []
    for rule in sorted(g.rules, key=lambda x: (x.order, x.id))[:limit]:
        rules.append({
            "id": rule.id, "name": rule.name, "order": rule.order,
            "enabled": rule.enabled, "action": rule.action,
            "source_zones": rule.source_zones,
            "destination_zones": rule.destination_zones,
            "source": resolve_side(rule.source),
            "destination": resolve_side(rule.destination),
            "services": resolve_side(rule.services),
            "logging": rule.logging, "hit_count": rule.hit_count,
            # Why a port question cannot be decided by this rule alone --
            # App-ID, negation, a schedule, or a program on a host firewall.
            "undecidable_for_ports": rule.program,
            "evidence": [e.model_dump(mode="json") for e in rule.evidence[:2]],
        })

    objects = []
    for n in list(g.nodes.values())[:limit]:
        objects.append({
            "name": n.name, "kind": n.kind.value, "values": n.values,
            "members": n.members, "attrs": n.attrs,
            "evidence": [e.model_dump(mode="json") for e in n.evidence[:1]],
        })

    by_kind: dict = {}
    for n in g.nodes.values():
        by_kind[n.kind.value] = by_kind.get(n.kind.value, 0) + 1

    return {
        "summary": {
            "objects": len(g.nodes), "rules": len(g.rules),
            "by_kind": by_kind,
            "zones": [n.name for n in g.of_kind(NodeKind.ZONE)],
            "untrusted_zones": sorted(g.untrusted_zones),
            "interfaces": g.zones_of_interface,
        },
        # `ordered` false means the platform does not evaluate top-to-bottom,
        # so shadow analysis is suppressed. Stating it here keeps a reader from
        # reading the absence of shadow findings as a tidy policy.
        "ordered": not g.unordered,
        "default_action": g.default_action,
        "default_action_observed": g.default_action_observed,
        "objects_shown": objects,
        "rules_shown": rules,
    }


@app.get("/assessment/{aid}/hygiene", tags=["analyse"])
def get_hygiene(aid: str, limit: int = Query(400, le=5000)):
    """Dead, shadowed, redundant and over-broad policy.

    Unevaluable rules are returned alongside the findings: a rule we could not
    resolve is not a clean rule, and a summary that hid them would report a
    policy as tidier than we can actually confirm.
    """
    from ..graph.hygiene import analyse

    da, _ = _get(aid)
    if da.graph is None:
        # Deliberately 200, not 422: a dashboard asks this for every device and
        # should not have to special-case an expected gap. But zero findings
        # here does NOT mean a tidy policy, so the response says the analysis
        # never ran rather than leaving a reader to infer it from a note.
        from ..pipeline import GRAPH_BUILDERS

        return {"analysis_ran": False, "not_a_finding": True,
                "summary": None, "findings": [],
                "reason": f"no rule-graph builder is registered for platform "
                          f"{da.identity.platform!r}, so rule hygiene could "
                          f"not be attempted; this is a gap in our coverage, "
                          f"not a statement about the device",
                "supported_platforms": [l for _, l in GRAPH_BUILDERS.values()]}
    rep = analyse(da.graph)
    return {"analysis_ran": True, "summary": rep.summary(),
            "findings": [f.to_json() for f in rep.findings[:limit]],
            "unevaluable": rep.unevaluable[:50]}


# ---------------------------------------------------------------- training
@app.get("/assessment/{aid}/training", response_model=list[TrainingCandidateOut],
         tags=["training"])
def get_training_queue(aid: str, limit: int = Query(200, le=2000),
                       suggest: bool = Query(True)):
    """Deliverable 2: what the administrator is asked to teach the system.

    Deduplicated by setting NAME, because one approval covers every instance
    of that name on every device of the platform. 84,214 unmapped records is a
    number that makes people give up; the same gap is 841 names.
    """
    from ..training import build_queue

    da, _ = _get(aid)
    return [candidate_out(c)
            for c in build_queue(da, with_suggestions=suggest, limit=limit)]


@app.post("/training/approve", response_model=ApprovalOut, tags=["training"])
def approve_mapping(body: ApprovalIn):
    """A human decision, regression-gated and hash-chained.

    The mapping is written, the golden corpus is re-run, and if any verified
    result would change the write is REVERTED and the approval refused with
    the specific expectation that broke. A blocked approval leaves nothing
    behind -- otherwise the gate itself becomes a way to poison the tool.
    """
    from ..ai.registry import MappingRegistry
    from ..training.apply import approve

    try:
        registry = MappingRegistry(str(APPROVALS_LOG))
    except Exception:                                  # noqa: BLE001
        registry = None

    if body.vendor:
        problem = _check_new_vendor(body)
        if problem:
            return ApprovalOut(accepted=False, reason=problem)

    r = approve(body.setting_name, body.field, body.platform, body.approved_by,
                value_hint=body.value_hint, registry=registry, kind=body.kind,
                vendor=body.vendor, reader=body.reader,
                signature=body.signature or None)
    return ApprovalOut(accepted=r.accepted, reason=r.reason,
                       registry_version=r.registry_version,
                       regression=r.to_json())


# ------------------------------------------------------- reachability
def _check_new_vendor(body) -> str | None:
    """Refuse a new-vendor signature that cannot work, before writing anything.

    Two failures are caught here because the pack loader cannot see them:
      * a signature that does not match the device's OWN file, so its next
        upload would be refused again, and
      * a signature that also matches another vendor's sample, so the taught
        pack would capture configs it knows nothing about.
    """
    import json as _json
    import re as _re

    if not body.assessment_id:
        return "teaching a new vendor needs the assessment it came from"
    da, dest = _get(body.assessment_id)
    known = (da.identity.platform or "").upper()
    if known and known != "UNKNOWN" and body.platform != da.identity.platform:
        return (f"this file was recognised as platform {da.identity.platform!r}; "
                "the new pack must use that platform id or it will never be selected")
    sigs = [s for s in (body.signature or []) if s.strip()]
    if not sigs:
        return "a signature is required so the next upload of this vendor is recognised"

    def matches(path) -> bool:
        try:
            raw = Path(path).read_text(encoding="utf-8", errors="replace")
        except Exception:                              # noqa: BLE001
            return False
        try:
            if body.reader == "json":
                from jsonpath_ng.ext import parse
                data = _json.loads(raw)
                return all(parse(s).find(data) for s in sigs)
            head = "\n".join(raw.splitlines()[:400])
            return all(_re.search(s, head, _re.M) for s in sigs)
        except Exception:                              # noqa: BLE001
            return False

    if not matches(dest):
        return ("the signature does not match this device's own file, so its "
                "next upload would be refused again")
    from ..engine.fingerprint import fingerprint_file

    for other in sorted(Path("samples").rglob("*")):
        if not other.is_file() or other.resolve() == Path(dest).resolve():
            continue
        if not matches(other):
            continue
        # A sample of the SAME vendor matching is the signature working. Only
        # a file recognised as some OTHER platform is a capture -- the first
        # version refused SONiC's own sample as "another vendor".
        try:
            theirs = fingerprint_file(other).platform
        except Exception:                              # noqa: BLE001
            theirs = "UNKNOWN"
        if theirs in (body.platform, da.identity.platform):
            continue
        return (f"the signature also matches {other.as_posix()}, which is "
                f"recognised as {theirs!r} -- too generic to identify this vendor")
    return None


class RejectIn(BaseModel):
    setting_name: str
    platform: str
    rejected_by: str
    reason: str = ""


@app.post("/training/reject", tags=["training"])
def reject_mapping(body: RejectIn):
    """Record that a person declined to map a setting; it leaves the queue."""
    from ..training.apply import reject

    try:
        return reject(body.setting_name, body.platform, body.rejected_by, body.reason)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@app.get("/training/learned", tags=["training"])
def learned_mappings():
    """Everything the training interface has taught, per platform."""
    from ..training.apply import learned_summary

    return learned_summary()


@app.get("/schema/fields", tags=["training"])
def schema_fields():
    """The vendor-neutral fields a setting can be mapped to, with the
    controls that read each one -- so an administrator can see what an
    approval will actually change."""
    from ..engine.rules import load_rules
    from ..schema.sbm import FIELD_TYPES

    readers: dict = {}
    for c in load_rules("rules"):
        readers.setdefault(c.field, []).append(c.id)
    return [{"field": f, "type": t, "domain": f.split(".")[0],
             "controls": sorted(readers.get(f, []))}
            for f, t in sorted(FIELD_TYPES.items())]


@app.get("/assessment/{aid}/training/context", tags=["training"])
def training_context(aid: str):
    """What the training page needs to know before a first approval."""
    import json as _json
    import re as _re

    from ..pipeline import guess_reader, load_packs

    da, dest = _get(aid)
    platform = da.identity.platform or ""
    known = bool(platform) and platform.upper() != "UNKNOWN"
    has_pack = any(p.platform == platform for p in load_packs())
    fp = da.fingerprint
    reader = (fp.reader if fp is not None and fp.reader else None) or guess_reader(dest)

    signature: list = []
    try:
        raw = Path(dest).read_text(encoding="utf-8", errors="replace")
        if reader == "json":
            data = _json.loads(raw)
            keys = [k for k in (data if isinstance(data, dict) else {})
                    if not str(k).startswith("_")]
            caps = [k for k in keys if str(k).isupper()] or keys
            signature = [f"$.{caps[0]}"] if caps else []
        else:
            lines = [l.strip() for l in raw.splitlines() if l.strip()
                     and not l.strip().startswith(("!", "#"))]
            pick = next((l for l in lines if _re.search(
                r"version|software|model|firmware", l, _re.I)),
                lines[0] if lines else "")
            if pick:
                signature = ["^" + _re.escape(pick[:60])]
    except Exception:                                  # noqa: BLE001
        pass

    return {"supported": da.supported, "has_pack": has_pack,
            "vendor": da.identity.vendor or "", "platform": platform,
            "platform_known": known, "reader": reader,
            "suggested_signature": signature,
            "source_file": da.identity.source_file,
            "coverage": da.coverage() if da.assessment else None}


@app.post("/assessment/{aid}/reassess", response_model=AssessmentOut,
          tags=["training"])
def reassess(aid: str):
    """Run the same file again with everything learned since.

    The proof that training changes behaviour without a redeploy: nothing is
    restarted, the next assessment simply reads the learned mappings.
    """
    from ..pipeline import assess

    _old, dest = _get(aid)
    meta = _STORE.meta(aid) or {}
    new_aid = uuid.uuid4().hex[:12]
    redact = meta.get("redact", True)
    fws = meta.get("frameworks")
    da = assess(dest, redact=redact, assessment_id=new_aid, frameworks=fws)
    _STORE.put(new_aid, da, dest, name=meta.get("name") or Path(dest).name,
               redact=redact, frameworks=fws)
    return assessment_out(da, new_aid)


@app.post("/assessment/{aid}/reach", tags=["analyse"])
def ask_reachability(aid: str, q: ReachQueryIn):
    """Would this device permit that traffic? First-match-wins, with the rule.

    The answer names the rule that decided it, so a reviewer can check the
    verdict rather than take it. A device with no object graph cannot answer
    at all, and says so instead of returning a default.
    """
    from ..graph.reach import Query, ask

    da, _ = _get(aid)
    _require_graph(da, "reachability")
    answer = ask(da.graph, Query(
        source=q.source, destination=q.destination, port=q.port,
        protocol=q.protocol, source_zone=q.source_zone,
        destination_zone=q.destination_zone))
    return {"answer": answer.to_json(), "explain": answer.explain()}


# ----------------------------------------------------------- topology
@app.post("/topology", tags=["topology"])
def build_topology(body: TopologyIn):
    """A fabric from several assessed devices, and an end-to-end question.

    Adjacency is INFERRED from shared subnets rather than read from the wire.
    That is true of most networks and false in some, so the caveat travels on
    every answer rather than sitting in documentation nobody opens.
    """
    from ..topology.fabric import Fabric

    fabric = Fabric()
    added, skipped = [], []
    for aid in body.assessment_ids:
        da, _ = _get(aid)
        try:
            fabric.add(da)
            added.append({
                "assessment_id": aid,
                "device": da.identity.hostname or da.identity.source_file})
        except Exception as exc:                          # noqa: BLE001
            # Whatever the cause -- unreadable addressing, an unsupported
            # platform -- it is a REASON, and reporting it beats silently
            # dropping the device from the fabric.
            skipped.append({"assessment_id": aid,
                            "reason": f"{type(exc).__name__}: {exc}"})

    out = {"devices": added, "skipped": skipped,
           "summary": fabric.summary(), "adjacency": fabric.adjacency()}

    if body.source and body.destination:
        answer = fabric.can_reach(body.source, body.destination,
                                  port=body.port, protocol=body.protocol)
        out["path"] = answer.to_json()
        out["explain"] = answer.explain()
    return out


@app.get("/assessment/{aid}/interfaces", tags=["topology"])
def get_interfaces(aid: str):
    """The addressing that topology is inferred from.

    Populated whether or not the upload was redacted. Redaction pseudonymises
    each address into a valid, stable, prefix-preserving stand-in, so the
    interface list, its zones and its subnet structure all survive; only the
    numbers are not the real ones.
    """
    from ..topology.interfaces import RedactedAddressing, extract

    da, _ = _get(aid)
    try:
        # strict: never answer "no interfaces" for a device that has them. This
        # is now a backstop rather than the expected path -- redaction used to
        # blank octets, which made every address unparseable and turned a
        # ten-interface firewall into an empty table.
        out = {"interfaces": [i.to_json() for i in extract(da, strict=True)]}
        if getattr(getattr(da, "document", None), "redacted", False):
            out["note"] = ("This upload was redacted: addresses shown are "
                           "stable pseudonyms, not the device's real "
                           "addressing. Interfaces on one real subnet remain "
                           "on one subnet here, so the structure is accurate "
                           "even though the numbers are not.")
        return out
    except RedactedAddressing:
        return {"interfaces": [],
                "note": "No addressing could be read from this redacted "
                        "upload, so topology cannot be inferred from it. The "
                        "device may well have interfaces -- we cannot see them "
                        "here. Re-run the assessment with redaction off."}


# ------------------------------------------------------ change tracking
@app.post("/assessment/{aid}/snapshot", tags=["change"])
def take_snapshot(aid: str):
    """Record this assessment so a later one can be compared against it."""
    from ..diff.compare import save, snapshot

    da, _ = _get(aid)
    snap = snapshot(da)
    path = save(snap)
    return {"device_key": snap.device_key, "saved_to": str(path),
            "taken_at": str(snap.taken_at)}


@app.get("/assessment/{aid}/diff", tags=["change"])
def get_diff(aid: str):
    """What changed since the last snapshot of THIS device.

    Device change and analysis change are reported separately. A new engine
    version altering a verdict is not configuration drift, and conflating the
    two would have an operator chasing a change nobody made.
    """
    from dataclasses import asdict

    from ..diff.compare import compare_latest

    da, _ = _get(aid)
    report = compare_latest(da)
    if report is None:
        return {"note": "no earlier snapshot for this device; "
                        "take one first via POST .../snapshot"}
    # DiffReport is a dataclass, not a pydantic model. asdict walks the nested
    # ControlChange list; summary() and explain() are what an operator reads
    # first, so they travel with the raw delta rather than being recomputed.
    return {**asdict(report), "summary": report.summary(),
            "explain": report.explain()}


@app.get("/assessment/{aid}/history", tags=["change"])
def get_history(aid: str):
    """Every recorded snapshot of THIS device, oldest first: the overall
    score, coverage and each framework's own score over time.

    Recording is explicit (POST .../snapshot or GET .../diff); viewing the
    history never writes one.
    """
    from ..diff.compare import _device_key, history

    da, _ = _get(aid)
    return [{"taken_at": s.taken_at,
             "score_pct": (s.coverage or {}).get("score_pct"),
             "assessed_pct": (s.coverage or {}).get("assessed_pct"),
             "frameworks": s.frameworks or {},
             "config_sha256": (s.config_sha256 or "")[:12],
             "analysis_version": s.analysis_version}
            for s in history(_device_key(da.identity))]


# ----------------------------------------------------- recertification
@app.get("/assessment/{aid}/recertification", tags=["workflow"])
def get_recertification(aid: str, expiring_within: int = Query(30, le=365)):
    """Which rules need re-certifying, and which look like deletion candidates."""
    from ..graph.hygiene import analyse
    from ..workflow.recert import Register, deletion_candidates, review

    da, _ = _get(aid)
    _require_graph(da, "recertification")
    register = Register()
    hygiene = analyse(da.graph)
    return {
        "due": [f.to_json()
                for f in review(da, register, hygiene=hygiene,
                                expiring_within=expiring_within)],
        # deletion_candidates already returns plain dicts, unlike review()
        # which returns RecertFinding objects.
        "deletion_candidates": deletion_candidates(da, hygiene, register),
    }


# ----------------------------------------------------- log correlation
@app.post("/assessment/{aid}/logs", tags=["analyse"])
async def correlate_logs(aid: str, file: UploadFile = File(...),
                         quiet_days: int = Query(90, le=3650)):
    """Is an unused rule genuinely unused, or was its counter reset?

    A rule with no hits is only dead if the logs covering that window agree.
    Without them the honest answer is that we do not know, and the verdicts
    below say which of the two it is.
    """
    from ..graph.hygiene import analyse
    from ..logs.correlate import corroborate, parse

    da, _ = _get(aid)
    if da.graph is None:
        raise HTTPException(
            422, f"no object graph for platform {da.identity.platform!r}")
    raw = (await file.read()).decode("utf-8", errors="replace")
    summary = parse(raw.splitlines())
    analyse(da.graph)                       # hit counters populate the graph
    return {"log_summary": summary.to_json(),
            "corroboration": [
                c.to_json()
                for c in corroborate(da.graph, summary, quiet_days=quiet_days)]}


# --------------------------------------------------------- corroboration
@app.get("/assessment/{aid}/consensus", tags=["analyse"])
def get_consensus(aid: str):
    """Where an independent second method disagrees with the first.

    Agreement only means something if both methods actually looked at the same
    thing, so a comparison with no shared paths is reported as inconclusive
    rather than as agreement.
    """
    da, _ = _get(aid)
    return {"consensus": da.consensus, "parser_agreement": da.parser_agreement}


# ------------------------------------------------------- host firewall
def _hostfw_report(fw, reach: "ReachQueryIn | None" = None) -> dict:
    """Graph + hygiene for a host firewall, using the appliance analysers.

    The whole point of the vendor-neutral graph is that a laptop and an
    appliance take the same code path once their rules are SecurityRule
    objects. Two host semantics survive into the response rather than being
    smoothed away: Windows Firewall has NO evaluation order, so shadow
    analysis is suppressed and `ordered` says so; and a profile whose default
    action was never observed is reported as unobserved, not assumed to block.
    """
    from ..graph.hostfw_builder import build
    from ..graph.hygiene import analyse

    g = build(fw)
    rep = analyse(g)
    out = {
        "host": {"source": fw.source_file, "os": fw.os,
                 "collected_at": fw.collected_at,
                 "rules_read": len(fw.rules),
                 "profiles_read": len(fw.profiles)},
        "ordered": not getattr(g, "unordered", False),
        "default_action_observed": getattr(g, "default_action_observed", None),
        "untrusted_zones": sorted(getattr(g, "untrusted_zones", []) or []),
        "hygiene": {"summary": rep.summary(),
                    "findings": [f.to_json() for f in rep.findings[:400]],
                    "unevaluable": rep.unevaluable[:50]},
    }
    if getattr(g, "unordered", False):
        out["note"] = ("this platform does not evaluate rules top-to-bottom, "
                       "so shadow analysis was not run; its absence from the "
                       "findings is correct, not a clean result")
    if reach is not None:
        from ..graph.reach import Query, ask

        a = ask(g, Query(source=reach.source, destination=reach.destination,
                         port=reach.port, protocol=reach.protocol,
                         source_zone=reach.source_zone,
                         destination_zone=reach.destination_zone))
        out["reach"] = {"answer": a.to_json(), "explain": a.explain()}
    return out


@app.post("/hostfw/iptables", tags=["host"])
async def assess_iptables(file: UploadFile = File(...)):
    """`iptables-save` output in, rule hygiene out. No shell, no host access."""
    from ..readers.hostfw import parse_iptables

    text = (await file.read()).decode("utf-8", "replace")
    if not text.strip():
        raise HTTPException(400, "empty upload")
    fw = parse_iptables(text, host=file.filename or "uploaded")
    if not fw.rules:
        raise HTTPException(422, {
            "error": "no iptables rules were parsed from this upload",
            "reason": "expected `iptables-save` output; a rule count of zero "
                      "here means we could not read the file, which is not "
                      "the same as a host with no rules",
            "not_a_finding": True})
    return _hostfw_report(fw)


@app.post("/hostfw/local", tags=["host"])
def assess_this_host(enable: bool = Query(
        False, description="must be true; this runs commands on the server")):
    """Assess the firewall of the machine RUNNING THIS API.

    Behind an explicit opt-in flag because, unlike every other endpoint, it
    reads the server itself rather than an uploaded file -- it shells out to
    `netsh`/`Get-NetFirewallRule` on Windows or `iptables-save` on Linux. That
    is a different trust decision from parsing an upload and is not something
    a caller should be able to trigger by accident.
    """
    if not enable:
        raise HTTPException(400, {
            "error": "refused: pass ?enable=true to assess the API host",
            "reason": "this endpoint inspects the server this API runs on, "
                      "not an uploaded configuration"})
    from ..readers.hostfw import collect

    try:
        fw = collect()
    except Exception as exc:                              # noqa: BLE001
        # Almost always insufficient privilege. Saying so beats a 500, and
        # beats returning an empty rule set that would read as "no rules".
        raise HTTPException(422, {
            "error": f"could not read this host firewall: "
                     f"{type(exc).__name__}: {exc}",
            "reason": "collection needs administrator/root; a failed "
                      "collection is reported, never returned as zero rules",
            "not_a_finding": True}) from exc
    return _hostfw_report(fw)


# -------------------------------------------------------------- frameworks
@app.get("/ai-governance", tags=["meta"])
def ai_governance():
    """How the AI *we* run is governed -- MITRE ATLAS and the NIST AI RMF.

    Deliberately NOT part of /frameworks. Those catalogues describe how a
    device should be configured; these describe how an AI system should be
    governed, and the AI system here is our own mapping suggester. Presenting
    them together would imply we audit firewalls against ATLAS, which would be
    meaningless -- ATLAS catalogues attacks on machine-learning systems.
    """
    from ..frameworks.ai_security import (GUARDRAIL_COVERAGE,
                                          INJECTION_SIGNATURES, load_atlas)

    techniques = mitigations = 0
    resolved = None
    try:
        kb = load_atlas("reference/ai_security/stix-atlas.json")
        techniques, mitigations = len(kb.techniques), len(kb.mitigations)
        claimed = {t for g in GUARDRAIL_COVERAGE for t in g["atlas"]}
        # Every identifier we cite is checked against the published bundle.
        # An invented technique id would be worse than none.
        resolved = {"claimed": len(claimed),
                    "resolve_in_atlas": len(claimed & set(kb.techniques))}
    except Exception:                                  # noqa: BLE001
        pass

    by_function: dict = {}
    for g in GUARDRAIL_COVERAGE:
        by_function.setdefault(g["ai_rmf"], []).append(g["guardrail"])

    return {
        "scope": "Governs the AI inside NCSA -- the mapping suggester that "
                 "reads untrusted configuration text. It does NOT assess the "
                 "audited device against these frameworks.",
        "atlas": {"techniques": techniques, "mitigations": mitigations,
                   "identifier_check": resolved},
        "ai_rmf_functions": by_function,
        "guardrails": GUARDRAIL_COVERAGE,
        "injection_signatures": len(INJECTION_SIGNATURES),
        "corpus_isolation": "Governance text is refused entry to the parser "
                            "corpus by assert_not_parser_corpus(). ATLAS is a "
                            "catalogue of attack descriptions; retrieval works "
                            "by similarity, so indexing it beside "
                            "configuration examples would let a line "
                            "mentioning 'inject' retrieve an attack as a "
                            "similar example.",
    }


# ----------------------------------------------------------------- memoising
# Two answers here are expensive to build and change only when a file on disk
# changes. The framework registry takes ~2 minutes to load even from its own
# cache, and ATT&CK coverage recomputes over every rule. Both were rebuilt on
# EVERY request, so a dashboard page that opens five panels at once paid the
# full price each time -- and paid it again on the next visit.
#
# The stamp is the source files' size and mtime, so a catalogue rebuild or an
# edited rule is picked up on the next request without restarting the engine.
# That matters more than the speed: a cache nobody can invalidate would answer
# from yesterday's catalogue and never say so.
_MEMO: dict[str, tuple] = {}


def _stamp(*paths: Path) -> tuple:
    """A cheap fingerprint of the files an answer was built from.

    Size and modification time, which is what make and pip settle for. A
    directory also carries its file count and total size, so a rule added or
    deleted is caught however fast it happened.

    The remaining limit: a file rewritten IN PLACE to the same size within one
    filesystem clock tick (~16 ms on Windows) lands on an identical stamp, and
    the held answer stays. Nothing here changes that fast -- the catalogue
    cache is rewritten after a ~20 minute parse and rules are edited by hand --
    so the alternative, hashing several megabytes on every request, would buy
    nothing real. Stated rather than hidden, because a cache that silently
    answers from a superseded catalogue is exactly the kind of confident wrong
    answer this tool exists to prevent.
    """
    out = []
    for p in paths:
        try:
            if p.is_dir():
                # Count and total size, not just the newest mtime: a rule file
                # added or deleted changes the count even when it lands in the
                # same clock tick as the last stamp, which mtime alone misses.
                n = total = newest = 0
                for f in p.rglob("*.yaml"):
                    st = f.stat()
                    n, total = n + 1, total + st.st_size
                    newest = max(newest, st.st_mtime_ns)
                out.append((n, total, newest))
            else:
                st = p.stat()
                out.append((st.st_size, st.st_mtime_ns))
        except OSError:
            out.append(None)      # absent is a state too, and a stable one
    return tuple(out)


def _memoised(key: str, stamp: tuple, build):
    hit = _MEMO.get(key)
    if hit is not None and hit[0] == stamp:
        return hit[1]
    value = build()
    _MEMO[key] = (stamp, value)
    return value


@app.get("/attack-coverage", tags=["meta"])
def attack_coverage():
    """Which MITRE ATT&CK techniques the control set stands in front of.

    ATT&CK describes the adversary; it is not a compliance framework, and no
    score is computed from it. Controls that prevent no specific technique are
    left untagged on purpose and counted as such.
    """
    from ..engine.rules import load_rules
    from ..extended.cve import CHECK_ID
    from ..extended.wireless import CHECKS
    from ..frameworks.attack import BUNDLE, coverage

    def build():
        ids = [c.id for c in load_rules("rules")]
        ids += (sorted(CHECKS) + [f"NCSA-X-VPN-00{i}" for i in range(1, 6)]
                + [CHECK_ID])
        return coverage(ids)

    return _memoised("attack", _stamp(Path("rules"), Path(BUNDLE)), build)


@app.get("/framework-controls", tags=["meta"])
def framework_controls(framework: str, ids: str = Query("")):
    """What a cited identifier actually says -- as far as its licence allows.

    "AU-2" tells an operator nothing. The catalogue knows it is "Event
    Logging", and for NIST and DISA STIG -- both public domain -- we may say
    so. CIS and ISO are identifier-only, so `citation()` returns the source
    document and the number and never the prose. That is the same rule the PDF
    report follows, enforced in one place rather than re-decided per surface.
    """
    from ..frameworks.models import Framework
    from ..frameworks.registry import CACHE_PATH, load_all

    try:
        fw = Framework(framework)
    except ValueError:
        raise HTTPException(
            422, f"unknown framework: {framework}") from None

    reg = _memoised("registry", _stamp(CACHE_PATH),
                    lambda: load_all("reference"))
    cat = reg.catalogs.get(fw)
    wanted = [i.strip() for i in ids.split(",") if i.strip()][:200]
    out: dict[str, str | None] = {}
    for i in wanted:
        entry = cat.by_id(i) if cat else None
        # None, not a guess: an id we cannot resolve is reported as such so the
        # page shows the bare identifier rather than inventing a description.
        out[i] = entry.citation() if entry else None
    return {"framework": framework, "controls": out}


@app.get("/frameworks", tags=["meta"])
def frameworks():
    from ..frameworks.registry import CACHE_PATH, load_all

    # Held until the catalogue cache file itself changes; see _memoised.
    reg = _memoised("registry", _stamp(CACHE_PATH),
                    lambda: load_all("reference"))
    return {"catalogs": {fw.value: len(cat.entries)
                         for fw, cat in reg.catalogs.items()},
            "note": "CIS and ISO entries are cited by identifier only; their "
                    "text is copyrighted and never leaves this machine."}


@app.get("/platforms", tags=["meta"])
def platforms():
    from ..pipeline import load_packs

    return [{"vendor": p.vendor, "platform": p.platform, "reader": p.reader,
             "mappings": len(p.mappings)} for p in load_packs()]


@app.get("/health", tags=["meta"])
def health():
    """Liveness, plus what this build can actually answer.

    Deliberately more than {"ok": true}. Several analyses -- rule hygiene,
    reachability, recertification -- need an object graph, and a graph is only
    built for platforms with a registered builder. Every other platform gets a
    truthful refusal instead. Publishing that list here means a caller can see
    the boundary before hitting it, and means the boundary is read from the
    code rather than from a slide that nobody re-checks.
    """
    from ..pipeline import GRAPH_BUILDERS, PACK_LOAD_ERRORS, load_packs

    packs = load_packs()          # repopulates PACK_LOAD_ERRORS
    return {
        # A pack that will not load is OUR fault, and it silently removes a
        # platform from the supported list. `ok` reports it rather than
        # leaving a device to be assessed with no pack and no explanation.
        "ok": not PACK_LOAD_ERRORS,
        "pack_load_errors": list(PACK_LOAD_ERRORS),
        "assessments": len(_STORE),
        "platforms_parsed": sorted({p.platform for p in packs}),
        "graph_analyses": {
            "capabilities": ["rule_hygiene", "reachability", "recertification"],
            "platforms": [label for _, label in GRAPH_BUILDERS.values()],
            "note": "platforms outside this list still parse and still produce "
                    "control findings; only the graph-based analyses above are "
                    "unavailable, and they refuse rather than returning zero",
        },
    }


# ---------------------------------------------------------------- internals
def _get(aid: str):
    if aid not in _STORE:
        raise HTTPException(404, f"no assessment {aid!r}")
    return _STORE[aid]


def _require_graph(da, capability: str):
    """Refuse a graph question the platform cannot answer, and say why.

    A bare "no object graph" reads as a fault. It usually is not: it means no
    builder is registered for that platform yet, which is a gap in us, not a
    finding about the device. The supported list is read from the pipeline so
    this message cannot claim more or less than the code actually does.
    """
    if da.graph is not None:
        return da.graph
    from ..pipeline import GRAPH_BUILDERS

    raise HTTPException(422, {
        "error": f"{capability} needs an object graph, and none was built "
                 f"for platform {da.identity.platform!r}",
        "reason": "no rule-graph builder is registered for this platform; "
                  "the configuration parsed correctly and its control "
                  "findings are unaffected",
        "supported_platforms": [lbl for _, lbl in GRAPH_BUILDERS.values()],
        "not_a_finding": True,
    })


def _sbm_for(da):
    """Re-derive the SBM for remediation's lockout check.

    Remediation needs to know which management transports are LIVE, which is a
    property of the parsed device rather than of the findings.
    """
    import hashlib

    from ..pipeline import _read_and_apply, load_packs, select_pack

    _da, path = _STORE[da.identity.sha256[:12]] if False else (None, None)
    for _aid, (stored, p) in _STORE.items():
        if stored is da:
            path = p
            break
    if path is None:
        return None
    pack = select_pack(load_packs(), da.fingerprint)
    if pack is None:
        return None
    try:
        sbm, _doc = _read_and_apply(
            path, pack, aid="remediation",
            sha=hashlib.sha256(Path(path).read_bytes()).hexdigest(),
            redact=True)
        return sbm
    except Exception:                                  # noqa: BLE001
        return None
