"""The HTTP contract.

These tests exist because a UI can undo the product's credibility in ways the
engine cannot: rendering UNKNOWN as green, showing a score without its
coverage, or dropping the evidence that lets a reviewer check us. The schema
is where that is prevented, so the schema is what is tested.
"""
from ncsa.paths import resolve_packs_dir
import html as html_mod
import os
import tempfile
import re

import pytest
from fastapi.testclient import TestClient

from ncsa.api.app import app

client = TestClient(app)
ASA = r"E:\ASA.txt"
asa_only = pytest.mark.skipif(not os.path.exists(ASA), reason="ASA sample absent")


def _assess(path):
    with open(path, "rb") as fh:
        r = client.post("/assess", files={"files": (os.path.basename(path), fh)})
    assert r.status_code == 200
    return r.json()[0]


def test_meta_endpoints():
    assert client.get("/health").json()["ok"] is True
    assert len(client.get("/platforms").json()) >= 5


@asa_only
def test_assess_returns_the_contract():
    a = _assess(ASA)
    assert a["identity"]["platform"] == "cisco_asa"
    assert a["findings"] and a["records"]["source_records"] > 0


@asa_only
def test_score_never_travels_without_its_coverage():
    """60% compliance means nothing if 46% of the device was assessed."""
    cov = _assess(ASA)["coverage"]
    assert cov["score_pct"] is not None
    assert cov["assessed_pct"] is not None
    assert (cov["controls_decided"] + cov["controls_undecided"]
            + cov["not_applicable"]) == cov["controls_total"]


@asa_only
def test_unknown_carries_no_risk_score():
    """A number there would imply we knew."""
    a = _assess(ASA)
    for f in a["findings"]:
        if f["state"] in ("UNKNOWN", "NOT_APPLICABLE", "PASS"):
            assert f["risk"] is None, f"{f['control_id']} must not carry risk"


@asa_only
def test_failures_carry_risk_and_evidence():
    a = _assess(ASA)
    fails = [f for f in a["findings"] if f["state"] == "FAIL"]
    assert fails
    assert any(f["risk"] for f in fails)
    anchored = [f for f in fails if f["evidence"]]
    assert anchored, "a finding without evidence is an assertion"
    ev = anchored[0]["evidence"][0]
    assert ev["raw"] and ev["file"]


@asa_only
def test_record_accounting_balances():
    r = _assess(ASA)["records"]
    assert r["mapped_to_schema"] + r["parsed_not_mapped"] \
        + r["unreadable_records"] == r["source_records"]


@asa_only
def test_training_queue_is_reachable_and_deduplicated():
    a = _assess(ASA)
    q = client.get(f"/assessment/{a['assessment_id']}/training",
                   params={"suggest": False}).json()
    assert len({c["name"] for c in q}) == len(q), "queue must be by NAME"


@asa_only
def test_remediation_separates_deferred_steps():
    a = _assess(ASA)
    rem = client.get(f"/assessment/{a['assessment_id']}/remediation").json()
    assert "script" in rem
    # A step that would sever the only management path must never be in the
    # runnable script.
    ids = {s["control_id"] for s in rem["steps"]}
    for s in rem["deferred"]:
        assert s["control_id"] not in ids


def test_unreadable_file_is_a_result_not_a_crash(tmp_path):
    """The tool refusing an encrypted backup is behaviour to surface, with
    the reason attached -- not a 500."""
    bad = tmp_path / "encrypted.bin"
    bad.write_bytes(b"Salted__" + os.urandom(4096))
    with bad.open("rb") as fh:
        r = client.post("/assess", files={"files": ("encrypted.bin", fh)})
    assert r.status_code == 200
    a = r.json()[0]
    assert a["supported"] is False
    assert a["notes"], "a refusal must say why"


def test_approval_refuses_fields_outside_the_schema():
    r = client.post("/training/approve", json={
        "setting_name": "x", "field": "not.a.real.field",
        "platform": "cisco_asa", "approved_by": "test"})
    assert r.json()["accepted"] is False
    assert "whitelist" in r.json()["reason"]


def test_approval_runs_the_regression_gate():
    """An approval is only accepted after the golden corpus is re-run with it
    in place, and the response carries what the corpus said."""
    from pathlib import Path
    try:
        r = client.post("/training/approve", json={
            "setting_name": "console timeout",
            "field": "management.console.exec_timeout",
            "platform": "cisco_asa", "approved_by": "api-test"}).json()
        assert "pass_rate_before" in r["regression"]
        assert "pass_rate_after" in r["regression"]
        if r["accepted"]:
            assert "corpus still holds" in r["reason"]
    finally:
        for p in resolve_packs_dir().glob("*.learned.yaml"):
            p.unlink(missing_ok=True)


def test_approval_refuses_an_anonymous_approver():
    """An approval that records nobody cannot be audited."""
    r = client.post("/training/approve", json={
        "setting_name": "x", "field": "logging.enabled",
        "platform": "cisco_asa", "approved_by": ""}).json()
    assert r["accepted"] is False


# ------------------------------------------------------------- the console
def test_console_is_served_by_the_same_process():
    """One command, no build step: a demo that needs two servers running is a
    demo that fails on stage.

    The console moved to /app when the landing page took /. Asserting on "/"
    would now pass against the landing page instead -- the test would still be
    green while the thing it names was broken.
    """
    r = client.get("/app")
    assert r.status_code == 200
    assert "dropzone" in r.text, "this must be the console, not the landing page"
    for asset in ("/static/app.css", "/static/app.js"):
        assert client.get(asset).status_code == 200


def test_landing_page_is_self_contained():
    """The public page must render with no network beyond this process.

    A hackathon venue is exactly where a CDN font or a hosted script fails, and
    the page that fails is the first one anybody sees.
    """
    r = client.get("/")
    assert r.status_code == 200
    assert "OPEN THE CONSOLE" in r.text
    for asset in ("/static/landing.css", "/static/landing.js",
                  "/static/graphics.js", "/static/favicon.svg",
                  "/static/fonts/inter-latin.woff2",
                  "/static/fonts/jetbrains-mono-latin.woff2"):
        assert client.get(asset).status_code == 200, f"{asset} must be served"

    page = (r.text + client.get("/static/landing.css").text
                   + client.get("/static/landing.js").text
                   + client.get("/static/graphics.js").text)

    # The SVG namespace is an identifier, not a fetch -- nothing is requested
    # from w3.org. Everything else pointing offsite is a real dependency.
    page = page.replace("http://www.w3.org/2000/svg", "")
    for host in ("http://", "https://", "//fonts.", "cdn."):
        assert host not in page, f"landing page reaches offsite via {host!r}"


def test_landing_page_capability_figures_come_from_the_engine():
    """Every capability number is fetched at runtime, never written into the
    page.

    A landing page carrying its own copy of "5,376 controls" drifts the moment
    a framework is added, and then the product's own front page is the thing
    stating a number nobody measured. SVG geometry is exempt -- a viewBox
    coordinate is not a claim -- so this checks rendered TEXT, not markup.
    """
    html = client.get("/").text
    js = client.get("/static/landing.js").text
    assert "/frameworks" in js and "/platforms" in js, "figures must be fetched"

    # Strip tags, so attributes (viewBox, path data, widths) are not mistaken
    # for claims, then strip the terminal sample, covered by its own test.
    text = re.sub(r"<svg.*?</svg>", " ", html, flags=re.S | re.I)
    text = re.sub(r'<p class="hero-note">.*?</p>', " ", text, flags=re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    # Decode entities BEFORE scanning: a numeric escape like &#8599; (an arrow)
    # is a glyph, and reads as a four-digit figure if left encoded.
    text = html_mod.unescape(text)
    # Standard identifiers are names, not quantities. "ISO/IEC 27001" is no
    # more a claim about capability than "IPv6" is.
    for standard in ("ISO/IEC 27001", "SP 800-53", "800-53", "27001"):
        text = text.replace(standard, " ")

    # A figure may only appear in the prose if another test proves it against
    # the engine. Anything else has to be fetched at runtime.
    verified_elsewhere = {
        "126": "test_the_schema_field_count_on_the_page_is_real",
    }
    for n in re.findall(r"\d[\d,.]{2,}", text):
        assert n in verified_elsewhere or n == "2026", (
            f"hardcoded capability figure {n!r} in the page. Either fetch it "
            f"from the engine, or add a test that proves it and list it in "
            f"verified_elsewhere.")


def test_the_schema_field_count_on_the_page_is_real():
    """The page says the baseline is a 126-field schema. It has to be one.

    This is the only capability figure written into the prose rather than
    fetched, because it describes the shape of the schema rather than the
    contents of a catalogue. That makes it exactly the kind of number that
    quietly goes stale, so it is pinned to the schema itself.
    """
    from ncsa.schema import FIELD_NAMES

    html = client.get("/").text
    m = re.search(r"(\d+)-field", html)
    assert m, "the page must state the schema's field count"
    assert int(m.group(1)) == len(FIELD_NAMES), (
        f"page says {m.group(1)}-field; the schema has {len(FIELD_NAMES)}")


@asa_only
def test_the_hero_terminal_shows_a_real_assessment():
    """The figures under the hero image are a real result, not plausible filler.

    It is the one place the page prints specific numbers, so they have to be
    numbers the engine actually produces for that device. Illustrative output
    that nobody checked is exactly the failure this product argues against --
    and if it were invented, this is where a reviewer would catch us.
    """
    html = client.get("/").text
    m = re.search(r"(\d+) controls</b>\s*&middot;\s*<b>(\d+) decided", html)
    assert m, "the hero must state controls and decided counts"
    shown_total, shown_decided = int(m.group(1)), int(m.group(2))

    m2 = re.search(r"<b>([\d.]+)% of what we could read", html)
    assert m2, "the hero must state the score"
    shown_score = float(m2.group(1))

    m3 = re.search(r"(\d+) undecided\. Not passing", html)
    assert m3, "the hero must state the undecided count"
    shown_undecided = int(m3.group(1))

    cov = _assess(ASA)["coverage"]
    assert shown_total == cov["controls_total"], (
        f"hero says {shown_total} controls; the engine reports "
        f"{cov['controls_total']}")
    assert shown_decided == cov["controls_decided"]
    assert shown_undecided == cov["controls_undecided"]
    assert abs(shown_score - cov["score_pct"]) < 0.05


def test_unknown_is_not_styled_as_a_pass():
    """UNKNOWN must never render green. It is the honest statement that we
    could not tell, and it is what makes the other numbers trustworthy."""
    css = client.get("/static/app.css").text
    assert ".pill.UNKNOWN" in css
    # the UNKNOWN pill uses the muted variable, not the pass colour
    unknown_rule = css.split(".pill.UNKNOWN")[1].split("}")[0]
    assert "--unknown" in unknown_rule and "--pass" not in unknown_rule


@asa_only
def test_hygiene_endpoint_is_honest_when_there_is_no_graph():
    """A platform with no object graph has no rule hygiene. Returning an empty
    finding list without saying why would read as a tidy policy."""
    a = _assess(ASA)
    h = client.get(f"/assessment/{a['assessment_id']}/hygiene").json()
    assert h["findings"] == []
    # `analysis_ran` is the load-bearing field: a UI that plots `summary` must
    # be able to tell "we looked and found nothing" from "we never looked".
    # A zeroed summary was the old answer and reads as a clean policy, so the
    # summary is now None and the flag carries the meaning.
    assert h["analysis_ran"] is False
    assert h["summary"] is None
    assert h["not_a_finding"] is True
    assert "not a statement about the device" in h["reason"]
    assert h["supported_platforms"], "must say which platforms CAN answer"


def test_hygiene_reports_unevaluable_rules_alongside_findings():
    import os
    sw = r"E:\sonicwall config file.txt"
    if not os.path.exists(sw):
        pytest.skip("SonicWall sample absent")
    a = _assess(sw)
    h = client.get(f"/assessment/{a['assessment_id']}/hygiene").json()
    assert h["summary"]["by_kind"], "expected hygiene findings on this device"
    assert h["summary"]["unevaluable"] > 0
    assert h["unevaluable"], "rules we could not resolve must be named"


def test_glass_never_dims_a_label_below_readable():
    """Translucent text on a translucent panel must still meet WCAG AA.

    The MotionSites glass direction layers rgba text over an rgba panel over a
    gradient. Both alphas composite, so a token that looks fine in the palette
    can land far below AA once rendered -- `--label-3` at .40 measured 3.28:1,
    and it carries every uppercase micro-label and table header at 10-11px.

    This is not a styling preference. The tool exists to be believed, and a
    number a reviewer squints at on a projector is a number they do not check.
    """
    def _srgb(c):
        c /= 255.0
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    def luminance(rgb):
        r, g, b = (_srgb(v) for v in rgb)
        return 0.2126 * r + 0.7152 * g + 0.0722 * b

    def contrast(fg, bg):
        a, b = luminance(fg), luminance(bg)
        hi, lo = max(a, b), min(a, b)
        return (hi + 0.05) / (lo + 0.05)

    def over(fg, alpha, bg):
        """Composite a translucent foreground onto an opaque backdrop."""
        return tuple(f * alpha + b * (1 - alpha) for f, b in zip(fg, bg))

    css = client.get("/static/app.css").text

    # The panel a label actually sits on: --glass white over the darkest part
    # of the gradient ground. Darkest is the worst case for light-on-dark text.
    ground = (7, 10, 18)                               # --bg-0
    m = re.search(r"--glass:rgba\(255,255,255,([\d.]+)\)", css)
    assert m, "--glass token must exist; it is the whole material"
    panel = over((255, 255, 255), float(m.group(1)), ground)

    for token in ("--label-2", "--label-3"):
        m = re.search(rf"{token}:rgba\((\d+),(\d+),(\d+),([\d.]+)\)", css)
        assert m, f"{token} must be defined as rgba so its alpha is explicit"
        rgb = tuple(int(m.group(i)) for i in (1, 2, 3))
        eff = over(rgb, float(m.group(4)), panel)
        ratio = contrast(eff, panel)
        assert ratio >= 4.5, (
            f"{token} composites to {ratio:.2f}:1 on glass, below WCAG AA 4.5. "
            f"Raise its alpha or lighten the token.")


# ---------------------------------------------------------------------------
# Capabilities that were BUILT AND TESTED but had no route to reach them.
#
# Topology, reachability, change tracking, recertification and the host
# firewall each had a module and a test file, and none of them could be called
# from the API. A capability nobody can reach is indistinguishable from one
# that does not exist, and the capability matrix claimed all of them. These
# tests exist to keep the route and the engine wired together.
# ---------------------------------------------------------------------------

SW = r"E:\sonicwall config file.txt"
sw_only = pytest.mark.skipif(not os.path.exists(SW),
                             reason="SonicWall sample absent")


@asa_only
def test_reachability_refuses_rather_than_guessing_without_a_graph():
    """A refusal has to distinguish OUR gap from a fact about the device.

    ASA parses fine and its control findings are sound; it simply has no
    rule-graph builder yet. Answering "no traffic permitted" would be a
    fabrication, and a bare error would read as a broken upload.
    """
    a = _assess(ASA)
    r = client.post(f"/assessment/{a['assessment_id']}/reach",
                    json={"source": "any", "destination": "any", "port": 22})
    assert r.status_code == 422
    d = r.json()["detail"]
    assert d["not_a_finding"] is True
    assert "no rule-graph builder" in d["reason"]
    assert d["supported_platforms"], "must name the platforms that CAN answer"


@sw_only
def test_reachability_names_the_rule_that_decided_it():
    """The verdict is checkable only if the deciding rule travels with it."""
    a = _assess(SW)
    r = client.post(f"/assessment/{a['assessment_id']}/reach",
                    json={"source": "any", "destination": "any",
                          "port": 3389, "protocol": "tcp"})
    assert r.status_code == 200
    body = r.json()
    # "permitted" is a tri-state on purpose: None means undecidable, which is
    # not the same as denied and must never be flattened into one.
    assert body["answer"]["permitted"] in {True, False, None}
    assert body["answer"]["decided_by"]
    assert "decided by" in body["explain"]


@sw_only
def test_an_unevaluable_rule_above_the_match_is_disclosed():
    """First-match-wins is only sound if every earlier rule was evaluated.

    On the real SonicWall export some rules reference objects we cannot
    resolve. A verdict that ignored them would be over-confident, so the
    caveat has to reach the caller rather than staying in the log.
    """
    a = _assess(SW)
    body = client.post(f"/assessment/{a['assessment_id']}/reach",
                       json={"source": "any", "destination": "any",
                             "port": 3389, "protocol": "tcp"}).json()
    assert "unevaluable" in body["explain"]


@sw_only
def test_recertification_returns_due_reviews_and_deletion_candidates():
    a = _assess(SW)
    r = client.get(f"/assessment/{a['assessment_id']}/recertification")
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body["due"], list)
    # Two different return shapes -- RecertFinding objects vs plain dicts --
    # which is exactly the mismatch that broke this route the first time.
    assert all(isinstance(d, dict) for d in body["deletion_candidates"])


@asa_only
def test_snapshot_then_diff_reports_no_change_for_the_same_device():
    """A DiffReport is a dataclass, not a pydantic model.

    The route originally called `.model_dump()` on it and 500'd. Serialisation
    is part of the contract, so it is asserted rather than assumed.
    """
    a = _assess(ASA)
    aid = a["assessment_id"]
    assert client.post(f"/assessment/{aid}/snapshot").status_code == 200
    d = client.get(f"/assessment/{aid}/diff").json()
    assert d["same_device"] is True
    assert d["summary"]["device_changed"] is False
    assert "explain" in d


@asa_only
def test_diff_says_so_when_there_is_nothing_to_compare_against():
    a = _assess(ASA)
    import sys
    from pathlib import Path

    # ncsa.diff re-exports a function named "compare", which shadows the
    # submodule of the same name -- "import ncsa.diff.compare as m" binds the
    # FUNCTION, not the module. sys.modules is the unambiguous handle.
    compare_mod = sys.modules["ncsa.diff.compare"]
    original = compare_mod.STORE
    compare_mod.STORE = Path(tempfile.mkdtemp()) / "empty"
    try:
        d = client.get(f"/assessment/{a['assessment_id']}/diff").json()
    finally:
        compare_mod.STORE = original
    assert "note" in d or d.get("same_device") is True


@sw_only
def test_topology_is_built_from_assessed_devices():
    a = _assess(SW)
    r = client.post("/topology", json={"assessment_ids": [a["assessment_id"]]})
    assert r.status_code == 200
    body = r.json()
    assert body["summary"]["devices"] == 1
    assert body["summary"]["interfaces"] >= 0


def test_topology_rejects_an_empty_device_list():
    """Zero devices is not a fabric; it is a caller mistake."""
    assert client.post("/topology", json={"assessment_ids": []}).status_code == 422


@asa_only
def test_topology_reports_a_reason_for_every_skipped_device():
    """A device dropped silently would shrink the fabric without saying so.

    A redacted upload has no addressing, so it cannot be placed -- that is a
    reason, and it has to be visible next to the devices that were placed.
    """
    r = client.post("/assess?redact=true",
                    files={"files": ("asa.txt", open(ASA, "rb").read())})
    aid = r.json()[0]["assessment_id"]
    body = client.post("/topology", json={"assessment_ids": [aid]}).json()
    assert len(body["devices"]) + len(body["skipped"]) == 1
    for s in body["skipped"]:
        assert s["reason"], "a skipped device must carry a reason"


IPTABLES = (
    "*filter\n"
    ":INPUT DROP [0:0]\n"
    ":FORWARD DROP [0:0]\n"
    ":OUTPUT ACCEPT [0:0]\n"
    "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
    "-A INPUT -s 0.0.0.0/0 -j ACCEPT\n"
    "COMMIT\n"
)


def test_an_uploaded_iptables_ruleset_gets_the_appliance_analysers():
    """The vendor-neutral graph is the claim; this is the proof.

    A laptop's rules become SecurityRule objects and the same hygiene analyser
    that runs on an NSA 3700 runs on them, with no host-specific analysis code.
    """
    r = client.post("/hostfw/iptables",
                    files={"file": ("iptables-save.txt", IPTABLES.encode())})
    assert r.status_code == 200
    body = r.json()
    assert body["host"]["rules_read"] >= 2
    assert body["hygiene"]["summary"]["rules_examined"] >= 2


def test_an_unreadable_upload_is_not_reported_as_a_host_with_no_rules():
    r = client.post("/hostfw/iptables",
                    files={"file": ("notes.txt", b"this is not iptables output")})
    assert r.status_code == 422
    assert r.json()["detail"]["not_a_finding"] is True


def test_assessing_the_api_host_needs_an_explicit_opt_in():
    """Unlike every other route this one reads the SERVER, not an upload.

    It shells out to the local firewall tooling, which is a different trust
    decision, so it must not be reachable by accident.
    """
    r = client.post("/hostfw/local")
    assert r.status_code == 400
    assert "enable=true" in r.json()["detail"]["error"]
