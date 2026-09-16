"""Live collection over SSH, tested without a device or an SSH library.

The fake connection records everything sent to it, so the read-only guarantee
is tested as behaviour rather than trusted as a comment.
"""
import sys
from pathlib import Path

import pytest

from ncsa.collect import live

RTR = Path("samples/cisco/edge-rtr-01.cfg")
PASSWORD = "S3cr3t-Pa55"
REAL_CONNECT = live._netmiko_connect        # before any fixture replaces it


class FakeConn:
    def __init__(self, output: str, fail: Exception | None = None):
        self.output, self.fail = output, fail
        self.sent: list = []
        self.enabled = self.closed = False

    def enable(self):
        self.enabled = True

    def send_command(self, cmd, read_timeout=None):
        if self.fail:
            raise self.fail
        self.sent.append(cmd)
        return self.output

    def send_config_set(self, *a, **k):          # must never be called
        raise AssertionError("the collector entered configuration mode")

    def disconnect(self):
        self.closed = True


@pytest.fixture
def fake(monkeypatch):
    holder = {}

    def connect(**params):
        holder["params"] = params
        holder["conn"] = FakeConn(holder.get("output", RTR.read_text()), holder.get("fail"))
        return holder["conn"]

    monkeypatch.setattr(live, "_netmiko_connect", connect)
    return holder


def test_only_the_platforms_show_commands_are_sent(fake):
    c = live.collect("10.0.0.1", "cisco_iosxe_router", "audit", PASSWORD)
    assert fake["conn"].sent == ["show running-config"]
    assert set(fake["conn"].sent) <= live.ALLOWED_COMMANDS
    assert fake["conn"].closed, "the session is always closed"
    assert fake["params"]["device_type"] == "cisco_ios"
    assert "show running-config" in c.note()


def test_every_allowed_command_is_a_read():
    """No profile may carry a command that changes the device."""
    for cmd in live.ALLOWED_COMMANDS:
        assert cmd.split()[0] in ("show", "set"), cmd
        if cmd.startswith("set"):                   # PAN-OS output format only
            assert cmd == "set cli config-output-format xml"


def test_the_password_never_appears_in_an_error(fake):
    fake["fail"] = OSError(f"Authentication failed for audit/{PASSWORD}")
    with pytest.raises(live.CollectionError) as exc:
        live.collect("10.0.0.1", "cisco_iosxe_router", "audit", PASSWORD)
    assert PASSWORD not in str(exc.value)
    assert "********" in str(exc.value)


@pytest.mark.parametrize("host,port", [("10.0.0.1; reboot", 22), ("", 22),
                                       ("-oProxyCommand=x", 22), ("10.0.0.1", 0),
                                       ("10.0.0.1", 70000)])
def test_targets_are_validated(host, port):
    with pytest.raises(ValueError):
        live.collect(host, "cisco_iosxe_router", "a", "b", port=port)


def test_unverified_platforms_are_refused():
    with pytest.raises(ValueError, match="does not support 'sonicwall_sonicos'"):
        live.collect("10.0.0.1", "sonicwall_sonicos", "a", "b")


def test_a_missing_library_is_a_clear_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "netmiko", None)
    with pytest.raises(live.CollectorUnavailable, match="pip install netmiko"):
        live.collect("10.0.0.1", "cisco_iosxe_router", "a", "b")


def test_an_empty_config_is_an_error_not_an_empty_report(fake):
    fake["output"] = "   \n"
    with pytest.raises(live.CollectionError, match="empty configuration"):
        live.collect("10.0.0.1", "cisco_iosxe_router", "a", "b")


def test_written_exactly_as_received(fake, tmp_path):
    c = live.collect("edge-rtr.example.net", "cisco_iosxe_router", "a", "b")
    p = live.write_collected(c, tmp_path)
    assert p.read_text() == RTR.read_text() and p.suffix == ".cfg"


# ------------------------------------------------------------------ API
def _client():
    from fastapi.testclient import TestClient
    from ncsa.api.app import app
    return TestClient(app)


def test_api_collects_and_assesses(fake):
    r = _client().post("/collect", json={
        "host": "10.0.0.1", "platform": "cisco_iosxe_router",
        "username": "audit", "password": PASSWORD})
    assert r.status_code == 200, r.text
    body = r.json()[0]
    assert body["identity"]["platform"] == "cisco_iosxe_router"
    assert any("Collected live from 10.0.0.1" in n for n in body["notes"])
    assert PASSWORD not in r.text


def test_api_reports_a_platform_mismatch(fake):
    """The user said ASA; the device sent IOS. The fingerprint wins, loudly."""
    r = _client().post("/collect", json={
        "host": "10.0.0.1", "platform": "cisco_asa",
        "username": "audit", "password": PASSWORD})
    body = r.json()[0]
    assert body["identity"]["platform"] == "cisco_iosxe_router"
    assert any("fingerprints as 'cisco_iosxe_router'" in n for n in body["notes"])


def test_api_error_codes(fake, monkeypatch):
    c = _client()
    base = {"host": "10.0.0.1", "username": "a", "password": PASSWORD}
    assert c.post("/collect", json={**base, "platform": "sonicwall_sonicos"}).status_code == 422
    fake["fail"] = TimeoutError("timed out")
    r = c.post("/collect", json={**base, "platform": "cisco_iosxe_router"})
    assert r.status_code == 502 and PASSWORD not in r.text
    # the real seam, with netmiko made unimportable
    monkeypatch.setattr(live, "_netmiko_connect", REAL_CONNECT)
    monkeypatch.setitem(sys.modules, "netmiko", None)
    r = c.post("/collect", json={**base, "platform": "cisco_iosxe_router"})
    assert r.status_code == 503 and "pip install netmiko" in r.text


def test_api_lists_the_supported_platforms():
    got = {p["platform"] for p in _client().get("/collect/profiles").json()}
    assert got == set(live.PROFILES)
