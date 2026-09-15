"""Live collection end to end, through the REAL netmiko driver.

A small SSH server (paramiko) plays an IOS-XE shell on 127.0.0.1: prompt,
command echo, and `show running-config`. Our collector connects with netmiko
exactly as it would to a device. What the server receives is recorded, so the
read-only guarantee is checked on the wire, not in our own code.

Skipped when netmiko is not installed (it is an optional dependency).
"""
import socket
import threading
from pathlib import Path

import pytest

netmiko = pytest.importorskip("netmiko")
paramiko = pytest.importorskip("paramiko")

from ncsa.collect import live  # noqa: E402
from ncsa.pipeline import assess  # noqa: E402

CONFIG = Path("samples/cisco/edge-rtr-01.cfg").read_text()
USER, PASSWORD = "audit", "Lab-Only-Pw1"
PROMPT = "edge-rtr-01#"


class _Server(paramiko.ServerInterface):
    def __init__(self):
        self.shell = threading.Event()

    def check_auth_password(self, username, password):
        ok = (username, password) == (USER, PASSWORD)
        return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else \
            paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *args):
        return True

    def check_channel_shell_request(self, channel):
        self.shell.set()
        return True


def _serve(sock, received: list, stop: threading.Event):
    conn, _ = sock.accept()
    t = paramiko.Transport(conn)
    t.add_server_key(paramiko.RSAKey.generate(2048))
    srv = _Server()
    t.start_server(server=srv)
    chan = t.accept(20)
    if chan is None:
        return
    srv.shell.wait(10)
    chan.send(f"\r\n{PROMPT}")
    buf = ""
    while not stop.is_set():
        try:
            data = chan.recv(4096)
        except Exception:                                   # noqa: BLE001
            break
        if not data:
            break
        buf += data.decode(errors="replace")
        while "\n" in buf or "\r" in buf:
            idx = min(i for i in (buf.find("\n"), buf.find("\r")) if i >= 0)
            line, buf = buf[:idx].strip(), buf[idx + 1:]
            received.append(line)
            out = CONFIG.replace("\n", "\r\n") if line == "show running-config" else ""
            chan.send(f"{line}\r\n{out}\r\n{PROMPT}")
    t.close()


def test_the_real_netmiko_path_collects_read_only_and_assesses(tmp_path):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]
    received: list = []
    stop = threading.Event()
    th = threading.Thread(target=_serve, args=(sock, received, stop), daemon=True)
    th.start()
    try:
        c = live.collect("127.0.0.1", "cisco_iosxe_router", USER, PASSWORD, port=port)
    finally:
        stop.set()
        sock.close()

    assert "hostname edge-rtr-01" in c.text
    sent = {r for r in received if r}
    # netmiko's own session setup and logout, plus the ONE command our
    # collector sends. `exit` is netmiko ending the session on disconnect.
    netmiko_session = {"terminal width 511", "terminal length 0", "exit"}
    assert "show running-config" in sent
    assert sent - netmiko_session <= {"show running-config"}, f"unexpected: {sent}"
    assert not any(r.startswith(("conf", "write", "copy", "reload")) for r in sent)

    da = assess(str(live.write_collected(c, tmp_path)), redact=False,
                assessment_id="T-E2E")
    assert da.identity.platform == "cisco_iosxe_router"


def test_a_wrong_password_is_a_clean_error_without_the_password(tmp_path):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]
    stop = threading.Event()
    threading.Thread(target=_serve, args=(sock, [], stop), daemon=True).start()
    try:
        with pytest.raises(live.CollectionError) as exc:
            live.collect("127.0.0.1", "cisco_iosxe_router", USER, "wrong-Pw-123", port=port)
    finally:
        stop.set()
        sock.close()
    assert "wrong-Pw-123" not in str(exc.value)
