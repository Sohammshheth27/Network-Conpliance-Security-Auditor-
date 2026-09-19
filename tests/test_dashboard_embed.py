"""The dashboard is served by the engine, and /api/* is the same API.

The React console calls the engine as `/api/<route>`; in development Vite
proxies that prefix away. If the engine did not answer the prefix too, every
page would work on the developer's machine and fail everywhere else -- the
worst kind of bug, because the demo machine hides it. So the prefix belongs to
the engine, and these tests keep it there.

The second thing held here is the client router. The dashboard uses real URLs,
so a refresh on /dashboard/assessments/<id> asks the engine for a path that is
not a file. The shell has to come back; a 404 would make every refresh look
like a broken link.
"""
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ncsa.api.app import app

client = TestClient(app)
DASHBOARD = Path(__file__).resolve().parents[1] / "ncsa" / "api" / "static" / "dashboard"
SHELL = DASHBOARD / "index.html"

built = pytest.mark.skipif(not SHELL.exists(),
                           reason="dashboard not built (npm run build in frontend/)")


def test_the_api_answers_under_the_api_prefix():
    plain = client.get("/health")
    prefixed = client.get("/api/health")
    assert plain.status_code == 200
    assert prefixed.status_code == 200
    assert prefixed.json() == plain.json(), (
        "/api/<route> must be the same request as /<route> -- one route table, "
        "one set of access checks, nothing to keep in step by hand")


def test_the_prefix_does_not_invent_routes():
    """Stripping a prefix must not turn an unknown path into a valid one."""
    assert client.get("/api/no-such-route").status_code == 404


def test_the_old_console_is_untouched():
    """The static console and its stylesheet are asserted by other tests and
    linked from the landing page. Embedding the dashboard must not move them."""
    r = client.get("/app")
    assert r.status_code == 200 and "dropzone" in r.text
    assert client.get("/static/app.css").status_code == 200


def test_an_unbuilt_dashboard_says_so_rather_than_404():
    """A missing build is our failure, and it has to name itself. A bare 404
    reads as 'no such feature'."""
    if SHELL.exists():
        pytest.skip("dashboard is built")
    r = client.get("/dashboard")
    assert r.status_code == 503 and "not built" in r.text


@built
def test_the_dashboard_shell_is_served():
    r = client.get("/dashboard")
    assert r.status_code == 200
    assert 'id="root"' in r.text


@built
def test_a_deep_link_returns_the_shell_not_a_404():
    r = client.get("/dashboard/assessments/any-id")
    assert r.status_code == 200 and 'id="root"' in r.text


@built
def test_every_asset_the_shell_references_is_served():
    html = SHELL.read_text(encoding="utf-8")
    refs = re.findall(r'(?:src|href)="/dashboard/([^"]+)"', html)
    assert refs, "the built shell must reference its own hashed assets"
    for ref in refs:
        assert client.get(f"/dashboard/{ref}").status_code == 200, ref


@built
def test_the_dashboard_path_cannot_read_the_rest_of_the_repo():
    """`rest` comes straight from the URL, so the traversal has to be shut."""
    r = client.get("/dashboard/../../pipeline.py")
    assert "def " not in r.text, "served a source file instead of the shell"
