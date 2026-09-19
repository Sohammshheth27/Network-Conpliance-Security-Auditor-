"""Several endpoints called at once must not break each other.

A dashboard page opens by firing every panel's request together -- the
Frameworks page asks for five. Endpoints declared with `def` run in a
threadpool, so those handlers genuinely run in parallel, and the handlers
import their heavy modules lazily. Two threads importing one module for the
first time is a deadlock in CPython's import lock, not a slow path: it raised
`_DeadlockError` and the page showed a 500 while the same endpoints answered
perfectly when called one at a time.

That is the failure mode this project cares most about -- our bug presented to
the operator as a fact about their network -- so it is held here.
"""
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from ncsa.api.app import app

# Endpoints that are cheap and safe to call in parallel. /frameworks is left
# out on purpose: the first call parses the CIS catalogue if the cache is cold,
# which takes minutes and would say nothing about concurrency.
PARALLEL = ["/health", "/platforms", "/assessments", "/attack-coverage",
            "/ai-governance", "/collect/profiles", "/monitor"]


def test_endpoints_answer_when_called_together():
    with TestClient(app) as client:          # `with` runs the startup hooks
        with ThreadPoolExecutor(max_workers=len(PARALLEL)) as pool:
            results = list(pool.map(lambda p: (p, client.get(p).status_code),
                                    PARALLEL))
    bad = [(p, s) for p, s in results if s >= 500]
    assert not bad, f"concurrent calls returned server errors: {bad}"


def test_the_heavy_modules_are_imported_before_any_request():
    """The guard itself: a fresh process must have them loaded after startup.

    Checked in a subprocess because the rest of the suite imports these modules
    anyway -- in this process the assertion would pass without the hook.
    """
    code = (
        "from fastapi.testclient import TestClient;"
        "from ncsa.api.app import app;"
        "import sys;"
        "c = TestClient(app);"
        "c.__enter__();"
        "mods = ['ncsa.frameworks.ai_security', 'ncsa.frameworks.attack',"
        "        'ncsa.frameworks.selection', 'ncsa.frameworks.registry',"
        "        'ncsa.engine.rules'];"
        "print(','.join(m for m in mods if m not in sys.modules))"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True,
                         text=True, timeout=300)
    assert out.returncode == 0, out.stderr[-2000:]
    missing = out.stdout.strip().splitlines()[-1] if out.stdout.strip() else ""
    assert missing == "", f"not imported at startup: {missing}"
