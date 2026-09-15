"""Continuous compliance: re-collect a device on a schedule, alert on drift.

A job is "collect this device every N minutes". Each run collects the running
configuration (read-only, ncsa/collect/live.py), assesses it exactly as an
upload, snapshots it, and compares it with the previous snapshot of the same
device. An alert is recorded when:

  * the overall score drops,
  * any framework's own score drops,
  * a control regresses (e.g. PASS -> FAIL), or
  * collection itself fails (an unreachable device is news too).

CREDENTIALS. A scheduled job has to keep the device password. It is stored
encrypted (Fernet, AES-128-CBC + HMAC-SHA256) with a key held in the data
directory, never returned by any endpoint, and never logged. The key sits on
the same machine as the ciphertext, so this protects against the database
being copied on its own -- not against someone with the whole data directory.
That limit is stated rather than hidden; use a read-only device account.

The scheduler is OPT-IN (NCSA_MONITOR=1): tests and demos never start
background threads.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

MIN_INTERVAL_MINUTES = 15

_SCHEMA = [
    """CREATE TABLE IF NOT EXISTS jobs (
        job_id TEXT PRIMARY KEY, host TEXT NOT NULL, platform TEXT NOT NULL,
        port INTEGER NOT NULL, driver TEXT NOT NULL, username TEXT NOT NULL,
        secret_blob BLOB NOT NULL, interval_minutes INTEGER NOT NULL,
        frameworks TEXT, redact INTEGER NOT NULL, created_at TEXT NOT NULL,
        last_run TEXT, last_aid TEXT, last_score REAL, last_frameworks TEXT,
        last_status TEXT)""",
    """CREATE TABLE IF NOT EXISTS alerts (
        alert_id TEXT PRIMARY KEY, job_id TEXT NOT NULL, at TEXT NOT NULL,
        kind TEXT NOT NULL, detail TEXT NOT NULL, aid TEXT)""",
]


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


class Monitor:
    def __init__(self, data_dir: str | Path, *, history_store=None):
        from cryptography.fernet import Fernet

        self.dir = Path(data_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        key_file = self.dir / "monitor.key"
        if not key_file.exists():
            key_file.write_bytes(Fernet.generate_key())
        self._fernet = Fernet(key_file.read_bytes())
        self._db = self.dir / "monitor.db"
        self._history = history_store
        self._lock = threading.Lock()
        self._thread = None
        with sqlite3.connect(self._db) as c:
            for stmt in _SCHEMA:
                c.execute(stmt)

    # ----------------------------------------------------------------- jobs
    def add_job(self, *, host: str, platform: str, username: str, password: str,
                secret: str | None = None, port: int = 22, driver: str = "netmiko",
                interval_minutes: int = 60, frameworks=None, redact: bool = True) -> dict:
        from . import live

        live.validate_target(host, port)
        live.profile_for(platform)
        if interval_minutes < MIN_INTERVAL_MINUTES:
            raise ValueError(f"interval must be at least {MIN_INTERVAL_MINUTES} minutes")
        blob = self._fernet.encrypt(json.dumps(
            {"password": password, "secret": secret}).encode())
        job_id = uuid.uuid4().hex[:12]
        with self._lock, sqlite3.connect(self._db) as c:
            c.execute("INSERT INTO jobs (job_id, host, platform, port, driver, username,"
                      " secret_blob, interval_minutes, frameworks, redact, created_at)"
                      " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                      (job_id, host.strip(), platform, port, driver, username, blob,
                       interval_minutes, json.dumps(frameworks) if frameworks else None,
                       int(bool(redact)), _now().isoformat()))
        return self.get(job_id)

    def get(self, job_id: str) -> dict | None:
        with sqlite3.connect(self._db) as c:
            c.row_factory = sqlite3.Row
            r = c.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        return self._public(r) if r else None

    def jobs(self) -> list[dict]:
        with sqlite3.connect(self._db) as c:
            c.row_factory = sqlite3.Row
            rows = c.execute("SELECT * FROM jobs ORDER BY created_at").fetchall()
        return [self._public(r) for r in rows]

    def alerts(self, job_id: str | None = None, limit: int = 100) -> list[dict]:
        q = "SELECT * FROM alerts" + (" WHERE job_id=?" if job_id else "") + \
            " ORDER BY at DESC LIMIT ?"
        args = (job_id, limit) if job_id else (limit,)
        with sqlite3.connect(self._db) as c:
            c.row_factory = sqlite3.Row
            return [dict(r) for r in c.execute(q, args).fetchall()]

    def delete(self, job_id: str) -> bool:
        with self._lock, sqlite3.connect(self._db) as c:
            n = c.execute("DELETE FROM jobs WHERE job_id=?", (job_id,)).rowcount
            c.execute("DELETE FROM alerts WHERE job_id=?", (job_id,))
        return n > 0

    @staticmethod
    def _public(r) -> dict:
        """A job WITHOUT its credentials -- the only shape that leaves here."""
        d = {k: r[k] for k in r.keys() if k != "secret_blob"}
        d["frameworks"] = json.loads(d["frameworks"]) if d["frameworks"] else None
        d["last_frameworks"] = json.loads(d["last_frameworks"]) if d["last_frameworks"] else None
        d["redact"] = bool(d["redact"])
        return d

    # ------------------------------------------------------------------ run
    def run(self, job_id: str, ingest, uploads: Path) -> dict:
        """Collect, assess, snapshot, compare. `ingest(dest, name, redact, fws,
        notes)` is the API's own ingest, so a monitored run is an upload."""
        import importlib

        from . import live

        # `from ..diff import compare` yields the compare() function that
        # ncsa.diff re-exports, not the module; import the module by name.
        cmp = importlib.import_module("ncsa.diff.compare")

        with sqlite3.connect(self._db) as c:
            c.row_factory = sqlite3.Row
            r = c.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        if r is None:
            raise KeyError(job_id)
        creds = json.loads(self._fernet.decrypt(r["secret_blob"]).decode())
        fws = json.loads(r["frameworks"]) if r["frameworks"] else None
        at = _now().isoformat()
        try:
            c_ = live.collect(r["host"], r["platform"], r["username"], creds["password"],
                              port=r["port"], driver=r["driver"], secret=creds.get("secret"))
        except Exception as exc:                            # noqa: BLE001
            msg = f"{type(exc).__name__}: {exc}"
            self._alert(job_id, at, "collection_failed", msg, None)
            self._update(job_id, at, None, None, None, "collection_failed")
            return {"status": "collection_failed", "detail": msg, "alerts": 1}

        dest = live.write_collected(c_, uploads)
        aid, da = ingest(dest, f"{c_.host} (monitored)", bool(r["redact"]), fws, [c_.note()])
        store = {"store": self._history} if self._history else {}
        snap = cmp.snapshot(da)
        prior = cmp.history(snap.device_key, **store)
        cmp.save(snap, **store)

        new_alerts = []
        if prior:
            rep = cmp.compare(prior[-1], snap)
            if (rep.score_before is not None and rep.score_after is not None
                    and rep.score_after < rep.score_before):
                new_alerts.append(("score_drop",
                                   f"score {rep.score_before}% -> {rep.score_after}%"))
            for fw, (b, a) in sorted(rep.framework_scores.items()):
                if b is not None and a is not None and a < b:
                    new_alerts.append(("framework_drop", f"{fw} {b}% -> {a}%"))
            for ch in rep.by_direction(cmp.REGRESSED):
                new_alerts.append(("control_regressed",
                                   f"{ch.control_id}: {ch.before} -> {ch.after}"))
        for kind, detail in new_alerts:
            self._alert(job_id, at, kind, detail, aid)
        cov = da.coverage()
        self._update(job_id, at, aid, cov.get("score_pct"), snap.frameworks,
                     "drift" if new_alerts else "ok")
        return {"status": "drift" if new_alerts else "ok", "assessment_id": aid,
                "alerts": len(new_alerts),
                "detail": [f"{k}: {d}" for k, d in new_alerts]}

    def _alert(self, job_id, at, kind, detail, aid):
        with self._lock, sqlite3.connect(self._db) as c:
            c.execute("INSERT INTO alerts VALUES (?,?,?,?,?,?)",
                      (uuid.uuid4().hex[:12], job_id, at, kind, detail, aid))

    def _update(self, job_id, at, aid, score, frameworks, status):
        with self._lock, sqlite3.connect(self._db) as c:
            c.execute("UPDATE jobs SET last_run=?, last_aid=?, last_score=?,"
                      " last_frameworks=?, last_status=? WHERE job_id=?",
                      (at, aid, score, json.dumps(frameworks) if frameworks else None,
                       status, job_id))

    # ------------------------------------------------------------ scheduler
    def due(self, now: datetime | None = None) -> list[str]:
        now = now or _now()
        out = []
        for j in self.jobs():
            last = j["last_run"]
            if last is None or datetime.fromisoformat(last) + timedelta(
                    minutes=j["interval_minutes"]) <= now:
                out.append(j["job_id"])
        return out

    def start(self, ingest, uploads: Path, *, tick_seconds: int = 30) -> None:
        if self._thread and self._thread.is_alive():
            return

        def loop():
            while True:
                for job_id in self.due():
                    try:
                        self.run(job_id, ingest, uploads)
                    except Exception:                       # noqa: BLE001
                        pass                                # recorded as an alert in run()
                time.sleep(tick_seconds)

        self._thread = threading.Thread(target=loop, name="ncsa-monitor", daemon=True)
        self._thread.start()
