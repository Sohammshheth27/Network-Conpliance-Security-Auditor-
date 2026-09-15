"""Assessments that survive a restart.

The store used to be a dict, so every restart -- and a low-memory kill is a
restart -- silently emptied the console. Now each assessment is recorded in
SQLite with the configuration it came from and the options it was made with
(redaction, frameworks). The full result stays in memory while it is used;
after a restart it is rebuilt on first access by assessing the SAME file with
the SAME options under the SAME id, which is deterministic, so the rebuilt
assessment is the one the operator saw.

Only what is needed to re-run is stored: the file path, its display name and
the options -- plus the headline numbers so the list renders without
re-assessing anything. Configurations stay on this machine, under the data
directory, which is excluded from git.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS assessments (
    aid          TEXT PRIMARY KEY,
    path         TEXT NOT NULL,
    name         TEXT NOT NULL,
    redact       INTEGER NOT NULL,
    frameworks   TEXT,
    created_at   TEXT NOT NULL,
    device       TEXT,
    vendor       TEXT,
    platform     TEXT,
    supported    INTEGER,
    score_pct    REAL,
    assessed_pct REAL
)
"""


class AssessmentStore(dict):
    """aid -> (DeviceAssessment, config path), persisted.

    Behaves like the dict it replaces for reads (`aid in store`, `store[aid]`,
    `items()` over what is loaded), so endpoints need no change beyond `put`.
    """

    def __init__(self, data_dir: str | Path):
        super().__init__()
        self.data_dir = Path(data_dir)
        self.uploads = self.data_dir / "uploads"
        self.uploads.mkdir(parents=True, exist_ok=True)
        self._db_path = self.data_dir / "assessments.db"
        self._lock = threading.Lock()
        with self._conn() as c:
            c.execute(_SCHEMA)
            # Each framework's own score, for the fleet view -- added after
            # the first schema, so older databases gain the column in place.
            cols = {r[1] for r in c.execute("PRAGMA table_info(assessments)")}
            if "frameworks_json" not in cols:
                c.execute("ALTER TABLE assessments ADD COLUMN frameworks_json TEXT")
            if "platform_fp" not in cols:
                c.execute("ALTER TABLE assessments ADD COLUMN platform_fp TEXT")

    # ------------------------------------------------------------ plumbing
    def _conn(self):
        return sqlite3.connect(self._db_path)

    def new_upload_path(self, filename: str, aid_hint: str) -> Path:
        """`uploads/<id>/<original name>`: the file keeps its real name, so the
        name shown in the console and in every evidence line is the user's."""
        d = self.uploads / aid_hint
        d.mkdir(parents=True, exist_ok=True)
        return d / (Path(filename or "config").name or "config")

    # --------------------------------------------------------------- write
    def put(self, aid: str, da, path: Path, *, name: str, redact: bool,
            frameworks: list | None) -> None:
        super().__setitem__(aid, (da, Path(path)))
        try:
            cov = da.coverage()
            score, assessed = cov.get("score_pct"), cov.get("assessed_pct")
        except Exception:                               # noqa: BLE001
            score = assessed = None
        ident = da.identity
        fw_scores = {}
        if getattr(da, "assessment", None) is not None:
            from ..frameworks.selection import framework_coverage
            fw_scores = {r["framework"]: r["framework_score_pct"]
                         for r in framework_coverage(da.assessment.findings,
                                                   ident.platform)}
        row = (aid, str(path), name, int(bool(redact)),
               json.dumps(frameworks) if frameworks else None,
               datetime.now(timezone.utc).isoformat(timespec="seconds"),
               ident.hostname or name, ident.vendor, ident.platform,
               int(bool(getattr(da, "supported", True))), score, assessed,
               json.dumps(fw_scores), ident.platform)
        with self._lock, self._conn() as c:
            c.execute("INSERT OR REPLACE INTO assessments (aid, path, name, redact, "
                      "frameworks, created_at, device, vendor, platform, supported, "
                      "score_pct, assessed_pct, frameworks_json, platform_fp) "
                      "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", row)

    def __setitem__(self, aid, value):
        da, path = value
        self.put(aid, da, path, name=Path(path).name, redact=True, frameworks=None)

    # ---------------------------------------------------------------- read
    def meta(self, aid: str) -> dict | None:
        with self._conn() as c:
            c.row_factory = sqlite3.Row
            r = c.execute("SELECT * FROM assessments WHERE aid=?", (aid,)).fetchone()
        if r is None:
            return None
        d = dict(r)
        d["redact"] = bool(d["redact"])
        d["frameworks"] = json.loads(d["frameworks"]) if d["frameworks"] else None
        return d

    def __contains__(self, aid) -> bool:
        return super().__contains__(aid) or self.meta(aid) is not None

    def __missing__(self, aid):
        """Rebuild an assessment recorded before a restart."""
        m = self.meta(aid)
        if m is None or not Path(m["path"]).exists():
            raise KeyError(aid)
        from ..pipeline import assess

        da = assess(m["path"], redact=m["redact"], assessment_id=aid,
                    frameworks=m["frameworks"])
        super().__setitem__(aid, (da, Path(m["path"])))
        return super().__getitem__(aid)

    def __len__(self) -> int:
        with self._conn() as c:
            return c.execute("SELECT COUNT(*) FROM assessments").fetchone()[0]

    def summaries(self) -> list[dict]:
        """The list view, from the database -- nothing is re-assessed to show it."""
        with self._conn() as c:
            c.row_factory = sqlite3.Row
            rows = c.execute("SELECT * FROM assessments ORDER BY created_at").fetchall()
        return [{"assessment_id": r["aid"], "device": r["device"],
                 "vendor": r["vendor"], "platform": r["platform"],
                 "supported": bool(r["supported"]),
                 "score_pct": r["score_pct"], "assessed_pct": r["assessed_pct"],
                 "frameworks": json.loads(r["frameworks_json"] or "{}"),
                 "assessed_at": r["created_at"]} for r in rows]
