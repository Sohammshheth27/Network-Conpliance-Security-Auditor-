"""Tamper-evident reports: every PDF the engine issues is signed.

An assessment report is what an auditor signs against, so it has to be
possible to prove later that a PDF is the one this engine produced and has
not been edited since. Each PDF is hashed (SHA-256) and the hash is signed
with an Ed25519 key:

  * the PRIVATE key lives in the data directory (git-ignored) and never
    leaves this machine;
  * the PUBLIC key is served, so anyone can verify a report offline with no
    secret -- which is the point of an asymmetric signature over an HMAC;
  * every issued report is recorded (hash, signature, assessment, time), so
    /verify-report can also say "this engine never issued that file".

The signature is DETACHED (response headers and the record), because writing
it into the PDF would change the bytes it signs.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
    sha256     TEXT PRIMARY KEY,
    signature  TEXT NOT NULL,
    aid        TEXT NOT NULL,
    framework  TEXT,
    issued_at  TEXT NOT NULL
)
"""


class ReportSigner:
    def __init__(self, data_dir: str | Path):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        self.dir = Path(data_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        key_file = self.dir / "report_signing_key.pem"
        if key_file.exists():
            self._key = serialization.load_pem_private_key(key_file.read_bytes(), None)
        else:
            self._key = Ed25519PrivateKey.generate()
            key_file.write_bytes(self._key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
        self.public_pem = self._key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        self._db = self.dir / "reports.db"
        with sqlite3.connect(self._db) as c:
            c.execute(_SCHEMA)

    # ------------------------------------------------------------------ sign
    def sign(self, data: bytes, *, aid: str, framework: str | None = None) -> dict:
        digest = hashlib.sha256(data).hexdigest()
        sig = base64.b64encode(self._key.sign(digest.encode())).decode()
        with sqlite3.connect(self._db) as c:
            c.execute("INSERT OR REPLACE INTO reports VALUES (?,?,?,?,?)",
                      (digest, sig, aid, framework,
                       datetime.now(timezone.utc).isoformat(timespec="seconds")))
        return {"sha256": digest, "signature": sig}

    # ---------------------------------------------------------------- verify
    def verify(self, data: bytes) -> dict:
        """authentic -- issued by this engine and unchanged;
        unknown   -- this engine never issued a file with these bytes
                     (edited, or produced elsewhere)."""
        from cryptography.exceptions import InvalidSignature

        digest = hashlib.sha256(data).hexdigest()
        with sqlite3.connect(self._db) as c:
            row = c.execute("SELECT signature, aid, framework, issued_at FROM reports "
                            "WHERE sha256=?", (digest,)).fetchone()
        if row is None:
            return {"verdict": "unknown", "sha256": digest,
                    "reason": "no report with these exact bytes was issued by this "
                              "engine -- it was altered, or produced elsewhere"}
        sig, aid, framework, issued = row
        try:
            self._key.public_key().verify(base64.b64decode(sig), digest.encode())
        except InvalidSignature:
            return {"verdict": "invalid", "sha256": digest,
                    "reason": "the recorded signature does not verify"}
        return {"verdict": "authentic", "sha256": digest, "assessment_id": aid,
                "framework": framework, "issued_at": issued, "signature": sig}


def verify_offline(data: bytes, signature_b64: str, public_pem: str) -> bool:
    """Check a report with only the public key -- no access to the engine."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_public_key(public_pem.encode())
    digest = hashlib.sha256(data).hexdigest().encode()
    try:
        key.verify(base64.b64decode(signature_b64), digest)
        return True
    except InvalidSignature:
        return False


def signature_note(meta: dict) -> str:
    return json.dumps({"sha256": meta["sha256"], "signature": meta["signature"],
                       "algorithm": "Ed25519 over the hex SHA-256 of the PDF"})
