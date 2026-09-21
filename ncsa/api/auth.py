"""Console sign-in: a password and a one-time code.

THIS IS LOCAL AUTHENTICATION WITH MFA, NOT SINGLE SIGN-ON
---------------------------------------------------------
SSO means federating to an identity provider -- Entra ID, Okta, Google
Workspace -- over SAML or OIDC, so the password is never seen by this
application at all. What this module does is verify a local credential and a
TOTP code. The distinction matters in a room where somebody knows it, so the
console says "Sign in", never "SSO".

WHY A HASH AND NOT THE PASSWORD
-------------------------------
The demo credential is stored as a bcrypt hash, and the plaintext appears
nowhere in this repository.

That is not fastidiousness. This product reports NCSA-PLT-002 -- "stored
credentials and configuration parameters must be encrypted" -- as a FAIL on
devices that keep credentials in the clear. A compliance auditor whose own
console shipped a plaintext password in every clone and every line of its git
history would be the finding it exists to report.

The same reasoning drives the rest of the module: this console is built to
satisfy the controls it audits for. Account lockout is NCSA-EXT-013.
Administrative MFA is NCSA-EXT-014. Failed-login logging is NCSA-EXT-021.

WHICH AUTHENTICATORS WORK
-------------------------
The code is standard TOTP (RFC 6238, 6 digits, 30-second step), so Google
Authenticator, Microsoft Authenticator, Authy, 1Password and the RSA
Authenticator app in TOTP mode all work from the same QR code.

RSA SecurID HARDWARE TOKENS DO NOT. SecurID is a proprietary scheme with its
own seed record and server; a tool cannot accept one by implementing TOTP, and
claiming otherwise would be the kind of overstatement this project refuses.
"""
from __future__ import annotations

import base64
import hmac
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

#: The account the console accepts. One operator, by design: this is an
#: appliance console, not a multi-tenant application, and inventing a user
#: table would be scope nobody asked for.
DEFAULT_USER = "Administrator"

#: bcrypt hash of the demo credential, cost 12. Override in any real
#: deployment with NCSA_ADMIN_PASSWORD_HASH.
DEFAULT_PASSWORD_HASH = "$2b$12$EmXVZKnEWbyx19OsDwDGge5rJ1KttcH4/vBbgZoqmJpJmHS/Y53sq"

ISSUER = "NCSA"
SESSION_HOURS = 8

#: NCSA-EXT-013 (account lockout) applied to ourselves.
MAX_FAILURES = 5
LOCKOUT_SECONDS = 300


def _data_dir() -> Path:
    d = Path(os.environ.get("NCSA_DATA_DIR")
             or Path(__file__).resolve().parents[2] / "data")
    d.mkdir(parents=True, exist_ok=True)
    return d


def _state_path() -> Path:
    """Where the TOTP secret and the failure counter live.

    Under the data directory, which is git-ignored because it holds customer
    configurations -- and now a shared secret, which must never be committed
    for exactly the same reason.
    """
    return _data_dir() / "auth.json"


def _load() -> dict:
    p = _state_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _save(state: dict) -> None:
    _state_path().write_text(json.dumps(state, indent=1), encoding="utf-8")


# --------------------------------------------------------------- the secret
def totp_secret() -> str:
    """The shared secret, generated on first use and kept thereafter.

    Generated rather than shipped: a secret committed to a repository is known
    to everyone who ever cloned it, which is not a second factor.
    """
    import pyotp

    state = _load()
    secret = state.get("totp_secret")
    if not secret:
        secret = pyotp.random_base32()
        state["totp_secret"] = secret
        _save(state)
    return secret


def provisioning_uri(account: str | None = None) -> str:
    """The `otpauth://` URI an authenticator app scans."""
    import pyotp

    return pyotp.TOTP(totp_secret()).provisioning_uri(
        name=account or admin_user(), issuer_name=ISSUER)


def qr_svg() -> str:
    """The provisioning URI as an inline SVG.

    Rendered here rather than in the browser so the console needs no QR
    library and works with no network at all -- a demo machine on a
    conference wifi is not somewhere to discover a CDN dependency.
    """
    import io

    import qrcode
    import qrcode.image.svg

    img = qrcode.make(provisioning_uri(),
                      image_factory=qrcode.image.svg.SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode("utf-8")


# ------------------------------------------------------------- credentials
def admin_user() -> str:
    return os.environ.get("NCSA_ADMIN_USER") or DEFAULT_USER


def _password_hash() -> bytes:
    return (os.environ.get("NCSA_ADMIN_PASSWORD_HASH")
            or DEFAULT_PASSWORD_HASH).encode("utf-8")


def check_password(username: str, password: str) -> bool:
    """Constant-time on the username, bcrypt on the password.

    Both are checked even when the username is wrong, so the response time
    does not reveal which half failed.
    """
    import bcrypt

    user_ok = hmac.compare_digest((username or "").strip(), admin_user())
    try:
        pw_ok = bcrypt.checkpw((password or "").encode("utf-8"), _password_hash())
    except (ValueError, TypeError):
        pw_ok = False
    return user_ok and pw_ok


def check_otp(code: str) -> bool:
    """A six-digit code, and never the same one twice.

    `valid_window=1` accepts the adjacent 30-second step, because a phone's
    clock and a laptop's are rarely identical and a demo that fails on clock
    skew is a demo that fails.

    REPLAY IS REFUSED. Without this, a code read over someone's shoulder stays
    valid for its whole window -- and the window is what the tolerance above
    just widened. The step counter of the last accepted code is recorded and
    anything at or below it is rejected.
    """
    import pyotp

    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return False

    totp = pyotp.TOTP(totp_secret())
    if not totp.verify(code, valid_window=1):
        return False

    counter = int(time.time()) // 30
    state = _load()
    # The accepted code may belong to the previous step; find which.
    for candidate in (counter, counter - 1, counter + 1):
        if totp.at(candidate * 30) == code:
            counter = candidate
            break
    if counter <= int(state.get("last_otp_counter", -1)):
        return False
    state["last_otp_counter"] = counter
    _save(state)
    return True


# ---------------------------------------------------------------- lockout
@dataclass
class Lockout:
    locked: bool = False
    seconds_left: int = 0
    failures: int = 0


def lockout_state() -> Lockout:
    state = _load()
    until = float(state.get("locked_until", 0))
    left = int(until - time.time())
    if left > 0:
        return Lockout(True, left, int(state.get("failures", 0)))
    return Lockout(False, 0, int(state.get("failures", 0)))


def record_failure() -> Lockout:
    state = _load()
    failures = int(state.get("failures", 0)) + 1
    state["failures"] = failures
    if failures >= MAX_FAILURES:
        state["locked_until"] = time.time() + LOCKOUT_SECONDS
        state["failures"] = 0
    _save(state)
    return lockout_state()


def clear_failures() -> None:
    state = _load()
    state["failures"] = 0
    state.pop("locked_until", None)
    _save(state)


# ---------------------------------------------------------------- sessions
def _session_key() -> bytes:
    """A signing key that survives a restart but never reaches the repo."""
    state = _load()
    key = state.get("session_key")
    if not key:
        key = base64.b64encode(os.urandom(32)).decode()
        state["session_key"] = key
        _save(state)
    return key.encode()


def issue_session(username: str) -> str:
    from itsdangerous import URLSafeTimedSerializer

    return URLSafeTimedSerializer(_session_key(), salt="ncsa-console").dumps(
        {"u": username})


def verify_session(token: str) -> str | None:
    """The username this token proves, or None. Expiry is enforced here."""
    from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

    if not token:
        return None
    try:
        data = URLSafeTimedSerializer(_session_key(), salt="ncsa-console").loads(
            token, max_age=SESSION_HOURS * 3600)
    except (BadSignature, SignatureExpired):
        return None
    return data.get("u") if isinstance(data, dict) else None
