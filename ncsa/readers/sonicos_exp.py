"""SonicOS `.exp` acquisition adapter -- plan 4.2's acquisition layer.

WHAT THE PLAN GOT WRONG
-----------------------
Plan 4.2 records the `.exp` as an "obfuscated settings dump -- Unusable. Use the
CLI export instead." That is incorrect, and the correction matters: the `.exp`
is plain base64 of a URL-encoded `key=value` blob. Decoded, our own NSA 3700
export yields **92,636 settings** -- roughly forty times what the CLI export
carries, including the full firewall policy.

  raw            3,646,910 bytes, base64 alphabet, entropy 5.63
  decoded        2,735,180 bytes, 100% printable
  form           k1=v1&k2=v2&...   (URL-encoded, single line)

Contrast with the Sophos backup, where the plan IS right: that file begins
`Salted__` with entropy 8.00/8.00 -- genuine OpenSSL AES, not obfuscation.

SECURITY
--------
The decoded blob contains credentials (`encUsernamePassword`, `userIV`,
password hashes) and real addressing. Plan 5.1 is not advisory here: nothing
derived from this file reaches a repo, a report or a screenshot without
sanitisation. :func:`redact` is applied by default for that reason.
"""
from __future__ import annotations

import base64
import re
import urllib.parse
from pathlib import Path

from ..schema.enums import RecordState
from ..schema.evidence import EvidenceRef

# Keys whose VALUES must never be emitted, even in an internal artifact.
SECRET_KEY = re.compile(
    r"(passwordUniqueNum|userIV|encUsername|encPassword|.*[Hh]ash.*|.*[Ss]ecret.*|"
    r".*PrivKey.*|.*psk.*|.*sharedKey.*|.*[Cc]ert.*Data|.*apiKey.*|.*token.*)", re.I)
SECRET_VAL = re.compile(r"^[A-Fa-f0-9]{16,}$|^\$[0-9a-z]\$")
_IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")


class SonicOsExport:
    """Decoded SonicOS settings export, exposed as a path-style reader.

    Presents the same ``get`` / ``glob`` / ``multi`` surface as the block and
    braces readers, so ``apply_path_pack`` works unchanged and a SonicWall pack
    needs no new engine code.
    """

    def __init__(self, text: str, source_file: str, *, redact: bool = True):
        self.source_file = source_file
        self.redacted = redact
        self.values: dict[str, tuple[str, int, str]] = {}
        self.multi: dict[str, list[tuple[str, int, str]]] = {}
        self._consumed: set[int] = set()
        self._parse(text, redact)

    # ------------------------------------------------------------------ parse
    def _parse(self, text: str, redact: bool) -> None:
        for i, pair in enumerate(text.split("&"), start=1):
            if not pair:
                continue
            k, _, v = pair.partition("=")
            key = urllib.parse.unquote_plus(k).strip()
            val = urllib.parse.unquote_plus(v).strip()
            if not key:
                continue
            if redact:
                val = _redact_value(key, val)
            # `.exp` is one physical line; the ORDINAL is the only location we
            # have, so it becomes the line number for evidence purposes.
            entry = (val, i, f"{key}={val}"[:200])
            self.values[key] = entry
            self.multi.setdefault(key, []).append(entry)

    # ------------------------------------------------------------------ query
    def get(self, path: str) -> tuple[str, int, str] | None:
        hit = self.values.get(path)
        if hit is None:
            # SonicOS keys are flat, but packs may address them with a
            # section-style prefix for readability.
            tail = path.rsplit("/", 1)[-1]
            hit = self.values.get(tail)
        if hit:
            self._consumed.add(hit[1] - 1)
        return hit

    def glob(self, pattern: str) -> list[tuple[str, str, int, str]]:
        """`administration/*` or `snmp*` -- both shapes accepted."""
        pat = pattern.replace("/", "")
        rx = re.compile("^" + re.escape(pat).replace(r"\*", ".*") + "$", re.I)
        out = []
        for key, entries in self.multi.items():
            if rx.match(key):
                for val, ln, raw in entries:
                    out.append((key, val, ln, raw))
                    self._consumed.add(ln - 1)
        return out

    def get_all(self, path: str) -> list[tuple[str, int, str]]:
        return self.multi.get(path, [])

    # --------------------------------------------------------------- evidence
    def evidence(self, lineno: int, raw: str) -> EvidenceRef:
        return EvidenceRef(file=self.source_file, line=None,
                           raw=raw.strip()[:200], record_id=f"setting[{lineno}]")

    # ------------------------------------------------------------- accounting
    @property
    def significant_lines(self) -> list[int]:
        return list(range(len(self.values)))

    @property
    def total_records(self) -> int:
        return len(self.values)

    def consume_keys(self, keys) -> None:
        """Mark records as read by a consumer other than a pack mapping.

        The object-graph builder reads thousands of `addrObj*`, `svcObj*` and
        `policy*` records directly off `values`, and originally marked none of
        them. Record accounting therefore reported 31 parsed of 92,635 -- a
        0.03% read rate for a device whose graph we had fully reconstructed.
        The number was not wrong so much as measuring the wrong consumer, and
        an audit report that understates its own coverage misleads in the same
        way one that overstates it does.
        """
        for k in keys:
            rec = self.values.get(k)
            if rec is not None:
                self._consumed.add(rec[1] - 1)

    def accounting_snapshot(self) -> dict[str, int]:
        """Plan 14.1: TOTAL == PARSED + MAPPED + QUARANTINED + UNKNOWN.

        PARSED and MAPPED are different fates and were being conflated. Every
        record in a `.exp` IS parsed -- the format is key=value and the lexer
        reads all 92,635 of them. What only 8,390 have is a MAPPING to an SBM
        field. Reporting the mapped count as "parsed" made a reader that
        succeeds completely look like one that failed on 91% of the file.

        UNKNOWN here means "could not be read at all", which for this format is
        genuinely zero.
        """
        mapped = len(self._consumed)
        return {RecordState.MAPPED.value: mapped,
                RecordState.PARSED.value: max(self.total_records - mapped, 0),
                RecordState.UNKNOWN.value: 0}

    def unrecognised(self) -> list[EvidenceRef]:
        out = []
        for key, (val, ln, raw) in self.values.items():
            if ln - 1 not in self._consumed:
                out.append(self.evidence(ln, raw))
        return out[:500]          # cap: 90k unread keys is not a useful report


# A switch, not a secret. `encUsernamePassword=on` says stored credentials ARE
# encrypted; it matches the secret-key pattern by name, and redacting it turned
# NCSA-PLT-002 from FAIL into UNKNOWN -- turning privacy on changed a verdict.
# A value from this set cannot disclose a credential, so it is never redacted.
_FLAG_VALUE = re.compile(r"^(on|off|true|false|yes|no|enabled?|disabled?|0|1)$", re.I)


def _redact_value(key: str, val: str) -> str:
    if _FLAG_VALUE.match(val):
        return val
    if SECRET_KEY.search(key) or SECRET_VAL.match(val):
        return "<REDACTED>"
    return _IPV4.sub(lambda m: f"10.{m.group(2)}.{m.group(3)}.x", val)


class NotASonicOsExport(ValueError):
    """The file is not a readable SonicOS export."""


# OpenSSL's salted-password header. Sophos SFOS backups begin with this, and so
# does anything else `openssl enc` produced.
_OPENSSL_MAGIC = b"Salted__"
# A SonicOS setting name: an identifier, optionally indexed.
_SETTING_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{2,}(_\d+)?$")


def decode(path: str | Path) -> str:
    """`.exp` -> decoded URL-encoded settings text."""
    raw = Path(path).read_bytes()
    if raw[:8] == _OPENSSL_MAGIC:
        raise NotASonicOsExport(
            f"{Path(path).name!r} is OpenSSL-encrypted (starts with 'Salted__'), "
            "not a SonicOS export. It cannot be read without the password that "
            "was set when the backup was taken.")
    return base64.b64decode(raw, validate=False).decode("utf-8", errors="replace")


def _assert_plausible(export, source_name: str) -> None:
    """Refuse a decode that produced noise.

    Base64-decoding arbitrary bytes always "succeeds", and splitting the
    resulting garbage on "=" always yields pairs. Fed an encrypted Sophos
    backup, this reader reported 12,088 settings of which 2 had names that were
    even identifier-shaped -- 0.0%. Nothing downstream could tell that from a
    real device: the SBM would fill, controls would evaluate, and a report would
    come out the other end describing a device nobody ever parsed.

    A parser that cannot fail is not a parser. This is the gate.
    """
    n = len(export.values)
    if n == 0:
        raise NotASonicOsExport(f"{source_name!r} decoded to no settings at all")
    named = sum(1 for k in export.values if _SETTING_NAME.match(k))
    ratio = named / n
    if ratio < 0.5:
        raise NotASonicOsExport(
            f"{source_name!r} does not look like a SonicOS export: only "
            f"{named} of {n} setting names ({ratio:.1%}) are identifier-shaped. "
            "This is what decoding encrypted or unrelated bytes looks like.")


def load(path: str | Path, *, redact: bool = True) -> SonicOsExport:
    p = Path(path)
    text = decode(p) if p.suffix.lower() == ".exp" else p.read_text(
        encoding="utf-8", errors="replace")
    exp = SonicOsExport(text, p.name, redact=redact)
    _assert_plausible(exp, p.name)
    return exp


def loads(text: str, source_file: str = "<string>", *, redact: bool = True) -> SonicOsExport:
    return SonicOsExport(text, source_file, redact=redact)
