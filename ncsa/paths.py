"""Where the engine reads its mapping packs from.

`packs/` is both read (every assessment) and written (every approved training
mapping lands in `packs/<platform>.learned.yaml`). `NCSA_PACKS_DIR` moves it:
the test suite points it at a per-session copy, so a test that approves a
mapping can never rewrite the real packs, and two test runs cannot read each
other's half-written files.

Resolved at CALL time, not import time, so setting the variable after import
still takes effect.
"""
from __future__ import annotations

import os
from pathlib import Path

DEFAULT_PACKS = "packs"


def resolve_packs_dir(packs_dir: str | Path | None = None) -> Path:
    """The default `packs` (or None) follows NCSA_PACKS_DIR; anything else is
    an explicit choice and is returned as given."""
    if packs_dir is None or str(packs_dir) in (DEFAULT_PACKS, f"./{DEFAULT_PACKS}"):
        return Path(os.environ.get("NCSA_PACKS_DIR") or DEFAULT_PACKS)
    return Path(packs_dir)
