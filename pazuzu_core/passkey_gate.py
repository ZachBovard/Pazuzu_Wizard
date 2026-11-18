"""The gate every firewall change goes through: a passkey touch on the plan.

A gate is a function `gate(digest, lines) -> bool`. `digest` names the exact
plan; `lines` are plain sentences saying what it will do. The real gate opens
the localhost page (passkey_server) and returns True only when a registered
passkey signed that digest. Code that changes the firewall takes a gate and
refuses to run without one that says yes.

Not gated, on purpose: undoing. The automatic undo when a window runs out,
the undo after a reboot, `revert` and `confirm` never wait for a person,
because an undo that needs a touch is an undo that may not happen.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Callable, Sequence

from pazuzu_core import passkey as pk
from pazuzu_core import passkey_server as ps

Gate = Callable[[str, Sequence[str]], bool]
DIGEST_LENGTH = 12

NO_PASSKEY = ("No passkey is registered on this device. Run:\n"
              "  python -m pazuzu_core.passkey_server register")


def plan_digest(kind: str, payload) -> str:
    """A short name for exactly this plan; any change to it changes the name."""

    body = json.dumps({"kind": kind, "plan": payload}, sort_keys=True,
                      separators=(",", ":"), default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()[:DIGEST_LENGTH]


def default_gate(creds_dir: Path | None = None, port: int = ps.DEFAULT_PORT,
                 timeout: float = 300, open_browser: bool = True,
                 say=print) -> Gate:
    folder = Path(creds_dir) if creds_dir else Path.home() / ".pazuzu"

    def gate(digest: str, lines: Sequence[str]) -> bool:
        try:
            if not pk.load_credentials(folder / pk.CREDENTIALS_FILE):
                say(NO_PASSKEY)
                return False
            return ps.serve_until(
                "approve", folder, port, ps.Pending(digest, tuple(lines)),
                timeout, open_browser, say)
        except (pk.PasskeyError, OSError) as exc:
            say(f"The passkey step could not run: {exc}")
            return False

    return gate
