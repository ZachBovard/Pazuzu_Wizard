"""The on-box timer for a guarded change (FreeBSD/OPNsense only).

Arming a window also schedules one `at` job on the firewall that runs the
recovery script after the window plus a margin. It uses a relative time
("now + N minutes") so a wrong or stepped clock cannot move it, and the script
is told the timer fired, so it undoes whatever is still armed without asking
the clock. If the change was confirmed, the job finds nothing to undo and does
nothing, so confirming never needs to cancel it.

Nothing here takes user input: the command and the paths are constants.
"""

from __future__ import annotations

import math
import re
import subprocess
from typing import Callable

AT = "/usr/bin/at"
RECOVER_SCRIPT = "/usr/local/libexec/hanbi/hanbi-recover"
MARGIN_SECONDS = 60
MAX_MINUTES = 24 * 60


def minutes_for(timeout_seconds: int, margin_seconds: int = MARGIN_SECONDS) -> int:
    """Whole minutes to wait: the window plus a margin, rounded up (at counts minutes)."""
    if (not isinstance(timeout_seconds, int) or isinstance(timeout_seconds, bool)
            or timeout_seconds <= 0):
        raise ValueError("timeout must be a positive whole number of seconds")
    minutes = math.ceil((timeout_seconds + margin_seconds) / 60)
    if minutes > MAX_MINUTES:
        raise ValueError("timer too long")
    return minutes


def arm(timeout_seconds: int,
        runner: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> str:
    """Schedule the recovery job. Returns a short description for the owner."""
    minutes = minutes_for(timeout_seconds)
    result = runner(
        [AT, "now", "+", str(minutes), "minutes"],
        input=f"{RECOVER_SCRIPT} --timer-fired\n",
        capture_output=True, text=True, timeout=15,
    )
    if result.returncode != 0:
        raise OSError(f"at failed with exit status {result.returncode}")
    found = re.search(r"job\s+(\d+)", (result.stderr or "") + (result.stdout or ""))
    job = f"job {found.group(1)}" if found else "a job"
    return f"{job}, runs in about {minutes} minute(s)"
