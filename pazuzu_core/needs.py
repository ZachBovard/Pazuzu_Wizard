"""Check, before anything else loads, that this Python has the packages the wizard needs.

Without this a missing package ends in a long traceback ("No module named 'requests'") and no hint which
Python to install it into. Here the answer names the very Python that is running and gives the exact command.
"""
from __future__ import annotations

import importlib.util
import sys

REQUIRED = ("requests", "cryptography")


def missing(find=importlib.util.find_spec, names=REQUIRED) -> list[str]:
    out = []
    for name in names:
        try:
            if find(name) is None:
                out.append(name)
        except (ImportError, ValueError):
            out.append(name)
    return out


def install_help(lacking: list[str], exe: str | None = None, platform: str | None = None) -> str:
    exe = exe or sys.executable or "python"
    call = f'"{exe}"' if " " in exe else exe
    if (platform or sys.platform).startswith("win") and " " in exe:
        call = "& " + call
    return (f"This Python ({exe}) is missing: {', '.join(lacking)}.\n"
            f"Install it into this same Python with:\n    {call} -m pip install {' '.join(lacking)}\n"
            "Then start the wizard again the same way.")


def check_or_exit() -> None:
    lacking = missing()
    if lacking:
        print(install_help(lacking))
        raise SystemExit(2)
