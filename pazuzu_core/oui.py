"""Who made a device, from the first half of its MAC address (the registry of maker prefixes).

The list is a file in this folder (oui_prefixes.txt: six, seven or nine hex digits and a short maker name per line, taken from the IEEE
registry as compiled by the Nmap project). Nothing is looked up over the network. A phone or laptop that uses a private
Wi-Fi address has a made-up MAC with no maker, and is told apart by its flag bit instead.
"""
from __future__ import annotations

import re
import threading
from pathlib import Path

DATA = Path(__file__).with_name("oui_prefixes.txt")
PRIVATE_WORDS = "private address (the device's privacy setting)"
_table: dict[str, str] | None = None
_lock = threading.Lock()


def _load() -> dict[str, str]:
    global _table
    with _lock:
        if _table is None:
            table: dict[str, str] = {}
            try:
                for line in DATA.read_text(encoding="utf-8", errors="replace").splitlines():
                    prefix, _, name = line.partition(" ")
                    if len(prefix) in (6, 7, 9) and name.strip():
                        table[prefix.upper()] = name.strip()
            except OSError:
                table = {}
            _table = table
        return _table


def _hex(mac) -> str:
    h = re.sub(r"[^0-9A-Fa-f]", "", str(mac or ""))
    return h.upper() if len(h) >= 6 else ""


def is_private(mac) -> bool:
    """The 'locally administered' bit is set: the address was made up by the device, not assigned to its maker."""
    h = _hex(mac)
    if not h:
        return False
    first = int(h[:2], 16)
    return bool(first & 2) and not first & 1        # a set low bit is a group (broadcast, multicast) address, not a device


def vendor(mac) -> str:
    """The maker's short name, or "" when the prefix is unknown or the address is a private one."""
    h = _hex(mac)
    if not h or is_private(mac):
        return ""
    table = _load()
    for n in (9, 7, 6):                  # the registry also hands out smaller blocks (seven and nine digits): the longest match wins
        got = table.get(h[:n]) if len(h) >= n else None
        if got:
            return got
    return ""


def label(mac) -> str:
    """What to show when a device has no name: its maker, or a note that the address is private, or nothing."""
    return vendor(mac) or (PRIVATE_WORDS if is_private(mac) else "")
