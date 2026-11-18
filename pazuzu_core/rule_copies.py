"""Pazuzu rules that are on the firewall more than once, and which copy to keep. Pure functions; nothing is changed here.

A copy is a second rule with the same Pazuzu name (description) that matches exactly the same traffic: same interface,
action, IP version, protocol, from, to and ports, same order number. Copies change nothing about what gets through, they
only clutter the rules list (an earlier build added the whole set again when its record of what it had added was lost).
Rules that share a name but differ in what they match are not copies: they are reported, and left alone.

Which copy stays: a switched-on one before a switched-off one (removing a switched-off copy changes nothing), then the one
Pazuzu's record (receipt) lists, then the lowest id, so the answer is the same every time it is asked.
"""
from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

_OURS = re.compile(r"^PAZUZU:[A-Za-z0-9_-]+:")
MATCH_FIELDS = ("interface", "action", "direction", "ipprotocol", "protocol", "source_net", "source_not",
                "source_port", "destination_net", "destination_not", "destination_port", "quick", "sequence")


def _on(row: Mapping[str, Any]) -> bool:
    return str(row.get("enabled", "1")).strip().lower() in ("1", "true", "yes") and \
        str(row.get("disabled", "")).strip().lower() not in ("1", "true", "yes")


def _shape(row: Mapping[str, Any]) -> tuple:
    return tuple(str(row.get(f) if row.get(f) is not None else "").strip().lower() for f in MATCH_FIELDS)


def find(rows: Iterable[Mapping[str, Any]], recorded: Iterable[str] = ()) -> dict[str, Any]:
    """{"groups": [{"name", "keep", "remove": [ids], "count"}], "extra": how many copies would go,
    "differ": [names that share a name but not what they match]}."""
    listed = {str(u) for u in recorded or ()}
    by_name: dict[str, list[Mapping[str, Any]]] = {}
    for r in rows or ():
        if not isinstance(r, Mapping):
            continue
        name = str(r.get("description") or "")
        if _OURS.match(name) and r.get("uuid"):
            by_name.setdefault(name, []).append(r)
    groups, differ = [], []
    for name in sorted(by_name):
        same = by_name[name]
        if len(same) < 2:
            continue
        shapes = {_shape(r) for r in same}
        if len(shapes) != 1:
            differ.append(name)
            continue
        ranked = sorted(same, key=lambda r: (not _on(r), str(r["uuid"]) not in listed, str(r["uuid"])))
        groups.append({"name": name, "keep": str(ranked[0]["uuid"]),
                       "remove": [str(r["uuid"]) for r in ranked[1:]], "count": len(same)})
    return {"groups": groups, "extra": sum(len(g["remove"]) for g in groups), "differ": differ}


def plain_name(name: str) -> str:
    """"PAZUZU:PZ-IOT-010:Allow IoT web [opt2/TCP]" -> "PZ-IOT-010 Allow IoT web [opt2/TCP]", for a person to read."""
    m = re.match(r"^PAZUZU:([A-Za-z0-9_-]+):(.*)$", str(name))
    return (m.group(1) + " " + m.group(2).strip()) if m else str(name)
