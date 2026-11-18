"""Port forwards the person already had, kept reachable once the baseline is on. Read and planned here; the writes
go through write_engine from "Finish getting to Happy" and from the Reaching-in sheet.

Found on a production firewall, 30 Oct 2026: a WordPress box on the DMZ had two forwards (80 and 443) made the usual
way, each with its own linked firewall rule ("Register rule"). The baseline's WAN deny (PZ-WAN-001, "quick") sits
above those linked rules in the loaded ruleset, so nothing from the internet reached the box: the site was down from
outside and nobody could tell why. The fix that does not depend on rule order is the forward's own "Firewall rule"
setting on 26.7's Destination NAT page: "Pass" admits the traffic together with the translation, ahead of every rule,
so no later write that reorders the WAN rules can bury it again.

Second thing, same house: from inside, the site's public name points at the internet address, and the firewall does
not loop a connection back to itself (no NAT reflection), so the name failed indoors too. A host override in the
firewall's resolver (that name -> the box's own address) is the clean answer and what the person had done by hand for
the other names. The forward does not say its public name, so the sheet asks for it and makes the override.

Only forwards on the internet side count, and only ones that are switched on and really translate (not "no rdr").
Everything a person made is left as it is except the one setting; a forward Pazuzu itself makes (PZ-NAT-DNS,
PZ-NAT-NTP) is on an inside network and is never in this list.
"""
from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

PASS = "pass"                                  # the forward's "Firewall rule" value that admits its traffic with the NAT
PAGE = "/api/firewall/d_nat/search_rule?rowCount=-1&searchPhrase="
OVERRIDE_PREFIX = "Pazuzu: "                 # the override is found again by its description: "Pazuzu: <name> inside the house"
_HOST = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_IPV4 = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")


def _on(v: Any) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _is_wan(interface: Any) -> bool:
    return "wan" in [p.strip().lower() for p in str(interface or "").split(",")]


def forwards(rows: Any) -> list[dict]:
    """The person's forwards on the internet side, from the Destination NAT search rows, in the page's order:
    [{"uuid", "ports", "target", "local_port", "protocol", "descr", "pass", "buried"}]. `buried` is True when the
    forward's traffic is admitted by a separate rule (or none), which the baseline's WAN deny can sit above."""
    out = []
    for r in rows if isinstance(rows, list) else []:
        if not isinstance(r, Mapping) or r.get("is_automatic"):
            continue
        if _on(r.get("disabled")) or _on(r.get("nordr")) or not _is_wan(r.get("interface")):
            continue
        target = str(r.get("target") or "").strip()
        if not target:
            continue
        mode = str(r.get("pass") or "").strip().lower()
        out.append({"uuid": str(r.get("uuid") or ""), "ports": str(r.get("destination.port") or "").strip(),
                    "target": target, "local_port": str(r.get("local-port") or "").strip(),
                    "protocol": str(r.get("protocol") or "").strip().lower(), "descr": str(r.get("descr") or "").strip(),
                    "pass": mode, "buried": mode != PASS})
    return out


def buried(fw: Iterable[Mapping]) -> list[dict]:
    return [dict(f) for f in fw if f.get("buried")]


def by_target(fw: Iterable[Mapping]) -> list[dict]:
    """The forwards grouped by the box they reach: [{"target", "ports": [..], "descr", "buried": bool, "uuids"}]."""
    groups: dict = {}
    for f in fw:
        g = groups.setdefault(f["target"], {"target": f["target"], "ports": [], "descr": "", "buried": False, "uuids": []})
        if f.get("ports") and f["ports"] not in g["ports"]:
            g["ports"].append(f["ports"])
        g["descr"] = g["descr"] or f.get("descr") or ""
        g["buried"] = g["buried"] or bool(f.get("buried"))
        g["uuids"].append(f["uuid"])
    return list(groups.values())


def findings(fw: Iterable[Mapping]) -> list[str]:
    out = []
    for g in by_target(fw):
        if g["buried"]:
            who = g["descr"] or g["target"]
            out.append(f"The forward to {who} ({', '.join(g['ports']) or 'its ports'}) is buried under the baseline's "
                       "internet-side deny: nothing from the internet reaches it. Finish getting to Happy sets the "
                       "forward to admit its own traffic (Pass), which no rule order can bury")
    return out


def lines(todo: Mapping) -> list[str]:
    """The passkey screen's words."""
    out = []
    for g in by_target(todo.get("forwards") or []):
        out.append(f"Set the forward to {g['descr'] or g['target']} ({', '.join(g['ports']) or 'its ports'}) to admit its "
                   "own traffic (Firewall rule: Pass), so the internet-side deny no longer buries it")
    return out


def clean_public_name(name: Any) -> str:
    n = str(name or "").strip().lower().rstrip(".")
    if not _HOST.match(n):
        raise ValueError("That does not look like a name on the internet (like shop.example.com).")
    return n


def split_name(name: str) -> tuple[str, str]:
    """"www.example.com" -> ("www", "example.com"); "example.com" -> ("", "example.com") (the bare name)."""
    parts = name.split(".")
    if len(parts) <= 2:
        return "", name
    return parts[0], ".".join(parts[1:])


def override_values(name: str, target: str) -> dict:
    """The Unbound host override: `name` answered with the box's own address, inside the house."""
    name = clean_public_name(name)
    m = _IPV4.match(str(target or ""))
    if not m or any(int(x) > 255 for x in m.groups()):
        raise ValueError("The forward's target is not a single address, so no override can point at it.")
    host, domain = split_name(name)
    return {"enabled": "1", "hostname": host, "domain": domain, "rr": "A", "server": target,
            "description": f"{OVERRIDE_PREFIX}{name} inside the house"}


def override_there(rows: Any, name: str) -> dict | None:
    """The host override row that already answers `name`, whoever made it, or None."""
    try:
        name = clean_public_name(name)
    except ValueError:
        return None
    host, domain = split_name(name)
    for r in rows if isinstance(rows, list) else []:
        if not isinstance(r, Mapping):
            continue
        if (str(r.get("hostname") or "").strip().lower(), str(r.get("domain") or "").strip().lower()) == (host, domain):
            return dict(r)
    return None
