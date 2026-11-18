"""Look at the firewall's ports before the finish page switches anything on.

The flight that cut a person off had nothing wrong with the rules: a USB network adapter had been swapped, the
numbers FreeBSD gives them (ue0, ue1, ue2) moved, and the saved settings still named the old ones. Nothing in the app
noticed. This compares what the firewall has now with the port choices saved earlier, and says what it finds.

Two kinds of finding:
  stop  something that is certain and makes the run unsafe to start (a port choice that is no longer true);
  warn  something worth a look that does not stop the run.
It only reads: the report it is given is the one the ports step reads, and nothing is sent.
"""
from __future__ import annotations

from typing import Any, Mapping

IPV6_OFF = ("Switch it off on the firewall: Interfaces, WAN, IPv6 Configuration Type: None, then Save and Apply.")


def _wan(report: Mapping[str, Any]) -> dict | None:
    for item in report.get("interfaces") or []:
        if isinstance(item, dict) and item.get("identifier") == "wan":
            return item
    return None


def _saved_ports(saved: Any) -> list[tuple[str, str, str]]:
    """(zone, device, identifier) for every port choice that names an existing port."""
    out = []
    assignments = (saved or {}).get("assignments") if isinstance(saved, dict) else None
    for zone, a in (assignments or {}).items() if isinstance(assignments, dict) else []:
        if isinstance(a, dict) and a.get("method") == "existing" and a.get("device"):
            out.append((str(zone), str(a.get("device")), str(a.get("identifier") or "")))
    return out


def check(report: Mapping[str, Any], saved_zones: Any = None) -> list[dict]:
    """The findings, most serious first. Each is {"id", "level", "text"}."""
    found: list[dict] = []
    items = [i for i in report.get("interfaces") or [] if isinstance(i, dict) and not i.get("system")]
    have = {str(i.get("device")): str(i.get("identifier") or "") for i in items if i.get("device")}

    moved, missing = [], []
    for zone, device, ident in _saved_ports(saved_zones):
        if device not in have:
            missing.append(device)
        elif ident and have[device] != ident:
            moved.append(device)
    if missing or moved:
        names = ", ".join(sorted(set(missing + moved)))
        what = ("The firewall no longer has " + ", ".join(sorted(set(missing))) if missing
                else "These ports are now used for something else: " + ", ".join(sorted(set(moved))))
        found.append({"id": "ports_moved", "level": "stop", "text": (
            f"The ports you chose earlier do not match the firewall any more ({names}). {what}. A USB network "
            "adapter that was swapped or plugged in again is the usual cause, because the numbers it gets (ue0, ue1, "
            "ue2) can move. Nothing was switched on. Open the ports step again so it reads the firewall as it is now, "
            "check LAN and WAN, then come back here.")})

    wan = _wan(report)
    if wan is not None:
        status = str(wan.get("status") or "").lower()
        if "no carrier" in status or status.strip() in ("down", "unknown"):
            found.append({"id": "wan_down", "level": "warn", "text": (
                "The WAN port reads as down (no cable or no adapter). The rules can still go on, but the firewall has "
                "no way out, so updates, block lists and time will not work until it is back.")})
        elif int(wan.get("ipv4_address_count") or 0) == 0:
            found.append({"id": "wan_no_address", "level": "warn", "text": (
                "The WAN has no address yet. The rules can still go on, but the firewall has no way out until it gets one.")})
        mode = str(wan.get("ipv6_mode") or "")
        if mode not in ("", "none"):
            found.append({"id": "wan_ipv6", "level": "warn", "text": (
                "IPv6 is switched on for the WAN. On some connections it keeps asking for an address and restarting the "
                "web page, SSH and DNS, which can look like the firewall dropping out. " + IPV6_OFF)})
    order = {"stop": 0, "warn": 1}
    return sorted(found, key=lambda f: order[f["level"]])
