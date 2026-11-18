"""A second way to the internet: find the port, and say, from what the firewall reports, what is left to do.

Pure: an interface report (and, if it could be read, the firewall's gateway list) in, a checklist out.
It never guesses what a port IS beyond its name: a `ue` port is a USB network port (a phone's tethering or
a USB network adapter, the firewall cannot tell which); a port already used as the internet side (WAN) or the
home network (LAN) is never offered. Each step is done, still to do, or not known yet, and a step still to do
says what to press. Nothing here changes the firewall.
"""

from __future__ import annotations

import re
from typing import Any, Mapping, Sequence

_USB = re.compile(r"^(ue|cdce|ure|axe|axge|ipheth|urndis|muge)\d+$")
_WIFI = re.compile(r"^(wlan|iwm|iwn|iwx|iwlwifi|ath|bwfm|rtwn|urtwn|run|rsu|bwi|ral|rum|zyd|otus|mt7\d*)\d*$")
LABELS = {"usb": "USB network port (a phone's tethering, or a USB adapter)", "wifi": "Wi-Fi card"}
IN_USE = ("wan", "lan")                    # roles that already carry the main internet or the home network


def kind_of(device: str) -> str | None:
    return "usb" if _USB.match(device or "") else "wifi" if _WIFI.match(device or "") else None


def candidates(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Ports that could carry a backup, never one the firewall already uses as WAN or LAN."""
    found = []
    for item in report.get("interfaces", []):
        kind = kind_of(item["device"])
        if not kind or item["system"] or (item["identifier"] or "").lower() in IN_USE:
            continue
        found.append({"device": item["device"], "kind": kind, "label": LABELS[kind],
                      "assigned": item["assigned"], "identifier": item["identifier"],
                      "name": item["description"] or item["identifier"] or ""})
    return found


def _rows(gateways: Any) -> list[dict]:
    rows = gateways.get("rows") if isinstance(gateways, Mapping) else gateways
    return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []


_V4_ADDRESS = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_NAMED_V6 = re.compile(r"(?i)ipv6|v6|[a-z_]6$")


def gateway_family(row: Mapping[str, Any] | None) -> int | None:
    """4 or 6: the kind of address a gateway works with, or None when nothing in the row says.

    The firewall says it in `ipprotocol` ("inet" is IPv4, "inet6" is IPv6). A row that does not is read from the addresses
    it holds, and last from its name (a port that gets both kinds by DHCP has WAN_DHCP and WAN_DHCP6). The family matters:
    the firewall refuses a check address of one kind on a gateway of the other ("Invalid IPv6 address")."""
    if not isinstance(row, Mapping):
        return None
    proto = str(row.get("ipprotocol") or "").strip().lower()
    if proto in ("inet6", "ipv6", "6"):
        return 6
    if proto in ("inet", "ipv4", "4"):
        return 4
    for key in ("gateway", "monitor"):
        val = str(row.get(key) or "").strip()
        if ":" in val:
            return 6
        if _V4_ADDRESS.match(val):
            return 4
    return 6 if _NAMED_V6.search(str(row.get("name") or "")) else None


def _gw_for(rows: Sequence[dict], names: Sequence[str]) -> dict | None:
    """The gateway row for a port: the one on that port (by the port's name or id), or one named for it (WAN_DHCP for wan).

    A port can have two, one for IPv4 and one for IPv6, and the list may give either first. The IPv4 one is returned: the
    backup internet is an IPv4 connection, and what is changed on a gateway (the address it is checked against) has to be of
    the gateway's own kind. The IPv6 one is returned only when the port has no other."""
    want = {n.lower() for n in names if n}
    found = []
    for r in rows:
        if str(r.get("interface", "")).lower() in want:
            found.append(r)
            continue
        gname = str(r.get("name", "")).lower()
        if any(gname.startswith(w + "_") or gname == w for w in want):
            found.append(r)
    rank = {4: 0, None: 1, 6: 2}
    return min(found, key=lambda r: rank[gateway_family(r)], default=None)      # min keeps the list's order for equals


def _num(v: Any) -> int | None:
    try:
        return int(str(v))
    except (TypeError, ValueError):
        return None


def _step(sid: str, title: str, state: str, detail: str = "", how: Sequence[str] = (), link: str = "") -> dict:
    return {"id": sid, "title": title, "state": state, "detail": detail, "how": list(how), "link": link}


def plan(report: Mapping[str, Any], gateways: Any = None) -> dict[str, Any]:
    """The checklist. `gateways` is the firewall's gateway answer, or None when it could not be read."""
    cands = candidates(report)
    chosen = next((c for c in cands if c["assigned"]), None) or (cands[0] if cands else None)
    steps: list[dict] = []
    if chosen is None:
        steps.append(_step("found", "Plug in the second connection", "todo",
                           "No USB network port or Wi-Fi card is showing on this firewall.",
                           ["Phone: plug it into a USB port, then switch on USB tethering (Android: Settings, "
                            "Network, Hotspot and tethering, USB tethering. iPhone: Personal Hotspot, and tap "
                            "Trust on the phone).",
                            "Or plug in a USB network adapter and connect it to a second router.",
                            "Wait ten seconds, then press Check again."]))
        return {"candidates": cands, "chosen": None, "steps": steps, "done": False, "gateways_read": gateways is not None}

    row = next(i for i in report["interfaces"] if i["device"] == chosen["device"])
    steps.append(_step("found", "A port for it is there", "done", f"{chosen['device']}: {chosen['label']}."))
    if chosen["assigned"]:
        steps.append(_step("assigned", "It is set up on the firewall", "done",
                           f"As {chosen['identifier'].upper()}" + (f" ({chosen['name']})." if chosen["name"] and chosen["name"] != chosen["identifier"] else ".")))
    else:
        steps.append(_step("assigned", "Give it a place on the firewall", "todo",
                           f"{chosen['device']} is not used by anything yet.",
                           ["On the firewall's own page, open Interfaces, then Assignments.",
                            f"Choose {chosen['device']} in the list at the bottom, press +, then Save.",
                            "Press Check again here."], "/interfaces_assign.php"))
        return {"candidates": cands, "chosen": chosen, "steps": steps, "done": False, "gateways_read": gateways is not None}

    mode = row.get("ipv4_mode") or ""
    if row.get("enabled") in (0, False, "0") or mode in ("", "none"):
        steps.append(_step("address", "Turn it on and let it get an address", "todo",
                           "It is set up but not switched on, or has no way to get an address.",
                           ["On the firewall's own page, open Interfaces, then this port. Tick Enable.",
                            "Set IPv4 configuration type to DHCP (a phone or a router hands out the address).",
                            "Leave Block private networks and Block bogon networks unticked: the phone's own "
                            "network is a private one.",
                            "Save, then Apply changes, then press Check again here."],
                           f"/interfaces.php?if={chosen['identifier']}"))
    elif row.get("ipv4_address_count", 0) < 1 or str(row.get("status", "")).lower() in ("no carrier", "down"):
        steps.append(_step("address", "It has an address", "todo",
                           "It is on, but it has no address yet or no link.",
                           ["Check the phone: tethering on, cable in, screen unlocked once.",
                            "Or check the cable to the second router, and that its own internet works.",
                            "Wait a minute, then press Check again."]))
    else:
        steps.append(_step("address", "It has an address", "done"))

    if gateways is None:
        steps.append(_step("gateway", "The firewall knows a gateway for it", "unknown",
                           "The gateway list could not be read. Press Check this firewall in the wizard first."))
        steps.append(_step("order", "The main internet is preferred", "unknown"))
    else:
        rows = _rows(gateways)
        mine = _gw_for(rows, [chosen["identifier"], chosen["name"]])
        main = _gw_for(rows, ["wan"])
        if mine is None:
            steps.append(_step("gateway", "The firewall knows a gateway for it", "todo",
                               "No gateway is listed for this port yet. A port that gets its address by DHCP "
                               "usually makes one by itself once it is on and has an address.",
                               ["On the firewall's own page, open System, then Gateways, then Configuration.",
                                "Look for a gateway on this port. If there is none, add one with the router's "
                                "address, or use the card in the wizard (Extras, Backup internet) to add it."],
                               "/ui/routing/configuration"))
        else:
            steps.append(_step("gateway", "The firewall knows a gateway for it", "done", str(mine.get("name", ""))))
            p_mine, p_main = _num(mine.get("priority")), _num((main or {}).get("priority"))
            if p_mine is None or p_main is None:
                steps.append(_step("order", "The main internet is preferred", "unknown",
                                   "The firewall did not say the priorities."))
            elif p_mine > p_main:
                steps.append(_step("order", "The main internet is preferred", "done",
                                   f"Main {p_main}, backup {p_mine} (the lower number is used first)."))
            else:
                steps.append(_step("order", "Make the backup the second choice", "todo",
                                   f"Backup is {p_mine} and main is {p_main}. The lower number is used first.",
                                   ["Open the backup gateway and set its Priority above the main one's "
                                    "(for example 255 for the backup).",
                                   "Save and Apply. Then press Check again."], "/ui/routing/configuration"))
    steps.append(_step("test", "Try it", "manual", "",
                       ["Unplug the main internet cable (or switch its modem off).",
                        "Wait about a minute. A web page should still open, now by the backup.",
                        "Plug the main one back in. It should take over again by itself within a few minutes."]))
    auto = [s for s in steps if s["state"] != "manual"]
    return {"candidates": cands, "chosen": chosen, "steps": steps,
            "done": all(s["state"] == "done" for s in auto), "gateways_read": gateways is not None}
