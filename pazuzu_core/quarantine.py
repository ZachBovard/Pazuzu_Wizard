"""Quarantine a device from the manager's Devices list (asked 29 Oct 2026), with the passkey; Release puts it back.

A wired device on the Trusted Network cannot be moved to another network by the firewall alone, so it is held where it
is: its hardware (MAC) address goes on one list, PZ_quarantine (a MAC-address alias, so it follows the device whatever
address it gets), and a block rule on each of the firewall's inside ports stops anything from that list going anywhere:
not to the internet, not to other devices, not to the firewall. Nothing else is touched.

What it does not do, said plainly to the person: connections the device already had open may carry on until they
close (unplug it or restart it to be sure), and a device that changes its own MAC address (some phones do per network)
is a new device to the list. A true move to the quarantine network needs a port or Wi-Fi Pazuzu manages.
"""
from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

ALIAS = "PZ_quarantine"
RULE = "Pazuzu: quarantine"            # + " (<port>)"
SEQ = "2"                             # before every pass rule Pazuzu makes, and the person's own lifeline rules
MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
_FIND = re.compile(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}")


def clean_mac(mac: Any) -> str:
    m = str(mac or "").strip().lower().replace("-", ":")
    if not MAC.match(m):
        raise ValueError("That is not a device's hardware (MAC) address.")
    if int(m[:2], 16) & 1:
        raise ValueError("That is a group address, not one device.")
    return m


def macs_in(content: Any) -> list[str]:
    """The MAC addresses an alias row holds, whatever shape the firewall shows them in (one per line, commas, or a
    pick-list of entries)."""
    if isinstance(content, Mapping):
        content = " ".join(str(k) for k in content)
    elif isinstance(content, (list, tuple)):
        content = " ".join(str(x) for x in content)
    out: list[str] = []
    for m in _FIND.findall(str(content or "")):
        m = m.lower()
        if m not in out:
            out.append(m)
    return out


def alias_values(macs: Iterable[str]) -> dict:
    return {"enabled": "1", "name": ALIAS, "type": "mac", "content": "\n".join(macs),
            "description": "Pazuzu: quarantined devices (by hardware address)"}


def rule_values(iface: str, zone_word: str) -> dict:
    return {"enabled": "1", "sequence": SEQ, "action": "block", "interface": iface, "direction": "in",
            "ipprotocol": "inet46", "protocol": "any", "source_net": ALIAS, "destination_net": "any", "log": "1",
            "description": f"{RULE} ({zone_word})"}


def ports(zones: Mapping[str, Mapping], ident_of) -> list[tuple[str, str]]:
    """(the firewall's short name, a word for it) for each inside port with a zone: every bound zone but the internet
    side. `ident_of(device)` gives the short name (opt1) or None."""
    from pazuzu_core.nat_audit import ZONE_WORDS
    out = []
    for z, a in zones.items():
        if z == "wan" or not isinstance(a, Mapping) or a.get("state") != "bound" or not a.get("device"):
            continue
        ident = ident_of(str(a["device"]))
        if ident and ident not in [i for i, _w in out]:
            out.append((ident, ZONE_WORDS.get(z, z)))
    return out


def held_words(name: str) -> list[str]:
    return [f"{name} is in quarantine: it can reach nothing, not the internet, not your other devices.",
            "Connections it already had open may carry on until they close; unplug it or restart it to be sure.",
            "Release puts it back (Devices, on the Data screen)."]
