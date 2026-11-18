"""Letting through something the firewall just stopped, from the Blocks list.

One row of the log becomes one pass rule: that device on the home network, that kind of traffic (TCP or UDP)
to that port, to any address. It is either permanent, or it closes itself after 30 seconds (a test: allow it,
try again, see whether that was the thing in the way). Nothing here touches a firewall: the write goes through
the write engine like every other change (passkey, read back, undo kept).

What is never offered: traffic that came in from the internet, anything that is not TCP or UDP with a port,
and a device whose address is not a private IPv4 one.

BUILD 426 (prod, 30 Oct 2026): "Always" follows the device, not its address, and never opens the home networks:
  - "out":  the device (its hardware address, on a list of its own, PZ_dev_<mac>) may use that port, to the internet only
  - "home": your home network may reach that device on that port (your phone to the Hue bridge), stateful, so the device
            still starts nothing toward home
  - "udp":  the device may send any UDP to the internet (a doorbell's live video, a port that changes every session)
The 30-second test stays by address: it is gone before the address could change.
"""
from __future__ import annotations

import ipaddress
import re

TEMP_SECONDS = 30
SEQUENCE = "21"                       # after the country block's rules (11 to 13), before the baseline's own
KEEP = "Pazuzu: allow "
TEMP = "Pazuzu: 30-second allow "
KINDS = ("out", "home", "udp")
_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
_HOME = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]   # not Python's is_private, which also takes documentation ranges
# BUILD 491 (prod, 10 Nov 2026: "The port it came in on was not understood" on Allow it for a Tuya bulb): OPNsense names a
# VLAN port "vlan0.10" and a Wi-Fi one "iwn0_wlan1"; the dot and the underscore were turned away, so nothing on the IoT
# network could be allowed. The firewall's own port list still decides (interface_id), this only screens the text.
_DEVICE = re.compile(r"^[a-z][a-z0-9_.]{0,31}$")


def description(src: str, proto: str, dport: str, temp: bool) -> str:
    return (TEMP if temp else KEEP) + f"{src} {proto.lower()}/{dport}"


def check(src, proto, dport, device) -> list[str]:
    """Why this block cannot be allowed from here. Empty means it can."""
    out: list[str] = []
    try:
        a = ipaddress.ip_address(str(src))
        if a.version != 4 or not any(a in n for n in _HOME) or str(src).endswith(".255"):
            out.append("Only a device on your own network can be allowed here.")
    except ValueError:
        out.append("That device's address was not understood.")
    if str(proto).lower() not in ("tcp", "udp"):
        out.append("Only TCP and UDP can be allowed here.")
    if not re.fullmatch(r"[0-9]{1,5}", str(dport or "")) or not 1 <= int(dport) <= 65535:
        out.append("That block has no port to allow.")
    if not _DEVICE.match(str(device or "")):
        out.append("The port it came in on was not understood.")
    return out


def clean_mac(mac) -> str:
    m = re.sub(r"[^0-9a-fA-F]", "", str(mac or "")).lower()
    m = ":".join(m[i:i + 2] for i in range(0, 12, 2)) if len(m) == 12 else ""
    if not _MAC.match(m):
        raise ValueError("That device's hardware address was not understood.")
    return m


def dev_alias(mac: str) -> str:
    return "PZ_dev_" + mac.replace(":", "")


def dev_alias_values(mac: str, name: str) -> dict[str, str]:
    return {"enabled": "1", "name": dev_alias(mac), "type": "mac", "content": mac,
            "description": "Pazuzu: " + (name or mac)}


def keep_description(kind: str, mac: str, proto: str, dport: str) -> str:
    if kind == "udp":
        return KEEP + f"{mac} any udp out"
    if kind == "home":
        return KEEP + f"home to {mac} {proto.lower()}/{dport}"
    return KEEP + f"{mac} {proto.lower()}/{dport} out"


def keep_values(kind: str, iface_id: str, mac: str, proto: str, dport: str, home_net: str = "") -> dict[str, str]:
    """The three kinds of Always. `iface_id` is the port the rule sits on: the device's for out and udp, the home
    network's for home (with `home_net` its network)."""
    base = {"enabled": "1", "sequence": SEQUENCE, "action": "pass", "direction": "in", "ipprotocol": "inet", "log": "0",
            "interface": iface_id, "description": keep_description(kind, mac, proto, dport)}
    if kind == "udp":
        return {**base, "protocol": "UDP", "source_net": dev_alias(mac), "destination_net": "private_networks",
                "destination_not": "1"}
    if kind == "home":
        return {**base, "protocol": str(proto).upper(), "source_net": home_net, "destination_net": dev_alias(mac),
                "destination_port": str(dport)}
    return {**base, "protocol": str(proto).upper(), "source_net": dev_alias(mac), "destination_net": "private_networks",
            "destination_not": "1", "destination_port": str(dport)}


def rule_values(iface_id: str, src: str, proto: str, dport: str, temp: bool) -> dict[str, str]:
    """By address: the 30-second test (to anywhere, it is gone in 30 seconds), or an Always on a firewall with no plugin
    to name the device, which is internet only (BUILD 426)."""
    return {"enabled": "1", "sequence": SEQUENCE, "action": "pass", "interface": iface_id, "direction": "in",
            "ipprotocol": "inet", "protocol": str(proto).upper(), "source_net": str(src),
            "destination_net": "any" if temp else "private_networks", **({} if temp else {"destination_not": "1"}),
            "destination_port": str(dport), "log": "0", "description": description(src, proto, dport, temp)}


def note_for(dst: str) -> str:
    """A plain warning for the kinds of block where allowing rarely helps; empty for the rest."""
    try:
        a = ipaddress.ip_address(str(dst))
    except ValueError:
        return ""
    if a.version == 4 and (a.is_multicast or str(dst) == "255.255.255.255" or str(dst).endswith(".255")):
        return "This is a broadcast or multicast. Allowing it rarely helps, because it does not cross to other networks."
    if any(a in n for n in _HOME):
        return "This is aimed at another network inside your home. Allow it only if you meant that device to reach it."
    return ""
