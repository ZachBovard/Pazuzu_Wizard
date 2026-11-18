"""What the VPN may reach, made by Pazuzu (decided 29 Oct 2026: full tunnel, and Pazuzu does all of it, NAT included).

A phone on the VPN sends everything home (full tunnel). Without rules on the firewall's WireGuard side nothing it
sends is let through (seen on a production firewall: a handshake, then silence). So, on the WireGuard interface group,
from the tunnel's own network only:
  - the firewall's page (its own port) and the box's feed (the app, the TV and the touch page): the management the
    baseline already allows from the VPN;
  - the firewall's DNS, so the phone gets the same filtered answers as at home;
  - the internet, and only the internet (not the home's other networks): what a full tunnel is for;
  - but not DNS (53, 853) or time (UDP 123) out there, nor QUIC (UDP 443): four blocks ahead of the full-tunnel rule,
    as the home networks have (BUILD 442; prod, 1 Nov 2026: the full-tunnel rule alone drifted DNS, time and QUIC).
    The phone asks the firewall for names already (BUILD 420); apps fall back from QUIC to ordinary HTTPS by themselves.
No outbound NAT rule is made: OPNsense's own automatic (and hybrid) source NAT already lists the WireGuard network on
the internet side (seen on a production firewall, 29 Oct 2026), so the tunnel's traffic leaves by the firewall's address.

Read and plan only; the writes go through write_engine from "Finish getting to Happy".
"""
from __future__ import annotations

import ipaddress
from typing import Any, Iterable, Mapping

PREFIX = "Pazuzu: VPN "
GROUP = "wireguard"                        # OPNsense's interface group for every WireGuard instance
SEQ = "22"                                 # after the lifeline and the 30-second allows, before the baseline's own
BLOCK_SEQ = "21"                           # the four blocks: matched before the full-tunnel pass
BLOCK_PREFIX = PREFIX + "no "              # egress_drift knows them by this
FEED_PORT = 8787


def tunnel_net(tunneladdress: str) -> str | None:
    """The tunnel's own network from the instance's address (192.168.222.1/24 -> 192.168.222.0/24), IPv4 only."""
    for part in str(tunneladdress or "").split(","):
        try:
            net = ipaddress.ip_interface(part.strip()).network
        except ValueError:
            continue
        if net.version == 4 and net.is_private:
            return str(net)
    return None


def wanted(net: str, gui_port: int, feed_port: int = FEED_PORT) -> list[dict[str, str]]:
    base = {"enabled": "1", "sequence": SEQ, "action": "pass", "interface": GROUP, "direction": "in",
            "ipprotocol": "inet", "source_net": net, "log": "0"}
    block = {**base, "action": "block", "sequence": BLOCK_SEQ, "destination_net": "private_networks", "destination_not": "1"}
    return [
        {**block, "protocol": "TCP/UDP", "destination_port": "53", "description": BLOCK_PREFIX + "DNS on the internet (the firewall answers)"},
        {**block, "protocol": "TCP/UDP", "destination_port": "853", "description": BLOCK_PREFIX + "encrypted DNS on the internet"},
        {**block, "protocol": "UDP", "destination_port": "123", "description": BLOCK_PREFIX + "time servers on the internet (the firewall keeps time)"},
        {**block, "protocol": "UDP", "destination_port": "443", "description": BLOCK_PREFIX + "QUIC to the internet (HTTPS instead)"},
        {**base, "protocol": "TCP", "destination_net": "(self)", "destination_port": str(gui_port),
         "description": PREFIX + "to the firewall's page"},
        {**base, "protocol": "TCP", "destination_net": "(self)", "destination_port": str(feed_port),
         "description": PREFIX + "to the box's feed (app, TV, touch page)"},
        {**base, "protocol": "TCP/UDP", "destination_net": "(self)", "destination_port": "53",
         "description": PREFIX + "to the firewall's DNS"},
        {**base, "protocol": "any", "destination_net": "private_networks", "destination_not": "1",
         "description": PREFIX + "to the internet (full tunnel)"},
    ]


def missing(rule_rows: Iterable[Mapping], want: list[dict[str, str]]) -> list[dict[str, str]]:
    """The wanted rules not on the firewall yet, by their description (an exact match, switched on)."""
    have = {str(r.get("description") or r.get("descr") or "") for r in rule_rows or []
            if isinstance(r, Mapping) and str(r.get("enabled", "1")) not in ("0", "false")}
    return [w for w in want if w["description"] not in have]


ACL_NAME = "Pazuzu_VPN"            # Unbound's access-list name takes no spaces: "Pazuzu VPN" was refused on prod every time (31 Oct 2026)


def acl_values(net: str) -> dict:
    """Unbound's access-list entry letting the tunnel's network ask the firewall's DNS."""
    return {"enabled": "1", "name": ACL_NAME, "action": "allow", "networks": net,
            "description": "Pazuzu: let the VPN ask the firewall's DNS"}


def acl_missing(acl_rows: Iterable[Mapping], net: str) -> bool:
    """True when no switched-on allow entry names the tunnel's network."""
    for r in acl_rows or []:
        if not isinstance(r, Mapping) or str(r.get("enabled", "1")) in ("0", "false"):
            continue
        action = str(r.get("action", "")).lower()
        if action.startswith("allow") and net in str(r.get("networks", "")):
            return False
    return True
