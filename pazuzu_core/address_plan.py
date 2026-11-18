"""Pick a random private network for each zone, so no two homes share the same addresses.

Pure planning: this chooses and checks. It does NOT change the firewall. Renumbering a live
network is not something the change guard's timer can undo, so applying a plan needs its own
verified path and is left off until then.

Each zone gets its own /24 inside 10.0.0.0/8. The firewall takes .1. Zones with ordinary
devices also get a lease pool (.100 to .199). Ranges people commonly pick by hand are avoided,
and so is anything already in use.
"""
from __future__ import annotations

import ipaddress
import secrets
from dataclasses import dataclass
from typing import Callable, Iterable, Mapping

# Zones that get a network, in the order they are handed out. The internet side (wan) gets none.
ZONES = ("trusted", "management", "iot", "guest", "kids", "dmz", "quarantine", "wireguard_admin")
# These have fixed or few members, so no lease pool is planned for them.
NO_POOL = {"management", "wireguard_admin"}
# Second octets people pick by hand, and that companies use for their own VPNs.
COMMON_SECOND_OCTETS = frozenset({0, 1, 2, 8, 10, 20, 30, 42, 50, 88, 100, 101, 110, 128, 192, 200, 254, 255})
POOL_FIRST, POOL_LAST = 100, 199


@dataclass(frozen=True)
class ZoneAddress:
    zone: str
    network: str
    firewall_ip: str
    dhcp_start: str | None
    dhcp_end: str | None


@dataclass(frozen=True)
class AddressPlan:
    zones: tuple[ZoneAddress, ...]

    def by_zone(self) -> dict[str, ZoneAddress]:
        return {z.zone: z for z in self.zones}


def _default_rng(low: int, high: int) -> int:
    return low + secrets.randbelow(high - low + 1)


def _net(text: str) -> ipaddress.IPv4Network:
    net = ipaddress.ip_network(str(text), strict=False)
    if not isinstance(net, ipaddress.IPv4Network):
        raise ValueError("only IPv4 networks are planned (IPv6 is off)")
    return net


def _overlaps(candidate: ipaddress.IPv4Network, others: Iterable[ipaddress.IPv4Network]) -> bool:
    return any(candidate.overlaps(o) for o in others)


def plan_addresses(zones: Iterable[str], avoid: Iterable[str] = (),
                   rng: Callable[[int, int], int] | None = None) -> AddressPlan:
    """A /24 for each zone asked for. `avoid` is networks already in use; the new ones never overlap
    them or each other. `rng(low, high)` can be replaced in tests."""

    pick = rng or _default_rng
    wanted = []
    for z in zones:
        if z not in ZONES:
            raise ValueError(f"no network is planned for zone {z!r}")
        if z not in wanted:
            wanted.append(z)
    taken = [_net(a) for a in avoid]
    out = []
    for zone in sorted(wanted, key=ZONES.index):
        for _ in range(500):
            second, third = pick(2, 253), pick(1, 254)
            if second in COMMON_SECOND_OCTETS:
                continue
            net = ipaddress.ip_network(f"10.{second}.{third}.0/24")
            if _overlaps(net, taken):
                continue
            break
        else:
            raise ValueError("could not find a free network; too many are in use")
        taken.append(net)
        base = int(net.network_address)
        pool = zone not in NO_POOL
        out.append(ZoneAddress(
            zone, str(net), str(ipaddress.ip_address(base + 1)),
            str(ipaddress.ip_address(base + POOL_FIRST)) if pool else None,
            str(ipaddress.ip_address(base + POOL_LAST)) if pool else None))
    return AddressPlan(tuple(out))


def validate_plan(plan: AddressPlan, avoid: Iterable[str] = ()) -> list[str]:
    """Problems with a plan, in plain words. Empty means it is sound."""

    problems = []
    taken = [_net(a) for a in avoid]
    seen: list[ipaddress.IPv4Network] = []
    for z in plan.zones:
        try:
            net = _net(z.network)
        except ValueError:
            problems.append(f"{z.zone}: not an IPv4 network")
            continue
        if net.prefixlen != 24:
            problems.append(f"{z.zone}: must be a /24")
        if not net.is_private:
            problems.append(f"{z.zone}: must be a private range")
        if _overlaps(net, taken) or _overlaps(net, seen):
            problems.append(f"{z.zone}: overlaps a network already in use")
        seen.append(net)
    return problems


_ZONE_WORDS = {
    "trusted": "Trusted Network (LAN)", "management": "Management", "iot": "Smart devices",
    "guest": "Guests", "kids": "KidsNet", "dmz": "Public servers", "quarantine": "Quarantine",
    "wireguard_admin": "Remote admin (VPN)",
}


def zone_word(zone: str) -> str:
    return _ZONE_WORDS.get(zone, zone)


def guidance_lines(plan: AddressPlan, ports: Mapping[str, str], virtual: Iterable[str] = ()) -> list[str]:
    """What the person does, in order. `ports` maps a zone to its port label, for example
    {"trusted": "LAN (em3)"}. The firewall is restarted once, because that is when every
    service picks up its new address."""

    virtual = set(virtual)
    lines = [
        "Before anything: download a backup of the firewall's configuration and keep it on this device.",
        "Keep a second way in open (the management port or the VPN). You cannot rely on the network "
        "you are renumbering to get you back in.",
        "The firewall must be restarted once after the change. The new addresses take effect when it "
        "starts again, and until then the old ones still work.",
    ]
    for z in plan.zones:
        port = ports.get(z.zone)
        where = (f"plug it into {port}" if port else
                 "it sits on a virtual interface for now, so no port is needed" if z.zone in virtual else
                 "it has no port yet")
        if z.zone == "wireguard_admin":
            lines.append(f"{zone_word(z.zone)}: tunnel network {z.network}, firewall end {z.firewall_ip}. "
                         "Every phone and laptop needs a new tunnel config afterwards.")
            continue
        pool = f" It hands out {z.dhcp_start} to {z.dhcp_end}." if z.dhcp_start else ""
        lines.append(f"{zone_word(z.zone)}: network {z.network}, the firewall is {z.firewall_ip}; "
                     f"{where}.{pool}")
    lines += [
        "After the restart, each computer keeps its old address until it reconnects: unplug its cable "
        "for five seconds, or turn Wi-Fi off and on. A device with a fixed address must be changed by hand.",
        "The firewall's settings page moves to the new address of your management network.",
    ]
    return lines
