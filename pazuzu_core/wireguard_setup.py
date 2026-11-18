"""Plan the secure remote-access tunnel (WireGuard). Pure: nothing here touches a firewall.

The wizard's `remote_admin` step ("Set up secure remote access") is done when
a device has enrolled: its tunnel has shaken hands with the firewall. This
module plans the parts the wizard owns and checks the result. It does not
make keys: each device makes its own key pair and only the public half ever
reaches the firewall (the manifest's `private_key_storage` rule), and the
firewall's own config builder already makes a peer config and a QR code.

What is planned:
  * a random UDP listen port, away from the default 51820 and the usual lists;
  * a tunnel subnet (a /24) that must not overlap anything in use;
  * which interfaces the tunnel's own port is opened on (the LAN in the lab;
    the WAN only if asked for, never by default);
  * one address per device, one device per peer;
  * the `peer_enrolled` check, from a recent handshake;
  * which peers have passed their expiry and must be revoked.

Applying a plan is separate work: `describe_changes` lists everything that
has to move together so nothing is changed halfway.
"""

from __future__ import annotations

import ipaddress
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping, Sequence

LOW = 10240
HIGH = 49151            # FreeBSD's ephemeral range starts at 49152
MAX_TRIES = 500
ZONE = "wireguard_admin"
INTERFACE = "wg0"
HANDSHAKE_FRESH_SECONDS = 180   # WireGuard re-handshakes about every 2 minutes
ALLOWED_LISTEN = ("lan", "wan")

# The default and the first ports a scanner or a tired admin tries.
AVOID = frozenset({
    51820, 51821, 51822, 1194, 1701, 4500, 500, 443, 53, 123, 5000, 8080,
    8443, 10000, 12345, 31337, 41641,
})


@dataclass(frozen=True)
class WireGuardPlan:
    listen_port: int
    tunnel_subnet: str
    listen_on: tuple[str, ...]
    interface: str = INTERFACE
    zone: str = ZONE

    @property
    def server_address(self) -> str:
        net = ipaddress.ip_network(self.tunnel_subnet)
        return f"{next(net.hosts())}/{net.prefixlen}"


def _default_rng(low: int, high: int) -> int:
    return low + secrets.randbelow(high - low + 1)


def _port_ok(port: int, reserved: frozenset[int]) -> bool:
    return LOW <= port <= HIGH and port not in AVOID and port not in reserved \
        and port % 100 != 0


def _network(value: str) -> ipaddress.IPv4Network:
    try:
        net = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise ValueError(f"not a network: {value!r}") from exc
    if net.version != 4:
        raise ValueError("the tunnel subnet must be IPv4 (IPv6 is off)")
    return net


def validate_tunnel_subnet(
    subnet: str, avoid: Iterable[str] = ()
) -> list[str]:
    errors = []
    try:
        net = _network(subnet)
    except ValueError as exc:
        return [str(exc)]
    if net.prefixlen != 24:
        errors.append("the tunnel subnet must be a /24")
    if not net.is_private:
        errors.append("the tunnel subnet must be a private range")
    for other in avoid:
        if net.overlaps(_network(other)):
            errors.append("the tunnel subnet overlaps a network already in use")
            break
    return errors


def plan_wireguard(
    *,
    tunnel_subnet: str,
    avoid_networks: Iterable[str] = (),
    reserved_udp_ports: Iterable[int] = (),
    listen_on: Sequence[str] = ("lan",),
    rng: Callable[[int, int], int] | None = None,
) -> WireGuardPlan:
    """Pick the port and check the subnet. The subnet is given, not guessed:
    it comes from the site plan (or, in the lab, from the person)."""
    problems = validate_tunnel_subnet(tunnel_subnet, avoid_networks)
    if problems:
        raise ValueError("; ".join(problems))
    where = tuple(listen_on)
    if not where or any(w not in ALLOWED_LISTEN for w in where) or \
            len(set(where)) != len(where):
        raise ValueError("listen_on must be lan, wan or both, each once")
    draw = rng or _default_rng
    taken = frozenset(int(p) for p in reserved_udp_ports)
    for _ in range(MAX_TRIES):
        port = draw(LOW, HIGH)
        if _port_ok(port, taken):
            return WireGuardPlan(port, str(_network(tunnel_subnet)), where)
    raise ValueError("could not find a free tunnel port")


def next_peer_address(plan: WireGuardPlan, used: Iterable[str]) -> str:
    """The next free host address in the tunnel, as a /32. The firewall holds
    the first address; one device gets one address."""
    net = ipaddress.ip_network(plan.tunnel_subnet)
    taken = {ipaddress.ip_interface(u).ip for u in used}
    hosts = net.hosts()
    taken.add(next(hosts))            # the firewall's own address
    for host in hosts:
        if host not in taken:
            return f"{host}/32"
    raise ValueError("the tunnel subnet has no free addresses")


def describe_changes(plan: WireGuardPlan) -> list[dict[str, str]]:
    """Everything that must be created together when the plan is applied."""
    if validate_tunnel_subnet(plan.tunnel_subnet):
        raise ValueError("invalid tunnel subnet")
    changes = [
        {"target": f"WireGuard instance {plan.interface}",
         "change": f"listen on UDP {plan.listen_port}, address {plan.server_address}"},
        {"target": "interface assignment",
         "change": f"assign and enable {plan.interface}"},
        {"target": f"zone {plan.zone}",
         "change": f"bind to {plan.interface} (lets PZ-MGMT-002 be created)"},
    ]
    for where in plan.listen_on:
        if where == "lan":
            changes.append({
                "target": "manifest rule PZ-WG-001 (the tunnel port, from the LAN)",
                "change": f"set service group wireguard_tunnel to udp/{plan.listen_port}, "
                          "so the tunnel survives the stock allow-all rules being "
                          "turned off"})
        else:
            changes.append({
                "target": f"firewall rule on {where} (outside the baseline)",
                "change": f"allow UDP {plan.listen_port} to this firewall. The baseline "
                          "prohibits inbound WAN allows, so this is an explicit owner "
                          "choice, never a default"})
    changes.append({
        "target": "enrolment",
        "change": "each device makes its own key pair; only its public key is "
                  "entered, with one address from next_peer_address"})
    return changes


def peer_enrolled(
    peers: Iterable[Mapping[str, Any]], public_key: str,
    *, now: float, fresh_seconds: int = HANDSHAKE_FRESH_SECONDS,
) -> bool:
    """True when this peer has shaken hands recently. `latest_handshake` is
    seconds since the epoch; zero or missing means it never has."""
    for peer in peers:
        if peer.get("public_key") != public_key:
            continue
        shaken = peer.get("latest_handshake")
        if isinstance(shaken, bool) or not isinstance(shaken, (int, float)):
            return False
        return shaken > 0 and 0 <= now - shaken <= fresh_seconds
    return False


def expired_peers(
    peers: Iterable[Mapping[str, Any]], *, now: datetime,
) -> list[str]:
    """Public keys of peers whose `expires_at` (ISO 8601 with a zone) has
    passed. A peer with no expiry never expires; one with an unreadable
    expiry is treated as expired, so a typo cannot keep access open."""
    if now.tzinfo is None:
        raise ValueError("now must carry a time zone")
    out = []
    for peer in peers:
        raw = peer.get("expires_at")
        if raw in (None, ""):
            continue
        try:
            when = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            if when <= now:
                out.append(str(peer.get("public_key")))
        except ValueError:
            out.append(str(peer.get("public_key")))
    return out
