"""Deterministic translation of Alpha 0.4 manifest rules to OPNsense rules.

Pure functions: no network access, no file access.

One manifest rule can become several OPNsense rules because an OPNsense
rule has exactly one interface and one protocol:

  * one concrete rule per configured source zone (the rule must sit on the
    interface the traffic enters);
  * one concrete rule per protocol found in the expanded service groups.

A rule's destination port is a single port or an alias. When a protocol
has several ports, the rule references a port alias (see
alias_definitions.port_alias_spec) that the caller must create first;
OPNsense rejects comma-separated ports in a rule.

Tokens are resolved strictly. Anything that cannot be resolved raises
TranslationSkip with a reason instead of being passed to the firewall as a
guess. Zones left unconfigured in the zone assignment are dropped from
source and destination lists; a rule left with no configured source or
destination zone is skipped.

Enforcement levels (the `level` argument) change only three fields of the
concrete rules, `enabled`, `action` and `log`, never the match, the
sequence or the description, so a rule can later be moved between levels
in place:

  paused   every rule is created disabled. Nothing takes effect. (default)
  watch    a deny rule becomes an enabled pass rule that logs the traffic
           the deny would have dropped: "what would enforce hit?". It
           really does allow that traffic. Allow rules have no weaker form
           than enforce, so they stay disabled; deny rules on the WAN stay
           disabled too (an allow on the WAN is never created). Each
           such case is reported in Translation.notes.
  enforce  rules are enabled exactly as the manifest states them, except an
           allow rule on the WAN, which stays disabled at every level.

Which fields each level produces is covered by offline tests; none of it
has run on a firewall yet.

Proven against OPNsense 26.7 on the lab VM: "(self)" as destination,
interface names as networks, "any" as source, single ports, and network
aliases. Still unproven: UDP rules, protocol "any", port aliases, inverted
destinations and multi-value destination lists.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Mapping

from pazuzu_core.alias_definitions import AliasSpec, port_alias_spec
from pazuzu_core.zone_assignment import ALL_ZONES

THIS_FIREWALL = "(self)"

# Destination tokens that mean "the firewall itself".
FIREWALL_DESTINATIONS = frozenset(
    {"firewall", "firewall_management", "firewall_core"}
)

# "internet" is expressed as NOT private_networks. The alias must exist.
INTERNET = "internet"
PRIVATE_NETWORKS_ALIAS = "private_networks"

# One manifest rule may expand to fewer than this many concrete rules.
SEQUENCE_STRIDE = 100

_SERVICE = re.compile(r"^(tcp|udp)/(\d{1,5})$", re.IGNORECASE)
# Ping: "icmp/echo" is ICMP echo requests only (the firewall's own name for that type is echoreq).
ICMP_ECHO = "icmp/echo"
_DESCRIPTION_LIMIT = 255


PAUSED = "paused"
WATCH = "watch"
ENFORCE = "enforce"
LEVELS = (PAUSED, WATCH, ENFORCE)


class TranslationSkip(Exception):
    """The rule cannot be translated with the current zone assignment."""


@dataclass(frozen=True)
class Translation:
    rules: tuple[dict[str, str], ...]
    dropped_zones: tuple[str, ...]
    alias_refs: frozenset[str]
    alias_specs: tuple[AliasSpec, ...] = ()
    level: str = PAUSED
    notes: tuple[str, ...] = ()


def apply_level(
    concrete: dict[str, str],
    *,
    level: str,
    zone: str,
    manifest_action: str,
) -> str | None:
    """Set enabled/action/log on one concrete rule for a level.

    Returns a note when the level could not be honoured and the rule was
    left disabled, otherwise None.
    """

    if level == PAUSED:
        return None

    if manifest_action == "pass" and zone == "wan":
        # An allow on the WAN is never switched on by a level. Only VPN setup opens the tunnel port.
        return "allow rules on the WAN are never enabled by a level; left disabled"

    if level == ENFORCE:
        concrete["enabled"] = "1"
        return None

    # watch
    if manifest_action != "block":
        return "allow rules have no watch mode; left disabled"
    if zone == "wan":
        return "deny rules on the WAN have no watch mode; left disabled"

    concrete["enabled"] = "1"
    concrete["action"] = "pass"
    concrete["log"] = "1"
    return None


def expand_services(
    tokens: list[str],
    service_groups: Mapping[str, list[str]],
) -> list[tuple[str, tuple[str, ...]]]:
    """Return [(protocol, ports)] with ports de-duplicated, sorted numerically."""

    names = [str(token) for token in tokens]

    if any(name.lower() == "all" for name in names):
        if len(names) != 1:
            raise TranslationSkip("'all' cannot be combined with other services")
        return [("any", ())]

    by_protocol: dict[str, set[int]] = {}
    icmp = False

    for name in names:
        group = service_groups.get(name)
        members = [name] if group is None else list(group)

        for member in members:
            if str(member).lower() == ICMP_ECHO:
                icmp = True
                continue
            match = _SERVICE.match(str(member))
            if not match:
                raise TranslationSkip(f"unsupported service {member!r}")

            port = int(match.group(2))
            if not 1 <= port <= 65535:
                raise TranslationSkip(f"port out of range in {member!r}")

            by_protocol.setdefault(match.group(1).upper(), set()).add(port)

    if not by_protocol and not icmp:
        raise TranslationSkip("rule has no services")

    return [
        (protocol, tuple(str(p) for p in sorted(by_protocol[protocol])))
        for protocol in sorted(by_protocol)
    ] + ([("ICMP", ())] if icmp else [])


def _sources(
    tokens: list[str],
    zones: Mapping[str, str],
) -> tuple[list[tuple[str, str]], list[str]]:
    resolved: list[tuple[str, str]] = []
    dropped: list[str] = []

    for token in tokens:
        name = str(token).lower()

        if name not in ALL_ZONES:
            raise TranslationSkip(f"source {token!r} has no interface binding")

        interface = zones.get(name)
        if interface is None:
            dropped.append(name)
        elif (name, interface) not in resolved:
            resolved.append((name, interface))

    if not resolved:
        raise TranslationSkip(
            "no configured source zone (" + ", ".join(sorted(set(dropped))) + ")"
        )

    return resolved, dropped


def _literal_ipv4(token: str) -> bool:
    """True for an IPv4 address or network written as numbers. Never a name."""
    try:
        net = ipaddress.ip_network(token.strip(), strict=True)
    except ValueError:
        return False
    return net.version == 4


def _destinations(
    tokens: list[str],
    zones: Mapping[str, str],
) -> tuple[str, str, set[str], list[str]]:
    """Return (destination_net, destination_not, alias_refs, dropped_zones)."""

    lowered = [str(token).lower() for token in tokens]

    if INTERNET in lowered:
        if len(lowered) != 1:
            raise TranslationSkip(
                "'internet' cannot be combined with other destinations"
            )
        return PRIVATE_NETWORKS_ALIAS, "1", {PRIVATE_NETWORKS_ALIAS}, []

    networks: list[str] = []
    aliases: set[str] = set()
    dropped: list[str] = []

    for token in tokens:
        name = str(token).lower()

        if name in ALL_ZONES:
            interface = zones.get(name)
            if interface is None:
                dropped.append(name)
                continue
            value = interface
        elif name == "any":
            value = "any"
        elif name in FIREWALL_DESTINATIONS:
            value = THIS_FIREWALL
        elif _literal_ipv4(str(token)):
            value = str(token).strip()          # one device, by address: nothing to look up
        else:
            value = str(token)
            aliases.add(value)

        if value not in networks:
            networks.append(value)

    if not networks:
        raise TranslationSkip(
            "no configured destination zone ("
            + ", ".join(sorted(set(dropped)))
            + ")"
        )

    if "any" in networks:
        networks = ["any"]
        aliases = set()

    return ",".join(networks), "0", aliases, dropped


def _description(object_id: str, name: str, interface: str, protocol: str) -> str:
    prefix = f"PAZUZU:{object_id}:"
    suffix = f" [{interface}/{protocol}]"
    room = _DESCRIPTION_LIMIT - len(prefix) - len(suffix)
    return f"{prefix}{name[:max(room, 0)]}{suffix}"


def translate_rule(
    rule: Mapping[str, Any],
    *,
    zones: Mapping[str, str],
    service_groups: Mapping[str, list[str]],
    level: str = PAUSED,
) -> Translation:
    if level not in LEVELS:
        raise ValueError(f"unknown enforcement level {level!r}")

    direction = str(rule["direction"]).lower()
    direction = {"inbound": "in", "outbound": "out"}.get(direction, direction)

    if direction != "in":
        raise TranslationSkip(f"direction {direction!r} is not supported yet")

    action = {"allow": "pass", "deny": "block", "reject": "reject"}.get(rule["action"])
    if action is None:
        raise TranslationSkip(f"unsupported action {rule['action']!r}")

    sources, dropped_sources = _sources(list(rule["source"]), zones)
    destination, negate, aliases, dropped_destinations = _destinations(
        list(rule["destination"]), zones
    )
    services = expand_services(list(rule["services"]), service_groups)

    port_specs: dict[str, AliasSpec] = {}
    port_values: dict[str, str] = {}

    for protocol, ports in services:
        if len(ports) >= 2:
            spec = port_alias_spec(protocol, ports)
            port_specs[spec.name] = spec
            port_values[protocol] = spec.name
        else:
            port_values[protocol] = ports[0] if ports else ""

    concrete: list[dict[str, str]] = []
    notes: list[str] = []

    for zone, interface in sources:
        # Traffic entering WAN can come from anywhere, not just the upstream
        # subnet that "WAN net" would describe.
        source_net = "any" if zone == "wan" else interface

        for protocol, _ports in services:
            entry = {
                "enabled": "0",
                "sequence": str(
                    int(rule["priority"]) * SEQUENCE_STRIDE + len(concrete)
                ),
                "action": action,
                "quick": "1",
                "interface": interface,
                "direction": direction,
                "ipprotocol": "inet",
                "protocol": protocol,
                "source_net": source_net,
                "source_not": "0",
                "source_port": "",
                "destination_net": destination,
                "destination_not": negate,
                "destination_port": port_values[protocol],
                "log": "1" if rule["log"] else "0",
                "description": _description(
                    str(rule["object_id"]),
                    str(rule["name"]),
                    interface,
                    protocol,
                ),
            }
            if protocol == "ICMP":
                entry["icmptype"] = "echoreq"         # ping only, not every kind of ICMP
            note = apply_level(
                entry, level=level, zone=zone, manifest_action=action
            )
            if note:
                notes.append(f"{rule['object_id']} [{interface}/{protocol}]: {note}")
            concrete.append(entry)

    return Translation(
        rules=tuple(concrete),
        dropped_zones=tuple(sorted(set(dropped_sources + dropped_destinations))),
        alias_refs=frozenset(aliases | set(port_specs)),
        alias_specs=tuple(port_specs[name] for name in sorted(port_specs)),
        level=level,
        notes=tuple(notes),
    )
