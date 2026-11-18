"""Aliases Pazuzu may create, with fixed and reviewable contents.

Two kinds:

  * static aliases (private_networks) with hand-written contents;
  * port aliases derived from a rule's service list. OPNsense rejects a
    comma-separated port list in a single rule ("53,67,123"), so several
    ports on one protocol are expressed as a port alias. The alias name is
    derived from its contents (pz_udp_53_67_123), so the same ports always
    give the same name and a name never describes different contents.

Only names produced here can be created by the tooling. Anything else a
rule references must already exist on the firewall.

private_networks is deliberately independent of any per-install addressing:
it covers every address that is not routable on the public internet, so
policy written as "deny to private_networks" or "allow to internet"
(= not private_networks) holds whichever subnets an install uses.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

PRIVATE_NETWORKS = (
    "10.0.0.0/8",       # RFC 1918
    "172.16.0.0/12",    # RFC 1918
    "192.168.0.0/16",   # RFC 1918
    "100.64.0.0/10",    # RFC 6598 shared space (carrier-grade NAT, Tailscale)
    "169.254.0.0/16",   # link-local
)

# OpenDNS's public resolvers. Used only by the direct-lookup rule that is off until switched on
# for a set time. Written as /32 networks, the alias type already proven on the firewall.
OPENDNS_RESOLVERS = (
    "208.67.222.222/32",
    "208.67.220.220/32",
)

_NAME_LIMIT = 32


@dataclass(frozen=True)
class AliasSpec:
    name: str
    type: str
    content: tuple[str, ...]
    description: str


_STATIC: dict[str, AliasSpec] = {
    "private_networks": AliasSpec(
        name="private_networks",
        type="network",
        content=PRIVATE_NETWORKS,
        description="PAZUZU managed: non-public address space",
    ),
    "opendns_resolvers": AliasSpec(
        name="opendns_resolvers",
        type="network",
        content=OPENDNS_RESOLVERS,
        description="PAZUZU managed: OpenDNS resolvers (direct lookups, by hand, for a set time)",
    ),
}


def static_spec(name: str) -> AliasSpec | None:
    return _STATIC.get(name)


def is_creatable(name: str) -> bool:
    """True for static aliases. Port aliases come from translation."""

    return name in _STATIC


def spec_payload(spec: AliasSpec) -> dict[str, str]:
    """Return the add_item payload for an alias."""

    return {
        "enabled": "1",
        "name": spec.name,
        "type": spec.type,
        "content": "\n".join(spec.content),
        "description": spec.description,
    }


def alias_payload(name: str) -> dict[str, str]:
    """Return the add_item payload for a static alias (KeyError if unknown)."""

    return spec_payload(_STATIC[name])


def port_alias_spec(protocol: str, ports: tuple[str, ...] | list[str]) -> AliasSpec:
    """Return the port alias for two or more single ports on one protocol."""

    proto = protocol.lower()
    if proto not in {"tcp", "udp"}:
        raise ValueError(f"port aliases need tcp or udp, not {protocol!r}")

    canonical = tuple(sorted(set(str(p) for p in ports), key=int))
    if len(canonical) < 2:
        raise ValueError("a port alias needs at least two ports")

    name = f"pz_{proto}_" + "_".join(canonical)
    if len(name) > _NAME_LIMIT:
        digest = hashlib.sha1(",".join(canonical).encode("ascii")).hexdigest()
        name = f"pz_{proto}_{digest[:12]}"

    return AliasSpec(
        name=name,
        type="port",
        content=canonical,
        description=f"PAZUZU managed: {proto.upper()} ports {', '.join(canonical)}",
    )
