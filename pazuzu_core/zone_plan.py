"""Turn a hardware profile into a zone plan. Pure functions, no I/O.

Each logical zone lands on exactly one of:
    port          a physical port that serves the zone by default
    vlan          tagged on a trunk port (only if a VLAN-aware device is
                  downstream)
    unconfigured  nothing available; the zone stays defined but unbound,
                  and rules that reference only unconfigured zones are
                  skipped by the translator

The plan is intent, not configuration. Resolving a port label to a real
interface (by MAC, PCI path or a plug-in-the-cable link-detect step) and
choosing VLAN IDs happen later.
"""

from __future__ import annotations

from dataclasses import dataclass

from pazuzu_core.hardware_profile import (
    HardwareProfile,
    Uplink,
    validate_profile,
)
from pazuzu_core.zone_assignment import ZONES


@dataclass(frozen=True)
class Binding:
    zone: str
    kind: str                  # "port" | "vlan" | "unconfigured"
    port: str | None = None    # the port, or the trunk carrying the VLAN
    reason: str = ""


@dataclass(frozen=True)
class UplinkState:
    uplink: Uplink
    available: bool
    reason: str = ""


def _checked(profile: HardwareProfile) -> None:
    errors = validate_profile(profile)
    if errors:
        raise ValueError(
            f"Invalid hardware profile {profile.profile_id!r}: "
            + "; ".join(errors)
        )


def plan_zones(
    profile: HardwareProfile,
    *,
    managed_switch: bool | None = None,
) -> tuple[Binding, ...]:
    """Return one binding per zone, in ZONES order.

    managed_switch overrides the profile's declaration, for example once
    the user confirms a VLAN-aware switch or access point is connected.
    """

    _checked(profile)

    vlans_allowed = (
        profile.managed_switch if managed_switch is None else managed_switch
    )
    by_landing = {p.landing: p for p in profile.ports if p.landing}
    trunk = next(
        (p for p in profile.ports if p.trunk and not p.control), None
    )
    vlans_possible = vlans_allowed and trunk is not None

    bindings: list[Binding] = []

    for zone in ZONES:
        port = by_landing.get(zone)

        if port is not None:
            reason = "lifeline port" if port.control else "default landing"
            bindings.append(Binding(zone, "port", port.label, reason))
        elif vlans_possible:
            bindings.append(
                Binding(zone, "vlan", trunk.label, "tagged on the trunk port")
            )
        else:
            why = "no port lands this zone"
            if not vlans_allowed:
                why += " and no VLAN-aware device is declared"
            elif trunk is None:
                why += " and the profile has no trunk port"
            bindings.append(Binding(zone, "unconfigured", None, why))

    return tuple(bindings)


def plan_uplinks(
    profile: HardwareProfile,
    *,
    setup_mode: bool = False,
) -> tuple[UplinkState, ...]:
    """Return uplinks in failover order with their availability.

    During setup mode a radio that cannot run ap and sta together is
    serving the setup network, so a wifi_client uplink on it is unavailable.
    """

    _checked(profile)

    radios = {radio.label: radio for radio in profile.radios}
    states: list[UplinkState] = []

    for uplink in sorted(profile.uplinks, key=lambda u: u.tier):
        if uplink.kind == "wifi_client" and setup_mode:
            radio = radios[uplink.source]
            if not radio.concurrent:
                states.append(
                    UplinkState(
                        uplink,
                        False,
                        "the radio is serving the setup network",
                    )
                )
                continue
        states.append(UplinkState(uplink, True))

    return tuple(states)


def failover_order(states: tuple[UplinkState, ...]) -> tuple[str, ...]:
    """Sources of the available uplinks, primary first."""

    return tuple(s.uplink.source for s in states if s.available)
