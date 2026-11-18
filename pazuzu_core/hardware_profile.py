"""Hardware profiles: what a device physically offers, separate from policy.

A profile describes ports, radios and uplinks. It says nothing about
firewall policy; zones stay logical objects and zone_plan.py decides where
each one lands on a given profile. New hardware (or a lab VM) is a new
profile, not a code change.

Uplink kinds:
    ethernet      a port with the WAN landing (or any port used as an uplink)
    wifi_client   a radio acting as a station
    cellular_usb  a USB modem, identified by a free-form source string

The Wi-Fi radio on Hanbi is modelled as AP-or-client, not both at once,
because FreeBSD drivers with access-point support are scarce and a single
radio cannot be assumed to do both. While the radio serves the setup
network, a wifi_client uplink on it is unavailable.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

from pazuzu_core.zone_assignment import ZONES

UPLINK_KINDS = ("ethernet", "wifi_client", "cellular_usb")
RADIO_ROLES = ("ap", "sta")


@dataclass(frozen=True)
class Port:
    label: str                      # as printed on the case
    landing: str | None = None      # zone this port serves by default
    trunk: bool = False             # may carry tagged VLANs
    control: bool = False           # lifeline: reserved for management
    speed_mbps: int = 1000


@dataclass(frozen=True)
class Radio:
    label: str
    roles: tuple[str, ...]
    concurrent: bool = False        # can run ap and sta at the same time


@dataclass(frozen=True)
class Uplink:
    kind: str
    source: str                     # port label, radio label or USB id
    tier: int                       # 1 = primary, higher = backup


@dataclass(frozen=True)
class HardwareProfile:
    profile_id: str
    name: str
    ports: tuple[Port, ...]
    uplinks: tuple[Uplink, ...]
    radios: tuple[Radio, ...] = ()
    managed_switch: bool = False    # a VLAN-aware switch or AP is downstream


def validate_profile(profile: HardwareProfile) -> tuple[str, ...]:
    errors: list[str] = []

    labels = [port.label for port in profile.ports]
    if not profile.ports:
        errors.append("ports: at least one port is required")
    if len(labels) != len(set(labels)):
        errors.append("ports: labels must be unique")

    landings = [port.landing for port in profile.ports if port.landing]
    for landing in landings:
        if landing not in ZONES:
            errors.append(f"ports: unknown landing zone {landing!r}")
    if len(landings) != len(set(landings)):
        errors.append("ports: a zone can land on only one port")

    controls = [port for port in profile.ports if port.control]
    if len(controls) > 1:
        errors.append("ports: at most one control port is allowed")
    for port in controls:
        if port.landing != "management" or port.trunk:
            errors.append(
                f"ports: control port {port.label!r} must land on "
                "management and cannot be a trunk"
            )

    radio_labels = [radio.label for radio in profile.radios]
    if len(radio_labels) != len(set(radio_labels)):
        errors.append("radios: labels must be unique")
    for radio in profile.radios:
        if not radio.roles or any(r not in RADIO_ROLES for r in radio.roles):
            errors.append(f"radios: {radio.label!r} has invalid roles")
        if radio.concurrent and set(radio.roles) != set(RADIO_ROLES):
            errors.append(
                f"radios: {radio.label!r} cannot be concurrent without "
                "both ap and sta roles"
            )

    if not profile.uplinks:
        errors.append("uplinks: at least one uplink is required")

    tiers = [uplink.tier for uplink in profile.uplinks]
    if any(type(tier) is not int or tier < 1 for tier in tiers):
        errors.append("uplinks: tiers must be integers of 1 or more")
    elif tiers and 1 not in tiers:
        errors.append("uplinks: a tier-1 (primary) uplink is required")
    if len(tiers) != len(set(tiers)):
        errors.append("uplinks: each tier may be used once")

    radios = {radio.label: radio for radio in profile.radios}
    for uplink in profile.uplinks:
        if uplink.kind not in UPLINK_KINDS:
            errors.append(f"uplinks: unknown kind {uplink.kind!r}")
        elif uplink.kind == "ethernet" and uplink.source not in labels:
            errors.append(f"uplinks: no port {uplink.source!r}")
        elif uplink.kind == "wifi_client":
            radio = radios.get(uplink.source)
            if radio is None or "sta" not in radio.roles:
                errors.append(
                    f"uplinks: {uplink.source!r} is not a radio with the "
                    "sta role"
                )
        elif uplink.kind == "cellular_usb" and not uplink.source:
            errors.append("uplinks: cellular_usb needs a source")

    wan_ports = [port for port in profile.ports if port.landing == "wan"]
    if not wan_ports:
        errors.append("ports: a port with the wan landing is required")
    for port in wan_ports:
        if not any(
            u.kind == "ethernet" and u.source == port.label
            for u in profile.uplinks
        ):
            errors.append(
                f"uplinks: wan port {port.label!r} must be an ethernet uplink"
            )

    return tuple(errors)


HANBI_V1 = HardwareProfile(
    profile_id="hanbi_v1",
    name="Hanbi (four ports, one radio)",
    ports=(
        Port("P0", landing="wan", speed_mbps=2500),
        Port("P1", landing="trusted", trunk=True, speed_mbps=2500),
        Port("P2", landing="iot", speed_mbps=2500),
        Port("P3", landing="dmz", speed_mbps=2500),
    ),
    radios=(Radio("R0", roles=("ap", "sta"), concurrent=False),),
    uplinks=(
        Uplink("ethernet", "P0", tier=1),
        Uplink("wifi_client", "R0", tier=2),
    ),
)

LAB_VM = HardwareProfile(
    profile_id="lab_vm",
    name="Lab VM (three bridged NICs plus a control NIC)",
    ports=(
        Port("nic0", landing="wan"),
        Port("nic1", landing="trusted"),
        Port("nic2", landing="iot"),
        Port("control", landing="management", control=True),
    ),
    uplinks=(Uplink("ethernet", "nic0", tier=1),),
)

GENERIC_TWO_PORT = HardwareProfile(
    profile_id="generic_two_port",
    name="Generic two-port router on a stick",
    ports=(
        Port("WAN", landing="wan"),
        Port("LAN", landing="trusted", trunk=True),
    ),
    uplinks=(Uplink("ethernet", "WAN", tier=1),),
    managed_switch=True,
)

PROFILES = MappingProxyType(
    {
        profile.profile_id: profile
        for profile in (HANBI_V1, LAB_VM, GENERIC_TWO_PORT)
    }
)
