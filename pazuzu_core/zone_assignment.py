from __future__ import annotations

from collections.abc import Mapping
from typing import Any


ZONES = (
    "wan",
    "management",
    "trusted",
    "iot",
    "guest",
    "dmz",
    "quarantine",
)

# Zones that sit on a tunnel interface rather than a port or a VLAN. They are
# optional, never planned onto hardware, and appear in an assignment only when
# one is bound. Kept apart from ZONES so the hardware planner never offers
# them a port or a VLAN.
VIRTUAL_ZONES = ("wireguard_admin",)

# KidsNet (the maintainer, 14 Nov 2026: "KidsNet as part of setup", "if the user picks to build a KidsNet"): a network a home
# builds only if it wants one. Like a virtual zone it is never required, never planned onto hardware by itself, and is
# in an assignment only once it has a port; its rules are its own (kids_net.py), not the baseline's.
OPTIONAL_ZONES = ("kids",)

ALL_ZONES = ZONES + OPTIONAL_ZONES + VIRTUAL_ZONES

REQUIRED_ZONES = {"wan"}

BLOCKING_STATES = {"pending_assignment", "pending_creation"}


def selectable_interfaces(
    discovery: Mapping[str, Any],
) -> list[dict[str, Any]]:
    interfaces = discovery.get("interfaces")
    if not isinstance(interfaces, list):
        raise ValueError("Discovery report must contain an interfaces list")

    selectable = []
    for item in interfaces:
        if not isinstance(item, dict):
            continue

        device = str(item.get("device") or "")
        if not device or bool(item.get("system")):
            continue

        selectable.append(
            {
                "device": device,
                "identifier": str(item.get("identifier") or ""),
                "description": str(item.get("description") or ""),
                "assigned": bool(item.get("assigned")),
                "enabled": item.get("enabled"),
                "physical": bool(item.get("physical")),
                "status": str(item.get("status") or ""),
            }
        )

    return sorted(selectable, key=lambda item: item["device"])


def vlan_parent_interfaces(
    discovery: Mapping[str, Any],
) -> list[dict[str, Any]]:
    return [
        interface
        for interface in selectable_interfaces(discovery)
        if interface["physical"]
    ]


def build_zone_assignment(
    discovery: Mapping[str, Any],
    selections: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    unknown = sorted(set(selections) - set(ALL_ZONES))
    missing = sorted(set(ZONES) - set(selections))

    if unknown:
        raise ValueError(f"Unknown zones: {', '.join(unknown)}")
    if missing:
        raise ValueError(f"Missing zone selections: {', '.join(missing)}")

    candidates = selectable_interfaces(discovery)
    by_device = {item["device"]: item for item in candidates}
    vlan_parents = {
        item["device"]: item for item in vlan_parent_interfaces(discovery)
    }

    used_devices: set[str] = set()
    used_vlans: set[tuple[str, int]] = set()
    assignments: dict[str, dict[str, Any]] = {}

    chosen_virtual = tuple(zone for zone in (*OPTIONAL_ZONES, *VIRTUAL_ZONES) if zone in selections)

    for zone in (*ZONES, *chosen_virtual):
        selection = selections[zone]
        if not isinstance(selection, Mapping):
            raise ValueError(f"Zone {zone} has an invalid selection")

        method = str(selection.get("method") or "")

        if zone in VIRTUAL_ZONES or zone in OPTIONAL_ZONES:
            if method == "unconfigured":
                continue
            if method != "existing":
                raise ValueError(
                    f"Zone {zone} can only use an existing interface "
                    "or be left unconfigured"
                )

        if method == "unconfigured":
            if zone in REQUIRED_ZONES:
                raise ValueError(f"Zone {zone} cannot be unconfigured")

            assignments[zone] = {
                "state": "unconfigured",
                "method": "unconfigured",
            }
            continue

        if method == "unavailable":
            assignments[zone] = {
                "state": "unavailable",
                "method": "unavailable",
                "reason": str(
                    selection.get("reason") or "No valid interface available"
                ),
            }
            continue

        if method == "existing":
            device = str(selection.get("device") or "")
            interface = by_device.get(device)

            if interface is None:
                raise ValueError(
                    f"Zone {zone} selected unavailable device {device}"
                )
            if device in used_devices:
                raise ValueError(f"Device {device} is assigned more than once")

            used_devices.add(device)
            identifier = interface["identifier"]

            if not identifier:
                state = "pending_assignment"
            elif interface["enabled"] is False:
                state = "disabled"
            else:
                state = "bound"

            assignments[zone] = {
                "state": state,
                "method": "existing",
                "device": device,
                "identifier": identifier or None,
                "description": interface["description"],
                "enabled": interface["enabled"],
                "physical": interface["physical"],
                "status": interface["status"],
            }
            continue

        if method == "vlan":
            parent = str(selection.get("parent") or "")
            if parent not in vlan_parents:
                raise ValueError(
                    f"Zone {zone} selected unavailable VLAN parent {parent}"
                )

            try:
                vlan_id = int(selection.get("vlan_id"))
            except (TypeError, ValueError):
                raise ValueError(
                    f"Zone {zone} has an invalid VLAN ID"
                ) from None

            if not 1 <= vlan_id <= 4094:
                raise ValueError(
                    f"Zone {zone} VLAN ID must be between 1 and 4094"
                )

            vlan_key = (parent, vlan_id)
            if vlan_key in used_vlans:
                raise ValueError(
                    f"VLAN {vlan_id} on {parent} is assigned more than once"
                )

            used_vlans.add(vlan_key)
            assignments[zone] = {
                "state": "pending_creation",
                "method": "vlan",
                "parent": parent,
                "vlan_id": vlan_id,
                "description": str(selection.get("description") or ""),
                "plan_only": True,
            }
            continue

        raise ValueError(
            f"Zone {zone} has unknown attachment method {method!r}"
        )

    states = (
        "bound",
        "pending_assignment",
        "pending_creation",
        "unconfigured",
        "disabled",
        "unavailable",
    )
    counts = {
        state: sum(
            assignment["state"] == state
            for assignment in assignments.values()
        )
        for state in states
    }

    required_unavailable = any(
        assignments[zone]["state"] == "unavailable"
        for zone in REQUIRED_ZONES
    )
    unresolved = any(
        assignment["state"] in BLOCKING_STATES
        for assignment in assignments.values()
    )

    return {
        "schema_version": 2,
        "report_type": "opnsense_zone_assignment",
        "source_collected_at": discovery.get("collected_at"),
        "summary": {
            **counts,
            "deployable": not unresolved and not required_unavailable,
        },
        "assignments": assignments,
    }
