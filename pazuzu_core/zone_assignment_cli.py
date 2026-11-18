"""Interactive CLI for mapping discovered interfaces to security zones."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from pazuzu_core.zone_assignment import (
    REQUIRED_ZONES,
    VIRTUAL_ZONES,
    ZONES,
    build_zone_assignment,
    selectable_interfaces,
    vlan_parent_interfaces,
)


DEFAULT_DISCOVERY = Path("scan_results/interface_discovery.json")
DEFAULT_OUTPUT = Path("scan_results/zone_assignment.json")


def load_discovery(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Discovery report must be a JSON object")
    return payload


def write_assignment(report: Mapping[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp")

    try:
        temporary.write_text(
            json.dumps(report, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)


def display_interfaces(
    interfaces: list[dict[str, Any]],
    output_fn: Callable[[str], None] = print,
) -> None:
    output_fn("Selectable interfaces:")
    for number, interface in enumerate(interfaces, start=1):
        identifier = interface["identifier"] or "unassigned"
        description = interface["description"] or "-"
        output_fn(
            f"  {number}. {interface['device']} | "
            f"{identifier} | {description} | "
            f"{interface['status'] or 'unknown'}"
        )


def _select_interface(
    interfaces: list[dict[str, Any]],
    prompt: str,
    input_fn: Callable[[str], str],
    output_fn: Callable[[str], None],
) -> dict[str, Any] | None:
    if not interfaces:
        output_fn("No valid interfaces are available")
        return None

    display_interfaces(interfaces, output_fn)
    answer = input_fn(prompt).strip()

    try:
        index = int(answer) - 1
        if index < 0:
            raise IndexError
        return interfaces[index]
    except (ValueError, IndexError):
        output_fn("Invalid selection")
        return None


def collect_selections(
    discovery: Mapping[str, Any],
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
) -> dict[str, dict[str, Any]]:
    interfaces = selectable_interfaces(discovery)
    parents = vlan_parent_interfaces(discovery)

    used_devices: set[str] = set()
    used_vlans: set[tuple[str, int]] = set()
    selections: dict[str, dict[str, Any]] = {}

    for zone in ZONES:
        required = zone in REQUIRED_ZONES

        while True:
            output_fn("")
            output_fn(f"Configure zone: {zone}")
            output_fn("  1. Use an existing interface")
            output_fn("  2. Create a VLAN")
            output_fn("  3. Leave unconfigured")

            method = input_fn("Attachment method [1/2/3]: ").strip().lower()

            if method in {"1", "e", "existing"}:
                interface = _select_interface(
                    interfaces,
                    "Interface number: ",
                    input_fn,
                    output_fn,
                )
                if interface is None:
                    continue

                device = interface["device"]
                if device in used_devices:
                    output_fn(f"{device} is already assigned")
                    continue

                used_devices.add(device)
                selections[zone] = {
                    "method": "existing",
                    "device": device,
                }
                break

            if method in {"2", "v", "vlan"}:
                parent = _select_interface(
                    parents,
                    "Parent trunk number: ",
                    input_fn,
                    output_fn,
                )
                if parent is None:
                    continue

                vlan_answer = input_fn("VLAN ID [1-4094]: ").strip()
                try:
                    vlan_id = int(vlan_answer)
                except ValueError:
                    output_fn("Invalid VLAN ID")
                    continue

                if not 1 <= vlan_id <= 4094:
                    output_fn("VLAN ID must be between 1 and 4094")
                    continue

                vlan_key = (parent["device"], vlan_id)
                if vlan_key in used_vlans:
                    output_fn(
                        f"VLAN {vlan_id} on {parent['device']} "
                        "is already assigned"
                    )
                    continue

                description = input_fn(
                    "VLAN description (optional): "
                ).strip()

                used_vlans.add(vlan_key)
                selections[zone] = {
                    "method": "vlan",
                    "parent": parent["device"],
                    "vlan_id": vlan_id,
                    "description": description,
                }
                break

            if method in {"3", "u", "unconfigured"}:
                if required:
                    output_fn(f"{zone} cannot be left unconfigured")
                    continue

                selections[zone] = {"method": "unconfigured"}
                break

            output_fn("Invalid attachment method")

    for zone in VIRTUAL_ZONES:
        while True:
            output_fn("")
            output_fn(f"Configure zone: {zone} (tunnel interface, optional)")
            output_fn("  1. Use an existing interface")
            output_fn("  3. Leave unconfigured")

            method = input_fn("Attachment method [1/3]: ").strip().lower()

            if method in {"1", "e", "existing"}:
                interface = _select_interface(
                    interfaces,
                    "Interface number: ",
                    input_fn,
                    output_fn,
                )
                if interface is None:
                    continue

                device = interface["device"]
                if device in used_devices:
                    output_fn(f"{device} is already assigned")
                    continue

                used_devices.add(device)
                selections[zone] = {"method": "existing", "device": device}
                break

            if method in {"3", "u", "unconfigured"}:
                selections[zone] = {"method": "unconfigured"}
                break

            output_fn("Invalid attachment method")

    return selections


def display_assignment(
    report: Mapping[str, Any],
    output_fn: Callable[[str], None] = print,
) -> None:
    output_fn("")
    output_fn("Proposed zone mapping:")

    assignments = report["assignments"]
    shown = (*ZONES, *(zone for zone in VIRTUAL_ZONES if zone in assignments))
    for zone in shown:
        assignment = assignments[zone]
        state = assignment["state"]

        if state in {"unconfigured", "unavailable"}:
            output_fn(f"  {zone}: {state}")
            continue

        if assignment["method"] == "vlan":
            description = assignment["description"] or "-"
            output_fn(
                f"  {zone}: VLAN {assignment['vlan_id']} on "
                f"{assignment['parent']} | {description} "
                f"[{state}, plan only]"
            )
            continue

        identifier = assignment["identifier"] or "pending assignment"
        output_fn(
            f"  {zone}: {assignment['device']} -> "
            f"{identifier} [{state}]"
        )

    output_fn(
        f"Deployable: "
        f"{'yes' if report['summary']['deployable'] else 'no'}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Map discovered OPNsense interfaces to security zones."
    )
    parser.add_argument(
        "--discovery",
        type=Path,
        default=DEFAULT_DISCOVERY,
        help=f"Discovery report (default: {DEFAULT_DISCOVERY})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Assignment destination (default: {DEFAULT_OUTPUT})",
    )
    args = parser.parse_args()

    try:
        discovery = load_discovery(args.discovery)
        selections = collect_selections(discovery)
        report = build_zone_assignment(discovery, selections)
        display_assignment(report)

        confirmation = input("Persist this mapping? [y/N]: ").strip().lower()
        if confirmation not in {"y", "yes"}:
            print("Mapping not saved")
            return 1

        write_assignment(report, args.output)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    except (EOFError, KeyboardInterrupt):
        print("\nMapping cancelled", file=sys.stderr)
        return 130

    print(f"Mapping saved: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
