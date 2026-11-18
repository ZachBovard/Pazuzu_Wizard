from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pazuzu_core.opnsense_client import discover_interfaces


SYSTEM_DEVICES = {"lo0", "enc0", "pflog0"}
KNOWN_MODES = {
    "",
    "none",
    "dhcp",
    "static",
    "pppoe",
    "slaac",
    "track6",
    "6rd",
    "6to4",
}


def _safe_mode(value: Any) -> str:
    text = str(value or "").lower()
    return text if text in KNOWN_MODES else "configured"


def _names(value: Any) -> list[str]:
    if isinstance(value, dict):
        return sorted(str(key) for key in value)
    if isinstance(value, list):
        return sorted(item for item in value if isinstance(item, str))
    return []


def build_interface_report(payload: dict[str, Any]) -> dict[str, Any]:
    rows = payload.get("rows")
    if not isinstance(rows, list):
        raise ValueError("Interface response does not contain a rows list")

    interfaces = []
    row_fields: set[str] = set()
    config_fields: set[str] = set()

    for row in rows:
        if not isinstance(row, dict):
            continue

        row_fields.update(row)
        config = row.get("config")
        config = config if isinstance(config, dict) else {}
        config_fields.update(config)

        device = str(row.get("device") or "")
        identifier = str(row.get("identifier") or "")
        system = device in SYSTEM_DEVICES

        interfaces.append(
            {
                "device": device,
                "identifier": identifier,
                "description": str(row.get("description") or ""),
                "assigned": bool(identifier),
                "enabled": row.get("enabled"),
                "physical": bool(row.get("is_physical")),
                "system": system,
                "comparison_eligible": bool(identifier) and not system,
                "status": str(row.get("status") or ""),
                "ipv4_mode": _safe_mode(config.get("ipaddr")),
                "ipv6_mode": _safe_mode(config.get("ipaddrv6")),
                "ipv4_address_count": len(row.get("ipv4") or []),
                "ipv6_address_count": len(row.get("ipv6") or []),
                "flags": _names(row.get("flags")),
                "capabilities": _names(row.get("capabilities")),
                "options": _names(row.get("options")),
            }
        )

    return {
        "schema_version": 1,
        "report_type": "opnsense_interface_discovery",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total": len(interfaces),
            "comparison_eligible": sum(
                item["comparison_eligible"] for item in interfaces
            ),
            "physical": sum(item["physical"] for item in interfaces),
            "system": sum(item["system"] for item in interfaces),
        },
        "observed_shape": {
            "row_fields": sorted(row_fields),
            "config_fields": sorted(config_fields),
        },
        "interfaces": interfaces,
    }


def scan_interfaces() -> dict[str, Any]:
    return build_interface_report(discover_interfaces())
