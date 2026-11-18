from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pazuzu_core.opnsense_client import discover_firewall_aliases


def _safe_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value

    text = str(value or "").strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return None


def _safe_count(value: Any) -> int | None:
    try:
        count = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return count if count >= 0 else None


def build_alias_report(payload: dict[str, Any]) -> dict[str, Any]:
    rows = payload.get("rows")
    if not isinstance(rows, list):
        raise ValueError("Alias response does not contain a rows list")

    aliases: list[dict[str, Any]] = []
    row_fields: set[str] = set()

    for row in rows:
        if not isinstance(row, dict):
            continue

        row_fields.update(row)

        aliases.append(
            {
                "uuid": str(row.get("uuid") or ""),
                "name": str(row.get("name") or ""),
                "enabled": _safe_bool(row.get("enabled")),
                "type": str(row.get("type") or ""),
                "protocol": str(row.get("proto") or ""),
                "interface": str(row.get("interface") or ""),
                "update_frequency": str(row.get("updatefreq") or ""),
                "current_item_count": _safe_count(
                    row.get("current_items")
                ),
            }
        )

    return {
        "schema_version": 1,
        "report_type": "opnsense_firewall_alias_discovery",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total": len(aliases),
            "enabled": sum(
                alias["enabled"] is True for alias in aliases
            ),
            "disabled": sum(
                alias["enabled"] is False for alias in aliases
            ),
            "unknown_enabled_state": sum(
                alias["enabled"] is None for alias in aliases
            ),
        },
        "observed_shape": {
            "row_fields": sorted(row_fields),
        },
        "aliases": aliases,
    }


def scan_aliases() -> dict[str, Any]:
    return build_alias_report(discover_firewall_aliases())
