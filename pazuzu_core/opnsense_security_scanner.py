from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pazuzu_core.opnsense_client import discover_interfaces


TRUE_VALUES = {"1", "true", "yes", "on", "enabled"}
FALSE_VALUES = {"", "0", "false", "no", "off", "disabled"}


def _optional_bool(config: dict[str, Any], key: str) -> bool | None:
    if key not in config:
        return None

    value = config[key]

    if isinstance(value, bool):
        return value

    if isinstance(value, int) and value in {0, 1}:
        return bool(value)

    text = str(value).strip().lower()
    if text in TRUE_VALUES:
        return True
    if text in FALSE_VALUES:
        return False

    return None


def build_security_observations(
    payload: dict[str, Any],
) -> dict[str, Any]:
    rows = payload.get("rows")
    if not isinstance(rows, list):
        raise ValueError("Interface response does not contain a rows list")

    services: dict[str, Any] = {}
    observed_paths: list[str] = []
    wan_found = False

    for row in rows:
        if not isinstance(row, dict):
            continue

        if str(row.get("identifier") or "").lower() != "wan":
            continue

        wan_found = True
        config = row.get("config")
        config = config if isinstance(config, dict) else {}

        mappings = {
            "blockbogons": "bogon_filtering",
            "blockpriv": "private_network_filtering_on_wan",
        }

        for config_key, observation_key in mappings.items():
            value = _optional_bool(config, config_key)
            if value is not None:
                services[observation_key] = value
                observed_paths.append(
                    f"network.services.{observation_key}"
                )

        break

    return {
        "schema_version": 1,
        "report_type": "opnsense_security_observations",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "evidence": {
            "endpoint": get_operation(OperationId.INTERFACES_OVERVIEW).path,
            "wan_found": wan_found,
            "observed_paths": observed_paths,
        },
        "network": {
            "services": services,
        },
    }


def scan_security_observations() -> dict[str, Any]:
    return build_security_observations(discover_interfaces())


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Collect read-only OPNsense security observations."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("scan_results/security_observations.json"),
    )
    args = parser.parse_args()

    report = scan_security_observations()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"Observed paths: {len(report['evidence']['observed_paths'])}")
    print(f"Report: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

