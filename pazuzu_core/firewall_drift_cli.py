"""Compare the live managed rules with the manifest. Read-only.

Usage:
    python -m pazuzu_core.firewall_drift_cli [--only PZ-ID,PZ-ID] [--limit N]

Use the same --only or --limit as the apply that created the rules, so the
expected set matches. Sends one GET. Exit status is 1 if anything drifted.
Correcting drift is a separate, approved step; this command only reports.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from pazuzu_core.firewall_manifest_smoke import (
    DEFAULT_LIMIT,
    _load,
    _select,
    _service_groups,
    _zone_map,
)
from pazuzu_core.firewall_rule_audit_cli import _check_complete, _quiet_lab_tls_warnings
from pazuzu_core.opnsense_client import discover_firewall_rules
from pazuzu_core.rule_drift import DriftReport, detect_drift
from pazuzu_core.security_baseline_v0_4 import validate_baseline_v0_4

DEFAULT_OUTPUT = "scan_results/firewall_drift_report.json"


def run(
    manifest_path: str,
    zones_path: str,
    only: list[str] | None,
    limit: int,
    output_path: str,
) -> DriftReport:
    manifest = _load(manifest_path)
    errors = validate_baseline_v0_4(manifest)
    if errors:
        raise RuntimeError("Invalid manifest:\n" + "\n".join(errors))

    pack = manifest["policy_pack"]
    zones = _zone_map(_load(zones_path))
    selected = _select(pack["rules"], zones, _service_groups(pack), only, limit)
    expected = [rule for item in selected for rule in item.rules]

    inventory = discover_firewall_rules()
    _check_complete(inventory)

    report = detect_drift(expected, inventory["rows"])

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(_as_json(report), indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")
    return report


def _as_json(report: DriftReport) -> dict[str, Any]:
    return {
        "report_type": "opnsense_rule_drift",
        "mode": "read_only",
        "in_sync": report.in_sync,
        "missing": list(report.missing),
        "modified": [
            {"description": m.description, "uuid": m.uuid,
             "diffs": [{"field": f, "expected": e, "actual": a} for f, e, a in m.diffs]}
            for m in report.modified
        ],
        "orphans": [{"description": o.description, "uuid": o.uuid} for o in report.orphans],
        "duplicates": [{"description": d.description, "uuids": list(d.uuids)} for d in report.duplicates],
    }


def print_report(report: DriftReport, output_path: str) -> None:
    print(
        f"in sync: {report.in_sync} | missing: {len(report.missing)} | "
        f"modified: {len(report.modified)} | orphans: {len(report.orphans)} | "
        f"duplicates: {len(report.duplicates)}"
    )
    for description in report.missing:
        print(f"MISSING   {description}")
    for item in report.modified:
        print(f"MODIFIED  {item.description}")
        for field, expected, actual in item.diffs:
            print(f"            {field}: expected {expected!r}, found {actual!r}")
    for item in report.orphans:
        print(f"ORPHAN    {item.description} ({item.uuid})")
    for item in report.duplicates:
        print(f"DUPLICATE {item.description} x{len(item.uuids)}")
    print(f"Report: {output_path}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default="manifests/security_baseline_v0_4.json")
    parser.add_argument("--zones", default="scan_results/zone_assignment.json")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--only")
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)

    only = (
        [item.strip() for item in args.only.split(",") if item.strip()]
        if args.only else None
    )

    _quiet_lab_tls_warnings()
    report = run(args.manifest, args.zones, only, args.limit, args.output)
    print_report(report, args.output)
    return 1 if report.drifted else 0


if __name__ == "__main__":
    raise SystemExit(main())
