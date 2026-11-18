"""Read-only: find the stock and lifeline rules Pazuzu could adopt.

Usage:
    python -m pazuzu_core.stock_rules_cli [--output scan_results/stock_rules_plan.json]

Sends one GET (firewall.rules) and changes nothing. Prints what adoption
would do and whether it is safe yet. Addresses are never printed or saved.
Exit status is 0 when nothing blocks adoption, 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from pazuzu_core.firewall_rule_audit_cli import _check_complete, _quiet_lab_tls_warnings
from pazuzu_core.opnsense_client import discover_firewall_rules
from pazuzu_core.stock_rules import detect_stock_rules

DEFAULT_OUTPUT = "scan_results/stock_rules_plan.json"


def run(output_path: str = DEFAULT_OUTPUT) -> dict[str, Any]:
    inventory = discover_firewall_rules()
    _check_complete(inventory)
    report = detect_stock_rules(inventory)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def _print(report: dict[str, Any], output_path: str) -> None:
    print(f"rules seen: {report['rules_seen']}")
    for item in report["found"]:
        state = "enabled" if item["enabled"] else "disabled"
        verdict = "adoptable" if item["adoptable"] else "NOT adoptable"
        print(f"  {item['role']}: {state}, source {item['source']} -> {verdict}")
        for reason in item["reasons"]:
            print(f"      - {reason}")
    for role in report["absent"]:
        print(f"  {role}: not found")
    print(f"enabled Pazuzu allow rules on lan: {report['enabled_pazuzu_allows_on_lan']}")
    print("plan (not applied):")
    for line in report["plan"] or ["  nothing to do"]:
        print(f"  {line}")
    if report["blockers"]:
        print("blockers:")
        for line in report["blockers"]:
            print(f"  - {line}")
    print("READY" if report["ready"] else "NOT READY")
    print(f"Report: {output_path}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    _quiet_lab_tls_warnings()
    report = run(args.output)
    _print(report, args.output)
    return 0 if report["ready"] or not report["blockers"] else 1


if __name__ == "__main__":
    sys.exit(main())
