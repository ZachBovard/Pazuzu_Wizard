"""Read-only audit of the live firewall rules against baseline v0.4.

Usage:
    python -m pazuzu_core.firewall_rule_audit_cli
        [--baseline manifests/security_baseline_v0_4.json]
        [--output scan_results/firewall_rule_audit_v0_4.json]

Sends one GET (firewall.rules in the operation registry) and changes
nothing. Refuses to audit an incomplete inventory, because a clean result
on partial data would be misleading. Exit status is 1 if any unsafe finding
is reported, 0 otherwise; errors raise.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from pazuzu_core.firewall_rule_audit import audit_firewall_rules
from pazuzu_core.opnsense_client import discover_firewall_rules
from pazuzu_core.security_baseline_v0_4 import validate_baseline_v0_4

DEFAULT_BASELINE = "manifests/security_baseline_v0_4.json"
DEFAULT_OUTPUT = "scan_results/firewall_rule_audit_v0_4.json"


def _load_baseline(path: str) -> dict[str, Any]:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    errors = validate_baseline_v0_4(document)
    if errors:
        raise RuntimeError("Invalid baseline:\n" + "\n".join(errors))
    return document


def _check_complete(inventory: Any) -> None:
    rows = inventory.get("rows") if isinstance(inventory, dict) else None
    if not isinstance(rows, list):
        raise RuntimeError("Unexpected rule inventory response: no rows list")

    total = inventory.get("total")
    if total is None:
        return

    try:
        expected = int(total)
    except (TypeError, ValueError):
        raise RuntimeError(f"Unexpected rule inventory total: {total!r}") from None

    if expected != len(rows):
        raise RuntimeError(
            f"Rule inventory is incomplete: {len(rows)} of {expected} rows "
            "returned. Refusing to audit partial data."
        )


def run(
    baseline_path: str = DEFAULT_BASELINE,
    output_path: str = DEFAULT_OUTPUT,
) -> dict[str, Any]:
    baseline = _load_baseline(baseline_path)

    inventory = discover_firewall_rules()
    _check_complete(inventory)

    report = audit_firewall_rules(baseline, inventory)

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report


def _print_report(report: dict[str, Any], output_path: str) -> None:
    print(json.dumps(report["summary"], indent=1))

    missing = 0
    for finding in report["findings"]:
        if finding["code"] == "managed_rule_missing":
            missing += 1
            continue
        print(
            finding["code"],
            finding.get("object_id", ""),
            finding.get("observed_rule_id", ""),
            "| shadowed_by:",
            finding.get("shadowed_by_description", ""),
        )

    print(f"managed_rule_missing: {missing}")
    print(f"Report: {output_path}")


def _quiet_lab_tls_warnings() -> None:
    verify_off = os.getenv("OPNSENSE_TLS_VERIFY", "true").strip().lower() in {
        "false", "0", "no", "off",
    }
    if verify_off and not os.getenv("OPNSENSE_CA_BUNDLE"):
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        print("Note: TLS verification is disabled (lab only).")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", default=DEFAULT_BASELINE)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)

    _quiet_lab_tls_warnings()
    report = run(args.baseline, args.output)
    _print_report(report, args.output)

    return 1 if report["summary"]["unsafe"] else 0


if __name__ == "__main__":
    sys.exit(main())
