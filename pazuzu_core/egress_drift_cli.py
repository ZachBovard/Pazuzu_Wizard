"""Read-only: is IPv6, client NTP, DNS bypass or QUIC permitted anywhere?

Usage:
    python -m pazuzu_core.egress_drift_cli [--output scan_results/egress_drift.json]

Sends GETs (rules and aliases) and changes nothing. Exit status is 1 when
anything is drifted, otherwise 0. Unverified items are listed but do not
change the exit status.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from pazuzu_core.egress_drift import evaluate
from pazuzu_core.firewall_rule_audit_cli import _check_complete, _quiet_lab_tls_warnings

DEFAULT_OUTPUT = "scan_results/egress_drift.json"


def _load_live() -> tuple[dict[str, Any], dict[str, Any]]:
    from pazuzu_core.opnsense_client import discover_firewall_aliases, discover_firewall_rules
    rules = discover_firewall_rules()
    _check_complete(rules)
    aliases = {}
    for row in discover_firewall_aliases().get("rows", []):
        if isinstance(row, dict) and isinstance(row.get("name"), str):
            aliases[row["name"]] = row.get("content", "")
    return rules, aliases


def main(argv: list[str] | None = None, *, loader=None) -> int:
    parser = argparse.ArgumentParser(prog="egress_drift_cli")
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    try:
        if loader is None:
            _quiet_lab_tls_warnings()
        rules, aliases = (loader or _load_live)()
        report = evaluate(rules, aliases)
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (RuntimeError, ValueError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    print(f"enabled pass rules considered: {report['rules_considered']}")
    for item in report["controls"]:
        print(f"  {item['control']}: {item['status'].upper()} ({item['detail']})")
        for finding in item["findings"]:
            print(f"      - {finding['description'] or finding['uuid']}")
        for finding in item["unchecked"]:
            print(f"      ? {finding['description'] or finding['uuid']}")
    summary = report["summary"]
    print("The app is happy." if summary["happy"] else "The app is not happy.")
    print(f"Report: {args.output}")
    return 1 if summary["drifted"] else 0


if __name__ == "__main__":
    sys.exit(main())
