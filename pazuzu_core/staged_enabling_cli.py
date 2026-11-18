"""Show the staged turn-on plan. Plan only: this tool changes nothing.

Usage:
    python -m pazuzu_core.staged_enabling_cli
    python -m pazuzu_core.staged_enabling_cli --output scan_results/staged_plan.json

It reads the firewall's rule list, works out the four stages (DNS/DHCP/NTP
allow, LAN-client check, outbound allow, firewall-services check,
stock-rule disable with its in-window checks) with the old
value of everything each step changes, and writes the plan. --approve is
refused: running a plan is not built yet.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from pazuzu_core.firewall_rule_audit_cli import _check_complete, _quiet_lab_tls_warnings
from pazuzu_core.staged_enabling import build_plan

DEFAULT_OUTPUT = "scan_results/staged_enabling_plan.json"


def _load_live() -> dict[str, Any]:
    from pazuzu_core.opnsense_client import discover_firewall_rules
    inventory = discover_firewall_rules()
    _check_complete(inventory)
    return inventory


def _print(plan: dict[str, Any], output: str) -> None:
    print(f"rules seen: {plan['rules_seen']}")
    for number, stage in enumerate(plan["stages"], 1):
        print(f"\n{number}. {stage['title']}  [{stage['status']}]")
        if stage.get("kind") == "human_check":
            for line in stage["checks"]:
                print(f"     check: {line}")
            continue
        print(f"   window: {stage['timeout_seconds']}s, {len(stage['steps'])} step(s)")
        for step in stage["steps"]:
            print(f"     {step['kind']}: {step['uuid']}  {step['before']!r} -> {step['after']!r}")
        for line in stage["blockers"]:
            print(f"     blocker: {line}")
        for line in stage.get("window_checks", []):
            print(f"     in the window: {line}")
    print("\nNot in this plan:")
    for line in plan["not_in_this_plan"]:
        print(f"  - {line}")
    print("\nPlan only: nothing was changed.")
    print("READY" if plan["ready"] else "NOT READY")
    print(f"Plan: {output}")


def main(argv: list[str] | None = None, *, loader=None) -> int:
    parser = argparse.ArgumentParser(prog="staged_enabling_cli")
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument("--approve", action="store_true")
    args = parser.parse_args(argv)
    if args.approve:
        print("error: --approve is not accepted: running a plan is not built "
              "yet. This tool only shows the plan.", file=sys.stderr)
        return 2
    try:
        if loader is None:
            _quiet_lab_tls_warnings()
        plan = build_plan((loader or _load_live)())
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _print(plan, args.output)
    return 0 if plan["ready"] else 1


if __name__ == "__main__":
    sys.exit(main())
