"""Command-line entry point for read-only OPNsense discovery."""

import argparse
import json
from pathlib import Path
from typing import Any

from pazuzu_core.opnsense_scanner import scan_interfaces


DEFAULT_OUTPUT = Path("scan_results/interface_discovery.json")


def write_report(report: dict[str, Any], output: Path) -> None:
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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a redacted, read-only OPNsense interface report."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Report destination (default: {DEFAULT_OUTPUT})",
    )
    args = parser.parse_args()

    report = scan_interfaces()
    write_report(report, args.output)

    summary = report["summary"]
    print(f"Report: {args.output}")
    print(
        "Interfaces: "
        f"{summary['total']} total, "
        f"{summary['comparison_eligible']} comparison eligible"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
