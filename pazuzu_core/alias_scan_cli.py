"""Command-line entry point for read-only firewall-alias discovery."""

import argparse
from pathlib import Path

from pazuzu_core.alias_scanner import scan_aliases
from pazuzu_core.scan_cli import write_report


DEFAULT_OUTPUT = Path("scan_results/alias_discovery.json")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a redacted, read-only OPNsense alias report."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Report destination (default: {DEFAULT_OUTPUT})",
    )
    args = parser.parse_args()

    report = scan_aliases()
    write_report(report, args.output)

    summary = report["summary"]
    print(f"Report: {args.output}")
    print(
        "Aliases: "
        f"{summary['total']} total, "
        f"{summary['enabled']} enabled, "
        f"{summary['disabled']} disabled"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
