"""CLI for read-only Pazuzu security-baseline validation."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence

from pazuzu_core.security_baseline import load_and_validate_baseline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate a Pazuzu security baseline without mutation."
    )
    parser.add_argument("baseline", help="Path to the baseline JSON file.")
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Emit machine-readable JSON.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = load_and_validate_baseline(args.baseline)

    if args.json_output:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        status = "PASS" if report.passed else "FAIL"
        print(f"Security baseline validation: {status}")
        print(f"Source: {report.source}")
        print(f"Valid: {report.valid}")
        print(f"Safe: {report.safe}")

        if report.issues:
            print("Issues:")
            for issue in report.issues:
                print(
                    f"  [{issue.category.upper()}] "
                    f"{issue.code} {issue.path}: {issue.message}"
                )
        else:
            print("Issues: none")

    return report.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
