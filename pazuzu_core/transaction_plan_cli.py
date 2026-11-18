"""CLI for generating a dry-run transaction plan."""

import argparse
import json
from pathlib import Path
from typing import Sequence

from pazuzu_core.transaction_plan import generate_transaction_plan


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a non-executable transaction plan."
    )
    parser.add_argument("compliance_report", type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("scan_results/transaction_plan.json"),
    )
    args = parser.parse_args(argv)

    with args.compliance_report.open(encoding="utf-8") as source:
        compliance_report = json.load(source)

    plan = generate_transaction_plan(compliance_report)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="\n") as destination:
        json.dump(
            plan,
            destination,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        destination.write("\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
