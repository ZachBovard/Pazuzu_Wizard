"""CLI for canonical read-only secure-profile evaluation."""

import argparse
import json
from pathlib import Path
from typing import Any

from pazuzu_core.security_compliance import (
    CANONICAL_RESULTS,
    evaluate_secure_profile,
)


def read_json_object(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)

    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")

    return value


def write_json(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate interrogation evidence against the canonical "
            "secure-profile baseline without changing OPNsense."
        )
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=Path("manifests/security_baseline_v0_1.json"),
        help="Canonical security baseline JSON.",
    )
    parser.add_argument(
        "--interrogation",
        type=Path,
        required=True,
        help="Read-only interrogation report JSON.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("scan_results/secure_profile_evaluation.json"),
        help="Destination evaluation report JSON.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    report = evaluate_secure_profile(
        baseline=read_json_object(args.baseline),
        interrogation=read_json_object(args.interrogation),
    )
    write_json(report, args.output)

    print("Canonical secure-profile evaluation")
    for result in CANONICAL_RESULTS:
        print(f"{result}: {report['summary'][result]}")
    print(f"Report: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

