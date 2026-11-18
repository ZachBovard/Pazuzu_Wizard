"""CLI for read-only security baseline comparison."""

import argparse
import json
from pathlib import Path
from typing import Any

from pazuzu_core.security_compliance import RESULTS, compare_security_baseline


def _read_object(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)

    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")

    return value


def _read_optional(path: Path | None) -> dict[str, Any] | None:
    return _read_object(path) if path is not None else None


def _write_json(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compare observed OPNsense state with the security baseline."
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=Path("manifests/security_baseline_v0_1.json"),
    )
    parser.add_argument("--observations", type=Path)
    parser.add_argument("--generated-values", type=Path)
    parser.add_argument(
        "--interfaces",
        type=Path,
        default=Path("scan_results/interface_discovery.json"),
    )
    parser.add_argument(
        "--aliases",
        type=Path,
        default=Path("scan_results/alias_discovery.json"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("scan_results/security_compliance.json"),
    )
    return parser


def main() -> int:
    args = _build_parser().parse_args()

    report = compare_security_baseline(
        baseline=_read_object(args.baseline),
        observations=_read_optional(args.observations),
        generated_values=_read_optional(args.generated_values),
        interface_discovery=_read_optional(args.interfaces),
        alias_discovery=_read_optional(args.aliases),
    )
    _write_json(args.output, report)

    print("Security baseline comparison (M2)")
    print(f"Mode: {report['mode']}")
    print(f"Platform: {report['platform']}")

    for result in RESULTS:
        print(f"{result}: {report['summary'][result]}")

    print(f"Report: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
