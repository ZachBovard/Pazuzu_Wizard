"""Compare desired state with a redacted discovery report."""

import argparse
import json
from pathlib import Path
from typing import Any

from pazuzu_core.desired_state import compare_interfaces

DEFAULT_DESIRED = Path("pazuzu_core/defaults/lab_default_config.json")
DEFAULT_DISCOVERY = Path("scan_results/interface_discovery.json")
DEFAULT_OUTPUT = Path("scan_results/interface_comparison.json")


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def write_json(data: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        temporary.write_text(
            json.dumps(data, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare desired interfaces with redacted discovery data."
    )
    parser.add_argument("--desired", type=Path, default=DEFAULT_DESIRED)
    parser.add_argument("--discovery", type=Path, default=DEFAULT_DISCOVERY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--fail-on-drift",
        action="store_true",
        help="Return exit code 2 when drift or missing interfaces are detected.",
    )
    args = parser.parse_args()

    comparison = compare_interfaces(
        load_json(args.desired),
        load_json(args.discovery),
    )
    write_json(comparison, args.output)

    summary = comparison["summary"]
    print(f"Comparison: {args.output}")
    print(
        f"Matched: {summary['matched']}, "
        f"drift: {summary['drift']}, "
        f"missing: {summary['missing']}, "
        f"not evaluated: {summary['not_evaluated']}"
    )

    if args.fail_on_drift and (summary["drift"] or summary["missing"]):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

