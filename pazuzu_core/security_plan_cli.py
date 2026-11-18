import argparse
import json
from pathlib import Path

from pazuzu_core.security_plan import render_security_plan


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate the read-only M3 security plan"
    )
    parser.add_argument(
        "--input",
        default="scan_results/security_compliance.json",
    )
    parser.add_argument(
        "--output",
        default="scan_results/security_plan.md",
    )
    args = parser.parse_args()

    with open(args.input, encoding="utf-8") as handle:
        report = json.load(handle)

    markdown = render_security_plan(report)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(markdown, encoding="utf-8")

    print(f"Security plan written to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
