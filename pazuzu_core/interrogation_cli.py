"""Read-only interrogation: ask the firewall the allowlisted questions and
save the evidence.

Usage:
    python -m pazuzu_core.interrogation_cli [--output scan_results/interrogation.json]

Sends one GET per capability (firmware, interfaces, interface settings,
aliases) and changes nothing. The report holds the raw responses, which
include addresses, so it belongs in the ignored scan_results folder. A
capability that fails is recorded as an error in the report rather than
stopping the run. Exit status is 1 if any capability could not be observed.

Feed the result to the secure-profile check:
    python -m pazuzu_core.secure_profile_cli --interrogation scan_results/interrogation.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from pazuzu_core.firewall_rule_audit_cli import _quiet_lab_tls_warnings
from pazuzu_core.interrogation import interrogate
from pazuzu_core.opnsense_client import ReadOnlyOPNsenseClient

DEFAULT_OUTPUT = "scan_results/interrogation.json"


def run(output_path: str) -> dict[str, Any]:
    client = ReadOnlyOPNsenseClient()
    try:
        report = interrogate(client)
    finally:
        client.close()

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)

    _quiet_lab_tls_warnings()
    report = run(args.output)

    summary = report.get("summary", {})
    print(
        "observed: {observed} of {total} | unavailable: {unavailable} | "
        "unsupported: {unsupported} | errors: {errors}".format(
            **{k: summary.get(k, 0) for k in
               ("observed", "total", "unavailable", "unsupported", "errors")}
        )
    )
    for item in report.get("observations", []):
        if item.get("status") != "observed":
            print(f"  {item.get('identifier')}: {item.get('status')} - {item.get('error')}")
    print(f"Report: {args.output}")

    return 0 if summary.get("observed") == summary.get("total") else 1


if __name__ == "__main__":
    raise SystemExit(main())
