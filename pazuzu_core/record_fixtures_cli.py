"""Record the firewall's read-only responses as redacted test fixtures.

Usage:
    python -m pazuzu_core.record_fixtures_cli --version-label 26.7.2
        [--out tests/fixtures/opnsense] [--redact TEXT ...]

Sends one GET per registered read-only operation and changes nothing. All
responses go through one Redactor (see fixture_redaction) and are checked
twice for leftovers. Nothing is written unless every response is clean; the
unredacted responses exist only in memory.

Name anything private that the patterns cannot know about (a hotspot name,
a user name) with --redact, once per value. Review the files before you
commit them.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import date
from pathlib import Path
from typing import Any

from pazuzu_core.firewall_rule_audit_cli import _quiet_lab_tls_warnings
from pazuzu_core.fixture_redaction import Redactor, find_unredacted
from pazuzu_core.operations import registered_operations
from pazuzu_core.opnsense_client import ReadOnlyOPNsenseClient

DEFAULT_OUT = "tests/fixtures/opnsense"
_LABEL = re.compile(r"^\d+\.\d+(\.\d+)?$")


def record(
    label: str,
    out_dir: str,
    extra_literals: list[str] | None = None,
    client_factory=ReadOnlyOPNsenseClient,
) -> tuple[Path, dict[str, int]]:
    if not _LABEL.match(label):
        raise ValueError("version label must look like 26.7 or 26.7.2")

    redactor = Redactor(extra_literals or [])
    scrubbed: dict[str, Any] = {}

    client = client_factory()
    try:
        for operation in registered_operations():
            raw = client.execute(operation.identifier)
            scrubbed[operation.identifier.value] = redactor.scrub(raw)
    finally:
        client.close()

    # An original found in one response is removed from all of them.
    scrubbed = {name: redactor.finalize(data) for name, data in scrubbed.items()}

    for name, data in scrubbed.items():
        leaks = redactor.leaks(data)
        remaining = find_unredacted(json.dumps(data))
        if leaks or remaining:
            where = "; ".join(f"{kind} at {path}" for kind, path in leaks[:5])
            what = "; ".join(sorted(set(remaining)))
            raise RuntimeError(
                f"{name}: redaction left {len(leaks)} original value(s)"
                + (f" ({where})" if where else "")
                + f" and {len(remaining)} suspicious item(s)"
                + (f" ({what})" if what else "")
                + "; nothing was written"
            )

    folder = Path(out_dir) / label
    folder.mkdir(parents=True, exist_ok=True)

    for name, data in scrubbed.items():
        (folder / f"{name}.json").write_text(
            json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    (folder / "_meta.json").write_text(
        json.dumps(
            {"label": label, "recorded": date.today().isoformat(),
             "operations": sorted(scrubbed), "redacted": True},
            indent=2, sort_keys=True,
        ) + "\n",
        encoding="utf-8",
    )
    return folder, redactor.counts()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version-label", required=True)
    parser.add_argument("--out", default=DEFAULT_OUT)
    parser.add_argument("--redact", action="append", default=[])
    args = parser.parse_args(argv)

    _quiet_lab_tls_warnings()
    folder, counts = record(args.version_label, args.out, args.redact)

    print(f"Recorded and redacted to {folder}")
    print("Replaced: " + ", ".join(f"{n} {k}" for k, n in counts.items()))
    print("Review the files, then commit them.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
