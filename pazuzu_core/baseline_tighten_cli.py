"""Apply the strict outbound decisions to the baseline manifest.

Usage:
    python -m pazuzu_core.baseline_tighten_cli            # dry run
    python -m pazuzu_core.baseline_tighten_cli --write

Removes udp/443 (QUIC) from approved_outbound and approved_web, and udp/123
from approved_outbound. Keeps the file's own formatting. Nothing is written
if the result would not validate or there is nothing to change. Rules
already created on the firewall are not touched: re-create them from the new
manifest (the smoke tool's apply and rollback).
"""

from __future__ import annotations

import argparse
import json
import sys

from pazuzu_core.baseline_tighten import tighten
from pazuzu_core.uplink_policy_cli import dump_like

DEFAULT_MANIFEST = "manifests/security_baseline_v0_4.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)
    try:
        with open(args.manifest, encoding="utf-8", newline="") as handle:
            original = handle.read()
        updated, changes = tighten(json.loads(original))
        if not changes:
            print("Nothing to change: the baseline is already tightened.")
            return 0
        if args.write:
            with open(args.manifest, "w", encoding="utf-8", newline="") as handle:
                handle.write(dump_like(original, updated))
            print(f"Updated {args.manifest}:")
        else:
            print("DRY RUN: the manifest was not changed. Would:")
        for line in changes:
            print(f"  {line}")
        print("The result validates." + ("" if args.write else " Re-run with --write to apply it."))
        return 0
    except (RuntimeError, ValueError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
