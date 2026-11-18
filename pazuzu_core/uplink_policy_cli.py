"""Add the uplink policy section to the baseline manifest.

Usage:
    python -m pazuzu_core.uplink_policy_cli                 # dry run
    python -m pazuzu_core.uplink_policy_cli --write         # change the file

The manifest's own formatting (indent, line endings, trailing newline) is
kept so the git diff shows only the new section. Nothing is written if the
result would not validate, or if the section is already present.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from pazuzu_core.uplink_policy import POLICY_PATH, add_to_baseline

DEFAULT_MANIFEST = "manifests/security_baseline_v0_4.json"

_INDENT = re.compile(r"^([ \t]+)\S", re.MULTILINE)


def dump_like(original_text: str, document: Any) -> str:
    """Serialise with the same indent, line endings and final newline."""

    match = _INDENT.search(original_text)
    indent: str | int = match.group(1) if match else 2
    newline = "\r\n" if "\r\n" in original_text else "\n"

    text = json.dumps(document, indent=indent, ensure_ascii=False)
    if original_text.endswith("\n"):
        text += "\n"
    return text.replace("\n", newline) if newline != "\n" else text


def run(manifest_path: str, write: bool) -> str:
    path = Path(manifest_path)
    with open(path, encoding="utf-8", newline="") as handle:
        original = handle.read()
    document = json.loads(original)

    updated = add_to_baseline(document)
    section = updated
    for key in POLICY_PATH:
        section = section[key]

    if write:
        with open(path, "w", encoding="utf-8", newline="") as handle:
            handle.write(dump_like(original, updated))
        return "written"

    print("DRY RUN: the manifest was not changed.")
    print(f"Would add at {'.'.join(POLICY_PATH)}:")
    print(json.dumps(section, indent=2))
    print("The result validates. Re-run with --write to apply it.")
    return "dry-run"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)

    outcome = run(args.manifest, args.write)
    if outcome == "written":
        print(f"Added the uplink policy to {args.manifest}.")
        print("Check the change with: git diff --stat " + args.manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
