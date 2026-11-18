"""Posture tools for the admin session control.

Usage:
    python -m pazuzu_core.posture_cli add                      # dry run
    python -m pazuzu_core.posture_cli add --write              # change the manifest
    python -m pazuzu_core.posture_cli check --observed 240     # what-if
    python -m pazuzu_core.posture_cli check --observed 45 --override-file ov.json

`add` puts the admin_session section in the baseline manifest, keeping the
file's own formatting so the git diff shows only the new section. Nothing is
written if the result would not validate or the section is already there.

`check` compares an idle timeout you give it with the manifest's target and
says whether it is enforced, overridden, drifted or unverified. It never
contacts a firewall: nothing yet reads the timeout from one. Leaving out
--observed reports "unverified". Exit status is 0 only when enforced, 1 when it is not, and 2 when the command could
not run (a missing or invalid manifest, or a section that is already there).
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from pazuzu_core.posture import (
    ENFORCED,
    SPEC_PATH,
    add_to_baseline,
    evaluate_idle_timeout,
    overall,
    validate_admin_session_spec,
)
from pazuzu_core.uplink_policy_cli import dump_like

DEFAULT_MANIFEST = "manifests/security_baseline_v0_4.json"


def _read(path: str) -> tuple[str, dict]:
    with open(path, encoding="utf-8", newline="") as handle:
        text = handle.read()
    return text, json.loads(text)


def add(manifest_path: str, write: bool) -> str:
    original, document = _read(manifest_path)
    updated = add_to_baseline(document)
    section = updated
    for key in SPEC_PATH:
        section = section[key]

    if write:
        with open(manifest_path, "w", encoding="utf-8", newline="") as handle:
            handle.write(dump_like(original, updated))
        return "written"

    print("DRY RUN: the manifest was not changed.")
    print(f"Would add at {'.'.join(SPEC_PATH)}:")
    print(json.dumps(section, indent=2))
    print("The result validates. Re-run with --write to apply it.")
    return "dry-run"


def check(
    manifest_path: str,
    observed: int | None,
    override_file: str | None,
    now: datetime,
) -> int:
    _, document = _read(manifest_path)
    spec = document.get("policy_pack", {}).get("platform_controls", {}).get("admin_session")
    if spec is None:
        raise RuntimeError(
            "The manifest has no admin_session section. Run `add --write` first."
        )
    problems = validate_admin_session_spec(spec)
    if problems:
        raise RuntimeError("Invalid admin_session section:\n" + "\n".join(problems))

    override = None
    if override_file:
        override = json.loads(Path(override_file).read_text(encoding="utf-8"))

    posture = evaluate_idle_timeout(spec, observed, override, now)
    summary = overall([posture])

    print(f"{posture.control}: {posture.status.upper()}")
    print(f"  {posture.detail}")
    print("The app is happy." if summary["happy"] else "The app is not happy.")
    return 0 if posture.status == ENFORCED else 1


def main(argv: list[str] | None = None, now: datetime | None = None) -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    add_parser = sub.add_parser("add")
    add_parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    add_parser.add_argument("--write", action="store_true")

    check_parser = sub.add_parser("check")
    check_parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    check_parser.add_argument("--observed", type=int)
    check_parser.add_argument("--override-file")

    args = parser.parse_args(argv)

    try:
        if args.command == "add":
            outcome = add(args.manifest, args.write)
            if outcome == "written":
                print(f"Added admin_session to {args.manifest}.")
                print("Check the change with: git diff --stat " + args.manifest)
            return 0

        return check(
            args.manifest,
            args.observed,
            args.override_file,
            now or datetime.now(timezone.utc),
        )
    except (RuntimeError, ValueError, OSError) as error:
        # JSONDecodeError is a ValueError.
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
