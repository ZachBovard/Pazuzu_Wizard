"""Guard a change, and look after one in progress.

Usage:
    python -m pazuzu_core.change_guard_cli status
    python -m pazuzu_core.change_guard_cli confirm
    python -m pazuzu_core.change_guard_cli revert
    python -m pazuzu_core.change_guard_cli recover            # dry run
    python -m pazuzu_core.change_guard_cli recover --approve  # acts
    python -m pazuzu_core.change_guard_cli recover --approve --after-reboot  # boot hook
    python -m pazuzu_core.change_guard_cli recover --approve --timer-fired   # on-box timer

`status`, `confirm` and `revert` only touch the journal file; the waiting
process (or `recover`) does the work. `recover` is a dry run unless given
--approve, because it talks to the firewall. There is no command here that
starts a change: changes begin from the staged-enabling tool, which is not
built yet.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from pazuzu_core.change_guard import CONFIRM, REVERT, ChangeGuard, GuardError

DEFAULT_JOURNAL = Path("scan_results") / "change_journal.json"


def main(argv: list[str] | None = None, *, client_factory=None, clock=None) -> int:
    parser = argparse.ArgumentParser(prog="change_guard_cli")
    parser.add_argument("command", choices=["status", "confirm", "revert", "recover"])
    parser.add_argument("--journal", default=str(DEFAULT_JOURNAL))
    parser.add_argument("--approve", action="store_true")
    parser.add_argument("--after-reboot", action="store_true",
                        help="boot hook: undo anything still armed, ignore the clock")
    parser.add_argument("--timer-fired", action="store_true",
                        help="on-box timer: the window is over, undo anything "
                             "still armed unless a confirm was recorded; ignore the clock")
    args = parser.parse_args(argv)

    try:
        if args.command == "recover" and args.approve:
            if client_factory is None:
                from pazuzu_core.opnsense_mutation_client import OPNsenseMutationClient
                client_factory = OPNsenseMutationClient
            guard = ChangeGuard(client_factory(), args.journal, clock=clock)
        else:
            guard = ChangeGuard(None, args.journal, clock=clock)

        if args.command == "status":
            print(json.dumps(guard.snapshot(), indent=2))
            return 0
        if args.command in ("confirm", "revert"):
            guard.decide(CONFIRM if args.command == "confirm" else REVERT)
            print(f"{args.command} recorded.")
            return 0
        result = guard.recover(dry_run=not args.approve,
                               after_reboot=args.after_reboot or args.timer_fired)
        print(json.dumps(result, indent=2, default=str))
        if not args.approve and result.get("action") not in ("none", "wait"):
            print("Dry run. Add --approve to act.")
        return 1 if result.get("state") == "revert_failed" else 0
    except (GuardError, RuntimeError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
