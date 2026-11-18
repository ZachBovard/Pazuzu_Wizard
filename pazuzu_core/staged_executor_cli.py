"""Run a stage of the staged plan, or a drill, under the change guard.

Usage:
    python -m pazuzu_core.staged_executor_cli stage core_services
    python -m pazuzu_core.staged_executor_cli stage core_services --approve-digest <digest>
    python -m pazuzu_core.staged_executor_cli stage stock_disable --services-checked
    python -m pazuzu_core.staged_executor_cli drill --list
    python -m pazuzu_core.staged_executor_cli drill --rule <uuid>
    python -m pazuzu_core.staged_executor_cli shield off [--timeout 300]
    python -m pazuzu_core.staged_executor_cli pause

shield off puts back, for a while, only the old allow-all rules Pazuzu itself switched
off; pause does the same for exactly 15 seconds. Both undo themselves.

Without --approve-digest this is a preview: it prints the steps and a digest
and sends nothing. Approving means giving that digest back. If anything
changed since the preview the digest differs and nothing is sent. After
approval a passkey touch on that plan is asked for (a page opens on this PC;
see passkey_server), and only then is the change applied and undone
automatically unless confirmed in time (see change_guard_cli). Exit status: 0 kept (or preview), 1 undone,
2 refused or failed, 3 undo failed and needs a person.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any

from pazuzu_core.change_guard import REVERT_FAILED, CONFIRMED, GuardError
from pazuzu_core.staged_executor import (
    STAGE_IDS, ExecutorError, list_drill_candidates, prepare_drill, prepare_shield,
    prepare_stage, run,
)

DEFAULT_JOURNAL = os.environ.get("HANBI_JOURNAL", "scan_results/change_journal.json")


def _load_live() -> dict[str, Any]:
    from pazuzu_core.staged_enabling_cli import _load_live as load
    return load()


def _live_client():
    from pazuzu_core.opnsense_mutation_client import OPNsenseMutationClient
    return OPNsenseMutationClient()


def _live_version():
    from pazuzu_core.firewall_manifest_smoke import _installed_version
    return _installed_version()


def main(argv: list[str] | None = None, *, loader=None, client_factory=None,
         version_reader=None, clock=None, sleep=None, reader=None, gate=None) -> int:
    parser = argparse.ArgumentParser(prog="staged_executor_cli")
    sub = parser.add_subparsers(dest="command", required=True)
    stage = sub.add_parser("stage")
    stage.add_argument("stage", choices=STAGE_IDS)
    stage.add_argument("--services-checked", action="store_true")
    stage.add_argument("--lab-lifeline", action="store_true",
                       help="lab box only: the firewall's own LAN lockout protection "
                            "is the way in, so no management network or VPN is needed")
    drill = sub.add_parser("drill")
    drill.add_argument("--rule")
    drill.add_argument("--list", action="store_true",
                       help="show the rules a drill may use, and exit")
    shield = sub.add_parser("shield")
    shield.add_argument("level", choices=["off"])
    pause = sub.add_parser("pause")
    for p in (stage, drill, shield, pause):
        p.add_argument("--approve-digest")
        p.add_argument("--timeout", type=int)
        p.add_argument("--journal", default=DEFAULT_JOURNAL)
        p.add_argument("--accept-untested-version", action="store_true")
        p.add_argument("--on-box-timer", action="store_true",
                       default=os.environ.get("HANBI_ON_BOX_TIMER") == "1",
                       help="also arm a timer on the firewall (at) that undoes the "
                            "change if this process is cut off; set by the on-box wrapper")
    args = parser.parse_args(argv)

    try:
        if loader is None and client_factory is None:
            from pazuzu_core.firewall_rule_audit_cli import _quiet_lab_tls_warnings
            _quiet_lab_tls_warnings()
        inventory = (loader or _load_live)()
        if args.command == "drill" and args.list:
            found = list_drill_candidates(inventory)
            print(f"{len(found)} rule(s) a drill may use (disabled, Pazuzu-managed, not lan or wan):")
            for item in found:
                print(f"  {item['uuid']}  [{item['interface']}]  {item['description']}")
            return 0
        if args.command == "drill" and not args.rule:
            raise ExecutorError("drill needs --rule <uuid> (see: drill --list)")
        if args.command == "shield":
            prepared = prepare_shield(inventory, args.timeout)
        elif args.command == "pause":
            prepared = prepare_shield(inventory, args.timeout, pause=True)
        elif args.command == "stage":
            prepared = prepare_stage(inventory, args.stage, timeout_seconds=args.timeout,
                                     services_checked=args.services_checked,
                                     lab_lifeline=args.lab_lifeline)
        else:
            prepared = prepare_drill(inventory, args.rule, timeout_seconds=args.timeout)

        if not args.approve_digest:
            print(f"{prepared.label}: {len(prepared.steps)} step(s), window {prepared.timeout_seconds}s")
            for step in prepared.steps:
                print(f"  {step['kind']}: {step['uuid']}  {step['before']!r} -> {step['after']!r}")
            print(f"Digest: {prepared.digest}")
            print("Preview only: nothing was sent. To run it, repeat the command with:")
            print(f"  --approve-digest {prepared.digest}")
            return 0

        if args.approve_digest != prepared.digest:
            raise ExecutorError(
                "the approval digest does not match what would be done now: the "
                "firewall changed since the preview, or the digest was mistyped. "
                "Nothing was sent. Run the preview again.")

        from pazuzu_core.version_policy import decide
        decision = decide((version_reader or _live_version)(),
                          accept_untested=args.accept_untested_version)
        print(decision.message)
        if not decision.allow_mutation:
            raise ExecutorError("Refusing to change the firewall: " + decision.message)

        if gate is None:
            from pazuzu_core.passkey_gate import default_gate
            gate = default_gate()
        client = (client_factory or _live_client)()
        try:
            kwargs = {}
            if clock is not None:
                kwargs["clock"] = clock
            if sleep is not None:
                kwargs["sleep"] = sleep
            if args.on_box_timer:
                from pazuzu_core.onbox_timer import arm
                kwargs["on_armed"] = lambda j: print(
                    "On-box timer set: " + arm(j["timeout_seconds"]))
            journal = run(prepared, client, args.journal,
                          approve_digest=args.approve_digest, gate=gate,
                          reader=reader if reader is not None
                          else (None if loader is not None else _load_live),
                          **kwargs)
        finally:
            close = getattr(client, "close", None)
            if close:
                close()
    except (ExecutorError, GuardError, RuntimeError, ValueError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    state = journal["state"]
    after_undo = journal.get("verification", {}).get("after_undo")
    if isinstance(after_undo, list):
        print("The undo did NOT restore every field: a person must check the rules above.")
        return 3
    if state == CONFIRMED:
        print("Confirmed: the change is kept.")
        return 0
    if state == REVERT_FAILED:
        print("UNDO FAILED: a person must act. See: python -m pazuzu_core.change_guard_cli status")
        return 3
    print("The change was undone.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
