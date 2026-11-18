"""Run one stage of the staged plan, or a drill, under the change guard.

Every run begins as a dry run that prints what would change and a digest of
exactly those steps. Approving means giving that digest back: if the
firewall changed between the preview and the approval, the digest differs
and nothing is sent. After approval the steps are applied, a timer starts,
and unless someone confirms in time everything is undone.

Rules about order, so a stage cannot be run out of sequence:
  * core_services needs lifeline done;
  * outbound needs core_services done;
  * stock_disable needs both done, and the operator must state they have
    checked the firewall services (time service, DHCP time-server option,
    IPv6 off), because nothing can read those yet;
  * blocking (Pazuzu's own block rules) needs all of those done, so it is last.

A drill is a harmless rehearsal on one Pazuzu rule that is disabled and not
on the LAN: it toggles the rule and edits its description, then the guard
undoes it. It proves the firewall accepts those calls and that the undo
works, before a stage depends on them.

The guard's limit applies: if a change cuts the path this program uses, the
undo cannot get through either. Run it from the management side.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from pazuzu_core.change_guard import (
    CONFIRMED, CONFIRM, DEFAULT_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS,
    MIN_TIMEOUT_SECONDS, PAUSE_SECONDS, REVERT, REVERTED, SET_DESCRIPTION, TOGGLE,
    ChangeGuard, GuardError,
)
from pazuzu_core.staged_enabling import build_plan, our_disabled_stock, shield_level  # noqa: F401

STAGE_IDS = ("lifeline", "core_services", "outbound", "stock_disable", "blocking")
_PREREQUISITES = {
    "lifeline": (),
    "core_services": ("lifeline",),
    "outbound": ("lifeline", "core_services"),
    "stock_disable": ("lifeline", "core_services", "outbound"),
    "blocking": ("lifeline", "core_services", "outbound", "stock_disable"),
}
DRILL_SUFFIX = " [drill]"

# Fields compared when reading the firewall back. Stable ones only: a field
# that can change on its own (counters, timestamps) must not be here.
STABLE_FIELDS = (
    "enabled", "description", "action", "interface", "direction", "ipprotocol",
    "protocol", "source_net", "source_not", "source_port", "destination_net",
    "destination_not", "destination_port", "quick", "log", "sequence",
    "sort_order",
)
DIGEST_LENGTH = 12
COUNTDOWN_EVERY = 30


class ExecutorError(RuntimeError):
    pass


@dataclass(frozen=True)
class Prepared:
    kind: str                 # "stage" or "drill"
    name: str
    label: str
    steps: tuple[dict[str, Any], ...]
    timeout_seconds: int
    digest: str
    before_rows: Mapping[str, Mapping[str, str]] | None = None
    min_seconds: int = MIN_TIMEOUT_SECONDS   # only the pause goes lower


def digest_of(kind: str, name: str, steps, timeout_seconds: int) -> str:
    body = json.dumps(
        {"kind": kind, "name": name, "timeout": timeout_seconds, "steps": list(steps)},
        sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()[:DIGEST_LENGTH]


def _norm(field: str, value: Any) -> str:
    text = "" if value is None else str(value).strip()
    if field in ("enabled", "source_not", "destination_not", "quick", "log"):
        return "1" if text.lower() in {"1", "true", "yes"} else "0"
    return text


def stable_rows(inventory: Mapping[str, Any]) -> dict[str, dict[str, str]]:
    rows = inventory.get("rows")
    if not isinstance(rows, list):
        raise ExecutorError("inventory rows must be an array")
    return {
        str(r["uuid"]): {f: _norm(f, r[f]) for f in STABLE_FIELDS if f in r}
        for r in rows if isinstance(r, dict) and r.get("uuid")
    }


def _expected(before: Mapping[str, str], steps, uuid: str) -> dict[str, str]:
    row = dict(before)
    for step in steps:
        if step["uuid"] != uuid:
            continue
        if step["kind"] == TOGGLE:
            row["enabled"] = "1" if step["after"] else "0"
        elif step["kind"] == SET_DESCRIPTION:
            row["description"] = step["after"]
    return row


def compare(before_rows, after_rows, steps, *, expect_restored: bool = False):
    """(problems with rules we touched, notes about other rules).

    After the change, each touched rule must equal its old row with only the
    step values changed. After an undo, it must equal its old row exactly.
    """
    touched = {s["uuid"] for s in steps}
    problems, notes = [], []
    for uuid in sorted(touched):
        before = before_rows.get(uuid)
        after = after_rows.get(uuid)
        if before is None:
            problems.append(f"{uuid}: was not on the firewall before")
            continue
        if after is None:
            problems.append(f"{uuid}: is no longer on the firewall")
            continue
        want = dict(before) if expect_restored else _expected(before, steps, uuid)
        for field in sorted(set(want) | set(after)):
            if want.get(field) != after.get(field):
                problems.append(
                    f"{uuid}: {field} is {after.get(field)!r}, expected {want.get(field)!r}")
    for uuid in sorted(set(before_rows) | set(after_rows)):
        if uuid in touched:
            continue
        if before_rows.get(uuid) != after_rows.get(uuid):
            notes.append(f"{uuid}: another rule changed during the window (not by this tool)")
    return problems, notes


def _timeout(value: int | None, default: int) -> int:
    timeout = default if value is None else value
    if (not isinstance(timeout, int) or isinstance(timeout, bool)
            or not MIN_TIMEOUT_SECONDS <= timeout <= MAX_TIMEOUT_SECONDS):
        raise ExecutorError(
            f"timeout must be {MIN_TIMEOUT_SECONDS}-{MAX_TIMEOUT_SECONDS} seconds")
    return timeout


def prepare_stage(
    inventory: Mapping[str, Any],
    stage_id: str,
    *,
    timeout_seconds: int | None = None,
    services_checked: bool = False,
    lab_lifeline: bool = False,
) -> Prepared:
    if stage_id not in STAGE_IDS:
        raise ExecutorError(f"unknown stage {stage_id!r}; choose one of: {', '.join(STAGE_IDS)}")
    plan = build_plan(inventory, lab_lifeline=lab_lifeline)
    stages = {s["id"]: s for s in plan["stages"]}
    if stage_id not in stages:
        raise ExecutorError(f"{stage_id} has nothing to change on this firewall")
    stage = stages[stage_id]

    for needed in _PREREQUISITES[stage_id]:
        if stages[needed]["status"] != "done":
            raise ExecutorError(
                f"{needed} must be done and confirmed first (it is {stages[needed]['status']})")
    if stage["status"] == "done":
        raise ExecutorError(f"{stage_id} is already done: nothing to change")
    if stage["blockers"]:
        raise ExecutorError(f"{stage_id} is blocked: " + "; ".join(stage["blockers"]))
    if not stage["steps"]:
        raise ExecutorError(f"{stage_id} has nothing to change")
    if stage_id == "stock_disable" and not services_checked:
        raise ExecutorError(
            "stock_disable needs --services-checked: confirm the firewall's time "
            "service, the DHCP time-server option and IPv6 off first")

    timeout = _timeout(timeout_seconds, stage["timeout_seconds"])
    steps = tuple(dict(s) for s in stage["steps"])
    return Prepared("stage", stage_id, f"stage: {stage_id}", steps, timeout,
                    digest_of("stage", stage_id, steps, timeout),
                    stable_rows(inventory))


# --- the shields: the old allow-all rules Pazuzu switched off, put back for a while
def _disabled_stock(inventory: Mapping[str, Any]) -> list[dict[str, Any]]:
    try:
        return our_disabled_stock(inventory)
    except ValueError as exc:
        raise ExecutorError(str(exc))


def prepare_shield(inventory: Mapping[str, Any], seconds: int | None = None, *,
                   pause: bool = False) -> Prepared:
    rows = _disabled_stock(inventory)
    if not rows:
        raise ExecutorError("nothing to lower: the old allow-all rules were not switched "
                            "off by Pazuzu yet, so nothing is being blocked by them")
    steps = tuple({"kind": TOGGLE, "uuid": str(r["uuid"]), "before": False, "after": True}
                  for r in rows
                  if str(r.get("enabled")).strip().lower() not in {"1", "true", "yes"})
    if not steps:
        raise ExecutorError("the shields are already down")
    if pause:
        if seconds not in (None, PAUSE_SECONDS):
            raise ExecutorError(f"a pause is exactly {PAUSE_SECONDS} seconds")
        timeout, low = PAUSE_SECONDS, PAUSE_SECONDS
    else:
        timeout, low = _timeout(seconds, DEFAULT_TIMEOUT_SECONDS), MIN_TIMEOUT_SECONDS
    kind = "pause" if pause else "shield"
    label = f"pause: {timeout} s" if pause else "shields: all off"
    return Prepared(kind, "pause" if pause else "off", label, steps, timeout,
                    digest_of(kind, "pause" if pause else "off", steps, timeout),
                    stable_rows(inventory), low)


def _drill_problem(row: Mapping[str, Any]) -> str | None:
    """Why this rule cannot be drilled, or None when it can."""
    description = str(row.get("description") or "")
    if not description.startswith("PAZUZU:"):
        return "a drill only runs on a Pazuzu-managed rule"
    if str(row.get("enabled")).strip().lower() in {"1", "true", "yes"}:
        return "a drill needs a rule that is disabled"
    if str(row.get("interface") or "").lower() in ("lan", "wan"):
        return "a drill never runs on a lan or wan rule"
    if len(description) + len(DRILL_SUFFIX) > 255:
        return "the description is too long to annotate"
    return None


def list_drill_candidates(inventory: Mapping[str, Any]) -> list[dict[str, str]]:
    rows = inventory.get("rows")
    if not isinstance(rows, list):
        raise ExecutorError("inventory rows must be an array")
    return [
        {"uuid": str(r.get("uuid")), "interface": str(r.get("interface") or ""),
         "description": str(r.get("description") or "")}
        for r in rows
        if isinstance(r, dict) and r.get("uuid") and _drill_problem(r) is None
    ]


def prepare_drill(
    inventory: Mapping[str, Any],
    rule_uuid: str,
    *,
    timeout_seconds: int | None = None,
) -> Prepared:
    rows = inventory.get("rows")
    if not isinstance(rows, list):
        raise ExecutorError("inventory rows must be an array")
    row = next((r for r in rows if isinstance(r, dict) and r.get("uuid") == rule_uuid), None)
    if row is None:
        raise ExecutorError("no rule with that uuid on the firewall")
    problem = _drill_problem(row)
    if problem:
        raise ExecutorError(problem)
    description = str(row.get("description") or "")

    timeout = _timeout(timeout_seconds, MIN_TIMEOUT_SECONDS)
    steps = (
        {"kind": TOGGLE, "uuid": rule_uuid, "before": False, "after": True},
        {"kind": SET_DESCRIPTION, "uuid": rule_uuid, "before": description,
         "after": description + DRILL_SUFFIX},
    )
    return Prepared("drill", rule_uuid, "drill", steps, timeout,
                    digest_of("drill", rule_uuid, steps, timeout),
                    stable_rows(inventory))


def name_of(description: Any, uuid: str) -> str:
    """What a person would call a rule: its description without the
    "PAZUZU:<id>:" tag. Falls back to the id when the description is empty."""

    text = str(description or "").strip()
    if text.startswith("PAZUZU:"):
        parts = text.split(":", 2)
        text = parts[2].strip() if len(parts) == 3 else text
    return text or f"rule {uuid}"


def _rule_name(prepared: Prepared, uuid: str) -> str:
    row = (prepared.before_rows or {}).get(uuid) or {}
    return name_of(row.get("description"), uuid)


def describe(prepared: Prepared) -> tuple[str, ...]:
    """Plain sentences for the approval screen: what this plan will do."""

    if prepared.kind in ("shield", "pause"):
        mins, secs = divmod(prepared.timeout_seconds, 60)
        span = f"{mins} min" if mins and not secs else f"{prepared.timeout_seconds} seconds"
        lines = [f"Lower the shields for {span}: {len(prepared.steps)} old allow-all rule(s) "
                 "come back on. They go off again by themselves."]
        for step in prepared.steps:
            lines.append(f"Turn on for now: {_rule_name(prepared, step['uuid'])}")
        return tuple(lines)
    lines = [f"{prepared.label}: {len(prepared.steps)} step(s). Unless confirmed "
             f"within {prepared.timeout_seconds} seconds, everything is undone."]
    for step in prepared.steps:
        name = _rule_name(prepared, step["uuid"])
        if step["kind"] == TOGGLE:
            verb = "Turn on" if step["after"] else "Turn off"
            lines.append(f"{verb}: {name}")
        elif step["kind"] == SET_DESCRIPTION:
            lines.append(f"Rename {name}: {step['before']!r} to {step['after']!r}")
        else:
            lines.append(f"{step['kind']}: {name}")
    return tuple(lines)


def run(
    prepared: Prepared,
    client: Any,
    journal_path: str,
    *,
    approve_digest: str,
    gate: Callable[[str, Any], bool] | None = None,
    clock: Callable | None = None,
    sleep: Callable[[float], None] = time.sleep,
    out: Callable[[str], None] = print,
    reader: Callable[[], Mapping[str, Any]] | None = None,
    on_armed: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Apply, read back, start the timer, wait. Returns the final journal.

    With a reader, the firewall is read after the change and again after an
    undo. A touched rule that is not as expected after the change is undone
    at once. The findings are returned under journal["verification"].
    """
    if approve_digest != prepared.digest:
        raise ExecutorError(
            "the approval digest does not match what would be done now: the "
            "firewall changed since the preview, or the digest was mistyped. "
            "Nothing was sent. Run the preview again.")

    # Every change needs a person's passkey on this exact plan. Asked before the
    # window starts, so the time spent approving never counts against it.
    if gate is None:
        raise ExecutorError(
            "changes need a passkey approval and none was given. Nothing was sent.")
    if not gate(prepared.digest, describe(prepared)):
        raise ExecutorError(
            "the change was not approved with a passkey. Nothing was sent.")

    elapsed = {"seconds": 0.0}
    guard = ChangeGuard(client, journal_path, clock=clock, sleep=lambda s: None,
                        on_armed=on_armed)

    def ticking_sleep(seconds: float) -> None:
        sleep(seconds)
        elapsed["seconds"] += seconds
        if elapsed["seconds"] >= COUNTDOWN_EVERY:
            elapsed["seconds"] = 0.0
            left = guard.snapshot().get("seconds_left")
            if left is not None:
                out(f"  {left} seconds left")

    guard.sleep = ticking_sleep
    journal = guard.start(prepared.label, list(prepared.steps), prepared.timeout_seconds,
                          min_seconds=prepared.min_seconds)
    verification: dict[str, Any] = {"after_change": None, "after_undo": None, "notes": []}

    def read_back(expect_restored: bool):
        if reader is None or prepared.before_rows is None:
            return None
        try:
            return compare(prepared.before_rows, stable_rows(reader()),
                           prepared.steps, expect_restored=expect_restored)
        except Exception as error:  # noqa: BLE001 - never block the timer
            out(f"Could not read the firewall back ({error}): the change is NOT verified.")
            return "unreadable"

    changed = read_back(False)
    reverting = False
    if isinstance(changed, tuple):
        problems, notes = changed
        verification["notes"] += notes
        verification["after_change"] = "ok" if not problems else problems
        if problems:
            out("The firewall does not match the plan after the change:")
            for line in problems:
                out(f"  {line}")
            out("Undoing it now.")
            guard.decide(REVERT)
            reverting = True
        else:
            out(f"Verified on the firewall: {len(prepared.steps)} step(s) took effect, nothing else on those rules changed.")
    elif changed == "unreadable":
        verification["after_change"] = "unverified"

    if not reverting:
        out(f"Applied. You have {prepared.timeout_seconds} seconds.")
        out("Check from a client now. To keep the change, in a second shell run:")
        out("    python -m pazuzu_core.change_guard_cli confirm")
        out("To undo it now: python -m pazuzu_core.change_guard_cli revert")
        out("If you do nothing, it is undone automatically.")
    try:
        final = guard.wait()
    except KeyboardInterrupt:
        out("Interrupted: undoing the change.")
        guard.decide(REVERT)
        final = guard.wait()
    if final["state"] == "reverted":
        restored = read_back(True)
        if isinstance(restored, tuple):
            problems, notes = restored
            verification["notes"] += notes
            verification["after_undo"] = "ok" if not problems else problems
            if problems:
                out("AFTER THE UNDO the firewall still differs from before:")
                for line in problems:
                    out(f"  {line}")
            else:
                out("Verified on the firewall: the undo restored the rules exactly.")
        elif restored == "unreadable":
            verification["after_undo"] = "unverified"
    final["verification"] = verification
    return final
