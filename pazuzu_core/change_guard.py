"""Guarded changes: apply, wait for a human, undo on silence.

A change that could lock the user out is made in a "guarded window". The
plan is written to a journal on disk first, then applied. If nobody confirms
before the deadline, every step is undone in reverse order. If this program
dies mid-change, `recover` reads the journal and finishes the job.

Honest limit: undo goes through the firewall's API. If a change cuts the path
this program uses to reach the firewall, the undo cannot get through either.
Run the guard from the management path, which the lifeline rules protect. An
on-box watchdog is a separate, later piece.

Nothing here talks to a firewall by itself: the caller passes in a client,
a clock and a sleep function, so everything is testable offline.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

# Journal states
PLANNED = "planned"        # written, nothing applied yet
APPLYING = "applying"      # steps being applied
ARMED = "armed"            # all applied, waiting for a decision
CONFIRMED = "confirmed"    # kept
REVERTED = "reverted"      # undone cleanly
REVERT_FAILED = "revert_failed"  # undo had errors: needs a human
UNRESOLVED = (PLANNED, APPLYING, ARMED, REVERT_FAILED)

# Decisions a person or the app can record
CONFIRM = "confirm"
REVERT = "revert"

# Step kinds -> (client method, field)
TOGGLE = "toggle_rule"
SET_DESCRIPTION = "set_description"
SET_SOURCE = "set_source"
KINDS = (TOGGLE, SET_DESCRIPTION, SET_SOURCE)

MIN_TIMEOUT_SECONDS = 30
PAUSE_SECONDS = 15          # the one shorter window: a pause that needs no passkey
MAX_TIMEOUT_SECONDS = 3600
DEFAULT_TIMEOUT_SECONDS = 300
POLL_SECONDS = 2


class GuardError(RuntimeError):
    pass


def _lock_file(handle) -> None:
    """Take an exclusive, non-blocking lock on an open file, or raise OSError.

    The operating system drops the lock when the process dies, so a crash can
    never leave a stale lock behind.
    """
    if os.name == "nt":  # pragma: no cover - exercised on Windows
        import msvcrt
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
    else:
        import fcntl
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock_file(handle) -> None:
    if os.name == "nt":  # pragma: no cover - exercised on Windows
        import msvcrt
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@dataclass(frozen=True)
class Step:
    kind: str
    uuid: str
    before: Any
    after: Any

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "uuid": self.uuid,
                "before": self.before, "after": self.after}


def _check_step(raw: Any) -> Step:
    if not isinstance(raw, dict):
        raise GuardError("a step must be an object")
    kind, uuid = raw.get("kind"), raw.get("uuid")
    if kind not in KINDS:
        raise GuardError(f"unknown step kind: {kind!r}")
    if not isinstance(uuid, str) or not uuid:
        raise GuardError("a step needs a uuid")
    if "before" not in raw or "after" not in raw:
        raise GuardError("a step needs both 'before' and 'after': "
                         "without the old value it cannot be undone")
    before, after = raw["before"], raw["after"]
    if kind == TOGGLE:
        if not isinstance(before, bool) or not isinstance(after, bool):
            raise GuardError("toggle steps need true/false values")
    else:
        if not isinstance(before, str) or not isinstance(after, str):
            raise GuardError(f"{kind} steps need text values")
    if before == after:
        raise GuardError("a step must change something")
    return Step(kind, uuid, before, after)


def _do(client: Any, kind: str, uuid: str, value: Any) -> None:
    if kind == TOGGLE:
        client.toggle_firewall_rule(uuid, value)
    elif kind == SET_DESCRIPTION:
        client.set_firewall_rule_fields(uuid, {"description": value})
    elif kind == SET_SOURCE:
        client.set_firewall_rule_fields(uuid, {"source_net": value})
    else:  # pragma: no cover - guarded by _check_step
        raise GuardError(f"unknown step kind: {kind!r}")


def _utc(now: datetime) -> str:
    return now.astimezone(timezone.utc).isoformat()


class ChangeGuard:
    def __init__(
        self,
        client: Any,
        journal_path: Path | str,
        *,
        clock: Callable[[], datetime] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        on_armed: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.on_armed = on_armed  # e.g. the on-box timer; see onbox_timer.py
        self.client = client
        self.path = Path(journal_path)
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.sleep = sleep
        self._lock_depth = 0
        self._lock_handle = None

    # --- one guard at a time ---------------------------------------------
    @contextlib.contextmanager
    def exclusive(self):
        """Hold the guard's lock. Only one process may change or undo at a
        time. Re-entrant within one guard object. Reading the journal and
        recording a decision do not need it."""
        if self._lock_depth:
            self._lock_depth += 1
            try:
                yield
            finally:
                self._lock_depth -= 1
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = open(str(self.path) + ".lock", "a+b")
        try:
            try:
                _lock_file(handle)
            except OSError:
                raise GuardError(
                    "another guard is already running on this journal; "
                    "wait for it, or use status") from None
            self._lock_depth = 1
            self._lock_handle = handle
            try:
                yield
            finally:
                self._lock_depth = 0
                self._lock_handle = None
                try:
                    _unlock_file(handle)
                except OSError:
                    pass
        finally:
            handle.close()

    # --- journal -------------------------------------------------------
    def load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None
        try:
            data = json.loads(self._read_text())
        except (OSError, ValueError) as exc:
            raise GuardError(f"journal unreadable ({exc}); "
                             "inspect it by hand before changing anything")
        if not isinstance(data, dict) or data.get("state") not in (
                PLANNED, APPLYING, ARMED, CONFIRMED, REVERTED, REVERT_FAILED):
            raise GuardError("journal has an unknown shape; "
                             "inspect it by hand before changing anything")
        return data

    def _read_text(self) -> str:
        """The journal's text. BUILD 545 (the maintainer's PC, 16 Nov 2026: "journal unreadable ([Errno 13] Permission denied
        ...change_journal.json); inspect it by hand before changing anything"): on Windows a read that lands in the
        instant another thread is swapping the new journal in is refused. That is the same instant `_save` waits out
        from its side, so the read waits it out too (two seconds at most) before it is called unreadable. Anywhere
        else the first read answers."""
        for attempt in range(40):
            try:
                return self.path.read_text(encoding="utf-8")
            except PermissionError:
                if attempt == 39:
                    raise
                time.sleep(0.05)
        raise OSError("unreachable")  # pragma: no cover

    def _save(self, journal: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(journal, handle, indent=2, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            for attempt in range(40):
                try:
                    os.replace(tmp, self.path)
                    break
                except PermissionError:
                    # Windows refuses the swap while a reader has the file
                    # open for an instant; wait it out, then give up loudly.
                    if attempt == 39:
                        raise
                    time.sleep(0.05)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    # --- starting ------------------------------------------------------
    def start(self, label: str, steps: list[dict[str, Any]],
              timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS, *,
              min_seconds: int = MIN_TIMEOUT_SECONDS) -> dict[str, Any]:
        with self.exclusive():
            return self._start(label, steps, timeout_seconds, min_seconds)

    def _start(self, label: str, steps: list[dict[str, Any]],
               timeout_seconds: int,
               min_seconds: int = MIN_TIMEOUT_SECONDS) -> dict[str, Any]:
        """Apply the steps and arm the timer. Returns the armed journal.

        If any step fails, everything already done is undone before the
        error is raised.
        """
        existing = self.load()
        if existing and existing["state"] in UNRESOLVED:
            raise GuardError(
                f"an earlier change ({existing.get('label')!r}) is still "
                f"{existing['state']}; resolve it first (status / recover)")
        if (not isinstance(timeout_seconds, int) or isinstance(timeout_seconds, bool)
                or not min_seconds <= timeout_seconds <= MAX_TIMEOUT_SECONDS):
            raise GuardError(
                f"timeout must be {min_seconds}-{MAX_TIMEOUT_SECONDS} seconds")
        if not isinstance(label, str) or not label.strip():
            raise GuardError("a change needs a label")
        if not steps:
            raise GuardError("a change needs at least one step")
        checked = [_check_step(raw) for raw in steps]
        seen = [(s.kind, s.uuid) for s in checked]
        if len(set(seen)) != len(seen):
            raise GuardError("the same rule and field appear twice")

        journal = {
            "label": label.strip(),
            "state": PLANNED,
            "decision": None,
            "created_at": _utc(self.clock()),
            "timeout_seconds": timeout_seconds,
            "deadline": None,
            "steps": [dict(s.as_dict(), status="pending") for s in checked],
            "errors": [],
        }
        self._save(journal)

        journal["state"] = APPLYING
        self._save(journal)
        for entry in journal["steps"]:
            # Mark as attempted BEFORE the call: a crash mid-call must still
            # be undone, since the firewall may have taken the change.
            entry["status"] = "attempted"
            self._save(journal)
            try:
                _do(self.client, entry["kind"], entry["uuid"], entry["after"])
            except Exception as exc:  # noqa: BLE001 - undo, then report
                journal["errors"].append(f"apply {entry['kind']}: {exc}")
                self._save(journal)
                self._undo(journal)
                raise GuardError(
                    f"step failed ({exc}); change undone: state is "
                    f"{journal['state']}") from exc
            entry["status"] = "applied"
            self._save(journal)
        try:
            self.client.apply_firewall_rules()
        except Exception as exc:  # noqa: BLE001
            journal["errors"].append(f"apply: {exc}")
            self._save(journal)
            self._undo(journal)
            raise GuardError(
                f"apply failed ({exc}); change undone: state is "
                f"{journal['state']}") from exc

        journal["deadline"] = _utc(self.clock() + timedelta(seconds=timeout_seconds))
        journal["state"] = ARMED
        self._save(journal)
        if self.on_armed is not None:
            # No timer means no safety net: undo rather than leave it armed.
            try:
                self.on_armed(journal)
            except Exception as exc:  # noqa: BLE001
                journal["errors"].append(f"timer: {exc}")
                self._save(journal)
                self._undo(journal)
                raise GuardError(
                    f"could not set the on-box timer ({exc}); change undone: "
                    f"state is {journal['state']}") from exc
        return journal

    # --- deciding ------------------------------------------------------
    def decide(self, decision: str) -> dict[str, Any]:
        """Record a decision. The waiting process (or recover) acts on it."""
        if decision not in (CONFIRM, REVERT):
            raise GuardError("decision must be 'confirm' or 'revert'")
        journal = self.load()
        if not journal or journal["state"] != ARMED:
            raise GuardError("no armed change to decide on")
        if self._expired(journal) and decision == CONFIRM:
            raise GuardError("the deadline has passed: this change is "
                             "being undone and can no longer be confirmed")
        journal["decision"] = decision
        self._save(journal)
        return journal

    def _expired(self, journal: dict[str, Any]) -> bool:
        deadline = journal.get("deadline")
        if not deadline:
            return True
        return self.clock() >= datetime.fromisoformat(deadline)

    def wait(self) -> dict[str, Any]:
        with self.exclusive():
            return self._wait()

    def _wait(self) -> dict[str, Any]:
        """Block until confirmed, reverted, or the deadline passes."""
        while True:
            journal = self.load()
            if not journal or journal["state"] != ARMED:
                raise GuardError("no armed change to wait on")
            if self._expired(journal):
                # An unconfirmed deadline always means undo, even if a
                # confirm was written in the final instant.
                return self._undo(journal)
            if journal["decision"] == CONFIRM:
                journal["state"] = CONFIRMED
                self._save(journal)
                return journal
            if journal["decision"] == REVERT:
                return self._undo(journal)
            self.sleep(POLL_SECONDS)

    # --- undoing -------------------------------------------------------
    def _undo(self, journal: dict[str, Any]) -> dict[str, Any]:
        """Undo every step that was attempted, newest first, each on its own
        so one failure does not stop the rest. Then apply once."""
        failed = False
        for entry in reversed(journal["steps"]):
            # "undo_failed" is retried too: a retry that skipped it would
            # report the change as undone while the rule stayed changed.
            if entry["status"] not in ("attempted", "applied", "undo_failed"):
                continue
            try:
                _do(self.client, entry["kind"], entry["uuid"], entry["before"])
                entry["status"] = "undone"
            except Exception as exc:  # noqa: BLE001
                entry["status"] = "undo_failed"
                journal["errors"].append(f"undo {entry['kind']}: {exc}")
                failed = True
            self._save(journal)
        try:
            self.client.apply_firewall_rules()
        except Exception as exc:  # noqa: BLE001
            journal["errors"].append(f"undo apply: {exc}")
            failed = True
        journal["state"] = REVERT_FAILED if failed else REVERTED
        self._save(journal)
        return journal

    # --- recovery ------------------------------------------------------
    def recover(self, *, dry_run: bool = True,
                after_reboot: bool = False) -> dict[str, Any]:
        """After a crash: say what would be done, or do it.

        Planned/applying or an expired armed change is undone. An armed
        change still inside its window is left to run out (or be decided).
        A failed undo is retried.

        after_reboot=True is for the boot hook. Nothing is waiting any more,
        and the clock may be wrong until time sync, so the deadline is not
        consulted: an armed change is undone unless a confirm was already
        recorded. Never keep a change just because the clock says time is left.
        """
        if dry_run:
            return self._recover(dry_run=True, after_reboot=after_reboot)
        with self.exclusive():
            return self._recover(dry_run=False, after_reboot=after_reboot)

    def _recover(self, *, dry_run: bool, after_reboot: bool) -> dict[str, Any]:
        journal = self.load()
        if not journal or journal["state"] in (CONFIRMED, REVERTED):
            return {"action": "none", "state": journal["state"] if journal else None}
        state = journal["state"]
        if state == ARMED and (after_reboot or not self._expired(journal)):
            if journal["decision"] == CONFIRM:
                action = "confirm"
            elif journal["decision"] == REVERT or after_reboot:
                action = "undo"
            else:
                return {"action": "wait", "state": state,
                        "deadline": journal["deadline"]}
        else:
            action = "undo"
        if dry_run:
            return {"action": action, "state": state, "dry_run": True}
        if action == "confirm":
            journal["state"] = CONFIRMED
            self._save(journal)
            return journal
        return self._undo(journal)

    # --- UI hook -------------------------------------------------------
    def snapshot(self) -> dict[str, Any]:
        """Plain facts for an interface: is a change pending, how long left."""
        journal = self.load()
        if not journal:
            return {"active": False}
        remaining = None
        if journal["state"] == ARMED and journal.get("deadline"):
            left = datetime.fromisoformat(journal["deadline"]) - self.clock()
            remaining = max(0, int(left.total_seconds()))
        return {
            "active": journal["state"] in UNRESOLVED,
            "label": journal["label"],
            "state": journal["state"],
            "decision": journal["decision"],
            "seconds_left": remaining,
            "steps": [{"kind": s["kind"], "status": s["status"], "uuid": s.get("uuid")}
                      for s in journal["steps"]],
            "needs_human": journal["state"] == REVERT_FAILED,
            "errors": list(journal["errors"]),
        }
