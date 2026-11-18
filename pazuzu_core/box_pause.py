"""Carry the box console's F-key pause request to the wizard, and the answer back.

The box only asks. This polls the box feed (the same link the manager already holds),
and when a new request is open it asks the wizard for the 15 second pause (no passkey, the
wizard's own rules apply: only rules Pazuzu switched off, a 60 second cooldown, never
while another change is open, always logged). Then it tells the box how it went, in a few
words, so the console can show it. Nothing here can change the firewall by itself.
"""
from __future__ import annotations

import threading
from typing import Any, Callable

from pazuzu_core.change_guard import PAUSE_SECONDS

POLL_SECONDS = 2.0
MAX_NOTE = 120


class BoxPauseBridge:
    def __init__(self, link, pause: Callable[[str], Any], *, poll: float = POLL_SECONDS):
        self.link, self._pause, self.poll = link, pause, poll
        self._seen: str | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def poll_once(self) -> str | None:
        """One look at the feed. Returns what was done ("paused", "refused") or None."""
        if not getattr(self.link, "url", None):
            return None
        status = self.link.read().get("status")
        req = status.get("pause_request") if isinstance(status, dict) else None
        if not isinstance(req, dict) or not isinstance(req.get("id"), str) or req["id"] == self._seen:
            return None
        self._seen = req["id"]
        try:
            self._pause("the box console")
            ok, note = True, ""
        except Exception as exc:                      # shown as text; never more than a short note
            ok, note = False, (str(exc) or "refused")[:MAX_NOTE]
        try:
            self.link.post("/pause_state", {"id": req["id"], "ok": ok,
                                            "seconds": PAUSE_SECONDS if ok else 0, "message": note})
        except Exception:
            pass                                      # the box shows "no answer"; the pause itself stands
        return "paused" if ok else "refused"

    def _loop(self) -> None:
        while not self._stop.wait(self.poll):
            try:
                self.poll_once()
            except Exception:
                continue

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._loop, daemon=True, name="box-pause")
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
