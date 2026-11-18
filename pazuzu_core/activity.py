"""A short, live record of what this program is doing, for a folded panel the person can open.

Each request to the firewall becomes one line: the time, the method, the page (its path only, never
the address after the question mark), and what came back. Passwords, keys, request bodies and answers
are never recorded. It lives in memory only, holds the last few hundred lines, and is gone when the
program stops.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from urllib.parse import urlsplit

MAX = 300

_lock = threading.Lock()
_lines: deque = deque(maxlen=MAX)
_count = 0


def note(text: str) -> None:
    """One plain line about what is happening (a job started, a check finished)."""
    global _count
    with _lock:
        _count += 1
        _lines.append({"n": _count, "t": time.strftime("%H:%M:%S"), "text": str(text)[:200]})


def recent(limit: int = 80) -> dict:
    with _lock:
        items = list(_lines)[-limit:]
    return {"items": items, "last": items[-1]["n"] if items else 0}


def clear() -> None:
    with _lock:
        _lines.clear()


def _path(url) -> str:
    try:
        return urlsplit(str(url)).path or "/"
    except ValueError:
        return "?"


def watch(session):
    """Make this requests-like session record one line per request. Returns the same session."""
    original = getattr(session, "request", None)
    if original is None or getattr(session, "_pz_watched", False):
        return session

    def request(method, url, *args, **kwargs):
        began = time.monotonic()
        try:
            reply = original(method, url, *args, **kwargs)
        except Exception as exc:
            note(f"{str(method).upper()} {_path(url)} -> no answer ({type(exc).__name__}, "
                 f"{time.monotonic() - began:.1f}s)")
            raise
        note(f"{str(method).upper()} {_path(url)} -> {getattr(reply, 'status_code', '?')} "
             f"({time.monotonic() - began:.1f}s)")
        return reply

    try:
        session.request = request
        session._pz_watched = True
    except Exception:       # a test double that refuses new attributes: leave it alone
        pass
    return session
