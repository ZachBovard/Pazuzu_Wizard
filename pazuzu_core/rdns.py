"""Names for the addresses on the Screen tab: a reverse lookup, one address at a time, never holding the page up.

Only addresses out on the internet are looked up (a device on your own network is named from the firewall's own
address leases, which the screen already has). A lookup runs in the background with a short wait; the page asks again
and gets the answer once it is there. Answers, and "no name", are kept for a while so the same address is not asked
about every few seconds. Nothing is looked up for a made-up or private address, and at most a few at a time.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

FIREWALL_PATH = "/api/diagnostics/dns/reverse_lookup?address="
KEEP_SECONDS = 6 * 3600
MAX_PER_CALL = 30
WAIT_SECONDS = 3


def public_ip(text) -> str | None:
    """The address as text if it is a public IPv4 or IPv6 address, else None."""
    try:
        a = ipaddress.ip_address(str(text).strip())
    except ValueError:
        return None
    if not a.is_global or a.is_multicast:
        return None
    return str(a)


_HOST = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+[A-Za-z0-9_-]{1,63}\.?$")


def name_from_reply(data, ip: str = "") -> str | None:
    """A host name out of the firewall's reverse-lookup reply, or None when none can be read from it. The reply's exact
    shape is not documented, so this accepts a plain text answer, or a name under a usual key, or a list of those."""
    if isinstance(data, str):
        s = data.strip().rstrip(".")
        return s if s != ip and _HOST.match(s) else None
    if isinstance(data, dict):
        for key in ("name", "hostname", "host", "ptr", "fqdn", "result", "response", "answer"):
            if key in data:
                got = name_from_reply(data[key], ip)
                if got:
                    return got
        return None
    if isinstance(data, list):
        for item in data:
            got = name_from_reply(item, ip)
            if got:
                return got
    return None


class Names:
    def __init__(self, resolver=None, now=time.time, workers: int = 4, firewall=None):
        self._resolver = resolver or (lambda ip: socket.gethostbyaddr(ip)[0])
        self.firewall = firewall      # a function that reads one path from the firewall's API; asked first
        self._now = now
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="rdns")
        self._lock = threading.Lock()
        self._done: dict[str, tuple[float, str]] = {}
        self._busy: set[str] = set()

    def _work(self, ip: str) -> None:
        name = ""
        ask = self.firewall
        if ask is not None:           # the firewall's own lookup first, so the question goes out through it
            try:
                name = name_from_reply(ask(FIREWALL_PATH + ip), ip) or ""
            except Exception:
                name = ""
        try:
            if not name:
                name = str(self._resolver(ip) or "")
        except Exception:                      # no name, a refusal, a timeout: all mean "no name to show"
            name = ""
        with self._lock:
            self._done[ip] = (self._now(), name)
            self._busy.discard(ip)

    def lookup(self, ips) -> dict[str, str | None]:
        """{address: name} where known; "" = looked up, no name; None = still being looked up."""
        out: dict[str, str | None] = {}
        todo = []
        for raw in list(ips)[:MAX_PER_CALL]:
            ip = public_ip(raw)
            if ip is None:
                continue
            with self._lock:
                hit = self._done.get(ip)
                if hit and self._now() - hit[0] < KEEP_SECONDS:
                    out[ip] = hit[1]
                    continue
                out[ip] = None
                if ip not in self._busy:
                    self._busy.add(ip)
                    todo.append(ip)
        futures = [self._pool.submit(self._work, ip) for ip in todo]
        deadline = time.monotonic() + WAIT_SECONDS
        for f in futures:                      # a short wait, so a quick answer comes back on the first call
            left = deadline - time.monotonic()
            if left > 0:
                try:
                    f.result(timeout=left)
                except Exception:
                    pass
        with self._lock:
            for ip in out:
                hit = self._done.get(ip)
                if hit and self._now() - hit[0] < KEEP_SECONDS:
                    out[ip] = hit[1]
        return out
