"""Tests the app runs from this device, standing in for "check from a LAN device".

Each test sends a real packet the way a device on the network would and says in
plain words what happened. Nothing here changes anything. A test has an
expectation: some should WORK once the baseline is on (names through the
firewall, time, a web page) and some should FAIL (an outside resolver, IPv6).
Standard library only.
"""
from __future__ import annotations

import socket
import ssl
import struct
import time
import urllib.request
from typing import Callable

WORKS, FAILS = "works", "fails"
GOOD, ATTENTION, UNKNOWN = "good", "attention", "unknown"
_NTP_EPOCH = 2208988800


def _dns_packet(name: str, ident: int = 0x4A5A) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.rstrip(".").split("."))
    return struct.pack(">HHHHHH", ident, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack(">HH", 1, 1)


def dns_answers(server: str, name: str = "example.com", timeout: float = 3.0,
                port: int = 53) -> int | None:
    """How many answers `server` gave for `name`, or None when nothing came back."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(_dns_packet(name), (server, port))
            data, _ = s.recvfrom(1500)
    except OSError:
        return None
    if len(data) < 12 or data[:2] != b"\x4a\x5a":
        return None
    rcode = data[3] & 0x0F
    return struct.unpack(">H", data[6:8])[0] if rcode == 0 else 0


def sntp(server: str, timeout: float = 3.0, port: int = 123) -> dict | None:
    """Ask `server` for the time. None when it does not answer."""
    packet = b"\x23" + 47 * b"\x00"           # version 4, client mode
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            sent = time.time()
            s.sendto(packet, (server, port))
            data, _ = s.recvfrom(512)
            got = time.time()
    except OSError:
        return None
    if len(data) < 48:
        return None
    li, stratum = data[0] >> 6, data[1]
    secs, frac = struct.unpack(">II", data[40:48])
    server_time = secs - _NTP_EPOCH + frac / 2**32
    return {"stratum": stratum, "leap": li, "offset": server_time - (sent + got) / 2}


def https_works(url: str = "https://example.com", timeout: float = 6.0) -> bool:
    try:
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(urllib.request.Request(url, method="HEAD"),
                                    timeout=timeout, context=ctx) as r:
            return 200 <= r.status < 400
    except Exception:
        return False


def ipv6_connects(host: str = "example.com", port: int = 443, timeout: float = 4.0) -> bool:
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET6, socket.SOCK_STREAM)
    except OSError:
        return False
    for family, kind, proto, _n, addr in infos[:2]:
        try:
            with socket.socket(family, kind, proto) as s:
                s.settimeout(timeout)
                s.connect(addr)
                return True
        except OSError:
            continue
    return False


def _row(test_id, title, expect, ok, works_text, fails_text):
    seen_works = bool(ok)
    status = GOOD if seen_works == (expect == WORKS) else ATTENTION
    return {"id": test_id, "title": title, "expect": expect, "status": status,
            "detail": works_text if seen_works else fails_text}


def run(firewall: str, *, outside_dns: str = "8.8.8.8", dns=dns_answers,
        time_fn=sntp, web=https_works, v6=ipv6_connects,
        only: tuple[str, ...] | None = None, lenient: bool = False) -> list[dict]:
    """Run the tests. `only` names the ones wanted (default: all).

    `lenient` is for test mode, where the internet is not required: a firewall that answers a name
    lookup or a time request, even without an answer from the outside, passes, and the web page test
    passes when it cannot open. Without it, every test is strict."""
    want = set(only) if only else None
    rows = []

    def on(test_id):
        return want is None or test_id in want

    if on("dns_firewall"):
        n = dns(firewall)
        row = _row("dns_firewall", "Names through the firewall", WORKS, bool(n),
                   "The firewall answered a name lookup.",
                   "The firewall did not answer a name lookup.")
        if lenient and not n and n is not None:
            row.update(status=GOOD, detail="The firewall answered, but had no outside answer. "
                                           "The internet is not needed in test mode.")
        rows.append(row)
    if on("time_firewall"):
        t = time_fn(firewall)
        synced = bool(t) and 1 <= t["stratum"] <= 15 and t["leap"] != 3
        row = _row("time_firewall", "Time from the firewall", WORKS, synced, "", "")
        if not t:
            row["detail"] = "The firewall did not answer a time request."
        elif not synced:
            row["detail"] = "The firewall answered, but says its own clock is not synced yet."
        else:
            row["detail"] = ("The firewall's clock is synced (stratum %d, about %.1f s from this device)."
                             % (t["stratum"], abs(t["offset"])))
        if lenient and t and not synced:
            row.update(status=GOOD, detail="The firewall answered, but its clock is not synced yet. "
                                           "The internet is not needed in test mode.")
        rows.append(row)
    if on("dns_outside"):
        n = dns(outside_dns)
        rows.append(_row("dns_outside", "An outside name server is unreachable", FAILS, bool(n),
                         f"{outside_dns} answered, so devices can skip the firewall's DNS.",
                         f"{outside_dns} did not answer, as it should not."))
    if on("web"):
        row = _row("web", "A web page opens", WORKS, web(),
                   "A secure web page opened.", "A secure web page did not open.")
        if lenient and row["status"] != GOOD:
            row.update(status=GOOD, detail="No web page opened. The internet is not needed in test mode.")
        rows.append(row)
    if on("no_ipv6"):
        rows.append(_row("no_ipv6", "No IPv6", FAILS, v6(),
                         "An IPv6 connection went through.", "No IPv6 connection, as it should be."))
    return rows
