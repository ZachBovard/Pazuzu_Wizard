"""Live numbers for the manager's Data tab, read through the firewall's own API.

No plugin is needed for this. It reads, never writes. Anything the API does not
give, or the account may not read, is listed in `notes` instead of guessed.
The endpoint shapes are from the OPNsense documentation and not yet proven on
26.7, so every field is read defensively.
"""
from __future__ import annotations

import time
from collections import deque
from typing import Any, Callable

try:
    from hanbi_box.rulenames import plain_name
except ImportError:                      # BUILD 513: the public beta 1 build has no plugin; a rule keeps its own words
    def plain_name(text) -> str:
        return " ".join(str(text or "").split())[:80]

HISTORY = 60
CACHE_SECONDS = 3
DNS_CACHE_SECONDS = 30
DNS_WINDOW_SECONDS = 86400    # the ad and tracker count is shown for the last 24 hours, rolling (BUILD 428)
DNS_TOTALS_PATH = "/api/unbound/overview/totals/10"


def _num(v) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def parse_memory(data: Any) -> dict | None:
    mem = data.get("memory") if isinstance(data, dict) else None
    if not isinstance(mem, dict):
        return None
    total, used = _num(mem.get("total")), _num(mem.get("used"))
    if not total or used is None:
        return None
    return {"total": int(total), "used": int(used), "pct": round(100.0 * used / total, 1)}


def parse_load(data: Any) -> list[float] | None:
    text = str((data or {}).get("loadavg", "")) if isinstance(data, dict) else ""
    vals = [_num(x) for x in text.replace(",", " ").split()]
    return [v for v in vals if v is not None][:3] or None


def parse_traffic(data: Any) -> dict[str, tuple[str, float, float]]:
    """device -> (name, bytes in, bytes out)."""
    out = {}
    ifs = data.get("interfaces") if isinstance(data, dict) else None
    for key, row in (ifs.items() if isinstance(ifs, dict) else []):
        if not isinstance(row, dict):
            continue
        rx, tx = _num(row.get("bytes received")), _num(row.get("bytes transmitted"))
        dev = str(row.get("device") or key)
        if rx is not None and tx is not None:
            out[dev] = (str(row.get("name") or key), rx, tx)
    return out


def _addr(entry: Any) -> str:
    """One address as text. The firewall may give a plain string or a small record."""
    if isinstance(entry, dict):
        entry = entry.get("ipaddr") or entry.get("address") or ""
    return str(entry).split("/")[0]


def parse_overview(data: Any) -> dict[str, dict]:
    out = {}
    rows = data.get("rows") if isinstance(data, dict) else None
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict) or not row.get("device"):
            continue
        addrs = [_addr(a) for a in (row.get("ipv4") or []) if a]
        out[str(row["device"])] = {"status": str(row.get("status") or ""), "addrs": [x for x in addrs if x],
                                   "name": str(row.get("description") or row.get("identifier") or "")}
    return out


CRITICAL = {"unbound": "DNS", "dnsmasq": "DNS", "ntpd": "Time", "chronyd": "Time",
            "dhcpd": "DHCP", "kea_dhcp4": "DHCP", "lighttpd": "Web page", "nginx": "Web page",
            "configd": "Settings service", "syslog-ng": "System log"}


def parse_services(data: Any) -> tuple[list[dict], dict] | None:
    """The firewall's own service list, as the box feed shows services."""
    rows = data.get("rows") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        return None
    seen: dict[str, dict] = {}
    for r in rows:
        if not isinstance(r, dict):
            continue
        key = str(r.get("id") or r.get("name") or "").lower()
        label = CRITICAL.get(key)
        up = str(r.get("running")).lower() in {"1", "true"}
        if label:
            cur = seen.setdefault(label, {"name": label, "up": False, "critical": True})
            cur["up"] = cur["up"] or up
    out = list(seen.values())
    if not out:
        return None
    return out, {"up": sum(1 for x in out if x["up"]), "total": len(out)}


def parse_arp_rows(data: Any) -> list[dict]:
    rows = data.get("rows") if isinstance(data, dict) else data
    out = []
    for r in rows if isinstance(rows, list) else []:
        if isinstance(r, dict) and r.get("ip"):
            out.append({"ip": str(r["ip"]), "mac": str(r.get("mac") or "").lower(),
                        "iface": str(r.get("intf") or r.get("intf_description") or ""),
                        "name": str(r.get("hostname") or "")})
    return out


def parse_log(data: Any, limit: int = 50) -> list[dict]:
    rows = data if isinstance(data, list) else (data.get("rows") if isinstance(data, dict) else [])
    out = []
    for r in rows if isinstance(rows, list) else []:
        if not isinstance(r, dict) or str(r.get("action", "")).lower() != "block":
            continue
        out.append({"time": str(r.get("__timestamp__") or r.get("timestamp") or ""),
                    "iface": str(r.get("interface") or r.get("interface_name") or ""),
                    "proto": str(r.get("protoname") or r.get("proto") or ""),
                    "src": str(r.get("src") or ""), "sport": str(r.get("srcport") or ""),
                    "dst": str(r.get("dst") or ""), "dport": str(r.get("dstport") or ""),
                    "tracker": str(r.get("tracker") or r.get("rid") or "")[:12],
                    "rule_name": plain_name(r.get("label") or r.get("descr") or "")})
    return out[-limit:]


def parse_dns_totals(data: Any) -> dict | None:
    """The DNS server's own totals (its Reporting page): lookups answered and lookups blocked by the blocklist.
    None when the reply is not in that shape, which is also what a firewall with statistics turned off gives."""
    if not isinstance(data, dict):
        return None

    def num(v):
        if isinstance(v, dict):
            v = v.get("total")
        if isinstance(v, bool):
            return None
        try:
            return int(v)
        except (TypeError, ValueError):
            return None
    total, blocked = num(data.get("total")), num(data.get("blocked"))
    if total is None or blocked is None or total < 0 or blocked < 0:
        return None
    return {"total": total, "blocked": blocked,
            "pct": round(100.0 * blocked / total, 2) if total > 0 else None,
            "blocklist_size": num(data.get("blocklist_size"))}


class ApiFeed:
    def __init__(self, getter: Callable[[str], Any], clock: Callable[[], float] = time.time, dns_state: str | None = None):
        from hanbi_box import dns_stats as ds
        self.get, self.clock = getter, clock
        self._ds, self._dns_state, self._dns_saved = ds, dns_state, 0.0
        self._last: tuple[float, dict] | None = None
        self._bytes: dict[str, tuple[float, float, float]] = {}
        self._hist: dict[str, deque] = {}
        self._seen_clients: dict[str, dict] = {}
        self._dns: tuple[float, dict] | None = None
        # (time, total, blocked): running totals, to take the last 24 hours from; kept on disk when dns_state is given
        # (BUILD 475: in memory only, each manager start began the window again)
        self._dns_hist: deque = ds.load_hist(dns_state, clock(), DNS_WINDOW_SECONDS)

    def _try(self, path: str, label: str, notes: list[str]):
        try:
            return self.get(path)
        except Exception as exc:
            text = str(exc)
            why = "this account may not read it" if ("403" in text or "401" in text) else type(exc).__name__
            notes.append(f"{label}: {why}")
            return None

    def dns_status(self) -> dict:
        """Lookups blocked by the DNS blocklist, from the firewall's API. Always a dict; `unavailable` when it
        could not be read (statistics off, or this account may not read them)."""
        now = self.clock()
        if self._dns and now - self._dns[0] < DNS_CACHE_SECONDS:
            return self._dns[1]
        notes: list[str] = []
        got = parse_dns_totals(self._try(DNS_TOTALS_PATH, "ad and tracker lookups", notes))
        out = got or {"unavailable": True, "why": notes[0] if notes else "no counts yet; statistics may be off"}
        if got:
            out = {**got, **self._dns_window(now, got)}
        self._dns = (now, out)
        return out

    def _dns_window(self, now: float, got: dict) -> dict:
        """The firewall only gives running totals, so the last hour is the difference from a reading about an hour ago.
        Until there is a reading to compare with, nothing is claimed (window_s is None). Totals that go down mean the
        counters were reset, so the old readings are dropped."""
        hist = self._dns_hist
        if hist and (got["total"] < hist[-1][1] or got["blocked"] < hist[-1][2]):
            hist.clear()
        hist.append((now, got["total"], got["blocked"]))
        self._ds.thin(hist)
        while len(hist) > 2 and now - hist[1][0] >= DNS_WINDOW_SECONDS:
            hist.popleft()                    # keep the newest reading that is at least a day old as the start
        if self._dns_state and now - self._dns_saved >= self._ds.SAVE_EVERY:
            self._ds.save_hist(self._dns_state, hist)
            self._dns_saved = now
        base = hist[0]
        span = now - base[0]
        if span < DNS_CACHE_SECONDS:
            return {"window_s": None, "blocked_win": None, "total_win": None, "pct_win": None}
        total_win, blocked_win = got["total"] - base[1], got["blocked"] - base[2]
        return {"window_s": int(min(span, DNS_WINDOW_SECONDS)), "total_win": total_win, "blocked_win": blocked_win,
                "pct_win": round(100.0 * blocked_win / total_win, 2) if total_win > 0 else 0.0}

    def sample(self) -> dict:
        now = self.clock()
        if self._last and now - self._last[0] < CACHE_SECONDS:
            return self._last[1]
        notes: list[str] = []
        mem = parse_memory(self._try("/api/diagnostics/system/systemResources", "memory", notes))
        load = parse_load(self._try("/api/diagnostics/system/systemTime", "load", notes))
        traffic = parse_traffic(self._try("/api/diagnostics/traffic/interface", "traffic", notes))
        info = parse_overview(self._try("/api/interfaces/overview/interfaces_info/true", "ports", notes))
        blocks = parse_log(self._try("/api/diagnostics/firewall/log?limit=200", "blocks", notes))
        svc = parse_services(self._try("/api/core/service/search", "services", notes))
        arp = parse_arp_rows(self._try("/api/diagnostics/interface/search_arp", "devices", notes))
        here = {a["mac"] or a["ip"] for a in arp}
        for a in arp:
            self._seen_clients.setdefault(a["mac"] or a["ip"], {"beat": deque(maxlen=HISTORY)}).update(a)
        clients = []
        for key, c in self._seen_clients.items():
            c["beat"].append(1 if key in here else 0)
            clients.append({"mac": c["mac"], "ip": c["ip"], "iface": c["iface"], "name": c["name"],
                            "here": key in here, "age_s": None, "first_seen": now, "beat": list(c["beat"])})
        ifaces = []
        for dev in sorted(set(traffic) | set(info)):
            rx = tx = None
            if dev in traffic:
                _n, inb, outb = traffic[dev]
                prev = self._bytes.get(dev)
                if prev and now > prev[2] and inb >= prev[0] and outb >= prev[1]:
                    rx, tx = (inb - prev[0]) / (now - prev[2]), (outb - prev[1]) / (now - prev[2])
                self._bytes[dev] = (inb, outb, now)
            h = self._hist.setdefault(dev, deque(maxlen=HISTORY))
            h.append(rx or 0.0)
            i = info.get(dev, {})
            ifaces.append({"name": dev, "label": i.get("name", ""), "status": i.get("status") or "?",
                           "addrs": i.get("addrs", []), "rx_bps": rx, "tx_bps": tx,
                           "rx_hist": list(h), "tx_hist": []})
        notes.append("CPU, block share, top blocked and temperatures need the box plugin")
        status = {"version": 1, "time": now, "host": "your firewall (through its API)",
                  "uptime_s": None, "load": load, "cpu_pct": None, "cpu_hist": [], "mem": mem,
                  "ifaces": ifaces, "pf": {"enabled": None, "states": None},
                  "blocks": blocks, "blocks_total_seen": len(blocks),
                  "services": svc[0] if svc else None, "critical": svc[1] if svc else None,
                  "clients": clients or None,
                  "zenarmor": {"installed": False, "packages": [], "engine_running": None,
                               "data": "not read yet"},
                  "notes": notes, "via": "api", "dns": self.dns_status()}
        self._last = (now, status)
        return status
