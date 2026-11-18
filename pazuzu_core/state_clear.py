"""When a block goes on, connections the firewall was already passing keep going: the firewall keeps a "state" for each
one and lets its packets through without looking at the rules again. So after a block is kept, the states it should
stop are cleared, and the next packet meets the rule.

Which ones: for each of Pazuzu's block rules that is switched on, the traffic it names (direct DNS: UDP/TCP 53 and TCP
853; QUIC: UDP 443) going anywhere but the firewall itself. Each state is read from the firewall's own state table
(Firewall, Diagnostics, States) and dropped one by one; nothing else is touched.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Callable, Iterable, Sequence

QUERY = "/api/diagnostics/firewall/query_states"
DROP = "/api/diagnostics/firewall/del_state/"
RULES = "/api/firewall/filter/search_rule?rowCount=-1&searchPhrase=PZ-"
MAX_DROP = 500

# Pazuzu's block rules (by the id in their description) and the traffic each stops: (protocol, port).
BLOCKS = {"PZ-DNS-010": (("udp", "53"), ("tcp", "53"), ("tcp", "853"))}
QUIC = (("udp", "443"),)
_ID = re.compile(r"^[0-9a-fA-F]{1,16}$")


def _on(row: dict) -> bool:
    return str(row.get("enabled", "1")) in ("1", "true", "True")


def wanted(rules: Iterable[dict]) -> list[tuple[str, str]]:
    """(protocol, port) pairs that switched-on Pazuzu block rules stop."""
    out: list[tuple[str, str]] = []
    for r in rules:
        if not isinstance(r, dict) or not _on(r):
            continue
        d = str(r.get("description") or "")
        if str(r.get("action") or "").lower() not in ("block", "reject"):
            continue
        for rid, pairs in BLOCKS.items():
            if rid in d:
                out += [p for p in pairs if p not in out]
        if "QUIC" in d.upper() and "PAZUZU" in d.upper():
            out += [p for p in QUIC if p not in out]
    return out


def _mine(addr: str, own: Sequence[str]) -> bool:
    return str(addr) in set(own)


def to_drop(rows: Iterable[dict], pairs: Sequence[tuple[str, str]], own: Sequence[str]) -> list[str]:
    """"id/creator" of each state that is one of `pairs` and does not go to the firewall's own address."""
    out = []
    for s in rows:
        if not isinstance(s, dict):
            continue
        proto = str(s.get("proto") or "").lower()
        port = str(s.get("dst_port") or "")
        if (proto, port) not in pairs or _mine(str(s.get("dst_addr") or ""), own):
            continue
        try:
            if not ipaddress.ip_address(str(s.get("dst_addr"))).is_global:
                continue                                    # inside the home: not what the block is for
        except ValueError:
            continue
        sid = str(s.get("id") or "")
        if sid.count("/") == 1 and all(_ID.match(x) for x in sid.split("/")) and sid not in out:
            out.append(sid)
    return out


def clear(req: Callable[..., Any], own: Sequence[str]) -> dict:
    """Read the switched-on block rules and the state table, drop what the blocks should stop. Returns
    {"pairs", "dropped", "failed"}. Raises nothing: a firewall that will not answer leaves things as they were."""
    try:
        rules = (req("get", RULES) or {}).get("rows") or []
    except Exception:
        return {"pairs": [], "dropped": 0, "failed": 0}
    pairs = wanted(rules)
    if not pairs:
        return {"pairs": [], "dropped": 0, "failed": 0}
    ids: list[str] = []
    for port in sorted({p for _proto, p in pairs}):
        try:
            got = req("post", QUERY, json={"current": 1, "rowCount": 2000, "searchPhrase": "0.0.0.0/0:" + port})
        except Exception:
            continue
        rows = got.get("rows") if isinstance(got, dict) else None
        for sid in to_drop(rows or [], pairs, own):
            if sid not in ids:
                ids.append(sid)
    dropped = failed = 0
    for sid in ids[:MAX_DROP]:
        state, creator = sid.split("/")
        try:
            req("post", DROP + state + "/" + creator, json={})
            dropped += 1
        except Exception:
            failed += 1
    return {"pairs": pairs, "dropped": dropped, "failed": failed}


def words(got: dict) -> str:
    if not got.get("dropped") and not got.get("failed"):
        return ""
    s = f"Cleared {got['dropped']} connection(s) that started before the block, so it holds for them too."
    if got.get("failed"):
        s += f" {got['failed']} could not be cleared; they end by themselves."
    return s
