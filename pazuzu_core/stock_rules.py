"""Find the stock and lifeline rules Pazuzu may later adopt. Read-only.

Pure functions over a rule inventory (the rows of search_rule). Nothing here
talks to a firewall or changes anything; it produces a plan that says what
adoption WOULD do, and whether it is safe to do yet.

Roles:
  stock_allow_v4 / stock_allow_v6   OPNsense's "Default allow LAN to any"
        rules. A rule is adoptable only if its description AND its shape
        match the stock rule exactly; a near miss (renamed, edited, or on
        another interface) is reported and left alone.
  lifeline_https / lifeline_ssh     floating quick passes to the firewall's
        own HTTPS / SSH. Matched by shape only (they have no description).
        They sit ahead of the managed blocks, so their source decides who
        can reach the firewall.

Adoption would never use a "PAZUZU:" description prefix on a stock rule:
that prefix marks rules Pazuzu created, and rollback deletes those. An
adopted stock rule carries DISABLED_NOTE as a suffix instead.

Addresses are never copied into the report: a source that is an address or
network is shown as "address or network (value withheld)".
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

DISABLED_NOTE = "[disabled by Pazuzu]"
MANAGED_PREFIX = "PAZUZU:"

STOCK = {
    "Default allow LAN to any rule": ("stock_allow_v4", "inet"),
    "Default allow LAN IPv6 to any rule": ("stock_allow_v6", "inet6"),
}
LIFELINE = {
    "lifeline_https": frozenset({"443", "https"}),
    "lifeline_ssh": frozenset({"22", "ssh"}),
}
ROLES = ("stock_allow_v4", "stock_allow_v6", "lifeline_https", "lifeline_ssh")

_ADDRESS = re.compile(r"^[0-9a-fA-F:.]+(/\d{1,3})?$")


def _flag(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes"}


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip().lower()


def _is_address(token: str) -> bool:
    return bool(_ADDRESS.match(token)) and any(
        c.isdigit() or c == ":" for c in token
    )


def describe_source(value: Any) -> str:
    """Describe a source without copying any address out of it."""

    text = "" if value is None else str(value).strip()
    if not text:
        return "any (empty)"
    if text.lower() in {"any", "*"}:
        return "any"
    return ",".join(
        "address or network (value withheld)" if _is_address(t) else t
        for t in (part.strip() for part in text.split(","))
        if t
    )


def _is_editable(row: Mapping[str, Any]) -> list[str]:
    problems = []
    if not row.get("uuid"):
        problems.append("no uuid")
    if _flag(row.get("legacy")) or _flag(row.get("is_automatic")):
        problems.append("automatic/legacy rule, not editable through the rule API")
    return problems


def _stock_mismatches(row: Mapping[str, Any], ipprotocol: str) -> list[str]:
    checks = {
        "interface": _text(row.get("interface")) == "lan",
        "direction": _text(row.get("direction")) == "in",
        "action": _text(row.get("action")) == "pass",
        "ipprotocol": _text(row.get("ipprotocol")) == ipprotocol,
        "protocol": _text(row.get("protocol")) in {"", "any"},
        "source_net": _text(row.get("source_net")) == "lan",
        "destination_net": _text(row.get("destination_net")) in {"", "any"},
        "destination_port": _text(row.get("destination_port")) in {"", "any"},
        "source_not": not _flag(row.get("source_not")),
        "destination_not": not _flag(row.get("destination_not")),
        "quick": _flag(row.get("quick")),
    }
    return [name for name, ok in checks.items() if not ok]


def _lifeline_role(row: Mapping[str, Any]) -> str | None:
    if str(row.get("description") or "").startswith(MANAGED_PREFIX):
        return None
    if _text(row.get("interface")) != "":
        return None
    if _text(row.get("direction")) != "in" or _text(row.get("action")) != "pass":
        return None
    if not _flag(row.get("quick")) or _text(row.get("protocol")) != "tcp":
        return None
    if _text(row.get("destination_net")) != "(self)":
        return None
    if _flag(row.get("source_not")) or _flag(row.get("destination_not")):
        return None
    port = _text(row.get("destination_port"))
    for role, ports in LIFELINE.items():
        if port in ports:
            return role
    return None


def _entry(role: str, row: Mapping[str, Any], reasons: list[str]) -> dict[str, Any]:
    return {
        "role": role,
        "uuid": row.get("uuid"),
        "sort_order": row.get("sort_order"),
        "enabled": _flag(row.get("enabled")) and not _flag(row.get("disabled")),
        "source": describe_source(row.get("source_net")),
        "adoptable": not reasons,
        "reasons": reasons,
    }


def _lan_coverage(rows: Iterable[Mapping[str, Any]]) -> int:
    return sum(
        1
        for row in rows
        if str(row.get("description") or "").startswith(MANAGED_PREFIX)
        and _text(row.get("action")) == "pass"
        and _text(row.get("interface")) == "lan"
        and _flag(row.get("enabled"))
        and not _flag(row.get("disabled"))
    )


def detect_stock_rules(inventory: Mapping[str, Any]) -> dict[str, Any]:
    rows = inventory.get("rows")
    if not isinstance(rows, list):
        raise ValueError("Inventory rows must be an array")
    rows = [row for row in rows if isinstance(row, dict)]

    found: list[dict[str, Any]] = []
    near_misses: list[dict[str, Any]] = []
    already_disabled: list[str] = []

    for row in rows:
        description = str(row.get("description") or "")
        bare = description
        suffixed = bare.endswith(" " + DISABLED_NOTE)
        if suffixed:
            bare = bare[: -len(DISABLED_NOTE) - 1]

        if bare in STOCK:
            role, ipprotocol = STOCK[bare]
            if suffixed and not (_flag(row.get("enabled")) and not _flag(row.get("disabled"))):
                already_disabled.append(role)
            reasons = _is_editable(row)
            reasons += [
                f"{name} differs from the stock rule"
                for name in _stock_mismatches(row, ipprotocol)
            ]
            found.append(_entry(role, row, reasons))
            continue

        if "default allow" in description.lower() and not description.startswith(MANAGED_PREFIX):
            near_misses.append(
                {"uuid": row.get("uuid"), "description": description,
                 "reason": "description is not exactly a stock description"}
            )
            continue

        role = _lifeline_role(row)
        if role:
            found.append(_entry(role, row, _is_editable(row)))

    present = {item["role"] for item in found}
    absent = [role for role in ROLES if role not in present]
    coverage = _lan_coverage(rows)

    stock_live = [
        i for i in found
        if i["role"].startswith("stock_") and i["enabled"]
    ]
    blockers: list[str] = []
    if stock_live and coverage == 0:
        blockers.append(
            "no enabled Pazuzu allow rule on lan: disabling the stock allows "
            "would cut the LAN off"
        )
    for item in found:
        if not item["adoptable"]:
            blockers.append(f"{item['role']} {item['uuid']}: " + "; ".join(item["reasons"]))
    for item in near_misses:
        blockers.append(f"near miss left alone: {item['description']!r}")

    plan = []
    for item in found:
        if not item["adoptable"]:
            continue
        if item["role"].startswith("stock_"):
            if item["role"] in already_disabled:
                continue
            plan.append(f"{item['role']}: disable and append {DISABLED_NOTE!r} to its description")
        else:
            plan.append(f"{item['role']}: restrict source to management and VPN (now: {item['source']})")

    return {
        "mode": "read_only",
        "rules_seen": len(rows),
        "found": found,
        "absent": absent,
        "near_misses": near_misses,
        "already_disabled": sorted(already_disabled),
        "enabled_pazuzu_allows_on_lan": coverage,
        "plan": plan,
        "ready": bool(plan) and not blockers,
        "blockers": blockers,
    }
