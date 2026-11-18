"""Plan the staged turn-on of the baseline. Plan only: nothing is applied.

The order, each stage under the change guard's timer:

  0. lifeline        enable the allows to the firewall's own web GUI
                     (PZ-MGMT-001 management, -002 WireGuard)
  1. core_services   enable the DNS / DHCP / NTP allow (PZ-CORE-001)
  2. lan_check       a person (later, the app) checks from a LAN client
  3. outbound        enable the trusted outbound allow (PZ-TRUST-010), and the
                     smart-device and guest internet allows (PZ-IOT-010,
                     PZ-GUEST-010) where those networks are on this firewall
  3b. firewall_services  a person confirms what clients will depend on
  4. stock_disable   disable the stock allow-all rules and note why, then
                     run the window checks under the timer
  5. blocking        enable Pazuzu's own block/reject rules, last of all (only when
                     the firewall has any), under the same timer and checks

Why this order: each stage only ADDS safe allowance until stage 4, which
removes the stock rules. Stage 4 is the one that can cut the LAN off, so it
is blocked unless the Pazuzu allows it relies on will exist. Stage 5 then
switches the blocking rules on, once everything that must keep working has
been tested without the stock rules.

The steps this module produces are in the change guard's step format, with
the old value of everything they change, so the guard can undo them.

Pure functions over a rule inventory (the rows of search_rule). Addresses
are never copied into the plan.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

from pazuzu_core.change_guard import (
    DEFAULT_TIMEOUT_SECONDS, SET_DESCRIPTION, TOGGLE, GuardError, _check_step,
)
from pazuzu_core.stock_rules import DISABLED_NOTE, STOCK, detect_stock_rules

_MANAGED = re.compile(r"^PAZUZU:([A-Za-z0-9_-]+):")
DESCRIPTION_LIMIT = 255

LIFELINE_OBJECTS = ("PZ-MGMT-001", "PZ-MGMT-002")
# The tunnel's own UDP port. Without it the WireGuard admin rule has nothing to
# stand on once the stock allow rules are off, so it rides with the lifeline.
TUNNEL_OBJECT = "PZ-WG-001"
WIREGUARD_ADMIN_OBJECT = "PZ-MGMT-002"
CORE_OBJECT = "PZ-CORE-001"
OUTBOUND_OBJECT = "PZ-TRUST-010"
# The other networks' way out (web only, never towards your own networks). They are allows, so they go on with the
# allows, before the stock rules come off and the blocks go on. Optional: a network not mapped on this firewall has none.
# PZ-DNS-020 (OpenDNS) is left out on purpose: it is a timed allow the plugin switches on, never part of the plan.
OUTBOUND_EXTRA_OBJECTS = ("PZ-IOT-010", "PZ-GUEST-010", "PZ-IOT-005", "PZ-IOT-011",   # 005/011: smart devices may ping
                          "PZ-DMZ-010")                    # 0.6.24: the public servers' way out (it was missing)
BLOCK_ACTIONS = ("block", "reject")

# Settings no verified endpoint can read yet, so a person confirms them
# before the stock rules go. With the stock rules off, clients depend on
# these. (Later the app reads them and these become drift controls.)
FIREWALL_CHECKS = (
    "The firewall's own time service is running and synced to upstream servers",
    "DHCP on LAN and IoT hands out the firewall as the time server (NTP option)",
    "Router advertisements and the DHCPv6 server are off on LAN and IoT",
    "IPv6 configuration is 'none' on LAN and IoT, so clients get no IPv6 address",
)

# Run from a LAN client inside stage 4's window. Confirm only if every
# line behaves as written; silence undoes the change.
WINDOW_CHECKS = (
    "WORKS: nslookup example.com <firewall LAN address>",
    "FAILS: nslookup example.com 8.8.8.8 (an outside resolver must be unreachable)",
    "WORKS: ipconfig /release then ipconfig /renew",
    "WORKS: w32tm /resync",
    "WORKS: open an https website in a browser",
    "FAILS: curl -6 -m 5 https://example.com (no IPv6)",
)

# What a person checks from a LAN client after stage 1.
LAN_CHECKS = (
    "Resolve a name through the firewall: nslookup example.com <firewall LAN address>",
    "Renew the DHCP lease: ipconfig /release then ipconfig /renew",
    "Sync the clock: w32tm /resync",
)


def _on(row: Mapping[str, Any]) -> bool:
    enabled = str(row.get("enabled")).strip().lower() in {"1", "true", "yes"}
    disabled = str(row.get("disabled")).strip().lower() in {"1", "true", "yes"}
    return enabled and not disabled


def _object_rules(rows: list[dict[str, Any]], object_id: str) -> list[dict[str, Any]]:
    found = []
    for row in rows:
        match = _MANAGED.match(str(row.get("description") or ""))
        if match and match.group(1) == object_id:
            found.append(row)
    return found


def _enable_stage(
    stage_id: str, title: str, object_id: str, rows: list[dict[str, Any]],
    timeout: int, extra: tuple[str, ...] = (),
) -> dict[str, Any]:
    rules = _object_rules(rows, object_id)
    blockers: list[str] = []
    steps: list[dict[str, Any]] = []
    if not rules:
        blockers.append(
            f"{object_id} has no rules on the firewall: create them first "
            "(firewall_manifest_smoke apply, paused level)")
    for row in rules:
        if row.get("action") not in (None, "pass"):
            blockers.append(f"{object_id} rule {row.get('uuid')} is not a pass rule")
        if not row.get("uuid"):
            blockers.append(f"{object_id} has a rule without a uuid")
        elif not _on(row):
            steps.append({"kind": TOGGLE, "uuid": row["uuid"],
                          "before": False, "after": True})
    notes: list[str] = []
    for extra_id in extra:
        more = _object_rules(rows, extra_id)
        if not more:
            notes.append(f"{extra_id} is not on this firewall (its network is not mapped here)")
            continue
        for row in more:
            if row.get("action") not in (None, "pass"):
                blockers.append(f"{extra_id} rule {row.get('uuid')} is not a pass rule")
            elif not row.get("uuid"):
                blockers.append(f"{extra_id} has a rule without a uuid")
            elif not _on(row):
                steps.append({"kind": TOGGLE, "uuid": row["uuid"],
                              "before": False, "after": True})
    status = "done" if rules and not steps and not blockers else (
        "blocked" if blockers else "pending")
    out = {"id": stage_id, "title": title, "object": object_id,
           "rules_found": len(rules), "steps": steps,
           "timeout_seconds": timeout, "status": status, "blockers": blockers}
    if extra:
        out["also"] = list(extra)
        out["notes"] = notes
    return out


LAB_NOTE = ("Lab box: the way in is the firewall's own LAN lockout protection, "
            "not a management network or a VPN")


def _lifeline_stage(rows: list[dict[str, Any]], timeout: int,
                    lab: bool = False, way_in: str = "") -> dict[str, Any]:
    """Enable every lifeline allow that exists on the firewall.

    The lifeline is the management zone and the WireGuard subnet only, never
    the LAN. A rule whose zone is not mapped on this box was never created,
    so it is noted and skipped; at least one must exist, or there would be
    nothing to stand on.
    """
    steps: list[dict[str, Any]] = []
    blockers: list[str] = []
    notes: list[str] = []
    found = 0
    for object_id in LIFELINE_OBJECTS:
        rules = _object_rules(rows, object_id)
        if not rules:
            notes.append(f"{object_id} is not on this firewall (its zone is not mapped here)")
            continue
        for row in rules:
            found += 1
            if row.get("action") not in (None, "pass"):
                blockers.append(f"{object_id} rule {row.get('uuid')} is not a pass rule")
            if not row.get("uuid"):
                blockers.append(f"{object_id} has a rule without a uuid")
            elif not _on(row):
                steps.append({"kind": TOGGLE, "uuid": row["uuid"],
                              "before": False, "after": True})
    if not found and lab:
        notes.append(LAB_NOTE)
    elif not found and way_in:
        # BUILD 434: a way in that is not a lifeline rule still counts: a switched-on VPN instance on the firewall, or
        # a bonded Bluetooth door on a box that has one (prod, 31 Oct 2026: the VPN was up and the step still said
        # "no way in", so the person ticked the lab box to get past it)
        notes.append(f"no lifeline rule is on the firewall yet, but {way_in} is a way in, so this step can go on")
    elif not found:
        blockers.append(
            "no lifeline rule is on the firewall: neither the management zone "
            "nor the WireGuard zone is mapped to a port here, or the rules were "
            "not created yet (firewall_manifest_smoke apply, paused level)")

    tunnel_rules = _object_rules(rows, TUNNEL_OBJECT)
    if _object_rules(rows, WIREGUARD_ADMIN_OBJECT) and not tunnel_rules:
        blockers.append(
            f"{WIREGUARD_ADMIN_OBJECT} is on the firewall but {TUNNEL_OBJECT} "
            "is not: nothing would allow the tunnel's own port once the stock "
            "rules are off (firewall_manifest_smoke apply)")
    for row in tunnel_rules:
        if row.get("action") not in (None, "pass"):
            blockers.append(f"{TUNNEL_OBJECT} rule {row.get('uuid')} is not a pass rule")
        if not row.get("uuid"):
            blockers.append(f"{TUNNEL_OBJECT} has a rule without a uuid")
        elif not _on(row):
            steps.append({"kind": TOGGLE, "uuid": row["uuid"],
                          "before": False, "after": True})
    status = "done" if (found or lab or way_in) and not steps and not blockers else (
        "blocked" if blockers else "pending")
    return {"id": "lifeline",
            "title": "Keep the firewall's web GUI reachable",
            "rules_found": found, "steps": steps, "notes": notes,
            "timeout_seconds": timeout, "status": status, "blockers": blockers}


def _stock_stage(rows: list[dict[str, Any]], will_cover_lan: int,
                 timeout: int) -> dict[str, Any]:
    by_uuid = {r.get("uuid"): r for r in rows}
    report = detect_stock_rules({"rows": rows})
    steps: list[dict[str, Any]] = []
    blockers: list[str] = []
    stock = [i for i in report["found"] if i["role"].startswith("stock_")]
    if not stock:
        blockers.append("no stock allow rules found: nothing to disable")
    for item in stock:
        if not item["adoptable"]:
            blockers.append(
                f"{item['role']} {item['uuid']}: " + "; ".join(item["reasons"]))
            continue
        row = by_uuid[item["uuid"]]
        before_desc = str(row.get("description") or "")
        if _on(row):
            steps.append({"kind": TOGGLE, "uuid": item["uuid"],
                          "before": True, "after": False})
        if not before_desc.endswith(" " + DISABLED_NOTE):
            after_desc = f"{before_desc} {DISABLED_NOTE}"
            if len(after_desc) > DESCRIPTION_LIMIT:
                blockers.append(f"{item['role']}: description too long to annotate")
            else:
                steps.append({"kind": SET_DESCRIPTION, "uuid": item["uuid"],
                              "before": before_desc, "after": after_desc})
    if steps and will_cover_lan == 0:
        blockers.append(
            "after the earlier stages there would be no enabled Pazuzu allow "
            "on lan: disabling the stock allows would cut the LAN off")
    for item in report["near_misses"]:
        blockers.append(f"near miss left alone: {item['description']!r}")
    status = "done" if stock and not steps and not blockers else (
        "blocked" if blockers else "pending")
    return {"id": "stock_disable",
            "title": "Disable the stock allow-all rules and note why",
            "steps": steps, "timeout_seconds": timeout, "status": status,
            "blockers": blockers, "window_checks": list(WINDOW_CHECKS)}


def _blocking_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Pazuzu-managed rules that block or reject, however many objects they belong to."""
    return [r for r in rows
            if _MANAGED.match(str(r.get("description") or ""))
            and str(r.get("action") or "").strip().lower() in BLOCK_ACTIONS]


def _blocking_stage(rows: list[dict[str, Any]], timeout: int) -> dict[str, Any] | None:
    """Switch on Pazuzu's own blocking rules. None when the firewall has none (nothing to do, so no stage).

    It is last on purpose: an allow can be added and a stock rule removed with the way in kept open,
    but a block can only take away. It waits until the stock allow-all rules are off, so what the
    block rules stop is what the baseline means to stop."""
    found = _blocking_rows(rows)
    if not found:
        return None
    steps: list[dict[str, Any]] = []
    blockers: list[str] = []
    for row in found:
        if not row.get("uuid"):
            blockers.append("a blocking rule has no uuid")
        elif not _on(row):
            steps.append({"kind": TOGGLE, "uuid": row["uuid"], "before": False, "after": True})
    status = "done" if not steps and not blockers else ("blocked" if blockers else "pending")
    return {"id": "blocking", "title": "Switch on the blocking rules",
            "rules_found": len(found), "steps": steps,
            "timeout_seconds": timeout, "status": status, "blockers": blockers,
            "window_checks": list(WINDOW_CHECKS)}


def build_plan(inventory: Mapping[str, Any],
               timeout: int = DEFAULT_TIMEOUT_SECONDS,
               lab_lifeline: bool = False, way_in: str = "") -> dict[str, Any]:
    rows = inventory.get("rows")
    if not isinstance(rows, list):
        raise ValueError("Inventory rows must be an array")
    rows = [r for r in rows if isinstance(r, dict)]

    lifeline = _lifeline_stage(rows, timeout, lab_lifeline, way_in)
    core = _enable_stage("core_services", "Allow DNS, DHCP and NTP",
                         CORE_OBJECT, rows, timeout)
    outbound = _enable_stage("outbound", "Allow trusted outbound",
                             OUTBOUND_OBJECT, rows, timeout, extra=OUTBOUND_EXTRA_OBJECTS)
    lan_cover = sum(
        1 for r in _object_rules(rows, OUTBOUND_OBJECT)
        if str(r.get("interface") or "").lower() == "lan"
        and str(r.get("action") or "pass").lower() == "pass"
    )
    stock = _stock_stage(rows, lan_cover, timeout)

    stages = [
        lifeline,
        core,
        {"id": "lan_check", "title": "Check from a LAN client",
         "kind": "human_check", "checks": list(LAN_CHECKS),
         "status": "pending", "blockers": [], "steps": []},
        outbound,
        {"id": "firewall_services", "title": "Confirm the firewall services clients will depend on",
         "kind": "human_check", "checks": list(FIREWALL_CHECKS),
         "status": "pending", "blockers": [], "steps": []},
        stock,
    ]
    blocking = _blocking_stage(rows, timeout)
    if blocking is not None:
        stages.append(blocking)
    # Every step must be one the guard would accept, with its old value.
    for stage in stages:
        for raw in stage["steps"]:
            try:
                _check_step(raw)
            except GuardError as exc:  # pragma: no cover - defensive
                stage["blockers"].append(f"invalid step: {exc}")
                stage["status"] = "blocked"

    blockers = [f"{s['id']}: {b}" for s in stages for b in s["blockers"]]
    actionable = any(s["steps"] for s in stages)
    return {
        "mode": "plan_only",
        "rules_seen": len(rows),
        "stages": stages,
        "not_in_this_plan": [
            "Pazuzu deny rules are switched on by the last stage, 'blocking', when the firewall has any",
            "Management and VPN lifeline rules for zones not mapped on this firewall yet",
        ],
        "ready": actionable and not blockers,
        "blockers": blockers,
        "lab_lifeline": bool(lab_lifeline), "way_in": way_in,
    }


# --- the shields: only reads here; the change itself lives in staged_executor
def our_disabled_stock(inventory: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Rows of the stock allow-all rules that Pazuzu itself switched off (they carry
    its note). Nothing else is ever touched by the shield or the pause."""

    rows = inventory.get("rows")
    if not isinstance(rows, list):
        raise ValueError("Inventory rows must be an array")
    suffix = " " + DISABLED_NOTE
    found = []
    for r in rows:
        if not isinstance(r, dict) or not r.get("uuid"):
            continue
        desc = str(r.get("description") or "")
        if desc.endswith(suffix) and desc[:-len(suffix)] in STOCK:
            found.append(r)
    return found


def shield_level(inventory: Mapping[str, Any]) -> dict[str, Any]:
    """"on" (they are off, so the shields are up), "off" (any is back on), or "na"
    (Pazuzu has not switched any off, so there is nothing to lower)."""

    try:
        rows = our_disabled_stock(inventory)
    except ValueError:
        return {"level": "na", "rules": 0}
    if not rows:
        return {"level": "na", "rules": 0}
    down = any(_on(r) for r in rows)
    return {"level": "off" if down else "on", "rules": len(rows)}


def blocker_kind(text: str) -> str:
    """What sort of fix a blocker needs, so a screen can offer the fix instead of the sentence:
    "way_in" (pick a management port), "create_rules" (the rules are not on the firewall yet),
    "wait" (it opens up after the stages before it), or "other"."""

    low = str(text).lower()
    if "no lifeline rule" in low:
        return "way_in"
    if "has no rules on the firewall" in low:
        return "create_rules"
    if "no enabled pazuzu allow" in low:
        return "wait"
    return "other"
