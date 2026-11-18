"""Tighten the baseline's service groups to the strict outbound decisions.

Decisions (2026-10-06):
  * QUIC (udp/443) is dropped from the baseline: browsers fall back to TCP.
  * Clients do not reach NTP servers on the internet (udp/123): they use the
    firewall's own time service, which firewall_core still allows.

So udp/443 leaves approved_outbound and approved_web, and udp/123 leaves
approved_outbound. firewall_core keeps udp/123: that is client-to-firewall.

Pure function: returns a changed copy and a list of what changed. Nothing
here touches a firewall.
"""

from __future__ import annotations

import copy
from typing import Any, Mapping

REMOVALS = {
    "approved_outbound": ("udp/443", "udp/123"),
    "approved_web": ("udp/443",),
}


def tighten(baseline: Mapping[str, Any]) -> tuple[dict[str, Any], list[str]]:
    from pazuzu_core.security_baseline_v0_4 import validate_baseline_v0_4

    if not isinstance(baseline, dict):
        raise ValueError("Baseline must be an object")
    result = copy.deepcopy(baseline)
    pack = result.get("policy_pack")
    groups = pack.get("service_groups") if isinstance(pack, dict) else None
    if not isinstance(groups, dict):
        raise ValueError("Baseline has no policy_pack.service_groups object")

    changes: list[str] = []
    for name, removals in REMOVALS.items():
        members = groups.get(name)
        if members is None:
            continue
        if not isinstance(members, list):
            raise ValueError(f"service_groups.{name} must be a list")
        kept = [m for m in members if m not in removals]
        if not kept:
            raise ValueError(f"service_groups.{name} would be left empty")
        for member in members:
            if member in removals:
                changes.append(f"remove {member} from {name}")
        groups[name] = kept

    if changes:
        problems = validate_baseline_v0_4(result)
        if problems:
            raise ValueError("Result would be invalid: " + "; ".join(problems))
    return result, changes
