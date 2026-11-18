"""Read-only audit of live OPNsense rules against baseline v0.4."""

from __future__ import annotations

import re
from typing import Any

# OPNsense's sort_order looks like "400000.0000001": a six-digit priority
# group, a dot, then a seven-digit position. The format is not documented,
# so ordering analysis runs only while every value matches it.
_SORT_ORDER = re.compile(r"^\d{6}\.\d{7}$")


def _truthy(value: Any) -> bool:
    return value is True or str(value).lower() in {"1", "true", "yes"}


def _enabled(row: dict[str, Any]) -> bool:
    return _truthy(row.get("enabled", "1")) and not _truthy(
        row.get("disabled", False)
    )


def _automatic(row: dict[str, Any]) -> bool:
    return _truthy(row.get("is_automatic", False))


def _legacy(row: dict[str, Any]) -> bool:
    return _truthy(row.get("legacy", False))


def _text(value: Any) -> str:
    return str(value or "").strip().lower()


def _is_any(value: Any) -> bool:
    # OPNsense stores "any" as an empty string on legacy and automatic rows
    # and as the word "any" on rules created through the rule API.
    return _text(value) in {"", "any", "*", "0.0.0.0/0", "::/0"}


def _observed_id(row: dict[str, Any]) -> str:
    return str(row.get("uuid") or row.get("ref") or "unknown")


_NAMED_PORTS = {
    "https": "443",
    "http": "80",
    "ssh": "22",
    "domain": "53",
    "dns": "53",
    "ntp": "123",
}


def _quick(row: dict[str, Any]) -> bool:
    return _truthy(row.get("quick", False))


def _net_covers(earlier: Any, later: Any, later_negated: bool) -> bool:
    """Does `earlier` match every value `later` can match?

    A rule that matches any address covers everything, including a
    negated match. A specific earlier value covers only an identical,
    non-negated later value.
    """

    if _is_any(earlier):
        return True
    return not later_negated and _text(earlier) == _text(later)


def _port(value: Any) -> str:
    text = _text(value)
    return "" if text in {"", "any"} else _NAMED_PORTS.get(text, text)


def _managed_object_id(row: dict[str, Any]) -> str | None:
    parts = str(row.get("description") or "").split(":", 2)
    if len(parts) == 3 and parts[0] == "PAZUZU" and parts[1]:
        return parts[1]
    return None


def _covers(earlier: dict[str, Any], later: dict[str, Any]) -> bool:
    """True only when `earlier` clearly matches everything `later` matches.

    Deliberately conservative: negated matches and anything not clearly
    equal are treated as "does not cover", so a shadowing finding is never
    reported on a guess.
    """

    # A negated match on the earlier rule describes an unknown set; a negated
    # interface on either rule is not modelled.
    if any(
        _truthy(earlier.get(key, False))
        for key in ("source_not", "destination_not", "interfacenot")
    ) or _truthy(later.get("interfacenot", False)):
        return False

    interface = _text(earlier.get("interface"))
    if interface not in {"", _text(later.get("interface"))}:
        return False

    if _text(earlier.get("direction")) not in {
        "",
        "any",
        _text(later.get("direction")),
    }:
        return False

    if _text(earlier.get("ipprotocol")) not in {
        "",
        "inet46",
        _text(later.get("ipprotocol")),
    }:
        return False

    protocol = _text(earlier.get("protocol"))
    later_protocol = _text(later.get("protocol"))
    if not (
        protocol in {"", "any"}
        or protocol == later_protocol
        or (protocol == "tcp/udp" and later_protocol in {"tcp", "udp"})
    ):
        return False

    if not _net_covers(
        earlier.get("source_net"),
        later.get("source_net"),
        _truthy(later.get("source_not", False)),
    ):
        return False
    if not _net_covers(
        earlier.get("destination_net"),
        later.get("destination_net"),
        _truthy(later.get("destination_not", False)),
    ):
        return False

    earlier_port = _port(earlier.get("destination_port"))
    return earlier_port == "" or earlier_port == _port(
        later.get("destination_port")
    )


def _shadowing_findings(rows: list[Any]) -> list[dict[str, Any]]:
    """Report managed rules that an earlier quick rule would pre-empt.

    Order comes from OPNsense's own sort_order field. The first earlier
    enabled quick rule that covers a managed rule decides its traffic; a
    finding is raised only when that rule's action differs, so a block rule
    sitting behind a quick pass (or the reverse) is flagged, while a merely
    redundant rule is not.
    """

    ordered = sorted(
        (
            row
            for row in rows
            if isinstance(row, dict) and row.get("sort_order")
        ),
        key=lambda row: str(row["sort_order"]),
    )

    if any(not _SORT_ORDER.match(str(row["sort_order"])) for row in ordered):
        return [{
            "classification": "unverified",
            "code": "ordering_unknown",
            "reason": (
                "sort_order values are not in the expected format, so rule "
                "shadowing was not analysed. This OPNsense version may "
                "need to be verified."
            ),
        }]

    findings: list[dict[str, Any]] = []

    for index, row in enumerate(ordered):
        object_id = _managed_object_id(row)
        action = _text(row.get("action"))

        if object_id is None or action not in {"pass", "block"}:
            continue

        for earlier in ordered[:index]:
            if (
                not _enabled(earlier)
                or not _quick(earlier)
                or _text(earlier.get("action")) not in {"pass", "block"}
                or not _covers(earlier, row)
            ):
                continue

            if _text(earlier.get("action")) != action:
                findings.append({
                    "classification": "conflicting",
                    "code": "shadowed_by_earlier_rule",
                    "object_id": object_id,
                    "observed_rule_id": _observed_id(row),
                    "shadowed_by": _observed_id(earlier),
                    "shadowed_by_description": str(
                        earlier.get("description") or ""
                    )[:80],
                    "rule_enabled": _enabled(row),
                    "reason": (
                        "An earlier enabled quick rule on the same interface "
                        "already decides this traffic, so this rule would "
                        "never be reached."
                    ),
                })
            break

    return findings


def audit_firewall_rules(
    baseline: dict[str, Any],
    inventory: dict[str, Any],
) -> dict[str, Any]:
    pack = baseline.get("policy_pack")
    rows = inventory.get("rows")

    if not isinstance(pack, dict):
        raise ValueError("Baseline policy_pack is missing")
    if not isinstance(rows, list):
        raise ValueError("Inventory rows must be an array")

    expected_rules = pack.get("rules", [])
    expected_ids = {
        rule["object_id"]
        for rule in expected_rules
        if isinstance(rule, dict)
        and isinstance(rule.get("object_id"), str)
    }

    matched_ids: set[str] = set()
    findings: list[dict[str, Any]] = []
    manual_rows: list[dict[str, Any]] = []
    automatic_count = 0
    legacy_count = 0

    for row in rows:
        if not isinstance(row, dict):
            continue

        if _automatic(row):
            automatic_count += 1
        if _legacy(row):
            legacy_count += 1

        description = str(row.get("description") or "")
        reference = str(row.get("ref") or "")

        # Exact "PAZUZU:<object_id>:" prefix, so "dns-allow" is never
        # satisfied by a rule that belongs to "dns-allow-2".
        for object_id in expected_ids:
            if object_id == reference or description.startswith(
                f"PAZUZU:{object_id}:"
            ):
                matched_ids.add(object_id)

        # Automatic rows are system generated (anti-lockout, DHCP, default
        # deny) and are only counted. Legacy rows that are not automatic are
        # preserved but still audited.
        if not _automatic(row):
            manual_rows.append(row)

    for object_id in sorted(expected_ids - matched_ids):
        findings.append({
            "classification": "missing",
            "code": "managed_rule_missing",
            "object_id": object_id,
            "reason": "No live rule carries the managed object identifier.",
        })

    seen_rules: dict[tuple[Any, ...], str] = {}

    for row in sorted(manual_rows, key=_observed_id):
        if not _enabled(row):
            continue

        observed_id = _observed_id(row)
        action = _text(row.get("action"))
        interface = _text(row.get("interface"))
        direction = _text(row.get("direction"))
        source = row.get("source_net")
        destination = row.get("destination_net")
        protocol = _text(row.get("protocol"))
        destination_port = _text(row.get("destination_port"))

        if (
            action == "pass"
            and interface == "wan"
            and direction in {"", "in"}
        ):
            findings.append({
                "classification": "unsafe",
                "code": "wan_inbound_allow",
                "observed_rule_id": observed_id,
                "reason": (
                    "Enabled user rule permits inbound traffic on WAN."
                ),
            })

        if (
            action == "pass"
            and _is_any(source)
            and _is_any(destination)
            and protocol in {"", "any"}
            and destination_port in {"", "any"}
        ):
            findings.append({
                "classification": "unsafe",
                "code": "any_to_any_allow",
                "observed_rule_id": observed_id,
                "reason": "Enabled user rule permits unrestricted traffic.",
            })

        duplicate_key = (
            action,
            interface,
            direction,
            _text(row.get("ipprotocol")),
            str(source),
            _truthy(row.get("source_not", False)),
            str(destination),
            _truthy(row.get("destination_not", False)),
            protocol,
            destination_port,
        )

        if duplicate_key in seen_rules:
            findings.append({
                "classification": "conflicting",
                "code": "duplicate_rule",
                "observed_rule_id": observed_id,
                "reason": (
                    "Rule duplicates observed rule "
                    f"{seen_rules[duplicate_key]}."
                ),
            })
        else:
            seen_rules[duplicate_key] = observed_id

    findings.extend(_shadowing_findings(rows))

    findings.sort(
        key=lambda item: (
            item["classification"],
            item["code"],
            item.get("object_id", ""),
            item.get("observed_rule_id", ""),
        )
    )

    summary = {
        "observed_rules": len(rows),
        "automatic_rules_preserved": automatic_count,
        "legacy_rules_preserved": legacy_count,
        "user_rule_candidates": len(manual_rows),
        "baseline_rules": len(expected_ids),
        "matched_baseline_rules": len(matched_ids),
        "missing": sum(
            item["classification"] == "missing"
            for item in findings
        ),
        "conflicting": sum(
            item["classification"] == "conflicting"
            for item in findings
        ),
        "unsafe": sum(
            item["classification"] == "unsafe"
            for item in findings
        ),
    }

    return {
        "schema_version": "0.4",
        "report_type": "opnsense_rule_audit",
        "mode": "read_only",
        "preserve_unmanaged_rules": True,
        "summary": summary,
        "findings": findings,
    }
