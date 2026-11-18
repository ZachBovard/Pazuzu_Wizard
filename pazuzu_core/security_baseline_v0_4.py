"""Strict validation for the Alpha 0.4 OPNsense policy pack."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from pazuzu_core.posture import validate_admin_session_spec


REQUIRED_RULE_FIELDS = {
    "object_id",
    "object_type",
    "ownership",
    "schema_version",
    "name",
    "enabled",
    "priority",
    "direction",
    "source",
    "destination",
    "action",
    "services",
    "log",
}


TUNNEL_EXCEPTION_ID = "PZ-WG-002"
_ONE_UDP_PORT = re.compile(r"^udp/\d{1,5}$", re.IGNORECASE)


def _is_tunnel_port_exception(
    rule: dict[str, Any],
    pack: dict[str, Any],
    source_tokens: set[str],
    destination_tokens: set[str],
    service_tokens: set[str],
) -> bool:
    """The one inbound WAN allow there is: the VPN's own UDP port, to the firewall, and nothing else.

    It must be exactly PZ-WG-002, from the WAN only, to the firewall only, for the
    wireguard_tunnel group only, and that group must be a single UDP port. It must also
    be written as off: only VPN setup switches it on. Any other WAN allow stays an error.
    """

    if rule.get("object_id") != TUNNEL_EXCEPTION_ID or rule.get("enabled") is not False:
        return False
    if source_tokens != {"wan"} or destination_tokens != {"firewall"}:
        return False
    if service_tokens != {"wireguard_tunnel"}:
        return False
    members = (pack.get("service_groups") or {}).get("wireguard_tunnel")
    return (
        isinstance(members, list)
        and len(members) == 1
        and isinstance(members[0], str)
        and bool(_ONE_UDP_PORT.match(members[0].strip()))
    )


def validate_baseline_v0_4(document: Any) -> tuple[str, ...]:
    errors: list[str] = []

    if not isinstance(document, dict):
        return ("$: baseline must be an object",)

    if document.get("schema_version") != "0.4":
        errors.append("$.schema_version: must equal '0.4'")

    if document.get("enforcement_mode") != "plan_only":
        errors.append("$.enforcement_mode: must equal 'plan_only'")

    pack = document.get("policy_pack")
    if not isinstance(pack, dict):
        return tuple(sorted(errors + [
            "$.policy_pack: required object is missing"
        ]))

    if pack.get("mode") != "plan_only":
        errors.append("$.policy_pack.mode: must equal 'plan_only'")

    if pack.get("preserve_unmanaged_rules") is not True:
        errors.append(
            "$.policy_pack.preserve_unmanaged_rules: must be true"
        )

    if pack.get("adoption_required_before_modification") is not True:
        errors.append(
            "$.policy_pack.adoption_required_before_modification: "
            "must be true"
        )

    rules = pack.get("rules")
    if not isinstance(rules, list) or not rules:
        errors.append("$.policy_pack.rules: must be a non-empty array")
        return tuple(sorted(errors))

    identifiers: set[str] = set()
    priorities: set[int] = set()

    for index, rule in enumerate(rules):
        path = f"$.policy_pack.rules[{index}]"

        if not isinstance(rule, dict):
            errors.append(f"{path}: must be an object")
            continue

        unknown = set(rule) - REQUIRED_RULE_FIELDS
        missing = REQUIRED_RULE_FIELDS - set(rule)

        for field in sorted(unknown):
            errors.append(f"{path}.{field}: unknown field")

        for field in sorted(missing):
            errors.append(f"{path}.{field}: required field is missing")

        identifier = rule.get("object_id")
        if not isinstance(identifier, str) or not identifier:
            errors.append(f"{path}.object_id: non-empty string required")
        elif identifier in identifiers:
            errors.append(f"{path}.object_id: duplicate {identifier!r}")
        else:
            identifiers.add(identifier)

        priority = rule.get("priority")
        if type(priority) is not int:
            errors.append(f"{path}.priority: integer required")
        elif priority in priorities:
            errors.append(f"{path}.priority: duplicate {priority}")
        else:
            priorities.add(priority)

        if rule.get("object_type") != "firewall_rule":
            errors.append(f"{path}.object_type: must be 'firewall_rule'")

        if rule.get("ownership") != "pazuzu_managed":
            errors.append(f"{path}.ownership: must be 'pazuzu_managed'")

        if rule.get("schema_version") != "0.4":
            errors.append(f"{path}.schema_version: must equal '0.4'")

        if rule.get("action") not in {"allow", "deny", "reject"}:      # reject: BUILD 501, QUIC turned away at once
            errors.append(f"{path}.action: must be allow, deny or reject")

        source = rule.get("source", [])
        destination = rule.get("destination", [])
        services = rule.get("services", [])

        if not all(
            isinstance(value, list)
            for value in (source, destination, services)
        ):
            errors.append(
                f"{path}: source, destination and services must be arrays"
            )
            continue

        if not all(
            isinstance(token, str) and token.strip()
            for token in (*source, *destination, *services)
        ):
            errors.append(
                f"{path}: source, destination and services must contain "
                "only non-empty strings"
            )
            continue

        # Compare case-insensitively and ignoring padding, because the
        # translator does too: "WAN" must not slip past a check for "wan".
        source_tokens = {token.strip().lower() for token in source}
        destination_tokens = {token.strip().lower() for token in destination}
        service_tokens = {token.strip().lower() for token in services}

        if (
            rule.get("action") == "allow"
            and "any" in source_tokens
            and "any" in destination_tokens
            and "all" in service_tokens
        ):
            errors.append(f"{path}: any-to-any allow is prohibited")

        if (
            rule.get("action") == "allow"
            and "wan" in source_tokens
            and not _is_tunnel_port_exception(rule, pack, source_tokens,
                                              destination_tokens, service_tokens)
        ):
            errors.append(f"{path}: inbound WAN allow is prohibited")

    ipv6 = (
        pack.get("platform_controls", {})
        .get("ipv6", {})
    )

    if ipv6.get("policy") != "disabled":
        errors.append(
            "$.policy_pack.platform_controls.ipv6.policy: "
            "must remain disabled"
        )

    if ipv6.get("ula_generation") != "prohibited":
        errors.append(
            "$.policy_pack.platform_controls.ipv6.ula_generation: "
            "must be prohibited"
        )

    controls = pack.get("platform_controls", {})
    if isinstance(controls, dict) and "admin_session" in controls:
        errors.extend(validate_admin_session_spec(controls["admin_session"]))

    return tuple(sorted(errors))


def load_and_validate_baseline_v0_4(
    path: str | Path,
) -> tuple[str, ...]:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    return validate_baseline_v0_4(document)
