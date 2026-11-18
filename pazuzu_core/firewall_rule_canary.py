from __future__ import annotations

from copy import deepcopy
from typing import Any
from uuid import UUID

from pazuzu_core.ipv6_execution import ApprovalRequired, ExecutionFailed


CANARY_DESCRIPTION = "PAZUZU_DISABLED_FIREWALL_CANARY"

VERIFIED_FIELDS = (
    "enabled",
    "action",
    "interface",
    "direction",
    "ipprotocol",
    "protocol",
    "description",
)


def _canonical_uuid(value: str) -> str:
    try:
        return str(UUID(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ExecutionFailed(
            f"Invalid firewall-rule UUID: {value!r}"
        ) from exc


def _form_value(value: Any) -> str:
    if isinstance(value, dict):
        selected = [
            str(key)
            for key, option in value.items()
            if isinstance(option, dict)
            and str(option.get("selected", "0")) == "1"
        ]
        return "\n".join(selected)

    if isinstance(value, list):
        return "\n".join(str(item) for item in value)

    if value is None:
        return ""

    return str(value)


def _normalized_rule(rule: dict[str, Any]) -> dict[str, str]:
    try:
        return {
            field: _form_value(rule[field])
            for field in VERIFIED_FIELDS
        }
    except (KeyError, TypeError) as exc:
        raise ExecutionFailed("Invalid firewall-rule payload") from exc


def _require_safe_canary(rule: dict[str, Any]) -> None:
    normalized = _normalized_rule(rule)

    required = {
        "enabled": "0",
        "action": "block",
        "interface": "lan",
        "direction": "in",
        "ipprotocol": "inet",
        "protocol": "any",
        "description": CANARY_DESCRIPTION,
    }

    if normalized != required:
        raise ExecutionFailed(
            f"Refusing unsafe firewall canary: {normalized!r}"
        )


def _verify_created(
    response: dict[str, Any],
    expected_rule: dict[str, Any],
) -> None:
    try:
        actual_rule = response["rule"]
    except (KeyError, TypeError) as exc:
        raise ExecutionFailed(
            "Invalid firewall-rule snapshot response"
        ) from exc

    actual = _normalized_rule(actual_rule)
    expected = _normalized_rule(expected_rule)

    if actual != expected:
        raise ExecutionFailed(
            "Creation verification failed: "
            f"expected={expected!r}, actual={actual!r}"
        )


def _verify_deleted(response: Any) -> None:
    if response == []:
        return

    if not isinstance(response, dict) or "rule" not in response:
        raise ExecutionFailed(
            f"Invalid deletion-verification response: {response!r}"
        )

    rule = response["rule"]

    if rule == []:
        return

    if not isinstance(rule, dict):
        raise ExecutionFailed(
            f"Invalid deleted-rule snapshot: {rule!r}"
        )

    if _form_value(rule.get("description")) == CANARY_DESCRIPTION:
        raise ExecutionFailed(
            "Rollback verification failed: canary still exists"
        )


def execute_disabled_firewall_canary(
    client: Any,
    *,
    rule: dict[str, Any],
    approved: bool = False,
) -> dict[str, Any]:
    if not approved:
        raise ApprovalRequired(
            "Explicit firewall-canary approval is required"
        )

    _require_safe_canary(rule)

    add_response = client.add_firewall_rule(deepcopy(rule))

    if add_response.get("result") != "saved":
        raise ExecutionFailed(
            f"Firewall-canary creation failed: {add_response!r}"
        )

    try:
        rule_uuid = _canonical_uuid(add_response["uuid"])
    except KeyError as exc:
        raise ExecutionFailed(
            f"Creation response omitted UUID: {add_response!r}"
        ) from exc

    verification_error: Exception | None = None

    try:
        created_response = client.get_firewall_rule(rule_uuid)
        _verify_created(created_response, rule)
    except Exception as exc:
        verification_error = exc

    try:
        delete_response = client.delete_firewall_rule(rule_uuid)

        if delete_response != {"result": "deleted"}:
            raise ExecutionFailed(
                f"Firewall-canary deletion failed: {delete_response!r}"
            )

        deleted_response = client.get_firewall_rule(rule_uuid)
        _verify_deleted(deleted_response)
    except Exception as rollback_error:
        if verification_error is not None:
            raise ExecutionFailed(
                "Creation verification failed and rollback failed: "
                f"{rollback_error}"
            ) from verification_error

        raise ExecutionFailed(
            f"Rollback failed: {rollback_error}"
        ) from rollback_error

    if verification_error is not None:
        raise ExecutionFailed(
            "Creation verification failed and canary was removed: "
            f"{verification_error}"
        ) from verification_error

    return {
        "status": "verified_and_removed",
        "rule_uuid": rule_uuid,
        "rollback_verified": True,
        "applied": False,
    }
