from __future__ import annotations

from copy import deepcopy
from typing import Any
from uuid import UUID

from pazuzu_core.ipv6_execution import ApprovalRequired, ExecutionFailed


CANARY_ALIAS_NAME = "PAZUZU_ROLLBACK_CANARY"

WRITABLE_ALIAS_FIELDS = (
    "enabled",
    "name",
    "type",
    "content",
    "description",
    "counters",
    "updatefreq",
    "interface",
    "proto",
    "categories",
)


def _canonical_uuid(value: str) -> str:
    try:
        return str(UUID(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ExecutionFailed(f"Invalid alias UUID: {value!r}") from exc


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


def alias_payload_from_snapshot(
    response: dict[str, Any],
) -> dict[str, Any]:
    try:
        alias = response["alias"]
        normalized = {
            field: _form_value(alias[field])
            for field in WRITABLE_ALIAS_FIELDS
        }
    except (KeyError, TypeError) as exc:
        raise ExecutionFailed("Invalid alias snapshot response") from exc

    return {
        "alias": normalized,
        "authgroup_content": "",
        "network_content": "",
    }


def _payload_alias(payload: dict[str, Any]) -> dict[str, str]:
    try:
        alias = payload["alias"]
        return {
            field: _form_value(alias[field])
            for field in WRITABLE_ALIAS_FIELDS
        }
    except (KeyError, TypeError) as exc:
        raise ExecutionFailed("Invalid alias mutation payload") from exc


def _require_canary_name(payload: dict[str, Any]) -> None:
    alias = _payload_alias(payload)
    if alias["name"] != CANARY_ALIAS_NAME:
        raise ExecutionFailed(
            f"Refusing non-canary alias: {alias['name']!r}"
        )


def _verify_alias(
    response: dict[str, Any],
    expected_payload: dict[str, Any],
    *,
    phase: str,
) -> None:
    actual = _payload_alias(alias_payload_from_snapshot(response))
    expected = _payload_alias(expected_payload)

    differences = {
        field: {
            "expected": expected[field],
            "actual": actual[field],
        }
        for field in WRITABLE_ALIAS_FIELDS
        if actual[field] != expected[field]
    }

    if differences:
        raise ExecutionFailed(
            f"{phase} verification failed: {differences!r}"
        )


def _save_and_apply(
    client: Any,
    alias_uuid: str,
    payload: dict[str, Any],
    *,
    phase: str,
) -> None:
    save_response = client.set_alias(
        alias_uuid,
        deepcopy(payload),
    )
    if save_response != {"result": "saved"}:
        raise ExecutionFailed(
            f"{phase} save failed: {save_response!r}"
        )

    apply_response = client.reconfigure_aliases()
    if apply_response != {"status": "ok"}:
        raise ExecutionFailed(
            f"{phase} reconfigure failed: {apply_response!r}"
        )


def execute_rollback_canary(
    client: Any,
    *,
    alias_uuid: str,
    approved_alias_uuid: str,
    mutation_payload: dict[str, Any],
    approved: bool = False,
) -> dict[str, Any]:
    if not approved:
        raise ApprovalRequired("Explicit canary approval is required")

    target_uuid = _canonical_uuid(alias_uuid)
    pinned_uuid = _canonical_uuid(approved_alias_uuid)

    if target_uuid != pinned_uuid:
        raise ExecutionFailed(
            "Alias UUID does not match the explicitly approved UUID"
        )

    _require_canary_name(mutation_payload)

    snapshot_response = client.get_alias(target_uuid)
    restore_payload = alias_payload_from_snapshot(snapshot_response)
    _require_canary_name(restore_payload)

    mutation_error: Exception | None = None

    try:
        _save_and_apply(
            client,
            target_uuid,
            mutation_payload,
            phase="Mutation",
        )
        mutated_response = client.get_alias(target_uuid)
        _verify_alias(
            mutated_response,
            mutation_payload,
            phase="Mutation",
        )
    except Exception as exc:
        mutation_error = exc

    try:
        _save_and_apply(
            client,
            target_uuid,
            restore_payload,
            phase="Restoration",
        )
        restored_response = client.get_alias(target_uuid)
        _verify_alias(
            restored_response,
            restore_payload,
            phase="Restoration",
        )
    except Exception as restoration_error:
        if mutation_error is not None:
            raise ExecutionFailed(
                "Mutation failed and restoration failed: "
                f"{restoration_error}"
            ) from mutation_error

        raise ExecutionFailed(
            f"Restoration failed: {restoration_error}"
        ) from restoration_error

    if mutation_error is not None:
        raise ExecutionFailed(
            "Mutation failed and original state was restored: "
            f"{mutation_error}"
        ) from mutation_error

    return {
        "status": "verified_and_restored",
        "alias_uuid": target_uuid,
        "rollback_verified": True,
    }
