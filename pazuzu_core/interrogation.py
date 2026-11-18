from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

from pazuzu_core.operations import OperationId, get_operation


class CapabilityUnavailableError(RuntimeError):
    pass


class CapabilityUnsupportedError(RuntimeError):
    pass


@dataclass(frozen=True)
class Capability:
    identifier: OperationId | str
    subsystem: str
    normalization_method: str = "identity"
    secure_controls: tuple[str, ...] = ()


CAPABILITIES = (
    Capability(
        identifier=OperationId.SYSTEM_FIRMWARE,
        subsystem="system",
        secure_controls=("system.firmware.current",),
    ),
    Capability(
        identifier=OperationId.INTERFACES_OVERVIEW,
        subsystem="interfaces",
        normalization_method="rows",
        secure_controls=(
            "network.interfaces.inventory",
            "network.services.wan_filtering",
        ),
    ),
    Capability(
        identifier=OperationId.INTERFACES_SETTINGS,
        subsystem="interfaces",
        secure_controls=(
            "network.interfaces.hardware_offloading",
            "network.ipv6.policy",
        ),
    ),
    Capability(
        identifier=OperationId.FIREWALL_ALIASES,
        subsystem="firewall",
        normalization_method="rows",
        secure_controls=("firewall.aliases.inventory",),
    ),
)


def _normalize(method: str, raw: Any) -> Any:
    if method == "identity":
        return raw
    if method == "rows":
        if not isinstance(raw, dict) or not isinstance(raw.get("rows"), list):
            raise ValueError("Response does not contain a rows list")
        return raw["rows"]
    raise ValueError(f"Unknown normalization method: {method}")


def _classify_exception(exc: Exception) -> str:
    if isinstance(exc, CapabilityUnavailableError):
        return "unavailable"
    if isinstance(exc, CapabilityUnsupportedError):
        return "unsupported"
    return "error"


def interrogate(
    client: Any,
    *,
    capabilities: Iterable[Capability] = CAPABILITIES,
) -> dict[str, Any]:
    selected = tuple(capabilities)
    resolved = []

    for capability in selected:
        if capability.normalization_method not in {"identity", "rows"}:
            raise ValueError(
                "Unknown normalization method: "
                f"{capability.normalization_method}"
            )
        resolved.append((capability, get_operation(capability.identifier)))

    observations: list[dict[str, Any]] = []

    for capability, operation in resolved:
        observation = {
            "identifier": operation.identifier.value,
            "subsystem": capability.subsystem,
            "endpoint": operation.path,
            "method": operation.method,
            "normalization_method": capability.normalization_method,
            "secure_controls": list(capability.secure_controls),
            "status": "observed",
            "raw": None,
            "normalized": None,
            "error": None,
        }

        try:
            raw = client.execute(operation.identifier)
            observation["raw"] = raw
            observation["normalized"] = _normalize(
                capability.normalization_method,
                raw,
            )
        except Exception as exc:
            observation["status"] = _classify_exception(exc)
            observation["error"] = f"{type(exc).__name__}: {exc}"

        observations.append(observation)

    statuses = ("observed", "unavailable", "unsupported", "error")
    summary = {
        "total": len(observations),
        **{
            status if status != "error" else "errors": sum(
                item["status"] == status for item in observations
            )
            for status in statuses
        },
    }

    controls: dict[str, list[dict[str, str]]] = {}
    for (capability, operation), observation in zip(resolved, observations):
        for control in capability.secure_controls:
            controls.setdefault(control, []).append(
                {
                    "capability": operation.identifier.value,
                    "endpoint": operation.path,
                    "status": observation["status"],
                }
            )

    return {
        "schema_version": 1,
        "report_type": "opnsense_interrogation",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "observations": observations,
        "secure_profile": {
            "profile": "secure",
            "controls": controls,
        },
    }
