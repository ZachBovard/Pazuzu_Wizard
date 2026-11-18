from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Literal


class OperationNotAllowedError(PermissionError):
    """Raised when an operation is not explicitly allowlisted."""


class OperationId(str, Enum):
    SYSTEM_FIRMWARE = "system.firmware"
    INTERFACES_OVERVIEW = "interfaces.overview"
    INTERFACES_SETTINGS = "interfaces.settings"
    FIREWALL_ALIASES = "firewall.aliases"
    FIREWALL_RULES = "firewall.rules"


@dataclass(frozen=True)
class Operation:
    identifier: OperationId
    method: Literal["GET"]
    path: str
    read_only: Literal[True] = True

    def __post_init__(self) -> None:
        if not self.path.startswith("/api/"):
            raise ValueError("Operation path must begin with /api/")
        if self.method != "GET" or self.read_only is not True:
            raise ValueError("Alpha 0.2 permits read-only GET operations only")


_OPERATIONS = MappingProxyType(
    {
        OperationId.SYSTEM_FIRMWARE: Operation(
            identifier=OperationId.SYSTEM_FIRMWARE,
            method="GET",
            path="/api/core/firmware/status",
        ),
        OperationId.INTERFACES_OVERVIEW: Operation(
            identifier=OperationId.INTERFACES_OVERVIEW,
            method="GET",
            path="/api/interfaces/overview/interfaces_info/true",
        ),
        OperationId.INTERFACES_SETTINGS: Operation(
            identifier=OperationId.INTERFACES_SETTINGS,
            method="GET",
            path="/api/interfaces/settings/get",
        ),
        OperationId.FIREWALL_ALIASES: Operation(
            identifier=OperationId.FIREWALL_ALIASES,
            method="GET",
            path="/api/firewall/alias/search_item",
        ),
        OperationId.FIREWALL_RULES: Operation(
            identifier=OperationId.FIREWALL_RULES,
            method="GET",
            path="/api/firewall/filter/search_rule",
        ),
    }
)


def get_operation(identifier: OperationId | str) -> Operation:
    try:
        typed_identifier = OperationId(identifier)
        return _OPERATIONS[typed_identifier]
    except (ValueError, KeyError) as exc:
        raise OperationNotAllowedError(
            f"Operation is not allowlisted: {identifier}"
        ) from exc


def registered_operations() -> tuple[Operation, ...]:
    return tuple(_OPERATIONS.values())
