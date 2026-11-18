from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable

from pazuzu_core.security_baseline import validate_baseline


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "manifests" / "security_baseline_v0_2.schema.json"

_INVALID_SEVERITIES = {"invalid", "unsupported", "unresolved"}


@dataclass(frozen=True)
class BaselineIssue:
    severity: str
    code: str
    path: str
    message: str


@dataclass(frozen=True)
class BaselineReport:
    issues: tuple[BaselineIssue, ...]

    @property
    def valid(self) -> bool:
        return not any(
            issue.severity in _INVALID_SEVERITIES for issue in self.issues
        )

    @property
    def safe(self) -> bool:
        return not any(issue.severity == "unsafe" for issue in self.issues)

    @property
    def passed(self) -> bool:
        return self.valid and self.safe

    @property
    def exit_code(self) -> int:
        if not self.valid:
            return 2
        if not self.safe:
            return 3
        return 0


def _report(issues: list[BaselineIssue]) -> BaselineReport:
    unique = {
        (i.severity, i.code, i.path, i.message): i for i in issues
    }
    ordered = tuple(
        unique[key]
        for key in sorted(
            unique,
            key=lambda item: (item[2], item[1], item[0], item[3]),
        )
    )
    return BaselineReport(ordered)


@lru_cache(maxsize=1)
def _load_schema() -> dict[str, Any]:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    if not isinstance(schema, dict):
        raise ValueError("Alpha 0.2 schema root must be an object.")
    return schema


def _matches_type(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return type(value) is bool
    if expected == "integer":
        return type(value) is int
    if expected == "number":
        return type(value) in (int, float)
    if expected == "null":
        return value is None
    return False


def _validate_shape(
    value: Any,
    schema: dict[str, Any],
    path: str,
    add: Callable[[str, str, str, str], None],
) -> None:
    alternatives = schema.get("anyOf")
    if isinstance(alternatives, list):
        for alternative in alternatives:
            captured: list[tuple[str, str, str, str]] = []
            _validate_shape(
                value,
                alternative,
                path,
                lambda *issue: captured.append(issue),
            )
            if not captured:
                return

        add(
            "invalid",
            "field_type",
            path,
            "Value does not match any permitted type.",
        )
        return

    expected = schema.get("type")
    if expected is None:
        return

    if not _matches_type(value, expected):
        add(
            "invalid",
            "field_type",
            path,
            f"Expected {expected}; received {type(value).__name__}.",
        )
        return

    if expected == "object":
        properties = schema.get("properties", {})
        required = schema.get("required", [])

        for key in sorted(required):
            if key not in value:
                add(
                    "invalid",
                    "missing_field",
                    f"{path}.{key}",
                    "Required field is missing.",
                )

        if schema.get("additionalProperties") is False:
            for key in sorted(set(value) - set(properties)):
                add(
                    "invalid",
                    "unknown_field",
                    f"{path}.{key}",
                    "Unknown fields are not permitted.",
                )

        for key in sorted(set(value) & set(properties)):
            _validate_shape(
                value[key],
                properties[key],
                f"{path}.{key}",
                add,
            )

    elif expected == "array":
        item_schema = schema.get("items", {})
        for index, item in enumerate(value):
            _validate_shape(
                item,
                item_schema,
                f"{path}[{index}]",
                add,
            )


def validate_baseline_v0_2(document: Any) -> BaselineReport:
    issues: list[BaselineIssue] = []

    def add(severity: str, code: str, path: str, message: str) -> None:
        issues.append(BaselineIssue(severity, code, path, message))

    try:
        schema = _load_schema()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        add("invalid", "schema_definition", "$", str(exc))
        return _report(issues)

    _validate_shape(document, schema, "$", add)

    if not isinstance(document, dict):
        return _report(issues)

    if document.get("schema_version") != "0.2":
        add(
            "unsupported",
            "schema_version",
            "$.schema_version",
            "Only schema version 0.2 is supported by this loader.",
        )

    if document.get("enforcement_mode") != "plan_only":
        add(
            "unsafe",
            "enforcement_mode",
            "$.enforcement_mode",
            "Alpha 0.2 must remain plan-only.",
        )

    safety = document.get("safety")
    if isinstance(safety, dict):
        if safety.get("automatic_apply") is not False:
            add(
                "unsafe",
                "automatic_apply",
                "$.safety.automatic_apply",
                "Automatic apply must remain disabled.",
            )
        if safety.get("mutation_allowed") is not False:
            add(
                "unsafe",
                "mutation_allowed",
                "$.safety.mutation_allowed",
                "Mutation must remain disabled.",
            )

    network = document.get("network")
    if isinstance(network, dict):
        ipv6 = network.get("ipv6")
        if (
            isinstance(ipv6, dict)
            and ipv6.get("policy") != "disabled"
        ):
            add(
                "unsafe",
                "ipv6_policy",
                "$.network.ipv6.policy",
                "IPv6 must remain disabled in Alpha 0.2.",
            )

    generation = document.get("generation")
    if isinstance(generation, dict):
        for key in sorted(generation):
            normalized = key.lower().replace("-", "_")
            if "ula" in normalized or "ipv6" in normalized:
                add(
                    "unsupported",
                    "ipv6_generation",
                    f"$.generation.{key}",
                    "IPv6 and ULA generation are not supported.",
                )

    # Reuse the established semantic checks while preserving the v0.1 API.
    if not issues:
        legacy_document = copy.deepcopy(document)
        legacy_document["schema_version"] = "0.1"
        legacy_report = validate_baseline(legacy_document)

        for issue in legacy_report.issues:
            add(
                issue.category,
                issue.code,
                issue.path,
                issue.message,
            )

    return _report(issues)


def load_and_validate_baseline_v0_2(
    path: str | Path,
) -> BaselineReport:
    baseline_path = Path(path)

    try:
        document = json.loads(
            baseline_path.read_text(encoding="utf-8")
        )
    except OSError as exc:
        return _report([
            BaselineIssue("invalid", "baseline_io", "$", str(exc))
        ])
    except json.JSONDecodeError as exc:
        return _report([
            BaselineIssue(
                "invalid",
                "baseline_json",
                "$",
                f"Invalid JSON at line {exc.lineno}, column {exc.colno}.",
            )
        ])

    return validate_baseline_v0_2(document)

