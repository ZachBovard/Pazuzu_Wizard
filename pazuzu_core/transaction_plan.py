"""Generate deterministic dry-run transaction plans from compliance reports."""

from copy import deepcopy
from typing import Any

BLOCKING_RESULTS = ("unresolved", "not_observed")


def _is_concrete(value: Any) -> bool:
    return value is not None


def generate_transaction_plan(
    compliance_report: dict[str, Any],
) -> dict[str, Any]:
    """Create a non-executable plan with rollback coverage."""

    checks = compliance_report.get("checks", [])
    if not isinstance(checks, list):
        raise ValueError("Compliance report checks must be a list.")

    operations: list[dict[str, Any]] = []
    manual_review: list[dict[str, Any]] = []

    ordered_checks = sorted(
        checks,
        key=lambda check: str(check.get("path", "")),
    )

    for check in ordered_checks:
        path = check.get("path")
        result = check.get("result")
        desired = check.get("desired")
        observed = check.get("observed")

        if result in BLOCKING_RESULTS:
            manual_review.append(deepcopy(check))
            continue

        if result != "noncompliant":
            continue

        if not path or not _is_concrete(desired) or not _is_concrete(observed):
            blocker = deepcopy(check)
            blocker["reason"] = (
                "Noncompliant check lacks a path, concrete desired value, "
                "or concrete observed value."
            )
            manual_review.append(blocker)
            continue

        operation_id = f"operation-{len(operations) + 1:04d}"
        target = {"path": path}

        operations.append(
            {
                "id": operation_id,
                "type": "set_value",
                "target": target,
                "precondition": {
                    "expected_current_value": deepcopy(observed),
                },
                "value": deepcopy(desired),
                "rollback": {
                    "type": "set_value",
                    "target": deepcopy(target),
                    "value": deepcopy(observed),
                },
            }
        )

    return {
        "schema_version": "0.1",
        "source_schema_version": compliance_report.get("schema_version"),
        "baseline_schema_version": compliance_report.get(
            "baseline_schema_version"
        ),
        "mode": "dry_run",
        "platform": compliance_report.get("platform", "opnsense"),
        "executable": False,
        "approval": {
            "required": True,
            "granted": False,
        },
        "summary": {
            "operations": len(operations),
            "rollback_operations": len(operations),
            "manual_review": len(manual_review),
        },
        "operations": operations,
        "manual_review": manual_review,
    }
