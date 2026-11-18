"""Compare redacted discovery data with normalized desired state."""

from typing import Any


def _normalize_mode(value: Any) -> str:
    mode = str(value or "").strip().lower()
    if mode in {"static", "configured"}:
        return "configured"
    return mode


def compare_interfaces(
    desired: dict[str, Any],
    discovery: dict[str, Any],
) -> dict[str, Any]:
    interfaces = discovery.get("interfaces")
    if not isinstance(interfaces, list):
        raise ValueError("Discovery report must contain an interfaces list")

    observed = {
        item.get("device"): item
        for item in interfaces
        if item.get("comparison_eligible") and item.get("device")
    }

    results: list[dict[str, Any]] = []

    wan = desired.get("wan")
    if not isinstance(wan, dict) or not wan.get("interface"):
        raise ValueError("Desired state must define wan.interface")

    wan_device = str(wan["interface"])
    wan_mode = _normalize_mode(wan.get("mode"))
    wan_observed = observed.get(wan_device)

    if wan_observed is None:
        wan_result = "missing"
        observed_mode = None
    else:
        observed_mode = _normalize_mode(wan_observed.get("ipv4_mode"))
        wan_result = "matched" if observed_mode == wan_mode else "drift"

    results.append(
        {
            "role": "wan",
            "device": wan_device,
            "management_state": "managed",
            "desired_ipv4_mode": wan_mode,
            "observed_ipv4_mode": observed_mode,
            "result": wan_result,
        }
    )

    setup = desired.get("setup_network")
    if isinstance(setup, dict) and setup.get("interface"):
        setup_device = str(setup["interface"])

        if not bool(setup.get("enabled", False)):
            results.append(
                {
                    "role": "setup_network",
                    "device": setup_device,
                    "management_state": "deferred",
                    "desired_ipv4_mode": None,
                    "observed_ipv4_mode": None,
                    "result": "not_evaluated",
                }
            )
        else:
            setup_mode = _normalize_mode(setup.get("mode", "configured"))
            setup_observed = observed.get(setup_device)

            if setup_observed is None:
                setup_result = "missing"
                setup_observed_mode = None
            else:
                setup_observed_mode = _normalize_mode(
                    setup_observed.get("ipv4_mode")
                )
                setup_result = (
                    "matched"
                    if setup_observed_mode == setup_mode
                    else "drift"
                )

            results.append(
                {
                    "role": "setup_network",
                    "device": setup_device,
                    "management_state": "managed",
                    "desired_ipv4_mode": setup_mode,
                    "observed_ipv4_mode": setup_observed_mode,
                    "result": setup_result,
                }
            )

    summary = {
        "matched": sum(item["result"] == "matched" for item in results),
        "drift": sum(item["result"] == "drift" for item in results),
        "missing": sum(item["result"] == "missing" for item in results),
        "not_evaluated": sum(
            item["result"] == "not_evaluated" for item in results
        ),
    }

    return {
        "schema_version": desired.get("schema_version"),
        "profile": desired.get("profile"),
        "source_generated_at": discovery.get("collected_at"),
        "summary": summary,
        "interfaces": results,
    }

