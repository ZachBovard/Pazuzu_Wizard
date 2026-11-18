"""Compare directly observed OPNsense state with the security baseline."""

from typing import Any

RESULTS = ("compliant", "noncompliant", "unresolved", "not_observed")


def _lookup(data: dict[str, Any], path: str) -> tuple[bool, Any]:
    value: Any = data
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return False, None
        value = value[part]
    return True, value


def _resolve_desired(
    desired: Any,
    generated_values: dict[str, Any],
) -> tuple[bool, Any]:
    if not isinstance(desired, str) or not desired.startswith("generation."):
        return True, desired
    return _lookup(generated_values, desired)


def _requirements(baseline: dict[str, Any]) -> list[tuple[str, Any]]:
    requirements: list[tuple[str, Any]] = []

    web = baseline.get("identity_and_access", {}).get("web_management", {})
    for name, desired in web.items():
        requirements.append((f"identity_and_access.web_management.{name}", desired))

    network = baseline.get("network", {})
    for name in ("default_interzone_policy", "default_inbound_wan_policy"):
        if name in network:
            requirements.append((f"network.{name}", network[name]))

    for zone in network.get("zones", []):
        zone_id = zone.get("id", "unknown")
        for name, desired in zone.items():
            if name != "id":
                requirements.append((f"network.zones.{zone_id}.{name}", desired))

    for section in ("ipv6", "services"):
        values = network.get(section, {})
        for name, desired in values.items():
            requirements.append((f"network.{section}.{name}", desired))

    for blocklist in baseline.get("dns_security", {}).get("blocklists", []):
        blocklist_id = blocklist.get("id", "unknown")
        for name in ("desired", "requested_url", "requested_format"):
            if name in blocklist:
                requirements.append(
                    (f"dns_security.blocklists.{blocklist_id}.{name}", blocklist[name])
                )

        activation = blocklist.get("activation")
        if activation is not None:
            requirements.append(
                (
                    f"dns_security.blocklists.{blocklist_id}.activation",
                    activation,
                )
            )

    return requirements


def compare_security_baseline(
    baseline: dict[str, Any],
    observations: dict[str, Any] | None = None,
    generated_values: dict[str, Any] | None = None,
    interface_discovery: dict[str, Any] | None = None,
    alias_discovery: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return an evidence-based, read-only compliance report."""

    observations = observations or {}
    generated_values = generated_values or {}
    checks: list[dict[str, Any]] = []

    for path, declared_desired in _requirements(baseline):
        resolved, desired = _resolve_desired(
            declared_desired,
            generated_values,
        )

        if not resolved:
            result = "unresolved"
            observed = None
            reason = "Referenced generated value is unavailable."
        elif path.endswith(".activation") and str(desired).startswith(
            "blocked_pending_"
        ):
            result = "unresolved"
            observed = None
            reason = f"Baseline explicitly declares activation as {desired}."
        else:
            found, observed = _lookup(observations, path)
            if not found:
                result = "not_observed"
                observed = None
                reason = "Current discovery data contains no direct evidence."
            elif observed == desired:
                result = "compliant"
                reason = "Directly observed value matches the baseline."
            else:
                result = "noncompliant"
                reason = "Directly observed value contradicts the baseline."

        checks.append(
            {
                "path": path,
                "declared_desired": declared_desired,
                "desired": desired if resolved else None,
                "observed": observed,
                "result": result,
                "reason": reason,
            }
        )

    summary = {
        result: sum(check["result"] == result for check in checks)
        for result in RESULTS
    }

    return {
        "schema_version": "0.1",
        "baseline_schema_version": baseline.get("schema_version"),
        "mode": "read_only",
        "platform": "opnsense",
        "summary": summary,
        "checks": checks,
        "evidence": {
            "interface_report_loaded": interface_discovery is not None,
            "alias_report_loaded": alias_discovery is not None,
            "alias_enforcement_inferred": False,
        },
    }
CANONICAL_RESULTS = (
    "compliant",
    "noncompliant",
    "unknown",
    "not_applicable",
)

_OFFLOADING_KEYS = (
    "disablechecksumoffloading",
    "disablesegmentationoffloading",
    "disablelargereceiveoffloading",
)


def _observation(
    interrogation: dict[str, Any],
    identifier: str,
) -> dict[str, Any] | None:
    for item in interrogation.get("observations", []):
        if item.get("identifier") == identifier:
            return item
    return None


def _find_value(value: Any, key: str) -> tuple[bool, Any]:
    if isinstance(value, dict):
        if key in value:
            return True, value[key]
        for child in value.values():
            found, result = _find_value(child, key)
            if found:
                return True, result

    if isinstance(value, list):
        for child in value:
            found, result = _find_value(child, key)
            if found:
                return True, result

    return False, None


def _evidence(
    observation: dict[str, Any] | None,
    values: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if observation is None:
        return {
            "capability": None,
            "endpoint": None,
            "status": "missing",
            "values": values or {},
        }

    return {
        "capability": observation.get("identifier"),
        "endpoint": observation.get("endpoint"),
        "status": observation.get("status"),
        "values": values or {},
    }


def evaluate_secure_profile(
    baseline: dict[str, Any],
    interrogation: dict[str, Any],
) -> dict[str, Any]:
    """Evaluate the canonical secure profile without changing configuration."""

    findings: list[dict[str, Any]] = []

    def add(
        control: str,
        result: str,
        desired: Any,
        observed: Any,
        reason: str,
        evidence: dict[str, Any],
    ) -> None:
        findings.append(
            {
                "control": control,
                "result": result,
                "desired": desired,
                "observed": observed,
                "reason": reason,
                "evidence": evidence,
            }
        )

    firmware = _observation(interrogation, "system.firmware")
    firmware_version = None
    if firmware and firmware.get("status") == "observed":
        _, firmware_version = _find_value(
            firmware.get("normalized"),
            "CORE_ABI",
        )

    add(
        "system.firmware.current",
        "unknown",
        "compatible and current firmware",
        firmware_version,
        (
            "Firmware was observed, but the baseline does not declare a "
            "version compatibility or current-release target."
            if firmware_version
            else "Firmware version evidence is unavailable."
        ),
        _evidence(firmware, {"CORE_ABI": firmware_version}),
    )

    overview = _observation(interrogation, "interfaces.overview")
    overview_observed = bool(
        overview and overview.get("status") == "observed"
    )
    interfaces = (
        overview.get("normalized", [])
        if overview_observed
        else None
    )

    add(
        "network.interfaces.inventory",
        "not_applicable" if overview_observed else "unknown",
        None,
        interfaces,
        (
            "Interface inventory is evidence, not a pass/fail requirement."
            if overview_observed
            else "Interface inventory evidence is unavailable."
        ),
        _evidence(overview),
    )

    settings = _observation(interrogation, "interfaces.settings")
    settings_observed = bool(
        settings and settings.get("status") == "observed"
    )
    offloading_values: dict[str, Any] = {}
    offloading_complete = settings_observed

    for key in _OFFLOADING_KEYS:
        found, value = _find_value(
            settings.get("normalized") if settings else None,
            key,
        )
        if not found:
            offloading_complete = False
        offloading_values[key] = value if found else None

    if not offloading_complete:
        offloading_result = "unknown"
        offloading_reason = (
            "Complete hardware-offloading evidence is unavailable."
        )
    elif all(str(value) == "1" for value in offloading_values.values()):
        offloading_result = "compliant"
        offloading_reason = (
            "Checksum, segmentation, and large-receive offloading are disabled."
        )
    else:
        offloading_result = "noncompliant"
        offloading_reason = (
            "One or more required hardware-offloading features are enabled."
        )

    add(
        "network.interfaces.hardware_offloading",
        offloading_result,
        {
            key: "1"
            for key in _OFFLOADING_KEYS
        },
        offloading_values,
        offloading_reason,
        _evidence(settings, offloading_values),
    )

    ipv6_policy = (
        baseline.get("network", {})
        .get("ipv6", {})
        .get("policy")
    )
    disable_found, disable_ipv6 = _find_value(
        settings.get("normalized") if settings else None,
        "disableipv6",
    )

    if not disable_found:
        ipv6_result = "unknown"
        ipv6_reason = "IPv6 enablement evidence is unavailable."
    elif ipv6_policy == "disabled":
        if str(disable_ipv6) == "1":
            ipv6_result = "compliant"
            ipv6_reason = "IPv6 is disabled as required by the baseline."
        else:
            ipv6_result = "noncompliant"
            ipv6_reason = (
                "IPv6 is enabled, contradicting the baseline policy."
            )
    elif ipv6_policy == "enabled_only_with_ipv4_policy_parity":
        if str(disable_ipv6) == "0":
            ipv6_result = "compliant"
            ipv6_reason = (
                "IPv6 is enabled as required; policy parity is evaluated "
                "separately."
            )
        else:
            ipv6_result = "noncompliant"
            ipv6_reason = (
                "IPv6 is disabled, contradicting the baseline policy."
            )
    else:
        ipv6_result = "unknown"
        ipv6_reason = "The baseline IPv6 policy is not recognized."

    add(
        "network.ipv6.policy",
        ipv6_result,
        ipv6_policy,
        {
            "disableipv6": disable_ipv6
            if disable_found
            else None
        },
        ipv6_reason,
        _evidence(
            settings,
            {
                "disableipv6": disable_ipv6
                if disable_found
                else None
            },
        ),
    )

    if ipv6_policy == "disabled":
        parity_result = "not_applicable"
        parity_desired = None
        parity_reason = (
            "IPv4/IPv6 policy parity is not applicable when IPv6 is "
            "disabled by the baseline."
        )
    else:
        parity_result = "unknown"
        parity_desired = True
        parity_reason = (
            "Interface settings establish IPv6 enablement but do not prove "
            "IPv4/IPv6 firewall-policy parity."
        )

    add(
        "network.ipv6.policy_parity",
        parity_result,
        parity_desired,
        None,
        parity_reason,
        _evidence(settings),
    )

    services = baseline.get("network", {}).get("services", {})
    for name in (
        "bogon_filtering",
        "private_network_filtering_on_wan",
    ):
        add(
            f"network.services.{name}",
            "unknown",
            services.get(name),
            None,
            (
                "Interface overview identifies the WAN interface but does "
                "not directly report this filtering state."
            ),
            _evidence(overview),
        )

    aliases = _observation(interrogation, "firewall.aliases")
    aliases_observed = bool(
        aliases and aliases.get("status") == "observed"
    )

    add(
        "firewall.aliases.inventory",
        "not_applicable" if aliases_observed else "unknown",
        None,
        aliases.get("normalized") if aliases_observed else None,
        (
            "Alias inventory is evidence; alias presence does not prove "
            "firewall-rule enforcement."
            if aliases_observed
            else "Alias inventory evidence is unavailable."
        ),
        _evidence(aliases),
    )

    summary = {
        result: sum(
            finding["result"] == result
            for finding in findings
        )
        for result in CANONICAL_RESULTS
    }

    return {
        "schema_version": "0.1",
        "report_type": "secure_profile_evaluation",
        "profile": "secure",
        "baseline_profile": baseline.get("profile"),
        "baseline_schema_version": baseline.get("schema_version"),
        "mode": "read_only",
        "summary": summary,
        "findings": findings,
    }
