"""Read-only parser and validator for Pazuzu security baselines."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


SUPPORTED_SCHEMA = "0.1"
SUPPORTED_DOCUMENT_TYPE = "pazuzu_security_baseline"
SUPPORTED_ENFORCEMENT_MODES = {"plan_only"}

REQUIRED_SECTIONS = {
    "safety",
    "generation",
    "identity_and_access",
    "network",
    "zone_policy",
    "device_awareness",
    "dns_security",
    "ids_ips",
    "layer7_security",
    "geo_awareness",
    "logging_and_alerting",
    "attack_vector_matrix",
    "preflight_requirements",
    "milestones",
}

SYMBOLIC_DESTINATIONS = {
    "managed_infrastructure",
    "firewall_management",
    "private_networks",
    "internet",
}

ALLOWED_ZONE_ACTIONS = {
    "allow",
    "deny",
    "deny_by_default",
    "allow_restricted",
    "allow_minimal",
}

ALLOWED_APPLY_GATES = {"hard_fail", "required", "warning"}


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    category: str
    code: str
    path: str
    message: str

    @property
    def blocking(self) -> bool:
        return self.category != "warning"


@dataclass(frozen=True, slots=True)
class ValidationReport:
    source: str
    issues: tuple[ValidationIssue, ...]

    @property
    def valid(self) -> bool:
        invalid_categories = {"invalid", "unsupported", "unresolved"}
        return not any(i.category in invalid_categories for i in self.issues)

    @property
    def safe(self) -> bool:
        return not any(i.category == "unsafe" for i in self.issues)

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

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "valid": self.valid,
            "safe": self.safe,
            "passed": self.passed,
            "exit_code": self.exit_code,
            "issues": [asdict(issue) for issue in self.issues],
        }


def load_and_validate_baseline(path: str | Path) -> ValidationReport:
    """Load and validate a baseline without changing any external state."""

    source = str(path)

    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        return ValidationReport(
            source,
            (
                ValidationIssue(
                    "invalid",
                    "file_read_error",
                    "$",
                    str(exc),
                ),
            ),
        )

    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        return ValidationReport(
            source,
            (
                ValidationIssue(
                    "invalid",
                    "invalid_json",
                    "$",
                    f"{exc.msg} at line {exc.lineno}, column {exc.colno}",
                ),
            ),
        )

    return validate_baseline(document, source=source)


def validate_baseline(
    document: Any,
    *,
    source: str = "<memory>",
) -> ValidationReport:
    issues: list[ValidationIssue] = []

    def add(category: str, code: str, path: str, message: str) -> None:
        issues.append(ValidationIssue(category, code, path, message))

    if not isinstance(document, dict):
        add("invalid", "root_type", "$", "Baseline root must be an object.")
        return ValidationReport(source, tuple(issues))

    for field in ("schema_version", "document_type", "profile", "enforcement_mode"):
        if not isinstance(document.get(field), str) or not document[field].strip():
            add(
                "invalid",
                "required_string",
                f"$.{field}",
                "A non-empty string is required.",
            )

    if document.get("schema_version") != SUPPORTED_SCHEMA:
        add(
            "unsupported",
            "schema_version",
            "$.schema_version",
            f"Supported version is {SUPPORTED_SCHEMA!r}.",
        )

    if document.get("document_type") != SUPPORTED_DOCUMENT_TYPE:
        add(
            "unsupported",
            "document_type",
            "$.document_type",
            f"Expected {SUPPORTED_DOCUMENT_TYPE!r}.",
        )

    if document.get("enforcement_mode") not in SUPPORTED_ENFORCEMENT_MODES:
        add(
            "unsupported",
            "enforcement_mode",
            "$.enforcement_mode",
            "Only read-only plan_only mode is supported.",
        )

    for section in sorted(REQUIRED_SECTIONS):
        if section not in document:
            add(
                "invalid",
                "missing_section",
                f"$.{section}",
                "Required section is missing.",
            )

    safety = document.get("safety")
    if isinstance(safety, dict):
        expected_safety = {
            "automatic_apply": False,
            "mutation_allowed": False,
            "requires_human_approval": True,
            "requires_local_console_recovery": True,
            "requires_encrypted_baseline": True,
            "requires_rollback_plan": True,
            "requires_local_rollback_watchdog": True,
            "requires_management_path_test": True,
            "single_writer_lock": True,
            "fail_closed_on_validation_error": True,
            "unresolved_references_block_apply": True,
        }
        for field, expected in expected_safety.items():
            actual = safety.get(field)
            if type(actual) is not bool:
                add(
                    "invalid",
                    "safety_boolean",
                    f"$.safety.{field}",
                    "A Boolean value is required.",
                )
            elif actual is not expected:
                add(
                    "unsafe",
                    "unsafe_safety_setting",
                    f"$.safety.{field}",
                    f"Required value is {str(expected).lower()}.",
                )
    else:
        add("invalid", "section_type", "$.safety", "Must be an object.")

    _validate_generation(document.get("generation"), add)
    zone_ids = _validate_network(document.get("network"), add)
    _validate_zone_policy(document.get("zone_policy"), zone_ids, add)
    _validate_security_invariants(document, add)
    _validate_attack_vectors(document.get("attack_vector_matrix"), add)
    _validate_preflight(document.get("preflight_requirements"), add)
    _validate_milestones(document.get("milestones"), add)

    return ValidationReport(source, tuple(issues))


def _validate_generation(generation: Any, add: Any) -> None:
    if not isinstance(generation, dict):
        add("invalid", "section_type", "$.generation", "Must be an object.")
        return

    if generation.get("store_generated_values_in_manifest") is not False:
        add(
            "unsafe",
            "generated_values_in_manifest",
            "$.generation.store_generated_values_in_manifest",
            "Generated values must not be stored in the manifest.",
        )

    port = generation.get("management_https_port")
    if isinstance(port, dict):
        minimum = port.get("minimum")
        maximum = port.get("maximum")
        if (
            type(minimum) is not int
            or type(maximum) is not int
            or not 1 <= minimum <= maximum <= 65535
        ):
            add(
                "invalid",
                "invalid_port_range",
                "$.generation.management_https_port",
                "Port range must be ordered and within 1-65535.",
            )

    ipv4 = generation.get("site_ipv4_supernet")
    if isinstance(ipv4, dict) and ipv4.get("require_reachability_probe") is not True:
        add(
            "unsafe",
            "reachability_probe_disabled",
            "$.generation.site_ipv4_supernet.require_reachability_probe",
            "A reachability probe is required.",
        )


def _validate_network(network: Any, add: Any) -> set[str]:
    if not isinstance(network, dict):
        add("invalid", "section_type", "$.network", "Must be an object.")
        return set()

    if network.get("default_interzone_policy") != "deny":
        add(
            "unsafe",
            "interzone_default",
            "$.network.default_interzone_policy",
            "Default interzone policy must be deny.",
        )

    if network.get("default_inbound_wan_policy") != "deny":
        add(
            "unsafe",
            "wan_default",
            "$.network.default_inbound_wan_policy",
            "Default inbound WAN policy must be deny.",
        )

    zones = network.get("zones")
    if not isinstance(zones, list) or not zones:
        add("invalid", "zones_type", "$.network.zones", "Must be a non-empty array.")
        return set()

    zone_ids: set[str] = set()
    vlan_ids: set[int] = set()

    for index, zone in enumerate(zones):
        path = f"$.network.zones[{index}]"
        if not isinstance(zone, dict):
            add("invalid", "zone_type", path, "Zone must be an object.")
            continue

        zone_id = zone.get("id")
        if not isinstance(zone_id, str) or not zone_id:
            add("invalid", "zone_id", f"{path}.id", "Non-empty ID required.")
        elif zone_id in zone_ids:
            add("invalid", "duplicate_zone", f"{path}.id", f"Duplicate {zone_id!r}.")
        else:
            zone_ids.add(zone_id)

        vlan_id = zone.get("vlan_id")
        if vlan_id is not None:
            if type(vlan_id) is not int or not 1 <= vlan_id <= 4094:
                add("invalid", "vlan_id", f"{path}.vlan_id", "Must be 1-4094.")
            elif vlan_id in vlan_ids:
                add(
                    "invalid",
                    "duplicate_vlan",
                    f"{path}.vlan_id",
                    f"Duplicate VLAN {vlan_id}.",
                )
            else:
                vlan_ids.add(vlan_id)

    ipv6 = network.get("ipv6")
    if isinstance(ipv6, dict):
        if ipv6.get("default_wan_inbound") != "deny":
            add(
                "unsafe",
                "ipv6_wan_default",
                "$.network.ipv6.default_wan_inbound",
                "IPv6 WAN inbound must default to deny.",
            )
        if ipv6.get("interzone_policy_parity") is not True:
            add(
                "unsafe",
                "ipv6_policy_parity",
                "$.network.ipv6.interzone_policy_parity",
                "IPv4/IPv6 policy parity is required.",
            )
        if ipv6.get("no_implicit_ipv6_trust") is not True:
            add(
                "unsafe",
                "implicit_ipv6_trust",
                "$.network.ipv6.no_implicit_ipv6_trust",
                "Implicit IPv6 trust must be prohibited.",
            )

    return zone_ids


def _validate_zone_policy(policies: Any, zone_ids: set[str], add: Any) -> None:
    if not isinstance(policies, list):
        add("invalid", "zone_policy_type", "$.zone_policy", "Must be an array.")
        return

    for index, policy in enumerate(policies):
        path = f"$.zone_policy[{index}]"
        if not isinstance(policy, dict):
            add("invalid", "zone_policy_entry", path, "Must be an object.")
            continue

        source = policy.get("source")
        destination = policy.get("destination")
        action = policy.get("action")

        if source not in zone_ids:
            add(
                "unresolved",
                "unknown_source_zone",
                f"{path}.source",
                f"Unknown source zone {source!r}.",
            )

        if destination not in zone_ids and destination not in SYMBOLIC_DESTINATIONS:
            add(
                "unresolved",
                "unknown_destination",
                f"{path}.destination",
                f"Unknown destination {destination!r}.",
            )

        if action not in ALLOWED_ZONE_ACTIONS:
            add(
                "unsupported",
                "zone_action",
                f"{path}.action",
                f"Unsupported action {action!r}.",
            )


def _validate_security_invariants(document: dict[str, Any], add: Any) -> None:
    access = document.get("identity_and_access")
    if isinstance(access, dict):
        admin = access.get("firewall_admin", {})
        password = admin.get("password", {}) if isinstance(admin, dict) else {}
        if password.get("minimum_length", 0) < 24:
            add(
                "unsafe",
                "password_length",
                "$.identity_and_access.firewall_admin.password.minimum_length",
                "Minimum password length must be at least 24.",
            )
        for field in ("never_log", "never_commit"):
            if password.get(field) is not True:
                add(
                    "unsafe",
                    f"password_{field}",
                    f"$.identity_and_access.firewall_admin.password.{field}",
                    f"{field} must be true.",
                )

        web = access.get("web_management", {})
        if isinstance(web, dict) and web.get("wan_access") != "deny":
            add(
                "unsafe",
                "wan_management",
                "$.identity_and_access.web_management.wan_access",
                "WAN management access must be denied.",
            )

    dns = document.get("dns_security")
    if isinstance(dns, dict):
        required_true = (
            "dnssec_validation",
            "clients_must_use_firewall_resolver",
            "block_external_tcp_udp_53",
            "block_external_dot_853",
        )
        for field in required_true:
            if dns.get(field) is not True:
                add(
                    "unsafe",
                    f"dns_{field}",
                    f"$.dns_security.{field}",
                    "Required DNS security control is disabled.",
                )


def _validate_attack_vectors(vectors: Any, add: Any) -> None:
    if not isinstance(vectors, list):
        add(
            "invalid",
            "attack_vector_type",
            "$.attack_vector_matrix",
            "Must be an array.",
        )
        return

    found: set[str] = set()
    for index, vector in enumerate(vectors):
        path = f"$.attack_vector_matrix[{index}]"
        if not isinstance(vector, dict):
            add("invalid", "attack_vector_entry", path, "Must be an object.")
            continue

        vector_id = vector.get("id")
        if not isinstance(vector_id, str) or not vector_id:
            add("invalid", "attack_vector_id", f"{path}.id", "ID required.")
        elif vector_id in found:
            add("invalid", "duplicate_attack_vector", f"{path}.id", vector_id)
        else:
            found.add(vector_id)

        controls = vector.get("controls")
        if (
            not isinstance(controls, list)
            or not controls
            or not all(isinstance(c, str) and c.strip() for c in controls)
        ):
            add(
                "unresolved",
                "attack_vector_controls",
                f"{path}.controls",
                "At least one named control is required.",
            )

        if vector.get("apply_gate") not in ALLOWED_APPLY_GATES:
            add(
                "unsupported",
                "apply_gate",
                f"{path}.apply_gate",
                f"Unsupported gate {vector.get('apply_gate')!r}.",
            )

    expected = {f"AV-{number:03d}" for number in range(1, 21)}
    for missing in sorted(expected - found):
        add(
            "unresolved",
            "missing_attack_vector",
            "$.attack_vector_matrix",
            f"Required attack vector {missing} is missing.",
        )


def _validate_preflight(requirements: Any, add: Any) -> None:
    if (
        not isinstance(requirements, list)
        or not requirements
        or not all(isinstance(item, str) and item.strip() for item in requirements)
    ):
        add(
            "invalid",
            "preflight_requirements",
            "$.preflight_requirements",
            "Must contain non-empty requirement names.",
        )


def _validate_milestones(milestones: Any, add: Any) -> None:
    if not isinstance(milestones, list):
        add("invalid", "milestones_type", "$.milestones", "Must be an array.")
        return

    found: set[str] = set()
    for index, milestone in enumerate(milestones):
        path = f"$.milestones[{index}]"
        if not isinstance(milestone, dict):
            add("invalid", "milestone_entry", path, "Must be an object.")
            continue

        milestone_id = milestone.get("id")
        if milestone_id in found:
            add("invalid", "duplicate_milestone", f"{path}.id", milestone_id)
        elif isinstance(milestone_id, str):
            found.add(milestone_id)
        else:
            add("invalid", "milestone_id", f"{path}.id", "String ID required.")

        mutation_allowed = milestone.get("mutation_allowed")
        if type(mutation_allowed) is not bool:
            add(
                "invalid",
                "milestone_mutation_type",
                f"{path}.mutation_allowed",
                "Boolean required.",
            )
        elif mutation_allowed and milestone.get("requires_explicit_approval") is not True:
            add(
                "unsafe",
                "mutation_without_approval",
                path,
                "Mutation milestones require explicit approval.",
            )

    for read_only_id in ("M1", "M2", "M3", "M4"):
        for milestone in milestones:
            if (
                isinstance(milestone, dict)
                and milestone.get("id") == read_only_id
                and milestone.get("mutation_allowed") is not False
            ):
                add(
                    "unsafe",
                    "read_only_milestone_mutation",
                    f"$.milestones.{read_only_id}",
                    f"{read_only_id} must remain read-only.",
                )
