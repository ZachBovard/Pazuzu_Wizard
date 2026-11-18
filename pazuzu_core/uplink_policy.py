"""Uplink and failover settings for the baseline manifest. Pure functions.

These are the settings the lab failover test taught us, written down so the
product applies them instead of rediscovering them:

  * Default-gateway switching must be on, or a failed uplink never hands
    over the default route.
  * Priority orders the uplinks, lower wins. A tier maps to
    priority = tier * tier_priority_step. OPNsense accepts 1 to 255 (check
    against the version in use), so plan_gateways refuses anything above.
  * Each uplink needs its own monitor address, and it must never be the
    uplink's own gateway: a phone hotspot answers its own address even
    when it has no internet.
  * Only uplink interfaces may carry an eligible gateway. In the lab, the
    management network's DHCP gateway could have become the default route.
  * The Wi-Fi supplicant runs under a supervisor with bounded retries.
    Credentials are kept as the derived key, and scan results (which list
    the neighbours' networks) are not retained.
  * The backup radio is unavailable while it serves the setup network.

The policy lives in the baseline manifest at
policy_pack.platform_controls.uplinks. Nothing here talks to the firewall;
applying gateway settings needs endpoints that are not allowlisted yet.
"""

from __future__ import annotations

import copy
import ipaddress
from dataclasses import dataclass
from typing import Any, Mapping

from pazuzu_core.hardware_profile import HardwareProfile, validate_profile
from pazuzu_core.security_baseline_v0_4 import validate_baseline_v0_4

POLICY_PATH = ("policy_pack", "platform_controls", "uplinks")
MAX_PRIORITY = 255

DEFAULT_UPLINK_POLICY: dict[str, Any] = {
    "schema_version": "0.1",
    "mode": "plan_only",
    "failover": {
        "default_gateway_switching": True,
        "tier_priority_step": 50,
        "monitor": {
            "distinct_address_per_uplink": True,
            "candidates": ["1.1.1.1", "9.9.9.9", "8.8.8.8"],
            "never_monitor_uplink_gateway": True,
        },
        "failback": {"automatic": True},
    },
    "eligibility": {
        "only_uplinks_may_be_gateways": True,
        "non_uplink_gateways": "mark_down",
    },
    "wifi_client": {
        "supplicant": {
            "supervised": True,
            "join_timeout_seconds": None,
            "retry": "bounded",
        },
        "security": {"minimum": "wpa2_psk"},
        "credentials": {"store": "derived_key_only"},
        "scan_results": {"retain": False},
    },
    "setup_mode": {"backup_uplink_available_during_setup": False},
}


def _keys(path: str, value: Any, expected: set[str], errors: list[str]) -> bool:
    if not isinstance(value, dict):
        errors.append(f"{path}: must be an object")
        return False
    for key in sorted(set(value) - expected):
        errors.append(f"{path}.{key}: unknown field")
    for key in sorted(expected - set(value)):
        errors.append(f"{path}.{key}: required field is missing")
    return True


def validate_uplink_policy(policy: Any) -> tuple[str, ...]:
    errors: list[str] = []
    root = "$.uplinks"

    if not _keys(
        root, policy,
        {"schema_version", "mode", "failover", "eligibility",
         "wifi_client", "setup_mode"},
        errors,
    ):
        return tuple(errors)

    if policy.get("schema_version") != "0.1":
        errors.append(f"{root}.schema_version: must equal '0.1'")
    if policy.get("mode") != "plan_only":
        errors.append(f"{root}.mode: must equal 'plan_only'")

    failover = policy.get("failover")
    if _keys(f"{root}.failover", failover,
             {"default_gateway_switching", "tier_priority_step",
              "monitor", "failback"}, errors):
        if failover.get("default_gateway_switching") is not True:
            errors.append(f"{root}.failover.default_gateway_switching: must be true")
        step = failover.get("tier_priority_step")
        if type(step) is not int or not 1 <= step <= MAX_PRIORITY:
            errors.append(
                f"{root}.failover.tier_priority_step: whole number from 1 to "
                f"{MAX_PRIORITY}"
            )

        monitor = failover.get("monitor")
        if _keys(f"{root}.failover.monitor", monitor,
                 {"distinct_address_per_uplink", "candidates",
                  "never_monitor_uplink_gateway"}, errors):
            for key in ("distinct_address_per_uplink",
                        "never_monitor_uplink_gateway"):
                if monitor.get(key) is not True:
                    errors.append(f"{root}.failover.monitor.{key}: must be true")
            errors += _candidate_errors(monitor.get("candidates"))

        failback = failover.get("failback")
        if _keys(f"{root}.failover.failback", failback, {"automatic"}, errors):
            if type(failback.get("automatic")) is not bool:
                errors.append(f"{root}.failover.failback.automatic: must be true or false")

    eligibility = policy.get("eligibility")
    if _keys(f"{root}.eligibility", eligibility,
             {"only_uplinks_may_be_gateways", "non_uplink_gateways"}, errors):
        if eligibility.get("only_uplinks_may_be_gateways") is not True:
            errors.append(f"{root}.eligibility.only_uplinks_may_be_gateways: must be true")
        if eligibility.get("non_uplink_gateways") not in {"mark_down", "disable"}:
            errors.append(f"{root}.eligibility.non_uplink_gateways: must be mark_down or disable")

    wifi = policy.get("wifi_client")
    if _keys(f"{root}.wifi_client", wifi,
             {"supplicant", "security", "credentials", "scan_results"}, errors):
        supplicant = wifi.get("supplicant")
        if _keys(f"{root}.wifi_client.supplicant", supplicant,
                 {"supervised", "join_timeout_seconds", "retry"}, errors):
            if supplicant.get("supervised") is not True:
                errors.append(f"{root}.wifi_client.supplicant.supervised: must be true")
            if supplicant.get("retry") != "bounded":
                errors.append(f"{root}.wifi_client.supplicant.retry: must be 'bounded'")
            timeout = supplicant.get("join_timeout_seconds")
            if timeout is not None and (type(timeout) is not int or not 10 <= timeout <= 300):
                errors.append(
                    f"{root}.wifi_client.supplicant.join_timeout_seconds: "
                    "null (not yet measured) or a whole number from 10 to 300"
                )
        security = wifi.get("security")
        if _keys(f"{root}.wifi_client.security", security, {"minimum"}, errors):
            if security.get("minimum") != "wpa2_psk":
                errors.append(f"{root}.wifi_client.security.minimum: must be 'wpa2_psk'")
        credentials = wifi.get("credentials")
        if _keys(f"{root}.wifi_client.credentials", credentials, {"store"}, errors):
            if credentials.get("store") != "derived_key_only":
                errors.append(f"{root}.wifi_client.credentials.store: must be 'derived_key_only'")
        scans = wifi.get("scan_results")
        if _keys(f"{root}.wifi_client.scan_results", scans, {"retain"}, errors):
            if scans.get("retain") is not False:
                errors.append(f"{root}.wifi_client.scan_results.retain: must be false")

    setup = policy.get("setup_mode")
    if _keys(f"{root}.setup_mode", setup,
             {"backup_uplink_available_during_setup"}, errors):
        if type(setup.get("backup_uplink_available_during_setup")) is not bool:
            errors.append(f"{root}.setup_mode.backup_uplink_available_during_setup: must be true or false")

    return tuple(errors)


def _candidate_errors(candidates: Any) -> list[str]:
    path = "$.uplinks.failover.monitor.candidates"
    if not isinstance(candidates, list) or len(candidates) < 2:
        return [f"{path}: needs at least two addresses"]

    errors: list[str] = []
    seen: set[str] = set()
    for value in candidates:
        try:
            address = ipaddress.IPv4Address(value)
        except (ValueError, TypeError):
            errors.append(f"{path}: {value!r} is not an IPv4 address")
            continue
        if not address.is_global:
            errors.append(f"{path}: {value} is not a public address")
        if str(address) in seen:
            errors.append(f"{path}: {value} is listed twice")
        seen.add(str(address))
    return errors


@dataclass(frozen=True)
class GatewayPlan:
    source: str          # port label, radio label or USB id
    kind: str            # ethernet | wifi_client | cellular_usb
    tier: int
    priority: int        # lower wins
    monitor_ip: str


def plan_gateways(
    profile: HardwareProfile,
    policy: Mapping[str, Any],
) -> tuple[GatewayPlan, ...]:
    """Gateway settings for every uplink of a profile, primary first."""

    problems = list(validate_profile(profile)) + list(validate_uplink_policy(policy))
    if problems:
        raise ValueError("Cannot plan gateways: " + "; ".join(problems))

    failover = policy["failover"]
    step = failover["tier_priority_step"]
    candidates = failover["monitor"]["candidates"]
    uplinks = sorted(profile.uplinks, key=lambda u: u.tier)

    if len(uplinks) > len(candidates):
        raise ValueError(
            f"Cannot plan gateways: {len(uplinks)} uplinks but only "
            f"{len(candidates)} monitor addresses"
        )

    plans = []
    for index, uplink in enumerate(uplinks):
        priority = uplink.tier * step
        if priority > MAX_PRIORITY:
            raise ValueError(
                f"Cannot plan gateways: tier {uplink.tier} would need priority "
                f"{priority}, above {MAX_PRIORITY}"
            )
        plans.append(
            GatewayPlan(uplink.source, uplink.kind, uplink.tier, priority,
                        candidates[index])
        )
    return tuple(plans)


def add_to_baseline(baseline: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy of the baseline with the default uplink policy added."""

    if not isinstance(baseline, dict):
        raise ValueError("Baseline must be an object")

    result = copy.deepcopy(baseline)
    controls = result.get("policy_pack", {}).get("platform_controls")
    if not isinstance(controls, dict):
        raise ValueError("Baseline has no policy_pack.platform_controls object")
    if POLICY_PATH[-1] in controls:
        raise ValueError("Baseline already has an uplinks section")

    controls[POLICY_PATH[-1]] = copy.deepcopy(DEFAULT_UPLINK_POLICY)

    problems = list(validate_baseline_v0_4(result)) + list(
        validate_uplink_policy(controls[POLICY_PATH[-1]])
    )
    if problems:
        raise ValueError("Result would be invalid: " + "; ".join(problems))
    return result
