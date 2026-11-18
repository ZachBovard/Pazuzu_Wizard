"""A narrated, read-only tour of the backend.

Usage:
    python -m pazuzu_core.demo              # offline tour, then a live read-only tour if the
                                            # lab variables are set
    python -m pazuzu_core.demo --offline    # offline tour only

Every section names the modules it exercises and what to notice, so the
output doubles as a map of the architecture. Nothing here changes the
firewall: the live part only reads, and the apply step is a dry run. The
live part writes its reports to the ignored scan_results folder.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import sys
from typing import Callable, TextIO

DEMO_RULE = {
    "object_id": "DEMO-001", "object_type": "firewall_rule",
    "ownership": "pazuzu_managed", "schema_version": "0.4",
    "name": "Management to firewall HTTPS", "enabled": True, "priority": 100,
    "direction": "in", "source": ["management"],
    "destination": ["firewall_management"], "action": "allow",
    "services": ["firewall_management"], "log": True,
}
DEMO_GROUPS = {"firewall_management": ["tcp/443"]}
DEMO_ZONES = {"wan": "wan", "trusted": "lan", "management": "opt1", "iot": "opt2"}


def _header(out: TextIO, number: int, title: str, modules: str, note: str) -> None:
    print(f"\n== {number}. {title}  [{modules}]", file=out)
    print(f"   {note}", file=out)


def run_offline(out: TextIO) -> None:
    from pazuzu_core.hardware_profile import HANBI_V1, PROFILES
    from pazuzu_core.isp_profile import wan_choices
    from pazuzu_core.rule_safety import check_concrete_rules
    from pazuzu_core.rule_translation import translate_rule
    from pazuzu_core.security_baseline_v0_4 import validate_baseline_v0_4
    from pazuzu_core.setup_flow import plan_steps
    from pazuzu_core.uplink_policy import DEFAULT_UPLINK_POLICY, plan_gateways
    from pazuzu_core.version_policy import SUPPORT_STATEMENT, decide
    from pazuzu_core.zone_plan import plan_zones

    _header(out, 1, "Which OPNsense versions may we change?",
            "version_policy", "Verified series are changed; newer ones are audit-only; unreadable is never changed.")
    print(f"   {SUPPORT_STATEMENT}", file=out)
    for raw in ("26.1", "26.7", "26.7.2", "27.1", "garbage"):
        decision = decide(raw)
        print(f"   {raw:<8} -> {decision.status:<11} may change: {decision.allow_mutation}", file=out)

    _header(out, 2, "Guided setup, one decision at a time",
            "setup_flow, isp_profile, hardware_profile", "The wizard is derived from the device's ports; the user never maps interfaces.")
    for index, step in enumerate(plan_steps(HANBI_V1), 1):
        print(f"   {index}. {step.title}{'' if not step.skippable else '  (optional)'}", file=out)
    print("   'What connects you to the internet?' offers:", file=out)
    for choice in wan_choices("US"):
        print(f"     - {choice.label}", file=out)

    _header(out, 3, "Zones are logical; hardware decides where they land",
            "zone_plan, hardware_profile", "Same zones, different devices. DMZ is carved out of the lab VM but stays defined.")
    for name in ("hanbi_v1", "lab_vm"):
        plan = {b.zone: f"{b.kind}:{b.port}" if b.port else b.kind for b in plan_zones(PROFILES[name])}
        print(f"   {name}: {plan}", file=out)

    _header(out, 4, "Backup uplink settings the lab taught us",
            "uplink_policy", "Lower priority wins; each uplink gets its own monitor address.")
    for gateway in plan_gateways(HANBI_V1, DEFAULT_UPLINK_POLICY):
        print(f"   {gateway.source:<4} {gateway.kind:<12} priority {gateway.priority:<4} monitor {gateway.monitor_ip}", file=out)

    _header(out, 5, "A manifest rule becomes concrete firewall rules",
            "rule_translation", "One rule per source interface and protocol; ports come from service groups.")
    translated = translate_rule(DEMO_RULE, zones=DEMO_ZONES, service_groups=DEMO_GROUPS)
    for rule in translated.rules:
        print(f"   {rule['action']} on {rule['interface']} {rule['protocol']}/{rule['destination_port']} "
              f"{rule['source_net']} -> {rule['destination_net']}  (enabled={rule['enabled']})", file=out)

    _header(out, 6, "Two gates keep forbidden rules out",
            "security_baseline_v0_4, rule_safety", "The same mistake is stopped before translation and again after it.")
    bad = dict(DEMO_RULE, source=["WAN"])
    document = {"schema_version": "0.4", "enforcement_mode": "plan_only", "policy_pack": {
        "mode": "plan_only", "preserve_unmanaged_rules": True,
        "adoption_required_before_modification": True, "rules": [bad],
        "platform_controls": {"ipv6": {"policy": "disabled", "ula_generation": "prohibited"}}}}
    for error in validate_baseline_v0_4(document):
        print(f"   validator: {error}", file=out)
    concrete = translate_rule(bad, zones=DEMO_ZONES, service_groups=DEMO_GROUPS).rules
    for problem in check_concrete_rules(concrete, wan_interface="wan"):
        print(f"   safety gate: {problem}", file=out)


def _installed_version() -> str | None:
    from pazuzu_core.firewall_manifest_smoke import _installed_version
    return _installed_version()


def run_live(out: TextIO, *, manifest: str, zones: str) -> None:
    from pazuzu_core import (
        firewall_drift_cli,
        firewall_manifest_smoke,
        firewall_rule_audit_cli,
        interrogation_cli,
    )
    from pazuzu_core.version_policy import decide

    def step(number: int, title: str, modules: str, note: str,
             action: Callable[[], None]) -> None:
        _header(out, number, title, modules, note)
        try:
            action()
        except Exception as error:
            print(f"   skipped: {type(error).__name__}: {error}", file=out)

    def version() -> None:
        raw = _installed_version()
        decision = decide(raw)
        print(f"   installed: {raw} -> {decision.status}; {decision.message}", file=out)

    def interrogate() -> None:
        report = interrogation_cli.run(interrogation_cli.DEFAULT_OUTPUT)
        summary = report.get("summary", {})
        print(f"   observed {summary.get('observed')} of {summary.get('total')}; errors: {summary.get('errors')}", file=out)

    def audit() -> None:
        report = firewall_rule_audit_cli.run(manifest, firewall_rule_audit_cli.DEFAULT_OUTPUT)
        summary = report["summary"]
        print("   " + ", ".join(f"{k}: {summary[k]}" for k in (
            "observed_rules", "matched_baseline_rules", "missing", "conflicting", "unsafe")), file=out)

    def drift() -> None:
        report = firewall_drift_cli.run(manifest, zones, None, firewall_manifest_smoke.DEFAULT_LIMIT,
                                        firewall_drift_cli.DEFAULT_OUTPUT)
        print(f"   in sync: {report.in_sync}, missing: {len(report.missing)}, modified: {len(report.modified)}, "
              f"orphans: {len(report.orphans)}, duplicates: {len(report.duplicates)}", file=out)

    def dry_run() -> None:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            firewall_manifest_smoke.apply(manifest, zones)
        lines = [line for line in buffer.getvalue().splitlines() if line.strip()]
        print("   " + lines[-1], file=out)

    step(7, "Live: what version is the firewall?", "version_policy + firmware read",
         "One read-only GET.", version)
    step(8, "Live: ask the firewall the allowlisted questions", "interrogation_cli",
         "Four reads, saved under scan_results.", interrogate)
    step(9, "Live: audit the rules against the baseline", "firewall_rule_audit_cli",
         "Missing, conflicting (shadowed) and unsafe rules.", audit)
    step(10, "Live: has anything drifted from the manifest?", "firewall_drift_cli",
         "Missing, edited, extra and duplicate managed rules.", drift)
    step(11, "Plan the baseline (dry run, nothing is sent)", "firewall_manifest_smoke",
         "What apply --approve would create.", dry_run)


def main(argv: list[str] | None = None, out: TextIO | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--manifest", default="manifests/security_baseline_v0_4.json")
    parser.add_argument("--zones", default="scan_results/zone_assignment.json")
    args = parser.parse_args(argv)
    out = out or sys.stdout

    run_offline(out)

    if args.offline:
        return 0
    if not os.getenv("OPNSENSE_BASE_URL"):
        print("\n(Live part skipped: OPNSENSE_BASE_URL is not set. "
              "Run . $env:USERPROFILE\\.pazuzu\\lab_env.ps1 first.)", file=out)
        return 0

    from pazuzu_core.firewall_rule_audit_cli import _quiet_lab_tls_warnings
    _quiet_lab_tls_warnings()
    run_live(out, manifest=args.manifest, zones=args.zones)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
