"""Human-readable security plan generation from M2 compliance evidence."""

import json
from collections import Counter
from typing import Any

RESULT_ORDER = ("noncompliant", "unresolved", "not_observed", "compliant")

ATTACK_VECTORS = {
    "Management-plane exposure": (
        "web_management", "wan_ssh", "wan_https", "wan_api"
    ),
    "Perimeter-policy bypass": (
        "inbound_wan", "bogon", "private_network", "source_route"
    ),
    "Network lateral movement": (
        "interzone", "zones", "isolation"
    ),
    "IPv6 policy bypass": ("ipv6",),
    "Automatic port exposure": ("upnp", "nat_pmp", "nat-pmp"),
    "Malicious-domain access": ("dns_blocklists",),
}


def _display(value: Any) -> str:
    if value is None:
        return "Not observed"
    text = json.dumps(value, sort_keys=True) if not isinstance(value, str) else value
    return text.replace("|", "\\|").replace("\n", " ")


def _vector_result(results: set[str]) -> str:
    if "noncompliant" in results:
        return "Control gap detected"
    if results & {"unresolved", "not_observed"}:
        return "Insufficient evidence"
    if results == {"compliant"}:
        return "Observed mitigation"
    return "Not evaluated"


def render_security_plan(report: dict[str, Any]) -> str:
    if report.get("mode") != "read_only":
        raise ValueError("M3 requires an M2 read-only compliance report")

    checks = report.get("checks")
    if not isinstance(checks, list):
        raise ValueError("Compliance report must contain a checks list")

    counts = Counter(check.get("result", "unknown") for check in checks)

    lines = [
        "# Project Pazuzu Security Plan",
        "",
        "## Operating constraints",
        "",
        "- Report mode: **read-only**",
        "- No configuration changes are authorized by this report.",
        "- Missing evidence is not treated as proof of vulnerability.",
        "- Alias existence is not treated as proof of firewall enforcement.",
        "",
        "## Executive summary",
        "",
        "| Result | Count |",
        "|---|---:|",
    ]

    for result in RESULT_ORDER:
        lines.append(f"| {result} | {counts[result]} |")

    lines.extend([
        "",
        "## Attack-vector assessment",
        "",
        "| Attack vector | Assessment | Related checks |",
        "|---|---|---:|",
    ])

    for title, terms in ATTACK_VECTORS.items():
        related = [
            check for check in checks
            if any(term in str(check.get("path", "")).lower() for term in terms)
        ]
        results = {check.get("result") for check in related}
        lines.append(
            f"| {title} | {_vector_result(results)} | {len(related)} |"
        )

    section_titles = {
        "noncompliant": "Confirmed control gaps",
        "unresolved": "Unresolved baseline requirements",
        "not_observed": "Evidence collection plan",
        "compliant": "Verified controls",
    }

    for result in RESULT_ORDER:
        lines.extend([
            "",
            f"## {section_titles[result]}",
            "",
        ])

        matching = [check for check in checks if check.get("result") == result]

        if not matching:
            lines.append("None.")
            continue

        lines.extend([
            "| Baseline path | Desired | Observed | Reason |",
            "|---|---|---|---|",
        ])

        for check in matching:
            lines.append(
                f"| {_display(check.get('path'))} "
                f"| {_display(check.get('desired'))} "
                f"| {_display(check.get('observed'))} "
                f"| {_display(check.get('reason'))} |"
            )

    lines.extend([
        "",
        "## Recommended next actions",
        "",
        "1. Investigate confirmed control gaps before any lower-priority work.",
        "2. Resolve generated or blocked desired-state references.",
        "3. Add read-only scanners for controls currently not observed.",
        "4. Require explicit approval before generating any mutation plan.",
        "",
    ])

    return "\n".join(lines)
