"""The guided setup flow, derived from the hardware profile. Pure functions.

The wizard walks the user forward, one decision at a time, in the order of
the ports on the device: "Let's connect your internet (port P0)", then the
home network, then the optional ports, the backup uplink, remote access and
a protection level. Nothing here asks the user to map interfaces; the
profile already knows what each labeled port is for, and a link-detect check
confirms the cable is in the right place.

Each step says whether it can be skipped and what must be true before the
wizard moves on. Progress is a set of step ids, so setup can be resumed.
The lifeline (control) port is never part of the user flow.
"""

from __future__ import annotations

from dataclasses import dataclass

from pazuzu_core.hardware_profile import HardwareProfile, validate_profile


@dataclass(frozen=True)
class Step:
    step_id: str
    title: str
    port: str | None
    skippable: bool
    verify: str           # the condition checked before moving on


def plan_steps(profile: HardwareProfile) -> tuple[Step, ...]:
    errors = validate_profile(profile)
    if errors:
        raise ValueError(
            f"Invalid hardware profile {profile.profile_id!r}: "
            + "; ".join(errors)
        )

    # Only wan, trusted, iot and dmz become steps. A control (lifeline) port
    # lands on management, which validation guarantees, so it never appears.
    by_landing = {p.landing: p for p in profile.ports if p.landing}
    steps: list[Step] = []

    wan = by_landing["wan"]
    steps.append(
        Step(
            "wan",
            f"Connect your internet (port {wan.label})",
            wan.label,
            skippable=False,
            verify="internet_reachable",
        )
    )

    lan = by_landing.get("trusted")
    if lan is not None:
        steps.append(
            Step(
                "lan",
                f"Set up your home network (port {lan.label})",
                lan.label,
                skippable=False,
                verify="link_up_and_leases_served",
            )
        )

    for zone, title, verify in (
        ("iot", "Add a separate network for smart-home devices", "link_up"),
        ("dmz", "Add a network for servers you want to expose", "link_up"),
    ):
        port = by_landing.get(zone)
        if port is not None:
            steps.append(
                Step(
                    zone,
                    f"{title} (port {port.label})",
                    port.label,
                    skippable=True,
                    verify=verify,
                )
            )

    backups = sorted(
        (u for u in profile.uplinks if u.tier > 1), key=lambda u: u.tier
    )
    if backups:
        steps.append(
            Step(
                "backup_uplink",
                "Add a backup internet connection",
                None,
                skippable=True,
                verify="backup_reachable",
            )
        )

    steps += [
        Step("remote_admin", "Set up secure remote access", None, True,
             "peer_enrolled"),
        Step("protection", "Choose your protection level", None, False,
             "baseline_applied_and_audited"),
        Step("summary", "Review and finish", None, False, "summary_shown"),
    ]

    return tuple(steps)


def next_step(
    steps: tuple[Step, ...],
    completed: frozenset[str] | set[str] = frozenset(),
    skipped: frozenset[str] | set[str] = frozenset(),
) -> Step | None:
    """The first step that is neither completed nor skipped, or None."""

    known = {s.step_id for s in steps}
    unknown = (set(completed) | set(skipped)) - known
    if unknown:
        raise ValueError(f"Unknown steps: {', '.join(sorted(unknown))}")

    for step in steps:
        if step.step_id not in completed and step.step_id not in skipped:
            return step
    return None


def skip(
    steps: tuple[Step, ...],
    step_id: str,
    skipped: frozenset[str] | set[str] = frozenset(),
) -> frozenset[str]:
    """Return the new skipped set, or refuse if the step is required."""

    match = next((s for s in steps if s.step_id == step_id), None)
    if match is None:
        raise ValueError(f"Unknown step: {step_id}")
    if not match.skippable:
        raise ValueError(f"Step {step_id!r} cannot be skipped")
    return frozenset(set(skipped) | {step_id})
