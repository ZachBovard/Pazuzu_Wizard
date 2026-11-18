"""Posture: every control has a target, and the target is the enforced state.

Pure functions; nothing here talks to a firewall or reads a clock.

A control is compared with what is observed and reported as one of:

  enforced    the observed value meets the target.
  overridden  the user chose a weaker value on purpose, within bounds, with
              a reason, an approver and an expiry, and it has not expired.
  drifted     the observed value is weaker than the target and nobody chose
              it, or the choice was rejected, expired, or exceeded.
  unverified  the observed value could not be read. Never shown as enforced.

The app is "happy" only when every control is enforced. Anything else shows
up in the interface, and the daily summary lists every active override.

Overrides have limits. A user can relax a value inside the bounds the
manifest sets, but the manifest itself cannot set bounds past the hard
limits in this module, and an override cannot cover a value that turns the
protection off (for example a session that never expires). Those stay
drifted whatever anyone approved.

The first control is the admin session idle timeout, kept in the baseline
manifest at policy_pack.platform_controls.admin_session:

  idle_timeout_minutes.target        the enforced value (default 15)
  idle_timeout_minutes.max_override  the weakest value a user may choose
  override_max_hours                 how long an override may last

Overrides are runtime state, not manifest content: the manifest is the
reviewed desired state in git, an override is a decision made on one
install. Where overrides are stored is not decided here.

Nothing yet reads the timeout from, or sets it on, a firewall. That needs
an endpoint that has been verified against the OPNsense documentation.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Mapping

ENFORCED = "enforced"
OVERRIDDEN = "overridden"
DRIFTED = "drifted"
UNVERIFIED = "unverified"

# Worst first. The overall posture is the worst status of any control.
SEVERITY = (DRIFTED, UNVERIFIED, OVERRIDDEN, ENFORCED)

SPEC_PATH = ("policy_pack", "platform_controls", "admin_session")
_PATH = "$.policy_pack.platform_controls.admin_session"

# Limits the manifest cannot exceed.
HARD_IDLE_MINUTES_MAX = 60
HARD_OVERRIDE_HOURS_MAX = 168
CLOCK_SKEW = timedelta(minutes=5)

DEFAULT_ADMIN_SESSION: dict[str, Any] = {
    "schema_version": "0.1",
    "mode": "plan_only",
    "idle_timeout_minutes": {"target": 15, "max_override": 60},
    "override_max_hours": 24,
}

_OVERRIDE_FIELDS = {"value", "reason", "approved_by", "approved_at", "expires_at"}
_REASON_LIMIT = 200


@dataclass(frozen=True)
class Posture:
    control: str
    status: str
    observed: int | None
    target: int
    detail: str


def _is_int(value: Any) -> bool:
    return type(value) is int


def validate_admin_session_spec(spec: Any) -> tuple[str, ...]:
    """Check the manifest's admin_session section."""

    if not isinstance(spec, dict):
        return (f"{_PATH}: must be an object",)

    errors: list[str] = []
    allowed = set(DEFAULT_ADMIN_SESSION)
    for field in sorted(set(spec) - allowed):
        errors.append(f"{_PATH}.{field}: unknown field")
    for field in sorted(allowed - set(spec)):
        errors.append(f"{_PATH}.{field}: required field is missing")

    if spec.get("schema_version") != "0.1":
        errors.append(f"{_PATH}.schema_version: must equal '0.1'")
    if spec.get("mode") != "plan_only":
        errors.append(f"{_PATH}.mode: must equal 'plan_only'")

    idle = spec.get("idle_timeout_minutes")
    if not isinstance(idle, dict):
        errors.append(f"{_PATH}.idle_timeout_minutes: must be an object")
    else:
        for field in sorted(set(idle) - {"target", "max_override"}):
            errors.append(f"{_PATH}.idle_timeout_minutes.{field}: unknown field")
        target, cap = idle.get("target"), idle.get("max_override")
        ok = True
        for name, value in (("target", target), ("max_override", cap)):
            if not _is_int(value) or not 1 <= value <= HARD_IDLE_MINUTES_MAX:
                errors.append(
                    f"{_PATH}.idle_timeout_minutes.{name}: integer from 1 to "
                    f"{HARD_IDLE_MINUTES_MAX} required"
                )
                ok = False
        if ok and target > cap:
            errors.append(
                f"{_PATH}.idle_timeout_minutes: target must not exceed max_override"
            )

    hours = spec.get("override_max_hours")
    if not _is_int(hours) or not 1 <= hours <= HARD_OVERRIDE_HOURS_MAX:
        errors.append(
            f"{_PATH}.override_max_hours: integer from 1 to "
            f"{HARD_OVERRIDE_HOURS_MAX} required"
        )

    return tuple(sorted(errors))


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def validate_override(
    spec: Mapping[str, Any],
    override: Any,
    now: datetime,
) -> tuple[str, ...]:
    """Check an override against the spec. Expiry is not an error here."""

    if not isinstance(override, dict):
        return ("override must be an object",)

    errors: list[str] = []
    for field in sorted(set(override) - _OVERRIDE_FIELDS):
        errors.append(f"{field}: unknown field")
    for field in sorted(_OVERRIDE_FIELDS - set(override)):
        errors.append(f"{field}: required field is missing")

    idle = spec["idle_timeout_minutes"]
    value = override.get("value")
    if not _is_int(value):
        errors.append("value: integer required")
    elif not idle["target"] < value <= idle["max_override"]:
        errors.append(
            f"value: must be above the target ({idle['target']}) and at most "
            f"{idle['max_override']}"
        )

    for field in ("reason", "approved_by"):
        text = override.get(field)
        if not isinstance(text, str) or not text.strip():
            errors.append(f"{field}: non-empty text required")
    reason = override.get("reason")
    if isinstance(reason, str) and len(reason) > _REASON_LIMIT:
        errors.append(f"reason: at most {_REASON_LIMIT} characters")

    approved = _parse_time(override.get("approved_at"))
    expires = _parse_time(override.get("expires_at"))
    if approved is None:
        errors.append("approved_at: ISO time with a time zone required")
    elif approved > now + CLOCK_SKEW:
        errors.append("approved_at: is in the future")
    if expires is None:
        errors.append("expires_at: ISO time with a time zone required")
    if approved is not None and expires is not None:
        if expires <= approved:
            errors.append("expires_at: must be after approved_at")
        elif expires - approved > timedelta(hours=spec["override_max_hours"]):
            errors.append(
                f"expires_at: an override lasts at most "
                f"{spec['override_max_hours']} hours"
            )

    return tuple(errors)


def evaluate_idle_timeout(
    spec: Mapping[str, Any],
    observed: int | None,
    override: Any,
    now: datetime,
) -> Posture:
    """Compare the observed idle timeout (minutes) with the target."""

    idle = spec["idle_timeout_minutes"]
    target = idle["target"]

    def result(status: str, detail: str) -> Posture:
        return Posture("admin_session.idle_timeout_minutes", status, observed, target, detail)

    if observed is None:
        return result(UNVERIFIED, "the idle timeout could not be read")
    if not _is_int(observed):
        return result(UNVERIFIED, "the idle timeout reading is not a whole number")

    if observed <= 0:
        return result(
            DRIFTED,
            "sessions never expire; no override can cover that "
            f"(target {target} minutes)",
        )

    if observed <= target:
        return result(ENFORCED, f"{observed} minutes (target {target})")

    base = f"{observed} minutes is above the target of {target}"

    if override is None:
        return result(DRIFTED, base + "; no override is recorded")

    problems = validate_override(spec, override, now)
    if problems:
        return result(DRIFTED, base + "; override rejected: " + "; ".join(problems))

    expires = _parse_time(override["expires_at"])
    if expires <= now:
        return result(DRIFTED, base + f"; the override expired at {override['expires_at']}")

    if observed > override["value"]:
        return result(
            DRIFTED,
            base + f"; the approved override only allows {override['value']}",
        )

    return result(
        OVERRIDDEN,
        f"{base}; approved by {override['approved_by'].strip()} until "
        f"{override['expires_at']}: {override['reason'].strip()}",
    )


def overall(postures: list[Posture]) -> dict[str, Any]:
    """Roll controls up into one status. Happy only if all are enforced."""

    worst = ENFORCED
    for status in SEVERITY:
        if any(p.status == status for p in postures):
            worst = status
            break
    return {
        "status": worst,
        "happy": bool(postures) and worst == ENFORCED,
        "controls": len(postures),
        "overridden": sorted(p.control for p in postures if p.status == OVERRIDDEN),
        "drifted": sorted(p.control for p in postures if p.status == DRIFTED),
        "unverified": sorted(p.control for p in postures if p.status == UNVERIFIED),
    }


def add_to_baseline(baseline: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy of the baseline with the default admin_session added."""

    from pazuzu_core.security_baseline_v0_4 import validate_baseline_v0_4

    if not isinstance(baseline, dict):
        raise ValueError("Baseline must be an object")

    result = copy.deepcopy(baseline)
    controls = result.get("policy_pack", {}).get("platform_controls")
    if not isinstance(controls, dict):
        raise ValueError("Baseline has no policy_pack.platform_controls object")
    if SPEC_PATH[-1] in controls:
        raise ValueError("Baseline already has an admin_session section")

    controls[SPEC_PATH[-1]] = copy.deepcopy(DEFAULT_ADMIN_SESSION)

    problems = validate_baseline_v0_4(result)
    if problems:
        raise ValueError("Result would be invalid: " + "; ".join(problems))
    return result
