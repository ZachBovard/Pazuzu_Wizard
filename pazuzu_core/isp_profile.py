"""ISP profiles and the WAN step of guided setup.

The wizard leads. For the port that lands the WAN it asks one question,
"what connects you to the internet?", from a list of profiles, then asks
only for the details that choice needs. The list is data, so new providers
are catalog entries, not code. Pure functions: no I/O, and no value passed
in here is ever logged or returned in an error message.

Starter profiles are generic connection types plus two named placeholders
that are marked unverified. Provider facts (VLAN, credentials, bridge mode)
must come from tested, moderated submissions before `verified` is set.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

CONNECTION_TYPES = ("dhcp", "pppoe", "static", "wifi_client")
NOT_LISTED = "not_listed"
GENERIC_REGION = "*"

_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass(frozen=True)
class IspProfile:
    profile_id: str
    name: str
    region: str                                  # ISO country, or "*"
    connection_types: tuple[str, ...]            # preferred first
    requires_vlan: bool = False
    vlan_id: int | None = None                   # None while required: ask
    requires_username: bool = False
    requires_password: bool = False
    extra_equipment: bool = False                # modem, ONT or gateway in front
    troubleshooting: tuple[str, ...] = ()
    verified: bool = False                       # tested on real equipment
    last_tested: str | None = None               # YYYY-MM-DD
    notes: str = ""


@dataclass(frozen=True)
class Choice:
    profile_id: str
    label: str
    verified: bool


def validate_isp_profile(profile: IspProfile) -> tuple[str, ...]:
    errors: list[str] = []

    if not profile.profile_id or not profile.name:
        errors.append("profile_id and name are required")
    if not profile.connection_types:
        errors.append("at least one connection type is required")
    for kind in profile.connection_types:
        if kind not in CONNECTION_TYPES:
            errors.append(f"unknown connection type {kind!r}")
    if len(set(profile.connection_types)) != len(profile.connection_types):
        errors.append("connection types must be unique")
    if not profile.requires_vlan and profile.vlan_id is not None:
        errors.append("vlan_id is set but requires_vlan is false")
    if profile.vlan_id is not None and not 1 <= profile.vlan_id <= 4094:
        errors.append("vlan_id must be between 1 and 4094")
    if profile.last_tested is not None and not _DATE.match(profile.last_tested):
        errors.append("last_tested must be YYYY-MM-DD")
    if profile.verified and not profile.last_tested:
        errors.append("a verified profile needs last_tested")
    if profile.region != GENERIC_REGION and not re.fullmatch(
        r"[A-Z]{2}", profile.region
    ):
        errors.append("region must be a two-letter country code or '*'")

    return tuple(errors)


def _profile(**kwargs) -> IspProfile:
    profile = IspProfile(**kwargs)
    errors = validate_isp_profile(profile)
    if errors:
        raise ValueError(f"{profile.profile_id}: {'; '.join(errors)}")
    return profile


PROFILES: Mapping[str, IspProfile] = MappingProxyType(
    {
        p.profile_id: p
        for p in (
            _profile(
                profile_id="generic_dhcp",
                name="Cable, fiber or modem with automatic setup (DHCP)",
                region=GENERIC_REGION,
                connection_types=("dhcp",),
                extra_equipment=True,
                troubleshooting=(
                    "Restart the modem or gateway after connecting Hanbi.",
                    "Check whether the provider ties service to a device address.",
                ),
            ),
            _profile(
                profile_id="generic_pppoe",
                name="DSL or provider login (PPPoE)",
                region=GENERIC_REGION,
                connection_types=("pppoe",),
                requires_username=True,
                requires_password=True,
                extra_equipment=True,
            ),
            _profile(
                profile_id="generic_static",
                name="Fixed address from your provider (static)",
                region=GENERIC_REGION,
                connection_types=("static",),
            ),
            _profile(
                profile_id="phone_hotspot",
                name="Phone hotspot or other Wi-Fi network",
                region=GENERIC_REGION,
                connection_types=("wifi_client",),
                troubleshooting=(
                    "Use the 2.4 GHz band; the radio cannot see 5 GHz.",
                    "Keep the hotspot screen open while joining.",
                ),
            ),
            _profile(
                profile_id="google_fiber",
                name="Google Fiber",
                region="US",
                connection_types=("dhcp",),
                extra_equipment=True,
                notes="Placeholder: details unverified, confirm before release.",
            ),
            _profile(
                profile_id="tmobile_home_internet",
                name="T-Mobile Home Internet",
                region="US",
                connection_types=("dhcp",),
                extra_equipment=True,
                notes="Placeholder: details unverified, confirm before release.",
            ),
        )
    }
)


def wan_choices(
    region: str,
    profiles: Mapping[str, IspProfile] = PROFILES,
) -> tuple[Choice, ...]:
    """The list the user picks from: their region, then generic, then 'not listed'."""

    def choices(selected):
        return [
            Choice(p.profile_id, p.name, p.verified)
            for p in sorted(selected, key=lambda p: p.name.lower())
        ]

    local = choices(p for p in profiles.values() if p.region == region)
    generic = choices(
        p for p in profiles.values() if p.region == GENERIC_REGION
    )
    return tuple(
        local
        + generic
        + [Choice(NOT_LISTED, "My provider is not listed", False)]
    )


def required_inputs(
    profile: IspProfile | None,
    connection_type: str,
) -> tuple[str, ...]:
    """Field names to ask for. profile=None is the 'not listed' path."""

    if connection_type not in CONNECTION_TYPES:
        raise ValueError(f"unknown connection type {connection_type!r}")
    if profile is not None and connection_type not in profile.connection_types:
        raise ValueError(
            f"{profile.profile_id} does not offer {connection_type!r}"
        )

    fields: list[str] = []

    if profile is not None and profile.requires_vlan and profile.vlan_id is None:
        fields.append("vlan_id")

    if connection_type == "pppoe":
        if profile is None or profile.requires_username:
            fields.append("username")
        if profile is None or profile.requires_password:
            fields.append("password")
    elif connection_type == "static":
        fields += ["address", "prefix", "gateway"]
    elif connection_type == "wifi_client":
        fields += ["ssid", "passphrase"]

    return tuple(fields)


def _control_free(value: str) -> bool:
    return not any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


def validate_wan_inputs(
    profile: IspProfile | None,
    connection_type: str,
    values: Mapping[str, object],
) -> tuple[str, ...]:
    """Return problems, as field names with a reason. Values are never echoed."""

    expected = required_inputs(profile, connection_type)
    errors: list[str] = []

    for field in sorted(set(values) - set(expected)):
        errors.append(f"{field}: not needed for this connection")
    for field in expected:
        value = values.get(field)
        if value is None or (isinstance(value, str) and not value.strip()):
            errors.append(f"{field}: required")

    def text(field: str) -> str | None:
        value = values.get(field)
        return value if isinstance(value, str) and value.strip() else None

    if "vlan_id" in values:
        vlan = values["vlan_id"]
        if type(vlan) is not int or not 1 <= vlan <= 4094:
            errors.append("vlan_id: must be a whole number from 1 to 4094")

    for field in ("username", "password"):
        value = text(field)
        if value is not None and (len(value) > 255 or not _control_free(value)):
            errors.append(f"{field}: too long or contains control characters")

    if connection_type == "wifi_client":
        ssid = text("ssid")
        if ssid is not None and not 1 <= len(ssid.encode("utf-8")) <= 32:
            errors.append("ssid: must be 1 to 32 bytes")
        phrase = text("passphrase")
        if phrase is not None and not (
            8 <= len(phrase) <= 63 or _HEX64.match(phrase)
        ):
            errors.append("passphrase: must be 8 to 63 characters or 64 hex digits")

    if connection_type == "static":
        errors += _static_errors(values)

    return tuple(errors)


def _static_errors(values: Mapping[str, object]) -> list[str]:
    errors: list[str] = []

    try:
        address = ipaddress.IPv4Address(str(values.get("address")))
    except ValueError:
        address = None
        if values.get("address") not in (None, ""):
            errors.append("address: not a valid IPv4 address")

    prefix = values.get("prefix")
    if type(prefix) is not int or not 1 <= prefix <= 30:
        prefix = None
        if "prefix" in values and values["prefix"] not in (None, ""):
            errors.append("prefix: must be a whole number from 1 to 30")

    try:
        gateway = ipaddress.IPv4Address(str(values.get("gateway")))
    except ValueError:
        gateway = None
        if values.get("gateway") not in (None, ""):
            errors.append("gateway: not a valid IPv4 address")

    if address is not None and prefix is not None and gateway is not None:
        network = ipaddress.ip_interface(f"{address}/{prefix}").network
        if gateway == address:
            errors.append("gateway: cannot be the same as the address")
        elif gateway not in network:
            errors.append("gateway: is not inside the address's network")

    return errors
