"""Which OPNsense versions Pazuzu will change, and which it will only read.

Support statement (use this wording in the app and documentation):

    Pazuzu supports OPNsense 26.7 and later. Releases in a series we have
    verified run with full functionality. A newer series runs in audit-only
    mode until it has passed our upgrade drill, or until you explicitly
    accept the risk.

Four outcomes:
    verified     at or above the floor, in a verified series: full function.
    untested     above the floor but in a series not yet verified (a newer
                 release, a pre-release or a development build): read-only
                 unless the caller explicitly accepts the risk.
    unsupported  below the floor: never mutated.
    unknown      the version could not be read: never mutated.

Versions compare numerically, so 26.10 is newer than 26.7. A hotfix suffix
such as _1 is ignored. Patch levels inside a verified series are accepted;
the recorded-fixture upgrade drill is what tightens that over time.

Pure functions, no I/O. The firmware status response is not parsed here;
the caller passes in the version string it found.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

SUPPORT_STATEMENT = (
    "Pazuzu supports OPNsense 26.7 and later. Releases in a series we have "
    "verified run with full functionality. A newer series runs in audit-only "
    "mode until it has passed our upgrade drill, or until you explicitly "
    "accept the risk."
)

MIN_SUPPORTED: tuple[int, int] = (26, 7)
VERIFIED_SERIES: tuple[tuple[int, int], ...] = ((26, 7),)

_VERSION = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")
_PRERELEASE = re.compile(r"(?:\.r\d|[-_.](?:rc|alpha|beta|dev|snapshot)\d*\b)", re.I)


@dataclass(frozen=True)
class Version:
    major: int
    minor: int
    patch: int = 0
    prerelease: bool = False

    @property
    def series(self) -> tuple[int, int]:
        return (self.major, self.minor)

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}" + (
            " (pre-release)" if self.prerelease else ""
        )


@dataclass(frozen=True)
class VersionDecision:
    status: str                 # verified | untested | unsupported | unknown
    version: Version | None
    allow_mutation: bool
    message: str


def parse_version(raw: object) -> Version | None:
    """Parse strings like '26.7', '26.7.2_1', '26.7-amd64', 'OPNsense 26.7.2'."""

    if not isinstance(raw, str):
        return None

    match = _VERSION.search(raw)
    if not match:
        return None

    return Version(
        major=int(match.group(1)),
        minor=int(match.group(2)),
        patch=int(match.group(3) or 0),
        prerelease=bool(_PRERELEASE.search(raw)),
    )


_PRODUCT_KEYS = (
    "product_version", "CORE_VERSION", "CORE_PKGVERSION", "product_abi", "CORE_ABI",
)


def firmware_version(status: object) -> str | None:
    """The installed version string from a firmware status response.

    Observed on OPNsense 26.7: the response carries a "product" object with
    product_version, CORE_VERSION, CORE_PKGVERSION, product_abi and CORE_ABI.
    The first one that parses is returned; None if none do, which decide()
    treats as an unknown version and never overrides.
    """

    if not isinstance(status, dict):
        return None

    product = status.get("product")
    sources = [(product, _PRODUCT_KEYS)] if isinstance(product, dict) else []
    sources.append((status, ("product_version",)))

    for container, keys in sources:
        for key in keys:
            value = container.get(key)
            if isinstance(value, str) and parse_version(value) is not None:
                return value

    return None


def decide(
    raw: object,
    *,
    accept_untested: bool = False,
    floor: tuple[int, int] = MIN_SUPPORTED,
    verified_series: tuple[tuple[int, int], ...] = VERIFIED_SERIES,
) -> VersionDecision:
    version = parse_version(raw)

    if version is None:
        return VersionDecision(
            "unknown",
            None,
            False,
            "The OPNsense version could not be determined, so nothing will "
            "be changed. Read-only audits still work.",
        )

    if version.series < floor:
        return VersionDecision(
            "unsupported",
            version,
            False,
            f"OPNsense {version} is older than the supported floor "
            f"{floor[0]}.{floor[1]}. Nothing will be changed.",
        )

    if version.series in verified_series and not version.prerelease:
        return VersionDecision(
            "verified", version, True, f"OPNsense {version} is verified."
        )

    reason = (
        "a pre-release build"
        if version.prerelease
        else "newer than the series verified so far"
    )

    if accept_untested:
        return VersionDecision(
            "untested",
            version,
            True,
            f"OPNsense {version} is {reason}. Changes are allowed only "
            "because the risk was explicitly accepted.",
        )

    return VersionDecision(
        "untested",
        version,
        False,
        f"OPNsense {version} is {reason}, so Pazuzu is in audit-only mode. "
        "Re-run with the explicit accept-untested option to allow changes.",
    )
