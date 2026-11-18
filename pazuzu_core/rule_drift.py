"""Compare the live managed rules with what the manifest says they should be.

Pure functions. A managed rule is one whose description starts with
"PAZUZU:"; its full description, which includes the object id and the
interface and protocol it was expanded for, is its identity.

Reported:
    missing      expected but not on the firewall
    modified     present, but fields differ from what the manifest produces
    orphans      managed rules the manifest does not expect
    duplicates   more than one live rule with the same managed description

Comparison is conservative. Values are normalised (case, empty versus
"any", flag spellings), and a field the live row does not carry is skipped
rather than reported, so a missing field is never taken for drift.

Unmanaged rules are never looked at here. Preserving them is a rule of the
project; they are the audit's concern, not this module's.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

MANAGED_PREFIX = "PAZUZU:"

COMPARED = (
    "action", "interface", "direction", "ipprotocol", "protocol",
    "source_net", "source_not", "source_port",
    "destination_net", "destination_not", "destination_port",
    "log", "quick", "sequence", "enabled",
)
_FLAGS = {"source_not", "destination_not", "log", "quick", "enabled"}
_NETS = {"source_net", "destination_net"}
_PORTS = {"source_port", "destination_port"}


@dataclass(frozen=True)
class Modified:
    description: str
    uuid: str
    diffs: tuple[tuple[str, str, str], ...]     # (field, expected, actual)


@dataclass(frozen=True)
class Orphan:
    description: str
    uuid: str


@dataclass(frozen=True)
class Duplicate:
    description: str
    uuids: tuple[str, ...]


@dataclass(frozen=True)
class DriftReport:
    in_sync: int
    missing: tuple[str, ...]
    modified: tuple[Modified, ...]
    orphans: tuple[Orphan, ...]
    duplicates: tuple[Duplicate, ...]

    @property
    def drifted(self) -> bool:
        return bool(
            self.missing or self.modified or self.orphans or self.duplicates
        )


def normalise(field: str, value: Any) -> str:
    text = "" if value is None else str(value).strip()
    low = text.lower()

    if field in _FLAGS:
        return "1" if low in {"1", "true", "yes"} else "0"
    if field in _NETS:
        return "any" if low in {"", "any", "*"} else low
    if field in _PORTS:
        return "" if low in {"", "any"} else low
    if field == "sequence" and text.isdigit():
        return str(int(text))
    return low


def field_diffs(
    expected: Mapping[str, Any],
    live: Mapping[str, Any],
) -> tuple[tuple[str, str, str], ...]:
    diffs = []
    for field in COMPARED:
        if field not in live or field not in expected:
            continue
        want = normalise(field, expected[field])
        have = normalise(field, live[field])
        if want != have:
            diffs.append((field, want, have))
    return tuple(diffs)


def _is_managed(row: Any) -> bool:
    return (
        isinstance(row, dict)
        and str(row.get("description") or "").startswith(MANAGED_PREFIX)
        and str(row.get("is_automatic", "")).lower() not in {"1", "true"}
    )


def detect_drift(
    expected_rules: Iterable[Mapping[str, Any]],
    live_rows: Iterable[Any],
) -> DriftReport:
    expected = {str(rule["description"]): rule for rule in expected_rules}

    live: dict[str, list[dict[str, Any]]] = {}
    for row in live_rows:
        if _is_managed(row):
            live.setdefault(str(row["description"]), []).append(row)

    missing = sorted(set(expected) - set(live))
    modified: list[Modified] = []
    orphans: list[Orphan] = []
    duplicates: list[Duplicate] = []
    in_sync = 0

    for description in sorted(live):
        rows = live[description]

        if len(rows) > 1:
            duplicates.append(
                Duplicate(
                    description,
                    tuple(str(r.get("uuid", "unknown")) for r in rows),
                )
            )

        if description not in expected:
            for row in rows:
                orphans.append(Orphan(description, str(row.get("uuid", "unknown"))))
            continue

        diffs = field_diffs(expected[description], rows[0])
        if diffs:
            modified.append(
                Modified(description, str(rows[0].get("uuid", "unknown")), diffs)
            )
        else:
            in_sync += 1

    return DriftReport(
        in_sync=in_sync,
        missing=tuple(missing),
        modified=tuple(modified),
        orphans=tuple(orphans),
        duplicates=tuple(duplicates),
    )
