"""Apply an Alpha 0.4 manifest as disabled OPNsense firewall rules.

Safe by default: without --approve both commands only print what they
would do and never change anything. (apply's dry run reads the firewall's
rules when it can, to show what is already there.)

With --approve, apply reads the firewall's aliases (read-only) first.
Aliases that are missing and creatable (private_networks and the port
aliases derived from service lists) are created before the rules; any other
missing alias stops the run before any change. If a run fails, everything it
created is removed again and the receipt is deleted; if that cleanup is
incomplete the receipt is kept so `rollback --approve` can finish the job.
Rollback removes the rules first, then the aliases, because OPNsense will
not delete an alias that rules still reference. Each removal is attempted on
its own, so one failure never stops the rest. Afterwards it checks what is
really left on the firewall (not what the replies said) and rewrites the
receipt to list only that, so a partial rollback can be finished by running
it again. The receipt is deleted only when nothing is left.

Adding to a finished deployment: when a receipt with status "applied" already
exists, apply does not stop. It reads the firewall's rules (read-only, even
on a dry run), skips every manifest rule whose description is already there,
and creates only the missing ones, adding them to the same receipt so one
rollback still removes everything. A rule that is already there but differs
from the manifest is reported and left alone: this tool never edits an
existing rule. If an incremental run fails, only what that run created is
removed and the receipt goes back to what it listed before.

No receipt (a fresh copy of the app): apply still reads the firewall's rules
first. Pazuzu rules an earlier run left there are adopted into a new receipt
and not added again, so a second copy of the set is never made. Aliases are
never adopted (one with the same name may be the person's own). A real run
that cannot read the rules adds nothing.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import replace as _replace
from pathlib import Path
from typing import Any

from pazuzu_core.alias_definitions import AliasSpec, spec_payload, static_spec
from pazuzu_core.opnsense_client import (
    discover_firewall_aliases,
    discover_firewall_rules,
)
from pazuzu_core.management_ports import gui_port_from_base_url, with_gui_port
from pazuzu_core.operations import OperationId
from pazuzu_core.opnsense_client import ReadOnlyOPNsenseClient
from pazuzu_core.opnsense_mutation_client import OPNsenseMutationClient
from pazuzu_core.version_policy import decide, firmware_version
from pazuzu_core.rule_safety import check_concrete_rules
from pazuzu_core.rule_translation import (
    LEVELS,
    PAUSED,
    Translation,
    TranslationSkip,
    translate_rule,
)
from pazuzu_core.security_baseline_v0_4 import validate_baseline_v0_4

RECEIPT = Path("scan_results/firewall_manifest_smoke_receipt.json")
DEFAULT_LIMIT = 4

# Fields compared between a manifest rule and the same rule already on the
# firewall. Enabled/log are left out: staging turns rules on by design.
_OURS = re.compile(r"^PAZUZU:[A-Za-z0-9_-]+:")

_COMPARED_FIELDS = (
    "interface", "action", "protocol", "source_net", "destination_net",
    "destination_port",
)


def _load(path: str) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"{path}: expected JSON object")
    return value


def _interface_value(value: Any) -> str | None:
    if isinstance(value, str) and value:
        return value
    if isinstance(value, dict):
        for key in ("identifier", "interface_id", "id", "name"):
            result = value.get(key)
            if isinstance(result, str) and result:
                return result
    return None


def _zone_map(report: dict[str, Any]) -> dict[str, str]:
    if report.get("summary", {}).get("deployable") is not True:
        raise RuntimeError("Zone assignment is not deployable")

    container = report.get("zones", report.get("assignments"))
    mapping: dict[str, str] = {}

    if isinstance(container, dict):
        entries = []
        for zone, assignment in container.items():
            if isinstance(assignment, dict):
                entries.append({"zone": zone, **assignment})
            else:
                entries.append({"zone": zone, "interface": assignment})
    elif isinstance(container, list):
        entries = container
    else:
        raise RuntimeError("Zone report has no zones or assignments collection")

    for entry in entries:
        if not isinstance(entry, dict):
            continue

        zone = entry.get("zone", entry.get("name"))
        interface = None

        for key in (
            "interface_id",
            "interface",
            "identifier",
            "assigned_interface",
        ):
            interface = _interface_value(entry.get(key))
            if interface:
                break

        if isinstance(zone, str) and interface:
            mapping[zone.lower()] = interface

    if not mapping:
        raise RuntimeError("No resolved zone-to-interface assignments found")

    return mapping


def _service_groups(pack: dict[str, Any]) -> dict[str, list[str]]:
    groups = pack.get("service_groups", {})

    if not isinstance(groups, dict) or not all(
        isinstance(name, str)
        and isinstance(members, list)
        and all(isinstance(member, str) for member in members)
        for name, members in groups.items()
    ):
        raise RuntimeError("policy_pack.service_groups must map names to lists")

    # The management rules follow the port the web GUI is actually reached on.
    return with_gui_port(groups, gui_port_from_base_url(os.environ.get("OPNSENSE_BASE_URL")))


def _select(
    rules: list[dict[str, Any]],
    zones: dict[str, str],
    groups: dict[str, list[str]],
    only: list[str] | None,
    limit: int,
    level: str = PAUSED,
) -> list[Translation]:
    if only is not None:
        unknown = sorted(set(only) - {rule["object_id"] for rule in rules})
        if unknown:
            raise RuntimeError(f"Unknown object ids: {', '.join(unknown)}")

    selected: list[Translation] = []

    for rule in rules:
        object_id = rule["object_id"]

        if only is not None and object_id not in only:
            continue

        try:
            translation = translate_rule(
                rule, zones=zones, service_groups=groups, level=level
            )
        except TranslationSkip as error:
            print(f"skipped {object_id}: {error}")
            continue

        note = ""
        if translation.dropped_zones:
            note = f"; unconfigured zones dropped: {', '.join(translation.dropped_zones)}"
        print(f"selected: {object_id} ({len(translation.rules)} rule(s){note})")
        for line in translation.notes:
            print(f"  note: {line}")
        selected.append(translation)

        if only is None and len(selected) == limit:
            break

    if not selected:
        raise RuntimeError("No manifest rules could be translated")

    return selected


def _live_alias_names() -> set[str]:
    rows = discover_firewall_aliases().get("rows", [])
    return {
        row["name"]
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("name"), str)
    }


def _installed_version() -> str | None:
    client = ReadOnlyOPNsenseClient()
    try:
        return firmware_version(client.execute(OperationId.SYSTEM_FIRMWARE))
    finally:
        client.close()


def _live_rule_uuids() -> set[str]:
    rows = discover_firewall_rules().get("rows", [])
    return {
        row["uuid"]
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("uuid"), str)
    }


def _live_alias_uuids() -> set[str]:
    rows = discover_firewall_aliases().get("rows", [])
    return {
        row["uuid"]
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("uuid"), str)
    }


def _live_rule_rows() -> list[dict[str, Any]]:
    return [
        row for row in discover_firewall_rules().get("rows", [])
        if isinstance(row, dict)
    ]


def _live_alias_rows() -> list[dict[str, Any]]:
    return [
        row for row in discover_firewall_aliases().get("rows", [])
        if isinstance(row, dict)
    ]


_ALIAS_FIELDS = ("source_net", "destination_net", "source_port", "destination_port")


def _rules_using(name: str, rows: list[dict[str, Any]]) -> list[tuple[str, str]]:
    """Rules whose network or port fields list this alias as a whole token."""

    users = []
    for row in rows:
        for field in _ALIAS_FIELDS:
            tokens = [t.strip() for t in str(row.get(field) or "").split(",")]
            if name in tokens:
                users.append(
                    (str(row.get("description") or "(no description)"),
                     str(row.get("uuid", "unknown")))
                )
                break
    return users


def _blocker_lines(alias_uuids: list[str]) -> list[str]:
    """Say which rules still use the aliases that could not be removed.

    Best effort: if the lookup fails, rollback's own result is unaffected.
    """

    if not alias_uuids:
        return []

    try:
        names = {
            row["uuid"]: row.get("name")
            for row in _live_alias_rows()
            if "uuid" in row
        }
        rows = _live_rule_rows()
    except Exception:
        return []

    lines = []
    for uuid in alias_uuids:
        name = names.get(uuid)
        if not name:
            continue
        users = _rules_using(name, rows)
        if users:
            for description, rule_uuid in users:
                lines.append(
                    f"  alias {name} is still used by rule {rule_uuid}: {description}"
                )
        else:
            lines.append(
                f"  alias {name}: no firewall rule uses it; check NAT, other "
                "aliases and other settings"
            )
    return lines


def _attempt(label: str, action) -> None:
    try:
        action()
    except Exception as error:
        print(f"could not remove {label}: {error}")


def _write_receipt(
    rule_uuids: list[str],
    alias_uuids: list[str],
    status: str,
) -> None:
    RECEIPT.parent.mkdir(parents=True, exist_ok=True)
    RECEIPT.write_text(
        json.dumps(
            {
                "status": status,
                "rule_uuids": rule_uuids,
                "alias_uuids": alias_uuids,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _undo(
    client: OPNsenseMutationClient,
    rule_uuids: list[str],
    alias_uuids: list[str],
) -> bool:
    """Remove what this run created: rules, apply, then aliases.

    Returns True only if every deletion succeeded.
    """

    clean = True

    for uuid in reversed(rule_uuids):
        try:
            client.delete_firewall_rule(uuid)
        except Exception as error:
            clean = False
            print(f"rollback failed for rule {uuid}: {error}")

    if rule_uuids:
        client.apply_firewall_rules()

    for uuid in reversed(alias_uuids):
        try:
            client.delete_alias(uuid)
        except Exception as error:
            clean = False
            print(f"rollback failed for alias {uuid}: {error}")

    if alias_uuids:
        client.reconfigure_aliases()

    return clean


def _spec_for(name: str, specs: dict[str, AliasSpec]) -> AliasSpec | None:
    return specs.get(name) or static_spec(name)


def _friendly_rule_name(rule: dict) -> str:
    text = str(rule.get("description") or "rule")
    parts = text.split(":", 2)
    return parts[2] if text.startswith("PAZUZU:") and len(parts) == 3 else text


def apply(
    manifest_path: str,
    zones_path: str,
    approve: bool = False,
    limit: int = DEFAULT_LIMIT,
    only: list[str] | None = None,
    accept_untested_version: bool = False,
    level: str = PAUSED,
    gate=None,
) -> None:
    if level not in LEVELS:
        raise RuntimeError(f"Unknown enforcement level {level!r}")

    if approve and level != PAUSED:
        raise RuntimeError(
            f"Creating rules at level {level!r} on the firewall is not "
            "allowed yet: this tool only creates disabled rules. "
            "Dry runs at every level are allowed."
        )

    prior_rules: list[str] | None = None
    prior_aliases: list[str] = []
    adopted = False
    if RECEIPT.exists():
        receipt = _load(str(RECEIPT))
        if receipt.get("status") != "applied":
            raise RuntimeError(
                f"{RECEIPT} already exists and is not a finished deployment; "
                "rollback before running again"
            )
        prior_rules = list(receipt.get("rule_uuids", []))
        prior_aliases = list(receipt.get("alias_uuids", []))

    manifest = _load(manifest_path)
    errors = validate_baseline_v0_4(manifest)
    if errors:
        raise RuntimeError("Invalid manifest:\n" + "\n".join(errors))

    zones = _zone_map(_load(zones_path))
    pack = manifest["policy_pack"]
    selected = _select(
        pack["rules"], zones, _service_groups(pack), only, limit, level
    )

    # The firewall is the record of what is there, not the receipt: a receipt lives in this folder, and a fresh copy of
    # the app has none, which used to add the whole set a second time. So the live rules are always read before adding
    # anything. A dry run that cannot read them (no firewall in reach) says so and carries on as before; a real run
    # refuses to add blind.
    live_rows: list[dict[str, Any]] | None = None
    unread = ""
    try:
        live_rows = _live_rule_rows()
    except Exception as exc:  # noqa: BLE001 (any failure to read means "not known")
        live_rows, unread = None, str(exc) or exc.__class__.__name__
        if prior_rules is not None:
            raise          # a deployment is recorded: what is already there cannot be told without reading it
    if live_rows is not None and prior_rules is None:
        found = [str(row.get("uuid")) for row in live_rows
                 if _OURS.match(str(row.get("description") or "")) and row.get("uuid")]
        if found:
            # Rules an earlier run made, with its receipt lost (a new copy of the app): kept and adopted, so they are not
            # added again and Undo (rollback) knows about them. Only rules: an alias with the same name may be the
            # person's own, so none is ever adopted.
            prior_rules = found
            adopted = True
            print(
                f"Found {len(found)} Pazuzu rule(s) already on the firewall from an earlier run. "
                "They are kept and not added again."
            )
    already_there: list[str] = []
    differing: list[tuple[str, list[str]]] = []
    if prior_rules is not None and live_rows is not None:
        live_by_description = {
            str(row.get("description") or ""): row for row in live_rows
        }
        remaining = []
        for item in selected:
            fresh = []
            for rule in item.rules:
                row = live_by_description.get(rule["description"])
                if row is None:
                    fresh.append(rule)
                    continue
                already_there.append(rule["description"])
                changed = [
                    field for field in _COMPARED_FIELDS
                    if str(row.get(field) or "").strip()
                    and str(row.get(field)).strip() != str(rule.get(field) or "").strip()
                ]
                if changed:
                    differing.append((rule["description"], changed))
            if fresh:
                remaining.append(_replace(item, rules=tuple(fresh)))
        selected = remaining
        print(
            f"Adding to the existing deployment: {len(already_there)} selected "
            "rule(s) are already on the firewall and are left alone."
        )
        for description, fields in differing:
            print(
                f"  differs from the manifest ({', '.join(fields)}): {description}. "
                "Left alone: this tool never edits a rule. To change it, run "
                "rollback --approve and apply again."
            )
        if not selected:
            print("Nothing to add: every selected rule is already on the firewall.")
            if approve and adopted:
                _write_receipt(list(prior_rules), prior_aliases, "applied")
            return

    translated = [rule for item in selected for rule in item.rules]

    unsafe = check_concrete_rules(
        translated,
        wan_interface=zones.get("wan"),
        allow_enabled=level != PAUSED,
    )
    if unsafe:
        raise RuntimeError(
            "Refusing to create unsafe rules:\n" + "\n".join(unsafe)
        )
    required_aliases = sorted(
        {alias for item in selected for alias in item.alias_refs}
    )
    specs = {
        spec.name: spec for item in selected for spec in item.alias_specs
    }

    if not approve:
        print("DRY RUN: no request was sent to OPNsense." if live_rows is None else
              "DRY RUN: nothing was changed on the firewall (its rules were only read).")
        for rule in translated:
            print(json.dumps(rule, indent=2, sort_keys=True))
        creatable = [a for a in required_aliases if _spec_for(a, specs)]
        other = [a for a in required_aliases if not _spec_for(a, specs)]
        if creatable:
            print("Aliases created with --approve if missing:")
            for name in creatable:
                spec = _spec_for(name, specs)
                print(f"  {name} ({spec.type}): {', '.join(spec.content)}")
        if other:
            print(
                "Aliases Pazuzu cannot create (must already exist): "
                + ", ".join(other)
            )
        if level == PAUSED:
            target = (
                " and added to the existing deployment"
                if prior_rules is not None else ""
            )
            print(
                f"{len(translated)} disabled rules from {len(selected)} "
                f"manifest rules would be created and applied{target}. "
                "Re-run with --approve to proceed."
            )
        else:
            enabled = sum(rule["enabled"] == "1" for rule in translated)
            print(
                f"At level {level!r}: {len(translated)} rules from "
                f"{len(selected)} manifest rules ({enabled} enabled, "
                f"{len(translated) - enabled} disabled) would be created. "
                "This is a preview only; --approve is not accepted above "
                "'paused' yet."
            )
        return

    if live_rows is None:
        raise RuntimeError(
            "Could not read the firewall's rules first, so nothing was added "
            "(adding blind could put a second copy of each rule on it): " + unread)

    # Policy gates creation only. Rollback is never blocked by a version.
    decision = decide(
        _installed_version(), accept_untested=accept_untested_version
    )
    print(decision.message)
    if not decision.allow_mutation:
        raise RuntimeError(
            "Refusing to change the firewall: " + decision.message
        )

    missing = (
        sorted(set(required_aliases) - _live_alias_names())
        if required_aliases
        else []
    )
    blocked = [name for name in missing if not _spec_for(name, specs)]
    if blocked:
        raise RuntimeError(
            "Aliases missing on the firewall and not creatable by Pazuzu: "
            + ", ".join(blocked)
            + ". No changes were made."
        )

    _require_passkey(
        gate, "manifest-apply", {"aliases": missing, "rules": translated},
        [f"Create {len(missing)} alias(es): {', '.join(missing) or 'none'}",
         f"Create {len(translated)} firewall rule(s), all disabled",
         "Then apply the rule changes"])

    client = OPNsenseMutationClient()

    alias_uuids: list[str] = []
    rule_uuids: list[str] = []

    try:
        for name in missing:
            response = client.add_alias(spec_payload(_spec_for(name, specs)))
            if response.get("result") != "saved" or not response.get("uuid"):
                raise RuntimeError(f"Alias creation failed: {response!r}")

            alias_uuids.append(response["uuid"])
            _write_receipt(
                (prior_rules or []) + rule_uuids, prior_aliases + alias_uuids, "staged")
            print(f"Added the address list: {name}")

        if alias_uuids:
            client.reconfigure_aliases()

        for rule in translated:
            response = client.add_firewall_rule(rule)
            if response.get("result") != "saved" or not response.get("uuid"):
                raise RuntimeError(f"Rule creation failed: {response!r}")

            rule_uuids.append(response["uuid"])
            _write_receipt(
                (prior_rules or []) + rule_uuids, prior_aliases + alias_uuids, "staged")
            print(f"Added, switched off: {_friendly_rule_name(rule)}")

        response = client.apply_firewall_rules()
        _write_receipt(
            (prior_rules or []) + rule_uuids, prior_aliases + alias_uuids, "applied")
        print(json.dumps(response, indent=2, sort_keys=True))
        print(
            f"Applied {len(rule_uuids)} disabled manifest rules "
            f"and created {len(alias_uuids)} alias(es)."
        )
        print(f"Rollback receipt: {RECEIPT}")

    except Exception:
        if _undo(client, rule_uuids, alias_uuids):
            if prior_rules is None:
                RECEIPT.unlink(missing_ok=True)
            else:
                _write_receipt(prior_rules, prior_aliases, "applied")
            print(
                f"Cleanup complete: removed {len(rule_uuids)} rule(s) and "
                f"{len(alias_uuids)} alias(es) created by this run."
            )
        else:
            print(
                "Cleanup incomplete; receipt kept. "
                "Run `rollback --approve` to retry."
            )
        raise
    finally:
        client.close()


def _require_passkey(gate, kind: str, plan, lines: list[str]) -> None:
    """Every change needs a passkey touch on this exact plan."""

    if gate is None:
        raise RuntimeError(
            "changes need a passkey approval and none was given. "
            "No changes were made.")
    from pazuzu_core.passkey_gate import plan_digest
    if not gate(plan_digest(kind, plan), lines):
        raise RuntimeError(
            "the change was not approved with a passkey. No changes were made.")


def rollback(approve: bool = False, gate=None) -> bool:
    """Remove what the receipt lists. True only if nothing is left."""

    receipt = _load(str(RECEIPT))
    rule_uuids = receipt.get("rule_uuids", [])
    alias_uuids = receipt.get("alias_uuids", [])

    if not approve:
        print("DRY RUN: no request was sent to OPNsense.")
        for uuid in reversed(rule_uuids):
            print(f"would delete rule {uuid}")
        for uuid in reversed(alias_uuids):
            print(f"would delete alias {uuid}")
        print("Re-run with --approve to delete these and apply.")
        return True

    _require_passkey(
        gate, "manifest-rollback",
        {"rules": rule_uuids, "aliases": alias_uuids},
        [f"Delete {len(rule_uuids)} firewall rule(s) listed in the receipt",
         f"Delete {len(alias_uuids)} alias(es) listed in the receipt",
         "Then apply the changes"])

    client = OPNsenseMutationClient()
    try:
        for uuid in reversed(rule_uuids):
            _attempt(f"rule {uuid}", lambda u=uuid: client.delete_firewall_rule(u))

        _attempt("the rule changes (apply)", client.apply_firewall_rules)

        for uuid in reversed(alias_uuids):
            _attempt(f"alias {uuid}", lambda u=uuid: client.delete_alias(u))

        if alias_uuids:
            _attempt("the alias changes (reconfigure)", client.reconfigure_aliases)
    finally:
        client.close()

    live_rules = _live_rule_uuids()
    live_aliases = _live_alias_uuids()
    left_rules = [u for u in rule_uuids if u in live_rules]
    left_aliases = [u for u in alias_uuids if u in live_aliases]

    if left_rules or left_aliases:
        _write_receipt(left_rules, left_aliases, "partial_rollback")
        print(
            f"Rollback incomplete: {len(left_rules)} rule(s) and "
            f"{len(left_aliases)} alias(es) remain. An alias that a rule "
            "created by hand still uses cannot be deleted: remove that rule, "
            "then run rollback --approve again. The receipt now lists only "
            "what remains."
        )
        for line in _blocker_lines(left_aliases):
            print(line)
        return False

    RECEIPT.unlink()
    print("Smoke deployment rolled back.")
    return True


def main(argv: list[str] | None = None, *, gate=None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    apply_parser = subparsers.add_parser("apply")
    apply_parser.add_argument(
        "--manifest",
        default="manifests/security_baseline_v0_4.json",
    )
    apply_parser.add_argument(
        "--zones",
        default="scan_results/zone_assignment.json",
    )
    apply_parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_LIMIT,
        help="Maximum manifest rules to translate (default: %(default)s)",
    )
    apply_parser.add_argument(
        "--only",
        help="Comma-separated manifest object ids; overrides --limit",
    )
    apply_parser.add_argument(
        "--level",
        choices=LEVELS,
        default=PAUSED,
        help="Enforcement level to preview (default: %(default)s). "
        "Only 'paused' can be applied.",
    )
    apply_parser.add_argument(
        "--approve",
        action="store_true",
        help="Create the rules on the firewall (default is a dry run)",
    )
    apply_parser.add_argument(
        "--accept-untested-version",
        action="store_true",
        help="Allow changes on an OPNsense series that is not verified yet",
    )

    rollback_parser = subparsers.add_parser("rollback")
    rollback_parser.add_argument(
        "--approve",
        action="store_true",
        help="Delete the receipt's items on the firewall (default is a dry run)",
    )
    args = parser.parse_args(argv)

    if args.approve and gate is None:
        from pazuzu_core.passkey_gate import default_gate
        gate = default_gate()

    if args.command == "apply":
        only = (
            [item.strip() for item in args.only.split(",") if item.strip()]
            if args.only
            else None
        )
        apply(
            args.manifest,
            args.zones,
            approve=args.approve,
            limit=args.limit,
            only=only,
            accept_untested_version=args.accept_untested_version,
            level=args.level,
            gate=gate,
        )
        return 0

    return 0 if rollback(approve=args.approve, gate=gate) else 1


if __name__ == "__main__":
    raise SystemExit(main())
