"""The rulesets packet inspection (IPS) uses: without any installed it has nothing to match, whatever its switch says.

When the shields reach the IPS level (and with "Finish getting to Happy"), the baseline's set is switched on and
downloaded through the firewall's own Intrusion Detection pages: list_rulesets to see them, toggle_ruleset to switch the
missing ones on, update_rules to download them, reconfigure to load them (the endpoints the firewall's documentation
lists for its ids module). Then the list is read back. Rulesets the person switched on themselves are never switched off.

The set: the abuse.ch lists (known botnet servers, bad certificates and addresses) and the core ET open groups (botnet
servers, compromised hosts, DShield, the drop list, attack responses, malware, coin miners). Chosen for few false alarms
on a home network: no policy-style groups that flag ordinary use (chat, games, P2P).
"""
from __future__ import annotations

import re
from typing import Any, Callable, Mapping, Sequence

LIST = "/api/ids/settings/list_rulesets"
TOGGLE = "/api/ids/settings/toggle_ruleset/"
UPDATE = "/api/ids/service/update_rules"
RECONFIGURE = "/api/ids/service/reconfigure"

WANTED = (
    r"^abuse\.ch/",
    r"^ET open/botcc$",
    r"^ET open/compromised$",
    r"^ET open/dshield$",
    r"^ET open/drop$",
    r"^ET open/emerging-attack_response$",
    r"^ET open/emerging-malware$",
    r"^ET open/emerging-coinminer$",
)
_FILE = re.compile(r"^[A-Za-z0-9_.\-]{1,120}$")


def rows_of(body: Any) -> list[dict]:
    rows = body.get("rows") if isinstance(body, Mapping) else body
    return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []


def _on(row: Mapping) -> bool:
    return str(row.get("enabled", "")).strip().lower() in ("1", "true", "yes")


def wanted(rows: Sequence[Mapping]) -> list[dict]:
    """The rows of the baseline's set, by their description, each with a plain file name."""
    out = []
    for r in rows:
        desc = str(r.get("description") or "").strip()
        if any(re.match(p, desc) for p in WANTED) and _FILE.match(str(r.get("filename") or "")):
            out.append(dict(r))
    return out


def missing(rows: Sequence[Mapping]) -> list[str]:
    """File names of the baseline's rulesets that are not switched on yet."""
    return [str(r["filename"]) for r in wanted(rows) if not _on(r)]


def installed(row: Mapping) -> bool:
    """Downloaded at least once: the firewall's list shows a date for it ("Last updated"), not "not installed"."""
    for key in ("modified_local", "last_updated", "updated"):
        val = str(row.get(key) or "").strip().lower()
        if val and val not in ("not installed", "none", "null"):
            return True
    return False


def apply(req: Callable[..., Any], gate: Callable[[str, Sequence[str]], bool] | None = None,
          refused: list | None = None) -> list[str]:
    """Switch on what is missing, download, load, read back. `req(method, path, json=...)` is the engine's own request.
    Returns plain lines. Raises nothing for a firewall without these pages: says so instead. A ruleset still off after
    the read back is asked for once more on its own; one the firewall keeps off even then is put in `refused` (it may no
    longer offer it), so it is said once and not counted as drift."""
    try:
        rows = rows_of(req("get", LIST))
    except Exception as exc:  # noqa: BLE001
        return [f"Packet inspection's rulesets could not be read ({exc}). Set them on the firewall: Services, Intrusion "
                "Detection, Administration, Download."]
    if not wanted(rows):
        return ["The firewall offers none of the baseline's rulesets by name, so none were switched on. Look at Services, "
                "Intrusion Detection, Administration, Download."]
    todo = missing(rows)
    lines: list[str] = []
    if todo:
        if gate is not None:
            from pazuzu_core.passkey_gate import plan_digest
            if not gate(plan_digest("ids-rulesets", {"files": todo}),
                        ["Switch on and download packet inspection's rulesets"] + todo):
                return ["Not approved with a passkey. The rulesets were not switched on."]
        res = req("post", TOGGLE + ",".join(todo) + "/1", json={})
        if not isinstance(res, Mapping):
            return ["The firewall did not answer when asked to switch the rulesets on. Nothing more was changed."]
        lines.append(f"Switched on {len(todo)} ruleset(s).")
        for f in todo:                                       # each on its own too: a list with one bad name may be refused whole
            try:
                req("post", TOGGLE + f + "/1", json={})
            except Exception:  # noqa: BLE001
                pass
    try:
        req("post", UPDATE, json={})
        req("post", RECONFIGURE, json={})
        lines.append("Asked the firewall to download them and load them (this takes a minute or two on its side).")
    except Exception as exc:  # noqa: BLE001
        lines.append(f"Switched on, but the download was not started ({exc}). Press Download & Update Rules on the "
                     "firewall's Intrusion Detection page.")
    try:
        after = rows_of(req("get", LIST))
        left = missing(after)
        if left:                                             # once more, one at a time
            for f in left:
                try:
                    req("post", TOGGLE + f + "/1", json={})
                except Exception:  # noqa: BLE001
                    pass
            left = missing(rows_of(req("get", LIST)))
        if not left:
            lines.append("Read back: all of the baseline's rulesets are switched on.")
        else:
            lines.append(f"Read back: the firewall keeps {len(left)} switched off even when asked on its own: "
                         + ", ".join(left[:6]) + ". It may no longer offer " + ("it" if len(left) == 1 else "them")
                         + ", so " + ("it is" if len(left) == 1 else "they are") + " no longer counted as missing.")
            if refused is not None:
                refused.extend(left)
    except Exception:  # noqa: BLE001
        pass
    return lines
