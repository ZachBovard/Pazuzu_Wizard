"""Why does a site not load? The DNS side: whether the firewall's block lists turned its name away, and a way to let
one name (and the names under it) through the block lists.

Reading: the firewall's own DNS query log (Reporting, Unbound DNS: /api/unbound/overview/search_queries), searched for
the name; a row the block list answered is shown with the device that asked. Nothing else is read.

Letting it through: the firewall's own quick allow (the Allow button on its DNS query report,
/api/unbound/settings/update_blocklist): the name goes on the block list's allow list and into the running block data at
once. Nothing is downloaded again and DNS is not restarted, so it takes no time and no name stops working meanwhile.
A firewall without that page gets the older way: the allow list saved from its own form, then the lists rebuilt and DNS
restarted (said plainly, since names can stop working for a few minutes). Each block-list entry that has an allow list
gets it; the old value is kept and the Undo puts it back (Undo always rebuilds, and says so). Nothing is guessed: a form
with no allow list is said plainly and left alone.
"""
from __future__ import annotations

import re
from typing import Any, Callable, Sequence
from urllib.parse import quote

from pazuzu_core import write_engine as we
from pazuzu_core.passkey_gate import plan_digest
from pazuzu_core.wifi_backup import Hotspot, Plan, Step, _flat

QUERIES = "/api/unbound/overview/search_queries"
DNSBL = "/api/unbound/settings"
APPLY = ("/api/unbound/service/dnsbl", "/api/unbound/service/reconfigure")
QUICK = "/api/unbound/settings/update_blocklist"
ALLOW_FIELDS = ("allowlists", "whitelists", "allowlist")
_NAME = re.compile(r"^(?=.{3,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")


def clean(name: Any) -> str:
    n = str(name or "").strip().lower().rstrip(".")
    for pre in ("https://", "http://"):
        if n.startswith(pre):
            n = n[len(pre):].split("/", 1)[0]
    if n.startswith("www."):
        n = n[4:]
    if not _NAME.match(n):
        raise we.WriteError("Type a site's name, like facebook.com.")
    return n


def _pick(row: dict, *keys: str) -> str:
    for k in keys:
        if row.get(k) not in (None, ""):
            return str(row[k])
    return ""


def blocked_rows(rows: Sequence[dict], name: str) -> list[dict]:
    """The query-log rows for `name` (or a name under it) that the block list answered."""
    out = []
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        dom = _pick(r, "domain", "query", "name").lower().rstrip(".")
        if not (dom == name or dom.endswith("." + name)):
            continue
        action = (_pick(r, "action", "status", "result") + " " + _pick(r, "blocklist", "source", "dnsbl", "policy")).lower()
        if "block" in action or "dnsbl" in action or "drop" in action:
            out.append({"domain": dom, "client": _pick(r, "client", "client_ip", "src"),
                        "list": _pick(r, "blocklist", "dnsbl", "policy", "source"), "time": _pick(r, "time", "timestamp")})
    return out


def trace(getter: Callable[[str], Any], name: str) -> dict:
    name = clean(name)
    try:
        body = getter(QUERIES + "?rowCount=500&searchPhrase=" + quote(name, safe="")) or {}
    except Exception as exc:  # noqa: BLE001
        return {"name": name, "readable": False, "why": f"The firewall's DNS log could not be read ({exc}).", "blocked": []}
    rows = body.get("rows") if isinstance(body, dict) else None
    if not isinstance(rows, list):
        return {"name": name, "readable": False, "why": "The firewall's DNS log is not switched on (Reporting, Settings, "
                "Unbound DNS reporting), so it cannot say.", "blocked": []}
    hits = blocked_rows(rows, name)
    return {"name": name, "readable": True, "asked": sum(1 for r in rows if isinstance(r, dict)), "blocked": hits[:50]}


class DnsAllow(Hotspot):
    def plan(self, name: str) -> Plan:  # type: ignore[override]
        name = clean(name)
        entries = []
        try:
            rows = self._rows(DNSBL + "/search_dnsbl")
        except we.WriteError:
            rows = None
        if rows is not None:
            for r in rows:
                if str(r.get("enabled", "1")) in ("0", "false"):
                    continue
                uuid = str(r.get("uuid") or "")
                if not we._UUID.match(uuid):
                    continue
                _w, form = self._form(f"{DNSBL}/get_dnsbl/{uuid}")
                field = next((f for f in ALLOW_FIELDS if f in form), None)
                if field:
                    entries.append({"get": f"{DNSBL}/get_dnsbl/{uuid}", "set": f"{DNSBL}/set_dnsbl/{uuid}", "field": field,
                                    "now": str(_flat(form.get(field)) or ""), "what": str(r.get("description") or "a block list"),
                                    "uuid": uuid})
        else:                                                 # an older firewall: one block-list setting for all
            _w, form = self._form(DNSBL + "/get")
            dn = form.get("dnsbl") if isinstance(form, dict) else None
            field = next((f for f in ALLOW_FIELDS if isinstance(dn, dict) and f in dn), None)
            if field:
                entries.append({"get": DNSBL + "/get", "set": DNSBL + "/set", "field": "dnsbl." + field,
                                "now": str(_flat(dn.get(field)) or ""), "what": "the block lists"})
        if not entries:
            raise we.WriteError("The firewall's block-list form has no allow list here, so nothing was changed. Add the name "
                                "by hand under Services, Unbound DNS, Blocklist.")
        todo = [e for e in entries if name not in [x.strip() for x in re.split(r"[,\s]+", e["now"]) if x.strip()]]
        if not todo:
            raise we.WriteError(f"{name} is already allowed on the block lists. Nothing was changed.")
        steps = [Step("allow", lambda e=e: self._do(e, name)) for e in todo]
        quick = all(e.get("uuid") for e in todo)
        lines = [f"Let {name} (and the names under it) through the DNS block lists",
                 "Only that name: everything else stays blocked as before",
                 ("It takes effect at once, without reloading the lists: DNS keeps working throughout" if quick else
                  "The block lists are rebuilt and DNS restarted: names can stop working for a few minutes"),
                 "Devices that remembered the block may need a minute (or a restart of the app) to try again",
                 "It uses the installer account, which can open every page"]
        return Plan(steps, lines, plan_digest("dns-allow", {"name": name, "n": len(todo)}), "", {"name": name})

    def apply(self, plan: Plan, gate: Callable[[str, Sequence[str]], bool]) -> list[Any]:
        if not gate(plan.digest, plan.lines):
            raise we.WriteError("Not approved with a passkey. Nothing was changed.")
        self.said = []
        self._slow = False
        outs = self._run(plan.steps)
        if self._slow:
            for path in APPLY:
                self._reconfigure(path)
        return outs

    def _quick(self, e: dict, name: str) -> bool:
        """The firewall's own quick allow. True when it took it (read back from the form), False when this firewall has
        no such page (then the older way is used). Raises when it refused."""
        try:
            res = self._call("post", QUICK, json={"domain": name, "type": e["field"], "uuid": e["uuid"]})
        except we.WriteError as exc:
            if "does not have that page" in str(exc) or "404" in str(exc):
                return False
            raise
        if not isinstance(res, dict) or str(res.get("status", "")).lower() == "failed":
            raise we.WriteError(f"The firewall did not take {name} on {e['what']}." + we._error_words(res))
        _w, form = self._form(e["get"])
        now = [x.strip() for x in re.split(r"[,\s]+", str(_flat(form.get(e["field"])) or "")) if x.strip()]
        if name not in now:
            raise we.WriteError(f"The firewall answered, but {name} is not on {e['what']}'s allow list when read back.")
        return True

    def _do(self, e: dict, name: str):
        if e.get("uuid") and self._quick(e, name):
            self.said.append(f"{name} is allowed on {e['what']}, at once.")

            def undo_quick() -> None:
                self._change(e["get"], e["set"], {e["field"]: e["now"]}, e["what"], free=(e["field"],))
                for path in APPLY:
                    self._reconfigure(path)
            return undo_quick
        new = ",".join([x for x in [e["now"].strip(", ")] if x] + [name])
        back = self._change(e["get"], e["set"], {e["field"]: new}, e["what"], free=(e["field"],))
        self._slow = True
        self.said.append(f"{name} is allowed on {e['what']} (the lists are rebuilt; names can stop working for a few minutes).")

        def undo() -> None:
            back()
            for path in APPLY:
                self._reconfigure(path)
        return undo
