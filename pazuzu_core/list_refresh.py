"""Keep the downloaded lists fresh: a nightly job on the firewall's own scheduler (System, Settings, Cron) for each.

  - the DNS block lists (Unbound's block-list update),
  - packet inspection's rulesets (download and reload the intrusion detection rules),
  - the firewall's lists that come from the internet, the country ranges among them (update and reload aliases).

The jobs are added through the firewall's own Cron page (its API): the command is picked from the firewall's own list
of commands, by its name or, failing that, by the words it shows for it, never typed in. A job for the same command that
is already there (the person's own, or the firewall's) counts, and nothing is added for it. Each one Pazuzu adds is
called "Pazuzu: ..." and can be taken back. Nothing here runs a download now: the setup already started each one.
"""
from __future__ import annotations

import re
from typing import Any, Callable, Sequence

from pazuzu_core import write_engine as we
from pazuzu_core.passkey_gate import plan_digest
from pazuzu_core.wifi_backup import Hotspot, Plan, Step

CRON = "/api/cron/settings"
APPLY = "/api/cron/service/reconfigure"
# (key, the firewall's command names, words it may show for it, description, hour, minute)
JOBS = (
    ("dnsbl", ("unbound dnsbl",), r"dnsbl|block ?list", "Pazuzu: refresh the DNS block lists", "3", "10"),
    ("ids", ("ids update",), r"intrusion detection rules", "Pazuzu: refresh packet inspection's rulesets", "3", "25"),
    ("aliases", ("filter refresh_aliases",), r"update and reload firewall aliases|refresh.*aliases",
     "Pazuzu: refresh the firewall's downloaded lists (country ranges)", "3", "40"),
)
WORDS = {"dnsbl": "the DNS block lists", "ids": "packet inspection's rulesets", "aliases": "the country ranges and other downloaded lists"}


def _pick(options: dict, names: Sequence[str], words: str) -> str:
    """The firewall's own key for a command: by name first, else by the words it shows. "" when it offers neither."""
    for n in names:
        if n in options:
            return n
    for key, label in options.items():
        if re.search(words, str(label), re.I) or re.search(words, str(key), re.I):
            return key
    return ""


def have(rows: Sequence[dict], options: dict | None = None) -> dict:
    """{key: True} for each list that already has an enabled job for its command (anyone's)."""
    out = {}
    for key, names, words, _d, _h, _m in JOBS:
        found = False
        for r in rows or []:
            if str(r.get("enabled", "1")) not in ("1", "true", "True"):
                continue
            cmd = str(r.get("command") or "")
            if cmd in names or re.search(words, cmd, re.I) or (options and _pick(options, names, words) == cmd and cmd):
                found = True
                break
        out[key] = found
    return out


def missing(rows: Sequence[dict]) -> list[str]:
    return [k for k, ok in have(rows).items() if not ok]


class ListRefresh(Hotspot):
    """Reuses the careful form handling: the form is read first and only named fields change."""

    def rows(self) -> list[dict]:
        return self._rows(CRON + "/search_jobs")

    def plan(self, *_a) -> Plan:  # type: ignore[override]
        wrapper, form = self._form(CRON + "/get_job")
        options = we._option_labels(form.get("command")) or {}
        if not options:
            raise we.WriteError("The firewall's Cron page did not list its commands, so no job was added. Nothing was changed.")
        got = have(self.rows(), options)
        todo, lines, steps = [], ["Keep the downloaded lists fresh: a nightly job on the firewall's own scheduler for each"], []
        for key, names, words, descr, hour, minute in JOBS:
            if got[key]:
                continue
            cmd = _pick(options, names, words)
            if not cmd:
                lines.append(f"The firewall offers no command for {WORDS[key]}, so that one is left out")
                continue
            todo.append(key)
            lines.append(f"Every night at {hour}:{minute.zfill(2)}: {WORDS[key]} (the firewall's own \"{options[cmd]}\")")
            steps.append(Step("cron", lambda c=cmd, d=descr, hh=hour, mm=minute: self._add(c, d, hh, mm)))
        if not steps:
            raise we.WriteError("Every list already has its nightly job. Nothing was changed.")
        lines.append("It uses the installer account, which can open every page")
        return Plan(steps, lines, plan_digest("list-refresh", {"todo": todo}), "", {"todo": todo})

    def apply(self, plan: Plan, gate: Callable[[str, Sequence[str]], bool]) -> list[Any]:
        if not gate(plan.digest, plan.lines):
            raise we.WriteError("Not approved with a passkey. Nothing was changed.")
        self.said = []
        outs = self._run(plan.steps)
        if not self._reconfigure(APPLY):
            self.said.append("The jobs are saved, but the firewall did not say it reloaded its scheduler. Press Apply on its "
                             "Cron page.")
        return outs

    def _add(self, cmd: str, descr: str, hour: str, minute: str):
        wrapper, form = self._form(CRON + "/get_job")
        res, _b = self._post_form(CRON + "/add_job", wrapper, form,
                                  {"enabled": "1", "minutes": minute, "hours": hour, "days": "*", "months": "*",
                                   "weekdays": "*", "command": cmd, "description": descr}, "the nightly job",
                                  optional=("description",))
        uuid = str(res.get("uuid", ""))
        if not we._UUID.match(uuid):
            raise we.WriteError("The firewall saved the job but did not say which row it is. Look at System, Settings, Cron.")
        self.said.append(f"Added: {descr}, every night at {hour}:{minute.zfill(2)}.")

        def back() -> None:
            got = self._call("post", f"{CRON}/del_job/{uuid}", json={})
            self._reconfigure(APPLY)
            if any(str(r.get("uuid")) == uuid for r in self.rows()):
                raise we.WriteError(f"the firewall kept the job (it answered {str(got)[:120]})")
        return back
