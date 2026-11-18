"""A phone's hotspot (Wi-Fi) as the backup way to the internet, set up through the firewall's own pages.

What the firewall's web page does by hand, in the same order, with the same calls:

  1. a Wi-Fi device (Interfaces, Wireless, Devices): the Wi-Fi card joins the phone's network as a client;
  2. a port for it (Interfaces, Assignments), left switched off;
  3. the main internet gateway is watched, so the firewall can tell when it is down (System, Gateways);
  4. "allow default gateway switching" (System, Settings, General): the plugin does this one, the page has no API;
  5. the port is switched on and gets its address from the phone (DHCP), then Apply;
  6. once it has an address, its gateway is watched too (a different address) and is made the second choice.

Nothing here guesses an address or a field. Each form is read from the firewall first (its own empty form to add, its own
row to change), only the named fields are changed, and the rest is sent back as the firewall gave it, as the page does.
A field the form lacks is refused before anything is sent. If a step is refused, the steps already done are taken back
in reverse order. The Wi-Fi password is held for this one call: it is never shown, logged, remembered or approved by value.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Sequence

from pazuzu_core import write_engine as we
from pazuzu_core.backup_plan import _gw_for, _num, _rows, gateway_family
from pazuzu_core.passkey_gate import plan_digest
from pazuzu_core.uplink_policy import DEFAULT_UPLINK_POLICY

WL = "/api/interfaces/wireless_settings"
AS = "/api/interfaces/assignment"
GW = "/api/routing/settings"
INFO = "/api/interfaces/overview/interfaces_info/true"
# A field the firewall's port form can leave with nothing chosen (an empty pick-list, or just blank), and refuses to take
# back blank ("Option [] not in list"). The page's own Save sends its first choice, so this does too. Seen in a real Save
# of the port: "0". Any other field the firewall refuses the same way is filled in from its own list when it says so.
PAGE_FIRST_PICK = {"disablevlanhwfilter": "0"}
# What the port page's own Save sends for its hardware settings (all "0", seen in a real Save of this port). A port form
# that does not carry one of these at all (the firewall may leave a field out of what it reads back) gets it from here,
# so the save is the page's own body and not a body with a hole in it.
PAGE_PORT_FIELDS = {"hw_settings_overwrite": "0", "disablechecksumoffloading": "0", "disablesegmentationoffloading": "0",
                    "disablelargereceiveoffloading": "0", "disablevlanhwfilter": "0"}
_SECRETISH = re.compile(r"pass|secret|key|psk|token", re.I)
# The firewall's Wi-Fi device page (and its API) came with OPNsense 26.7.4; an older 26.7 answers "not found".
NO_WIFI_PAGE = ("This firewall's version has no Wi-Fi device page yet: OPNsense added it in 26.7.4. Update the firewall "
                "first (the first step, \u201cIs your firewall up to date?\u201d), then try again. Nothing was changed.")
NAME = "WiFiBackup"                                 # what the port is called on the firewall
STANDBY_WORDS = ("The firewall now lets go of the phone while the main internet works (within about two minutes). When the "
                 "main internet stops answering for about half a minute, it joins the hotspot again, so open the "
                 "phone's hotspot then; it lets go again a few minutes after the main internet is back.")
JOIN_WORDS = ("Set it to join the way a phone's hotspot needs: Minimum standard 11ng (2.4 GHz too), Pure 802.11n mode "
              "off, WPA Mode WPA2, Pre-Shared Key, WPA Pairwise AES (modern)")         # BUILD 502
DEVICE_NAME = "Pazuzu Wi-Fi backup"                   # what a Wi-Fi device made here is called
MONITORS = tuple(DEFAULT_UPLINK_POLICY["failover"]["monitor"]["candidates"])
# The same three providers by their IPv6 addresses (Cloudflare, Quad9, Google, in the order of MONITORS). A gateway takes a
# check address of its own kind only: the firewall refuses an IPv4 one on an IPv6 gateway ("Invalid IPv6 address") and the
# other way round.
MONITORS6 = ("2606:4700:4700::1111", "2620:fe::fe", "2001:4860:4860::8888")


def monitors_for(row: dict | None) -> tuple[str, ...]:
    """The addresses a gateway may be checked against: of the kind the gateway works with (IPv4 when its row does not say)."""
    return MONITORS6 if gateway_family(row) == 6 else MONITORS
WAIT_SECONDS = 90
APPLY_SECONDS = 60.0                                        # the firewall's own Apply can take longer than an ordinary page
_WIFI_CARD = re.compile(r"^(iwn|iwm|iwx|iwlwifi|ath|bwfm|rtwn|urtwn|run|rsu|bwi|ral|rum|zyd|otus|mt7\d*|wlan)\d+$")
_CLONE = re.compile(r"^[a-z]+\d+_wlan\d+$")
_ID = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_UUID = we._UUID
_PRINTABLE = re.compile(r"^[\x20-\x7e]{8,63}$")


# The steps in plain words, for a message that says which one could not be taken back.
STEP_WORDS = {"tidy": "the interface changes that were waiting", "wifi": "the Wi-Fi device", "assign": "the port",
              "main": "the check of the main internet gateway", "switching": "default gateway switching",
              "enable": "switching the port on", "finish": "the order of the two connections",
              "order": "the order of the two connections", "standby": "keeping the hotspot in reserve", "vlan": "the VLAN", "dhcp": "the address handout",
              "leftover": "an unfinished try"}


@dataclass
class Step:
    id: str
    do: Callable[[], Callable[[], None] | None]       # runs it; returns what takes it back, or None


@dataclass
class Plan:
    steps: list[Step]
    lines: list[str]
    digest: str
    ssid: str
    facts: dict = field(default_factory=dict)


class Undoer:
    """What the wizard keeps so one touch takes everything back: the engine-shaped object write_undo expects."""

    def undo(self, out) -> bool:
        out.revert()
        return True


def _flat(node: Any) -> Any:
    """The firewall's form as the page sends it back: a pick-list gives its selected keys, a section stays a section."""
    if we._option_labels(node) is not None:
        return we._value_of(node)
    if isinstance(node, dict):
        return {k: _flat(v) for k, v in node.items()} if node else ""
    if isinstance(node, list):
        # BUILD 466: an empty pick-list comes from PHP as [] (an empty array), not {}. It went back as the text "[]",
        # and Kea refused the whole address handout: "option: Option [[]] not in list" (lab box, 3 Nov 2026).
        return ",".join(str(x) for x in node if not isinstance(x, (dict, list)))
    return "" if node is None else str(node)


def _get_in(body: dict, path: str) -> Any:
    node: Any = body
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return we._MISSING
        node = node[part]
    return node


def _put(body: dict, path: str, value: str) -> None:
    node = body
    parts = path.split(".")
    for part in parts[:-1]:
        node = node[part]
    node[parts[-1]] = value


def _same(a: Any, b: Any) -> bool:
    return str(a) == str(b)


_ON = ("1", "true", "True")
TRACE_LIMIT = 300                                          # requests kept in the trace of one run


def _off(value: Any) -> bool:
    """A yes/no the firewall wrote as text ("1" is yes)."""
    return str(value) in _ON


def _brief(node: Any, depth: int = 0) -> Any:
    """A short, safe copy of a request or an answer, for the trace: no password or key (by the field's name), long text
    cut, a pick-list as the keys it chose and the keys it offered."""
    if depth > 6:
        return "..."
    if isinstance(node, dict):
        labels = we._option_labels(node)
        if labels is not None:
            return {"pick": we._value_of(node), "of": sorted(labels)[:30]}
        out: dict[str, Any] = {}
        for i, (k, v) in enumerate(node.items()):
            if i >= 80:
                out["..."] = f"{len(node) - 80} more"
                break
            out[str(k)] = "***" if _SECRETISH.search(str(k)) else _brief(v, depth + 1)
        return out
    if isinstance(node, list):
        kept = [_brief(v, depth + 1) for v in node[:40]]
        return kept + ([f"... {len(node) - 40} more"] if len(node) > 40 else [])
    if isinstance(node, str):
        return node if len(node) <= 160 else node[:160] + "..."
    return node


def _describe(body: Any) -> str:
    """What an answer was, in a few plain words, for a message: its shape and the keys it had, never its values."""
    if isinstance(body, list):
        return "a list with nothing in it" if not body else f"a list of {len(body)}"
    if isinstance(body, dict):
        if not body:
            return "an empty answer"
        said = ""
        for key in ("errorMessage", "message", "error", "status", "result"):
            val = body.get(key)
            if isinstance(val, (str, int)) and str(val).strip():
                said = f" ({key}: {' '.join(str(val).split())[:80]})"
                break
        return "an answer with the keys " + ", ".join(str(k) for k in list(body)[:6]) + said
    return "something that is not a form" if body is not None else "nothing"


class Hotspot:
    PORT_NAME = NAME                                   # what the port it makes is called on the firewall
    WHAT = "the Wi-Fi device"
    NOT_JOINED = ("The port is on, but the phone has not let it join yet. On the phone, switch the hotspot on and keep its "
                  "screen open (an iPhone drops the hotspot after a minute without a visitor), then press Finish.")

    def __init__(self, engine: we.Engine, switch=None, sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic, wait: float = WAIT_SECONDS,
                 trace_to: Path | str | None = None):
        self.e, self.switch, self.sleep, self.clock, self.wait = engine, switch, sleep, clock, wait
        self.said: list[str] = []                           # what finish() found, in plain words
        self.trace: list[dict[str, Any]] = []               # every request of this run, safe to keep
        self.trace_to = Path(trace_to) if trace_to else None

    # ------------------------------------------------------------------ the trace
    def _call(self, method: str, path: str, **kw) -> Any:
        """Every request goes through here, so a run can say afterwards exactly what the firewall was asked and answered."""
        entry: dict[str, Any] = {"n": len(self.trace) + 1, "method": method.upper(), "path": path.split("?")[0]}
        if "json" in kw:
            entry["sent"] = _brief(kw["json"])
        try:
            res = self.e._req(method, path, **kw)
        except we.WriteError as exc:
            entry["error"] = str(exc)[:300]
            self._keep(entry)
            if path.startswith(WL) and "does not have that page" in str(exc):
                raise we.WriteError(NO_WIFI_PAGE) from None
            raise
        entry["got"] = _brief(res)
        self._keep(entry)
        return res

    def _keep(self, entry: dict) -> None:
        self.trace.append(entry)
        if len(self.trace) > TRACE_LIMIT:
            del self.trace[:len(self.trace) - TRACE_LIMIT]

    def save_trace(self) -> Path | None:
        """Write the trace next to the saved scan results. Best effort: a disk that will not take it never stops a run."""
        if self.trace_to is None or not self.trace:
            return None
        try:
            self.trace_to.parent.mkdir(parents=True, exist_ok=True)
            text = json.dumps({"saved": datetime.now().isoformat(timespec="seconds"), "said": list(self.said),
                               "requests": self.trace}, indent=1, default=str)
            fd, tmp = tempfile.mkstemp(dir=str(self.trace_to.parent), prefix=".trace", suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(text)
            os.replace(tmp, self.trace_to)
        except OSError:
            return None
        return self.trace_to

    # ------------------------------------------------------------------ plain reads
    def _rows(self, path: str) -> list[dict]:
        body = self._call("get", path + "?rowCount=-1&searchPhrase=")
        rows = body.get("rows") if isinstance(body, dict) else None
        return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []

    def _form(self, path: str) -> tuple[str, dict]:
        body = self._call("get", path)
        if not isinstance(body, dict) or len(body) != 1:
            raise we.WriteError(self._odd(path, body))
        (wrapper, form), = body.items()
        if not isinstance(form, dict):
            raise we.WriteError(self._odd(path, form, inside=str(wrapper)))
        return str(wrapper), form

    @staticmethod
    def _odd(path: str, body: Any, inside: str = "") -> str:
        """The refusal for a form that is not in the usual shape: which page, and what it gave instead."""
        page = path.split("?")[0].replace("/api/", "", 1)
        what = f"its {inside} was {_describe(body)}" if inside else f"gave {_describe(body)}"
        return f"The firewall's form was not in the usual shape ({page} {what}). Nothing was changed."

    def _ports(self) -> list[dict]:
        body = self._call("get", INFO)
        rows = body.get("rows") if isinstance(body, dict) else body
        return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []

    @staticmethod
    def _port(rows: Sequence[dict], device: str) -> dict | None:
        mine = [r for r in rows if str(r.get("device")) == device and str(r.get("identifier") or "")]
        return mine[0] if mine else None

    @staticmethod
    def _joined(row: dict | None) -> bool:
        return bool(row and (row.get("ipv4") or row.get("addr4")))

    def _clone_name(self, uuid: str) -> str:
        """The name the firewall gave a Wi-Fi device it made, read from the device's own form."""
        _w, form = self._form(f"{WL}/get_item/{uuid}")
        for key in ("cloneif", "device", "name"):
            val = _flat(form.get(key)) if key in form else ""
            if isinstance(val, str) and _CLONE.match(val):
                return val
        return ""

    # ------------------------------------------------------------------ what is there now
    def look(self) -> dict:
        """Everything the card needs, from reads only."""
        out: dict[str, Any] = {"card": None, "parent": "", "uuid": None, "ssid": "", "device": "", "identifier": "", "joined": False,
                               "enabled": False, "gateway": None, "main": None, "reuse": False, "stage": "none",
                               "mode": ""}
        wifi = self._rows(WL + "/search_item")
        if len(wifi) > 1:
            named = [r for r in wifi if str(r.get("descr")) in (NAME, DEVICE_NAME)]
            wifi = named if len(named) == 1 else wifi
        out["wifi_rows"] = len(wifi)
        if len(wifi) == 1 and _UUID.match(str(wifi[0].get("uuid", ""))):
            r = wifi[0]
            out["uuid"] = str(r["uuid"])
            out["ssid"] = str(r.get("ssid") or "")
            out["mode"] = str(r.get("mode") or "")
            out["parent"] = str(r.get("if") or "")
            out["descr"] = str(r.get("descr") or "")
            out["device"] = self._clone_name(out["uuid"]) or str(r.get("cloneif") or "")
            out["reuse"] = True
        ports = self._ports()
        if out["reuse"] and not out["device"] and out["parent"]:
            mine = [r for r in ports if re.fullmatch(re.escape(out["parent"]) + r"_wlan\d+", str(r.get("device")))
                    and str(r.get("identifier") or "") and str(r.get("description") or "") == NAME]
            if len(mine) == 1:
                out["device"] = str(mine[0]["device"])
        if out["device"]:
            row = self._port(ports, out["device"])
            if row:
                out["identifier"] = str(row.get("identifier"))
                out["enabled"] = str(row.get("enabled")) not in ("0", "False", "false", "")
                out["joined"] = self._joined(row)
        gws = _rows(self._call("get", GW + "/search_gateway?rowCount=-1&searchPhrase="))
        out["main"] = _gw_for(gws, ["wan"])
        if out["identifier"]:
            out["gateway"] = _gw_for(gws, [out["identifier"], self.PORT_NAME])
        if out["identifier"] and out["enabled"]:
            out["stage"] = "done" if out["joined"] and out["gateway"] and self._order_ok(out["main"], out["gateway"]) \
                else "joined" if out["joined"] else "set"
        return out

    @staticmethod
    def _order_ok(main: dict | None, mine: dict | None) -> bool:
        if not main or not mine:
            return False
        pm, pb = _num(main.get("priority")), _num(mine.get("priority"))
        return (pm is not None and pb is not None and pb > pm
                and str(main.get("monitor_disable")) not in ("1", "true", "True")
                and str(mine.get("monitor_disable")) not in ("1", "true", "True"))

    def cards(self) -> list[str]:
        """The Wi-Fi cards the firewall offers for a new device (the pick-list of its own empty form)."""
        _w, form = self._form(f"{WL}/get_item")
        labels = we._option_labels(form.get("if")) or {}
        return sorted(k for k in labels if _WIFI_CARD.match(k))

    # ------------------------------------------------------------------ checks on what the person typed
    @staticmethod
    def clean(ssid: Any, passphrase: Any) -> tuple[str, str]:
        if not isinstance(ssid, str) or not ssid.strip() or len(ssid.encode("utf-8")) > 32 \
                or any(ord(c) < 32 or ord(c) == 127 for c in ssid):
            raise we.WriteError("Type the name of the phone's hotspot exactly as the phone shows it (at most 32 characters).")
        if not isinstance(passphrase, str) or not _PRINTABLE.match(passphrase):
            raise we.WriteError("The hotspot's password is 8 to 63 letters, digits or signs. Type it as the phone shows it.")
        return ssid, passphrase

    # ------------------------------------------------------------------ the plan (reads only)
    def plan(self, ssid: Any, passphrase: Any) -> Plan:
        ssid, passphrase = self.clean(ssid, passphrase)
        cur = self.look()
        if not cur["reuse"] and cur["wifi_rows"] > 1:
            raise we.WriteError("The firewall has more than one Wi-Fi device and Pazuzu cannot tell which one is for the phone. "
                                "Nothing was changed.")
        leftover = None
        if cur["reuse"] and not cur["parent"]:
            # A Wi-Fi device that is on no card any more (seen after a try that the firewall's own crash cut short): the
            # firewall refuses to save it back with no card, and refuses to move it to one. Pazuzu's own, with no port on
            # it, is taken away and made again; anyone else's is left alone and said.
            if cur.get("descr") == DEVICE_NAME and not cur["identifier"]:
                leftover = cur["uuid"]
                cur = dict(cur, reuse=False, uuid=None, device="", parent="", wifi_rows=0, mode="")
            else:
                raise we.WriteError("The firewall has a Wi-Fi device that is on no Wi-Fi card (Interfaces, Wireless, Devices), "
                                    "so Pazuzu cannot use it and left it alone. Remove it there, then press Set it up again. "
                                    "Nothing was changed.")
        if cur["reuse"] and cur["mode"] and cur["mode"] != "bss":
            raise we.WriteError("The firewall's Wi-Fi device is set up as an access point, not to join a phone's network, "
                                "so Pazuzu left it alone. Nothing was changed.")
        gws = _rows(self._call("get", GW + "/search_gateway?rowCount=-1&searchPhrase="))
        main = _gw_for(gws, ["wan"])
        if main is None or not self._gw_id(main):
            raise we.WriteError("The firewall shows no gateway for its internet port, so there is nothing to switch away from. "
                                "Nothing was changed.")
        if not self.switch or self.switch.status() is None:
            raise we.WriteError("The plugin on the firewall is older than this step needs. Update it in the plugin step.")
        card = cur["parent"]
        if not cur["reuse"]:
            cards = self.cards()
            if not cards:
                raise we.WriteError("The firewall does not list a Wi-Fi card it can use, so there is nothing to join the phone "
                                    "with. Nothing was changed.")
            card = cards[0]
        waiting = self._pending()                              # a port taken away earlier is only gone once that is applied
        facts = {"reuse": cur["reuse"], "uuid": cur["uuid"], "device": cur["device"], "identifier": cur["identifier"],
                 "card": card, "main": self._gw_id(main), "first": cur["wifi_rows"] == 0}
        steps: list[Step] = []
        lines = ["Set up the phone's hotspot as the backup internet"]
        if waiting:
            lines.append("Apply the interface changes that are already waiting on the firewall (Interfaces, Assignments shows "
                         "them), so a port taken away earlier is really gone before a new one is made")
            steps.append(Step("tidy", lambda: self._do_tidy()))
        if leftover:
            lines.append("Remove Pazuzu's own unfinished Wi-Fi device from an earlier try (it is on no card)")
            steps.append(Step("leftover", lambda: self._drop_leftover(leftover)))
        if cur["reuse"]:
            lines.append(f"Change the Wi-Fi device already on the firewall to join the network {ssid} (password set, not shown)")
        else:
            lines.append(f"Add a Wi-Fi device on {card} that joins the network {ssid} (password set, not shown)")
        lines.append(JOIN_WORDS)
        steps.append(Step("wifi", lambda: self._do_wifi(facts, ssid, passphrase)))
        lines.append(f"Give it a port on the firewall called {NAME}" if not cur["identifier"]
                     else f"Use the port already there ({cur['identifier']}, {NAME}) and switch it on")
        steps.append(Step("assign", lambda: self._do_assign(facts)))
        held = self._settings(main)                           # what is saved on it, not what the list shows
        if _off(held["monitor_disable"]):                     # checking on, with or without an address, is somebody's setting
            lines.append("Switch on the check of your main internet gateway"
                         + (f" (it asks {monitors_for(main)[0]} whether the internet answers)" if not held["monitor"] else "")
                         + ", so the firewall can tell when it is down")
        steps.append(Step("main", lambda: self._do_main(facts)))
        lines.append("Allow default gateway switching (System, Settings, General), so the firewall can hand the internet to the backup")
        steps.append(Step("switching", lambda: self._do_switching()))
        lines.append("Switch the port on and let it get its address from the phone (DHCP), then Apply")
        steps.append(Step("enable", lambda: self._do_enable(facts)))
        lines.append("Make the backup the second choice and check it too")
        lines.append("While the main internet is down, everything uses the phone's data")
        lines.append("It uses the installer account, which can open every page")
        digest = plan_digest("wifi-backup", {"ssid": ssid, "reuse": cur["reuse"], "device": cur["device"],
                                             "identifier": cur["identifier"], "card": card, "main": facts["main"],
                                             "tidy": waiting, "leftover": leftover or ""})
        return Plan(steps, lines, digest, ssid, facts)

    def plan_client(self, ssid: Any, passphrase: Any) -> Plan:
        """A management-only station join: join a Wi-Fi network to REACH a device (e.g. an access point), with NO gateway
        and NO default-route switching. Same wifi/assign/enable steps as plan(), minus the backup-uplink parts, so routing
        is never touched. The link is only a way in; drop it (undo) once the device is on our scheme."""
        ssid, passphrase = self.clean(ssid, passphrase)
        cur = self.look()
        if not cur["reuse"] and cur["wifi_rows"] > 1:
            raise we.WriteError("The firewall has more than one Wi-Fi device and Pazuzu cannot tell which one to use. "
                                "Nothing was changed.")
        leftover = None
        if cur["reuse"] and not cur["parent"]:
            if cur.get("descr") == DEVICE_NAME and not cur["identifier"]:
                leftover = cur["uuid"]
                cur = dict(cur, reuse=False, uuid=None, device="", parent="", wifi_rows=0, mode="")
            else:
                raise we.WriteError("The firewall has a Wi-Fi device that is on no Wi-Fi card (Interfaces, Wireless, Devices), "
                                    "so Pazuzu cannot use it and left it alone. Remove it there, then try again. Nothing was changed.")
        if cur["reuse"] and cur["mode"] and cur["mode"] != "bss":
            raise we.WriteError("The firewall's Wi-Fi device is set up as an access point, not to join a network, so Pazuzu "
                                "left it alone. Nothing was changed.")
        card = cur["parent"]
        if not cur["reuse"]:
            cards = self.cards()
            if not cards:
                raise we.WriteError("The firewall does not list a Wi-Fi card it can use to join a network. Nothing was changed.")
            card = cards[0]
        waiting = self._pending()
        facts = {"reuse": cur["reuse"], "uuid": cur["uuid"], "device": cur["device"], "identifier": cur["identifier"],
                 "card": card, "main": None, "first": cur["wifi_rows"] == 0, "client_only": True}
        steps: list[Step] = []
        lines = [f"Join the Wi-Fi network {ssid} to reach the device — no gateway, no routing change"]
        if waiting:
            lines.append("Apply the interface changes already waiting on the firewall first")
            steps.append(Step("tidy", lambda: self._do_tidy()))
        if leftover:
            lines.append("Remove Pazuzu's own unfinished Wi-Fi device from an earlier try")
            steps.append(Step("leftover", lambda: self._drop_leftover(leftover)))
        if cur["reuse"]:
            lines.append(f"Change the Wi-Fi device already on the firewall to join {ssid} (password set, not shown)")
        else:
            lines.append(f"Add a Wi-Fi device on {card} that joins {ssid} (password set, not shown)")
        lines.append(JOIN_WORDS)
        steps.append(Step("wifi", lambda: self._do_wifi(facts, ssid, passphrase)))
        lines.append(f"Give it a port on the firewall called {NAME}" if not cur["identifier"]
                     else f"Use the port already there ({cur['identifier']}, {NAME}) and switch it on")
        steps.append(Step("assign", lambda: self._do_assign(facts)))
        lines.append("Switch the port on and let it get an address (DHCP), then Apply")
        steps.append(Step("enable", lambda: self._do_enable(facts)))
        lines.append("No gateway is added and default-route switching is left alone: this link only reaches the device")
        digest = plan_digest("wifi-client", {"ssid": ssid, "reuse": cur["reuse"], "device": cur["device"],
                                             "identifier": cur["identifier"], "card": card,
                                             "tidy": waiting, "leftover": leftover or ""})
        return Plan(steps, lines, digest, ssid, facts)

    # ------------------------------------------------------------------ run it
    def apply(self, plan: Plan, gate: Callable[[str, Sequence[str]], bool]) -> list[Any]:
        """One passkey touch for the whole plan. Returns outcomes, each of which can be taken back. If a step is refused,
        the steps already done are taken back in reverse order and the refusal is raised."""
        if not gate(plan.digest, plan.lines):
            raise we.WriteError("Not approved with a passkey. Nothing was changed.")
        self.said = []
        outs = self._run(plan.steps)
        try:
            outs += self.finish(plan.facts)
        except we.WriteError as exc:                        # everything above is saved: say so, keep it takeable back
            self.said.append(f"The port is on, but the firewall could not be asked how it went: {exc} Press Finish to look again.")
        return outs

    def _run(self, steps: Sequence[Step]) -> list[Any]:
        done: list[tuple[str, Callable[[], None]]] = []
        try:
            for step in steps:
                back = step.do()
                if back is not None:
                    done.append((step.id, back))
        except we.WriteError as exc:
            undone, stuck = 0, []
            for sid, back in reversed(done):
                try:
                    back()
                    undone += 1
                except we.WriteError as why:              # what the firewall said, so the next report shows it
                    stuck.append(STEP_WORDS.get(sid, sid) + f" ({str(why)[:160]})")
            if not done:
                tail = ""
            elif not stuck:
                tail = (f" The {undone} thing(s) already done were taken back, so nothing is left half-done. You can press "
                        "Set it up to try again; if it is refused again, copy this message (it says what the firewall was given).")
            else:                                              # say so: "nothing is left half-done" would not be true
                tail = (f" {undone} of the {len(done)} things already done were taken back"
                        + ("." if undone else "; none could be.")
                        + f" Not taken back: {', '.join(reversed(stuck))}. Look at the firewall's own pages for "
                        + ("that" if len(stuck) == 1 else "those") + ", then press Set it up again.")
            raise we.WriteError(str(exc) + tail)
        return [self._outcome(sid, back) for sid, back in done]

    @staticmethod
    def _outcome(sid: str, back: Callable[[], None]):
        out = we.Outcome("wifi_backup", saved=True, undo_path=sid)
        out.revert = back                                          # type: ignore[attr-defined]
        return out

    def finish_plan(self) -> Plan:
        """Only the last part, for a port that is already on: wait for the phone, then set the order of the two
        connections. Reads only until it is approved."""
        cur = self.look()
        if not cur["identifier"] or not cur["enabled"]:
            raise we.WriteError("The Wi-Fi backup port is not switched on yet, so there is nothing to finish.")
        if cur["main"] is None:
            raise we.WriteError("The firewall shows no gateway for its internet port. Nothing was changed.")
        facts = {"device": cur["device"], "identifier": cur["identifier"], "main_monitor": ""}
        lines = ["Finish the Wi-Fi backup: wait for the phone to let the firewall join",
                 "Then make the backup the second choice and have the firewall check it with its own address",
                 "It uses the installer account, which can open every page"]
        step = Step("finish", lambda: self._finish_back(facts))
        return Plan([step], lines, plan_digest("wifi-backup-finish", {"device": cur["device"], "identifier": cur["identifier"]}),
                    cur["ssid"], facts)

    def finish_apply(self, plan: Plan, gate: Callable[[str, Sequence[str]], bool]) -> list[Any]:
        if not gate(plan.digest, plan.lines):
            raise we.WriteError("Not approved with a passkey. Nothing was changed.")
        self.said = []
        return self._run(plan.steps)

    def _finish_back(self, facts: dict) -> Callable[[], None] | None:
        outs = self.finish(facts)
        backs = [o.revert for o in outs]

        def back() -> None:
            for b in reversed(backs):
                b()
        return back if backs else None

    def finish(self, facts: dict) -> list[Any]:
        """Wait for the phone, then set the order of the two connections. A phone that has not let the port join is
        said plainly (not an error: the step can be run again). Returns outcomes that can be taken back."""
        device = facts.get("device")
        end = self.clock() + self.wait
        while True:
            if self._joined(self._port(self._ports(), device)):
                break
            if self.clock() >= end:
                self.said.append(self.NOT_JOINED)
                return []
            self.sleep(3)
        self.said.append("The phone let the firewall join: the port has an address.")
        try:
            outs = [self._outcome("order", b) for b in self._order(facts)]
        except we.WriteError as exc:
            self.said.append(f"Joined, but the order of the two connections was not set: {exc} Press Finish to try again.")
            return []
        return outs + self._standby(facts)

    STANDBY = True                       # BUILD 502: a Wi-Fi hotspot is joined only while the main internet is down

    def _standby(self, facts: dict) -> list[Any]:
        """BUILD 502 (the maintainer, 11 Nov 2026: "should only connect when wan is down", "try join-only-when-down"): once the
        order is set, the plugin keeps the Wi-Fi port's link off while the main gateway answers, and joins the hotspot
        when it stops answering. An older plugin cannot: the firewall then stays joined, said plainly."""
        ask = getattr(self.switch, "hotspot_standby", None)
        device = str(facts.get("device") or "")
        if not self.STANDBY or ask is None or not device or facts.get("client_only"):
            return []                    # BUILD 512: a link that only reaches an access point stays up; it is no backup
        main = _gw_for(self._gateways(), ["wan"])
        name = self._gw_id(main) if main else ""
        monitor = self._settings(main)["monitor"] if main else ""
        try:
            got = ask("on", {"device": device, "gateway": name, "monitor": monitor})
        except Exception as exc:  # noqa: BLE001 - the backup itself is set up either way
            got = {"ok": False, "error": str(exc)}
        if not isinstance(got, dict) or not got.get("ok"):
            self.said.append("The backup is set up and stays joined to the phone: " + str((got or {}).get("error") or
                             "the plugin did not take the reserve setting.") )
            return []
        self.said.append(STANDBY_WORDS)

        def back() -> None:
            res = ask("off", {})
            if not (isinstance(res, dict) and res.get("ok")):
                raise we.WriteError("The plugin would not stop keeping the hotspot in reserve.")
        return [self._outcome("standby", back)]

    # ------------------------------------------------------------------ the steps
    def _saved(self, res: Any, what: str) -> dict:
        if isinstance(res, dict) and str(res.get("result", "")) == "saved":
            return res
        bad = res.get("validations") if isinstance(res, dict) else None
        if isinstance(bad, dict) and bad:
            said = "; ".join(f"{str(k).split('.')[-1]}: {v}" for k, v in list(bad.items())[:4])
            raise we.WriteError(f"The firewall did not accept {what} ({said}). Nothing more was changed.")
        raise we.WriteError(f"The firewall did not save {what}. Nothing more was changed.")

    def _reconfigure(self, path: str) -> bool:
        """Press Apply. It waits longer than an ordinary page: the firewall answers when it has finished applying."""
        was = getattr(self.e, "timeout", None)
        if isinstance(was, (int, float)):
            self.e.timeout = max(float(was), APPLY_SECONDS)
        try:
            res = self._call("post", path, json={})
        except we.WriteError:
            return False
        finally:
            if isinstance(was, (int, float)):
                self.e.timeout = was
        return isinstance(res, dict) and str(res.get("status", "ok")).lower() in ("ok", "done", "")

    def _pending(self) -> bool:
        """True when the firewall says interface changes are waiting to be applied (the bar on Interfaces, Assignments).
        A page this firewall does not have counts as nothing waiting."""
        try:
            body = self._call("get", AS + "/pending")
        except we.WriteError:
            return False
        return isinstance(body, dict) and str(body.get("status")) == "pending"

    @staticmethod
    def _try_back(back: Callable[[], None]) -> None:
        try:
            back()
        except we.WriteError:
            pass

    def _prepare(self, form: dict, changes: dict[str, str], what: str, optional: Sequence[str] = (),
                 fixes: dict[str, str] | None = None, page: dict[str, str] | None = None,
                 free: Sequence[str] = ()) -> tuple[dict, dict]:
        """(before, after): the form as the firewall gave it, and the same with only `changes` altered. A name the form
        lacks, or a value its pick-list does not offer, is refused here, before anything is sent. `page` is what the
        page's own Save sends for fields the form may not carry at all."""
        before = {k: _flat(v) for k, v in form.items()}
        after = {k: _flat(v) for k, v in form.items()}
        for key, first in PAGE_FIRST_PICK.items():
            if key not in form or before.get(key) != "":
                continue
            labels = we._option_labels(form.get(key))
            if labels is None or ("" not in labels and first in labels):
                before[key] = after[key] = first               # what the page's own Save sends for it
        for key, value in (page or {}).items():
            if key not in form:
                before[key] = after[key] = value               # the form left it out; the page's Save does not
        for key, value in (fixes or {}).items():               # what the firewall said it needs, from its own list
            if before.get(key, "") == "":
                before[key] = after[key] = value
        for path, value in changes.items():
            node = _get_in(form, path)
            if node is we._MISSING:
                if path in optional:
                    continue
                raise we.WriteError(f"This firewall's own form for {what} has no field called {path}. Nothing was changed.")
            labels = we._option_labels(node)
            # `free`: a field the firewall shows as a list but that takes values typed in (addresses), not a fixed choice.
            if labels is not None and value not in labels and path not in free:
                offered = ", ".join(sorted(labels)[:10])
                raise we.WriteError(f"{value!r} is not one of the firewall's choices for {path} on {what}"
                                    + (f" (it offers: {offered})" if offered else "") + ". Nothing was changed.")
            _put(after, path, value)
        for body in (before, after):
            if body.get("channel") == "0":
                body["channel"] = ""                           # the form refuses 0; blank means automatic
        return before, after

    @staticmethod
    def _blank_fixes(res: Any, form: dict, sent: dict) -> dict[str, str]:
        """Fields the firewall refused as blank ("Option [] not in list") that its own form can fill in: the choice the
        page's Save is known to send, else the first of the field's own list. Nothing is guessed beyond that."""
        bad = res.get("validations") if isinstance(res, dict) else None
        out: dict[str, str] = {}
        if not isinstance(bad, dict):
            return out
        for key, msg in bad.items():
            field = str(key).split(".")[-1]
            if "not in list" not in str(msg) or sent.get(field, "") != "":
                continue
            labels = we._option_labels(form.get(field))
            pick = PAGE_FIRST_PICK.get(field) or PAGE_PORT_FIELDS.get(field) or (next(iter(labels)) if labels else "")
            if pick and (labels is None or pick in labels):
                out[field] = pick
        return out

    @staticmethod
    def _sent_note(res: Any, sent: dict) -> str:
        """For a refusal: what was sent for each refused field, so the next report says what the firewall was given.
        Never a password or key."""
        bad = res.get("validations") if isinstance(res, dict) else None
        if not isinstance(bad, dict):
            return ""
        parts = []
        for key in list(bad)[:4]:
            field = str(key).split(".")[-1]
            if _SECRETISH.search(field):
                continue
            value = sent.get(field)
            parts.append(f"{field} was " + ("not in the form the firewall gave" if value is None
                                            else "blank" if value == "" else f"sent as {value!r}"))
        return (" (" + "; ".join(parts) + ".)") if parts else ""

    def _post_form(self, post_path: str, wrapper: str, form: dict, changes: dict[str, str], what: str,
                   optional: Sequence[str] = (), page: dict[str, str] | None = None,
                   free: Sequence[str] = ()) -> tuple[dict, dict]:
        """Save the form with `changes`. If the firewall refuses a blank in a pick-list, send it once more with what the
        page's own Save would send. Returns (the firewall's answer, the form as it was, to put it back)."""
        fixes: dict[str, str] = {}
        for attempt in (1, 2):
            before, after = self._prepare(form, changes, what, optional, fixes, page, free)
            res = self._call("post", post_path, json={wrapper: after})
            if attempt == 1 and not (isinstance(res, dict) and str(res.get("result", "")) == "saved"):
                fixes = self._blank_fixes(res, form, after)
                if fixes:
                    continue
            try:
                return self._saved(res, what), before
            except we.WriteError as exc:
                note = self._sent_note(res, after)
                raise we.WriteError(str(exc) + note) from None
        raise we.WriteError(f"The firewall did not save {what}. Nothing more was changed.")     # not reached

    def _change(self, get_path: str, set_path: str, changes: dict[str, str], what: str,
                optional: Sequence[str] = (), page: dict[str, str] | None = None,
                free: Sequence[str] = ()) -> Callable[[], None]:
        """Read the firewall's own row, change only `changes`, send it back whole. Returns what puts it back."""
        wrapper, form = self._form(get_path)
        _res, before = self._post_form(set_path, wrapper, form, changes, what, optional, page, free)

        def back() -> None:
            res = self._call("post", set_path, json={wrapper: before})
            if not (isinstance(res, dict) and str(res.get("result")) == "saved"):
                raise we.WriteError(f"The firewall would not put {what} back. Look at its own page.")
        return back

    # -- 1. the Wi-Fi device
    # BUILD 502 ("the wizard didn't do it ... joined but after i manually changed those
    # settings"): a Wi-Fi device made earlier ("test") kept Minimum standard 11a (5 GHz only, so a 2.4 GHz hotspot was
    # never seen), Pure 802.11n on, WPA Mode WPA (the first one) and Pairwise "Both (legacy)", which a phone's
    # hotspot will not take. Joining a phone needs the device to look on 2.4 GHz too and to speak WPA2 with AES, so
    # those are set every time, each only where this firewall's own form has the field and offers the choice.
    JOIN_PICKS = (                       # (field, the choice's own key, else the label it is shown as, in words)
        ("standard", ("11ng",), r"^11ng$", "Minimum standard 11ng (2.4 GHz, so a phone's hotspot is seen)"),
        ("wpa.wpa_mode", ("2",), r"^WPA2$", "WPA Mode WPA2"),
        ("wpa.wpa_key_mgmt", ("WPA-PSK",), r"^Pre-?Shared Key$", "WPA Key Management Mode Pre-Shared Key"),
        ("wpa.wpa_pairwise", ("CCMP",), r"^AES", "WPA Pairwise AES (modern)"),
    )
    JOIN_OFF = (("puren", "Pure 802.11n mode off"), ("puren.enable", "Pure 802.11n mode off"),
                ("pureg", "Pure 802.11g mode off"), ("pureg.enable", "Pure 802.11g mode off"))

    @classmethod
    def _join_changes(cls, form: dict) -> tuple[dict[str, str], list[str]]:
        """What joining a phone's hotspot needs on this firewall's own Wi-Fi form, read from the form: {path: value}
        and the same in the page's own words. A field the form lacks, or a choice it does not offer, is left alone."""
        out: dict[str, str] = {}
        words: list[str] = []
        for path, keys, label_re, said in cls.JOIN_PICKS:
            node = _get_in(form, path)
            if node is we._MISSING:
                continue
            labels = we._option_labels(node)
            if labels is None:                              # a plain field: the key itself
                out[path] = keys[0]
                words.append(said)
                continue
            pick = next((k for k in keys if k in labels), None) or \
                next((k for k, lab in labels.items() if re.search(label_re, str(lab).strip(), re.I)), None)
            if pick is not None:
                out[path] = pick
                words.append(said)
        for path, said in cls.JOIN_OFF:
            node = _get_in(form, path)
            if node is not we._MISSING and not isinstance(node, dict):
                out[path] = "0"
                if said not in words:
                    words.append(said)
        return out, words

    def _do_wifi(self, facts: dict, ssid: str, passphrase: str) -> Callable[[], None]:
        changes = {"ssid": ssid, "wpa.enable": "1", "wpa.passphrase": passphrase, "mode": "bss"}
        if facts["reuse"]:
            _w, now = self._form(f"{WL}/get_item/{facts['uuid']}")
            extra, words = self._join_changes(now)
            changes.update(extra)
            put_back = self._change(f"{WL}/get_item/{facts['uuid']}", f"{WL}/set_item/{facts['uuid']}", changes,
                                    "the Wi-Fi device", optional=("mode",) + tuple(extra))

            def back() -> None:
                put_back()
                self._after_wifi()
            try:
                self._after_wifi()
                self._verify_ssid(facts["uuid"], ssid)
            except we.WriteError:
                self._try_back(back)
                raise
            self.said.append("The Wi-Fi device on the firewall now joins the hotspot you named"
                             + (" (" + ", ".join(words) + ")" if words else "") + ".")
            return back
        wrapper, form = self._form(f"{WL}/get_item")
        extra, words = self._join_changes(form)
        changes.update(extra)
        changes.update({"if": facts["card"], "descr": DEVICE_NAME})
        if facts.get("first"):
            # The firewall wants exactly one Wi-Fi device marked "used for common settings". Its empty form offers 0, and
            # refuses that for the first device there is ("Exactly one device should be marked ..."). A second device
            # keeps the form's 0: the first one already carries the mark.
            changes["use_common"] = "1"
        res, _before = self._post_form(f"{WL}/add_item", wrapper, form, changes, "the Wi-Fi device",
                                       optional=("use_common",) + tuple(extra))
        uuid = str(res.get("uuid", ""))
        if not _UUID.match(uuid):
            raise we.WriteError("The firewall saved a Wi-Fi device but did not say which row; look at its own page.")
        facts["uuid"] = uuid

        def remove() -> None:
            got = self._call("post", f"{WL}/del_item/{uuid}", json={})
            if not (isinstance(got, dict) and str(got.get("result")) == "deleted"):
                raise we.WriteError("The firewall would not remove the Wi-Fi device. Look at its own page.")
            self._after_wifi()
        try:
            self._after_wifi()
            self._verify_ssid(uuid, ssid)
            facts["device"] = self._clone_name(uuid)
        except we.WriteError:
            self._try_back(remove)
            raise
        self.said.append("Added a Wi-Fi device that joins the hotspot you named"
                         + (" (" + ", ".join(words) + ")" if words else "") + ".")
        return remove

    def _after_wifi(self) -> None:
        if not self._reconfigure(WL + "/reconfigure"):
            raise we.WriteError("The firewall saved the Wi-Fi device but would not apply it. "
                                "Press Apply on its Wi-Fi devices page.")

    def _verify_ssid(self, uuid: str, ssid: str) -> None:
        _w, form = self._form(f"{WL}/get_item/{uuid}")
        if _flat(form.get("ssid")) != ssid:
            raise we.WriteError("The firewall saved the Wi-Fi device but it did not read back the same. Look at its own page.")

    # -- 2. the port
    def _do_assign(self, facts: dict) -> Callable[[], None] | None:
        device = facts["device"]
        if not device:
            _w, form = self._form(f"{AS}/get_item")
            options = we._option_labels(form.get("if")) or {}
            fresh = sorted(k for k in options if _CLONE.match(k) and k.startswith(str(facts["card"]) + "_"))
            if len(fresh) != 1:
                raise we.WriteError("The firewall made the Wi-Fi device but Pazuzu could not tell which port name it has, "
                                    "so it was not assigned.")
            device = facts["device"] = fresh[0]
        row = self._port(self._ports(), device)
        if row is not None:
            ident = str(row.get("identifier"))
            self._known(ident)
            facts["identifier"] = ident
            self.said.append(f"{self.WHAT[0].upper() + self.WHAT[1:]} already has a port ({ident}); it was used as it is.")
            return None                                       # already a port; the enable step switches it on
        wrapper, form = self._form(f"{AS}/get_item")
        self._post_form(f"{AS}/add_item", wrapper, form, {"if": device, "descr": self.PORT_NAME, "enable": "0"}, "the port",
                        page=PAGE_PORT_FIELDS)
        row = self._port(self._ports(), device)
        if row is None or not _ID.match(str(row.get("identifier"))):
            raise we.WriteError("The firewall saved the port but did not show which one it is. Look at Interfaces, Assignments.")
        ident = facts["identifier"] = str(row["identifier"])
        self.said.append(f"Gave {self.WHAT} a port on the firewall ({ident}, called {self.PORT_NAME}), switched off for now.")

        def back() -> None:
            got = self._call("post", f"{AS}/del_item/{ident}", json={})
            if not (isinstance(got, dict) and str(got.get("result")) == "deleted"):
                raise we.WriteError("The firewall would not remove the port. Look at Interfaces, Assignments.")
            # Removing a port only marks it for removal: it stays on the firewall's list, and out of its own forms, until
            # Apply. Left like that, the next try finds the port, cannot open it, and stops.
            if not self._reconfigure(AS + "/reconfigure"):
                raise we.WriteError("The firewall took the port off its list but would not apply that. On the firewall open "
                                    "Interfaces, Assignments and press Apply changes.")
        return back

    def _drop_leftover(self, uuid: str) -> None:
        if not _UUID.match(str(uuid or "")):
            raise we.WriteError("The unfinished Wi-Fi device has no usual id, so it was left alone. Nothing was changed.")
        got = self._call("post", f"{WL}/del_item/{uuid}", json={})
        if not (isinstance(got, dict) and str(got.get("result")) == "deleted"):
            raise we.WriteError("The firewall would not remove the unfinished Wi-Fi device. Remove it on Interfaces, Wireless, "
                                "Devices, then press Set it up again. Nothing else was changed.")
        self.said.append("Removed Pazuzu's unfinished Wi-Fi device from an earlier try.")
        return None

    def _do_tidy(self) -> None:
        if not self._reconfigure(AS + "/reconfigure"):
            raise we.WriteError("The firewall has interface changes waiting and would not apply them. On the firewall open "
                                "Interfaces, Assignments, press Apply changes, then press Set it up again. Nothing was changed.")
        self.said.append("Applied the interface changes that were waiting on the firewall.")

    def _known(self, ident: str) -> None:
        """A port on the firewall's list must also be one its own form opens. One whose removal is still waiting to be applied
        is on the list (the list reads the saved configuration) but has no form, and going on from it would stop later."""
        try:
            self._form(f"{AS}/get_item/{ident}")
        except we.WriteError as exc:
            raise we.WriteError(f"The port {ident} is on the firewall's list but its own form for it will not open (a port taken "
                                "away earlier is still waiting to be applied). On the firewall open Interfaces, Assignments, "
                                f"press Apply changes if it offers that, then press Set it up again. Detail: {exc}") from None

    # -- 3. watch the main gateway
    @staticmethod
    def _gw_id(row: dict | None) -> str:
        """The row's own id (a uuid, or the gateway's name for one the firewall makes itself)."""
        if not row:
            return ""
        for key in ("uuid", "name"):
            val = str(row.get(key) or "")
            if _ID.match(val):
                return val
        return ""

    def _gateways(self) -> list[dict]:
        return _rows(self._call("get", GW + "/search_gateway?rowCount=-1&searchPhrase="))

    @staticmethod
    def _stored(row: dict | None) -> bool:
        """True when the firewall holds this gateway as a saved row. A gateway it makes by itself from a port's DHCP answer
        (its list row says `virtual`) has nothing saved yet: the list shows its name where a saved row shows its id."""
        return bool(row) and not row.get("virtual")

    def _settings(self, row: dict) -> dict[str, str]:
        """What is saved on a gateway: its own form for a saved one (the list shows a check address the firewall fills in by
        itself, which is not one anybody chose), the list's row for one the firewall made by itself (nothing saved on it)."""
        if self._stored(row):
            _w, form = self._form(f"{GW}/get_gateway/{self._gw_id(row)}")
            flat = {k: _flat(v) for k, v in form.items()}
            return {"monitor": str(flat.get("monitor") or "").strip(), "monitor_disable": str(flat.get("monitor_disable") or ""),
                    "priority": str(flat.get("priority") or row.get("priority") or "")}
        return {"monitor": "", "monitor_disable": str(row.get("monitor_disable") or "1"),
                "priority": str(row.get("priority") or "")}

    @staticmethod
    def _row_form(row: dict) -> dict[str, str]:
        """A gateway the firewall made by itself, as the fields of its form, from the list's row: for when the firewall's own
        form for it cannot be read. Only what the row says; the rest is left to the firewall's defaults."""
        form = {"disabled": "0", "gateway": "", "monitor": "", "monitor_disable": "1", "priority": "255", "weight": "1"}
        for key in ("name", "descr", "interface", "ipprotocol", "priority", "weight", "monitor_noroute", "monitor_disable"):
            val = row.get(key)
            if val is not None and not isinstance(val, (dict, list)) and str(val) != "":
                form[key] = str(val)
        return form

    def _edit_gateway(self, row: dict, changes: dict[str, str], what: str) -> Callable[[], None]:
        """Change a gateway. A saved one is read, changed and saved where it is. One the firewall makes by itself has nothing
        saved, so what is changed is saved as a row of its own with that name (that is what the firewall's page does when
        such a gateway is edited), and taking it back removes that row, so the gateway is the firewall's own again."""
        gid = self._gw_id(row)
        if self._stored(row):
            return self._change(f"{GW}/get_gateway/{gid}", f"{GW}/set_gateway/{gid}", changes, what)
        wrapper, form = "gateway_item", None
        try:
            wrapper, got = self._form(f"{GW}/get_gateway/{gid}")
            if _flat(got.get("name")) == str(row.get("name")):  # a form for some other (or no) gateway is not this one's
                form = got
        except we.WriteError:
            form = None                                          # it is in the trace; the row has what is needed
        if form is None:
            form = self._row_form(row)
        res, _before = self._post_form(f"{GW}/add_gateway", wrapper, form, changes, what)
        uuid = str(res.get("uuid", ""))
        if not _UUID.match(uuid):
            raise we.WriteError(f"The firewall saved {what} but did not say which row it is; look at System, Gateways.")

        def back() -> None:
            got = self._call("post", f"{GW}/del_gateway/{uuid}", json={})
            if not (isinstance(got, dict) and str(got.get("result")) == "deleted"):
                raise we.WriteError(f"The firewall would not remove what was saved for {what}. Look at System, Gateways.")
        return back

    def _do_main(self, facts: dict) -> Callable[[], None] | None:
        main = _gw_for(self._gateways(), ["wan"])
        gid = self._gw_id(main)
        if not main or not gid:
            raise we.WriteError("The firewall shows no gateway for its internet port. Nothing was changed.")
        held = self._settings(main)
        facts["main_monitor"] = held["monitor"]
        changes: dict[str, str] = {}
        if _off(held["monitor_disable"]):                     # only a gateway that is not checked is changed
            changes["monitor_disable"] = "0"
            if not facts["main_monitor"]:                     # and an address somebody chose is never replaced
                changes["monitor"] = monitors_for(main)[0]
        if not changes:
            self.said.append("The firewall was already checking the main internet gateway.")
            return None
        put_back = self._edit_gateway(main, changes, f"the main internet gateway {gid}")
        facts["main_monitor"] = changes.get("monitor") or facts["main_monitor"]
        self.said.append("The firewall now checks the main internet gateway" + (
            f" (it asks {changes['monitor']} whether the internet answers)." if "monitor" in changes else "."))

        def back() -> None:
            put_back()
            self._routing()
        self._routing()
        return back

    def _routing(self) -> None:
        self._reconfigure(GW + "/reconfigure")

    # -- 4. default gateway switching (the plugin)
    def _do_switching(self) -> Callable[[], None] | None:
        got = self.switch.gateway_switch("on")
        if not got.get("ok"):
            raise we.WriteError(str(got.get("error") or "The plugin did not switch default gateway switching on.")
                                + " Nothing more was changed.")
        if not got.get("changed"):
            self.said.append("Default gateway switching was already on.")
            return None                                        # it was already on: not ours to put back
        self.said.append("Default gateway switching is on.")

        def back() -> None:
            res = self.switch.gateway_switch("undo")
            if not res.get("ok"):
                raise we.WriteError(str(res.get("error") or "The plugin would not put default gateway switching back."))
        return back

    # -- 5. switch the port on
    def _do_enable(self, facts: dict) -> Callable[[], None]:
        ident = facts["identifier"]
        if not ident or not _ID.match(ident):
            raise we.WriteError("The port has no name on the firewall yet. Nothing more was changed.")
        put_back = self._change(f"{AS}/get_item/{ident}", f"{AS}/set_item/{ident}",
                                {"enable": "1", "type4": "dhcp", "blockpriv": "0", "blockbogons": "0"}, "the port",
                                optional=("blockpriv", "blockbogons"), page=PAGE_PORT_FIELDS)

        def back() -> None:
            put_back()
            self._reconfigure(AS + "/reconfigure")
        if not self._reconfigure(AS + "/reconfigure"):
            self._try_back(back)
            raise we.WriteError("The firewall saved the port but would not apply it. It was put back.")
        self.said.append("The port is on and asks the phone for an address.")
        return back

    # -- 6. the order of the two connections, once the port has an address
    def _order(self, facts: dict) -> list[Callable[[], None]]:
        deadline = self.clock() + 30
        while True:
            gws = self._gateways()
            main, mine = _gw_for(gws, ["wan"]), _gw_for(gws, [facts["identifier"], self.PORT_NAME])
            if mine is not None or self.clock() >= deadline:
                break
            self.sleep(3)
        if mine is None:
            self.said.append("The firewall has not made a gateway for the port yet. Press Finish in a minute.")
            return []
        if main is None:
            raise we.WriteError("The main internet gateway is not listed.")
        gid, mid = self._gw_id(mine), self._gw_id(main)
        pm, pb = _num(main.get("priority")), _num(mine.get("priority"))
        if not gid or not mid or pm is None or pb is None:
            raise we.WriteError("The firewall did not give the gateways usual names and priorities.")
        held_main, held_mine = self._settings(main), self._settings(mine)
        main_monitor = held_main["monitor"] or str(facts.get("main_monitor") or "")
        own = held_mine["monitor"]                             # a check address already chosen for it is kept
        changes: dict[str, str] = {}
        main_changes: dict[str, str] = {}
        if pb <= pm:                                           # a lower number is used first: the backup must be higher
            if pm >= 255:
                main_changes["priority"], changes["priority"] = "100", "200"
            else:
                changes["priority"] = "255"
        if _off(held_mine["monitor_disable"]):
            changes["monitor_disable"] = "0"
        if not own or own == main_monitor:
            pool = monitors_for(mine)
            changes["monitor"] = next((m for m in pool if m != main_monitor), pool[-1])
        if not changes and not main_changes:
            self.said.append("The backup is already the second choice and is being watched.")
            return []
        backs: list[Callable[[], None]] = []
        try:
            if main_changes:
                backs.append(self._edit_gateway(main, main_changes, f"the main internet gateway {mid}"))
            backs.append(self._edit_gateway(mine, changes, f"the backup gateway {gid}"))
        except we.WriteError:
            for b in reversed(backs):
                self._try_back(b)
            raise
        self._routing()

        def undo_all() -> None:
            for b in reversed(backs):
                b()
            self._routing()
        self.said.append("Made the backup the second choice" + (
            f" (number {changes['priority']}; the lower number is used first)" if "priority" in changes else "")
            + (f", and the firewall now asks {changes['monitor']} whether it answers" if "monitor" in changes else "") + ".")
        return [undo_all]


class UsbBackup(Hotspot):
    """A USB network port (a phone's USB tethering, or a USB network adapter to a second router) as the backup internet.

    The same steps as the hotspot, without the Wi-Fi device: the port is already there (ue0 and the like), so it is given a
    place on the firewall, the main gateway is watched, gateway switching is allowed, the port is switched on with DHCP,
    and once it has an address its gateway is made the second choice. Each step can be taken back."""
    PORT_NAME = "USBBackup"
    WHAT = "the USB port"
    STANDBY = False                      # a USB link is not a Wi-Fi join: nothing to hold in reserve
    NOT_JOINED = ("The port is on, but it has no address yet. A phone: plug it in, switch USB tethering on and unlock it "
                  "once (an iPhone asks to Trust this computer). A USB adapter: check its cable to the second router. "
                  "Then press Finish.")

    def __init__(self, engine: we.Engine, device: str, **kw):
        super().__init__(engine, **kw)
        from pazuzu_core.backup_plan import kind_of
        if not isinstance(device, str) or kind_of(device) != "usb":
            raise we.WriteError("That is not a USB network port. Nothing was changed.")
        self.device = device

    def look(self) -> dict:
        out: dict[str, Any] = {"card": None, "parent": "", "uuid": None, "ssid": "", "device": self.device, "identifier": "",
                               "joined": False, "enabled": False, "gateway": None, "main": None, "reuse": False,
                               "stage": "none", "mode": "", "wifi_rows": 0}
        ports = self._ports()
        if not any(str(r.get("device")) == self.device for r in ports):
            out["missing"] = True
        row = self._port(ports, self.device)
        if row:
            out["identifier"] = str(row.get("identifier"))
            out["enabled"] = str(row.get("enabled")) not in ("0", "False", "false", "")
            out["joined"] = self._joined(row)
        gws = self._gateways()
        out["main"] = _gw_for(gws, ["wan"])
        if out["identifier"]:
            out["gateway"] = _gw_for(gws, [out["identifier"], self.PORT_NAME])
        if out["identifier"].lower() in ("wan", "lan"):
            out["in_use"] = True
        if out["identifier"] and out["enabled"]:
            out["stage"] = "done" if out["joined"] and out["gateway"] and self._order_ok(out["main"], out["gateway"]) \
                else "joined" if out["joined"] else "set"
        return out

    def plan(self, *_ignored) -> Plan:                     # type: ignore[override]
        cur = self.look()
        if cur.get("in_use"):
            raise we.WriteError(f"{self.device} is already the firewall's {cur['identifier'].upper()} port, so it was left alone. "
                                "Nothing was changed.")
        if cur.get("missing") and not self._offered():
            raise we.WriteError(f"The firewall does not show {self.device} any more. Plug the phone or adapter in again, wait "
                                "ten seconds, and press Check again. Nothing was changed.")
        main = cur["main"]
        if main is None or not self._gw_id(main):
            raise we.WriteError("The firewall shows no gateway for its internet port, so there is nothing to switch away from. "
                                "Nothing was changed.")
        if not self.switch or self.switch.status() is None:
            raise we.WriteError("The plugin on the firewall is older than this step needs. Update it in the plugin step.")
        waiting = self._pending()
        facts = {"reuse": False, "uuid": None, "device": self.device, "identifier": cur["identifier"], "card": "",
                 "main": self._gw_id(main), "first": False}
        steps: list[Step] = []
        lines = [f"Set up the USB port {self.device} as the backup internet"]
        if waiting:
            lines.append("Apply the interface changes that are already waiting on the firewall (Interfaces, Assignments shows "
                         "them)")
            steps.append(Step("tidy", lambda: self._do_tidy()))
        lines.append(f"Give it a port on the firewall called {self.PORT_NAME}" if not cur["identifier"]
                     else f"Use the port already there ({cur['identifier']}) and switch it on")
        steps.append(Step("assign", lambda: self._do_assign(facts)))
        held = self._settings(main)
        if _off(held["monitor_disable"]):
            lines.append("Switch on the check of your main internet gateway"
                         + (f" (it asks {monitors_for(main)[0]} whether the internet answers)" if not held["monitor"] else "")
                         + ", so the firewall can tell when it is down")
        steps.append(Step("main", lambda: self._do_main(facts)))
        lines.append("Allow default gateway switching (System, Settings, General), so the firewall can hand the internet to the backup")
        steps.append(Step("switching", lambda: self._do_switching()))
        lines.append("Switch the port on and let it get its address by DHCP, then Apply")
        steps.append(Step("enable", lambda: self._do_enable(facts)))
        lines.append("Make the backup the second choice and check it too")
        lines.append("While the main internet is down, everything goes through this port")
        lines.append("It uses the installer account, which can open every page")
        digest = plan_digest("usb-backup", {"device": self.device, "identifier": cur["identifier"], "main": facts["main"],
                                            "tidy": waiting})
        return Plan(steps, lines, digest, "", facts)

    def _offered(self) -> bool:
        """The port is on the firewall's own pick-list of ports that can be assigned."""
        try:
            _w, form = self._form(f"{AS}/get_item")
        except we.WriteError:
            return False
        return self.device in (we._option_labels(form.get("if")) or {})

    def finish_plan(self) -> Plan:
        cur = self.look()
        if not cur["identifier"] or not cur["enabled"]:
            raise we.WriteError("The USB backup port is not switched on yet, so there is nothing to finish.")
        if cur["main"] is None:
            raise we.WriteError("The firewall shows no gateway for its internet port. Nothing was changed.")
        facts = {"device": cur["device"], "identifier": cur["identifier"], "main_monitor": ""}
        lines = ["Finish the USB backup: wait for the port to get an address",
                 "Then make the backup the second choice and have the firewall check it with its own address",
                 "It uses the installer account, which can open every page"]
        step = Step("finish", lambda: self._finish_back(facts))
        return Plan([step], lines, plan_digest("usb-backup-finish", {"device": cur["device"], "identifier": cur["identifier"]}),
                    "", facts)
