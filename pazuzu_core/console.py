"""The Hanbi console, alpha: a local, read-only web page.

Usage:
    python -m pazuzu_core.console --offline           # sample data, no firewall
    python -m pazuzu_core.console                     # live, read-only, lab variables set
    python -m pazuzu_core.console --port 8765

Then open http://127.0.0.1:8765/ in a browser on the same PC.

What it is: the posture, the staged turn-on plan and the guard's journal,
drawn from the same read-only checks the command-line tools use. What it is
not: it cannot change anything. Every request other than GET is refused, and
no code path here builds a mutation client. Starting a stage stays a
command-line step in this build.

Safe by construction for a local tool: it binds to loopback only, refuses
requests whose Host header is not loopback (guards against DNS rebinding),
sends no-store and a strict content policy, and renders firewall text as
text, never as markup. There is no sign-in yet; that arrives with the
on-box console.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import parse_qs, quote, urlparse
import urllib.request

from pazuzu_core import feed_pin

from pazuzu_core.change_guard import ChangeGuard, GuardError
from pazuzu_core import box_controls, rule_copies
from pazuzu_core.egress_drift import UNREADABLE_SETTINGS, admin_session_verdict, evaluate
from pazuzu_core.opnsense_scanner import SYSTEM_DEVICES, build_interface_report
from pazuzu_core.posture import DRIFTED, ENFORCED, UNVERIFIED
from pazuzu_core.stock_rules import DISABLED_NOTE, detect_stock_rules
from pazuzu_core.staged_enabling import blocker_kind, build_plan, shield_level
from pazuzu_core import ap_openwrt, backup_plan
from pazuzu_core import oui, rdns
from pazuzu_core import strings as _strings

DEFAULT_JOURNAL = Path("scan_results") / "change_journal.json"
DEFAULT_ZONES = Path("scan_results") / "zone_assignment.json"
DEFAULT_PORT = 8765
SETTLE_READS = 2  # a port counts as down only after this many readings in a row
CACHE_SECONDS = 10
FAIL_SECONDS = 20          # after a failed read, do not ask the firewall again for this long (the page stays alive)
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}

TITLES = {
    "ipv6": "IPv6 is off, everywhere",
    "client_ntp": "Devices use the firewall for time",
    "dns_bypass": "Devices use only the firewall for DNS",
    "quic": "No QUIC to the internet",
}
TODAY_TEXT = {
    "ipv6": "An enabled rule still allows IPv6.",
    "client_ntp": "An enabled rule lets devices reach time servers directly.",
    "dns_bypass": "An enabled rule lets a device use any resolver and skip the blocklist.",
    "quic": "An enabled rule lets UDP 443 reach the internet.",
}


# ---------------------------------------------------------------- sample data
def _row(uuid, description, interface, enabled, *, protocol="TCP", ipprotocol="inet",
         source="lan", destination="(self)", ports="53", sort="20000.1"):
    return {
        "uuid": uuid, "description": description, "sort_order": sort,
        "enabled": "1" if enabled else "0", "action": "pass", "quick": "1",
        "interface": interface, "direction": "in", "ipprotocol": ipprotocol,
        "protocol": protocol, "source_net": source, "source_not": "0",
        "destination_net": destination, "destination_not": "0",
        "destination_port": ports,
    }


def sample_inventory(scenario: str = "today") -> dict[str, Any]:
    """A lab-shaped rule list. 'today': stock allow-all rules on, ours off.
    'after': ours on, the stock rules off and annotated."""
    after = scenario == "after"
    rows = [
        _row("mgmt-opt1", "PAZUZU:PZ-MGMT-001:Management zone to firewall HTTPS [opt1/TCP]",
             "opt1", after, source="opt1", ports="443", sort="19000.1"),
    ]
    for zone in ("opt1", "lan", "opt2"):
        for proto in ("TCP", "UDP"):
            rows.append(_row(
                f"core-{zone}-{proto.lower()}",
                f"PAZUZU:PZ-CORE-001:Internal zones to firewall [{zone}/{proto}]",
                zone, after, protocol=proto, source=zone, ports="53,67,123"))
    rows.append(_row(
        "out-lan", "PAZUZU:PZ-TRUST-010:Allow approved trusted outbound [lan/TCP]",
        "lan", after, destination="PZ_PRIVATE_NETS", ports="80,443",
        sort="20000.2"))
    rows[-1]["destination_not"] = "1"
    stock4 = _row("stock-v4", "Default allow LAN to any rule", "lan", not after,
                  protocol="any", destination="any", ports="", sort="400000.0000001")
    stock6 = _row("stock-v6", "Default allow LAN IPv6 to any rule", "lan", not after,
                  protocol="any", ipprotocol="inet6", destination="any", ports="",
                  sort="400000.0000011")
    if after:
        stock4["description"] += f" {DISABLED_NOTE}"
        stock6["description"] += f" {DISABLED_NOTE}"
    rows += [stock4, stock6]
    return {"rows": rows}


SAMPLE_ALIASES = {"PZ_PRIVATE_NETS": "10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16"}

SAMPLE_INTERFACES = {"rows": [
    {"device": "em0", "identifier": "wan", "description": "WAN", "is_physical": True,
     "enabled": True, "status": "no carrier", "config": {}},
    {"device": "em1", "identifier": "lan", "description": "LAN", "is_physical": True,
     "enabled": True, "status": "up", "config": {}},
    {"device": "em2", "identifier": "opt1", "description": "", "is_physical": True,
     "enabled": True, "status": "up", "config": {}},
    {"device": "ue0", "identifier": "", "description": "", "is_physical": True,
     "enabled": False, "status": "no carrier", "config": {}},
]}
SAMPLE_ZONES = {"assignments": {
    "wan": {"state": "bound"}, "trusted": {"state": "bound"},
    "management": {"state": "unconfigured"}}}


# -------------------------------------------------------------------- state
def _rule_words(uuid: str, row: Mapping[str, Any] | None) -> str:
    """A rule that has no name, said in words so it can be found: what it does, for which traffic, and the start of its id."""
    short = str(uuid)[:8]
    if not isinstance(row, Mapping):
        return str(uuid)
    fam = {"inet": "IPv4", "inet6": "IPv6", "inet46": "IPv4 and IPv6"}.get(str(row.get("ipprotocol") or "").lower(), "")
    proto = str(row.get("protocol") or "")
    port = str(row.get("destination_port") or "")
    what = " ".join(x for x in (str(row.get("action") or "").lower(), fam, "" if proto in ("", "any") else proto) if x)
    where = ("on " + str(row.get("interface"))) if row.get("interface") else ""
    path = "from " + (str(row.get("source_net") or "any")) + " to " + (str(row.get("destination_net") or "any")) \
        + (" port " + port if port else "")
    return "Rule with no name (" + ", ".join(x for x in (what, where, path) if x) + "), id " + short


def _finding_name(f: Mapping[str, Any], by_uuid: Mapping[str, Any] | None) -> str:
    if f.get("description"):
        return str(f["description"])
    return _rule_words(str(f.get("uuid") or ""), (by_uuid or {}).get(str(f.get("uuid"))))


def _side(net: Any, negated: Any, port: Any) -> str:
    text = str(net or "").strip() or "any"
    text = text.replace("(self)", "the firewall itself")
    if text != "any" and str(negated).strip().lower() in ("1", "true", "yes"):
        text = "everything except " + text
    port = str(port or "").strip()
    return text + (" port " + port if port and port.lower() != "any" else "")


def _rule_detail(row: Mapping[str, Any] | None) -> str:
    """What a rule allows, in words, so a person auditing their own firewall can judge it without opening the rules
    page: action, IP version, protocol, where it sits, which way, and from where to where on which ports."""
    if not isinstance(row, Mapping) or not row.get("action"):
        return ""
    fam = {"inet": "IPv4", "inet6": "IPv6", "inet46": "IPv4 and IPv6"}.get(str(row.get("ipprotocol") or "").lower(), "")
    proto = str(row.get("protocol") or "")
    what = " ".join(x for x in (str(row.get("action") or "").lower(), fam, "" if proto.lower() in ("", "any") else proto) if x)
    iface = str(row.get("interface") or "").strip()
    where = ("on " + iface) if iface else "floating (all interfaces)"
    way = {"in": "inbound", "out": "outbound", "any": "both ways"}.get(str(row.get("direction") or "").lower(), "")
    path = "from " + _side(row.get("source_net"), row.get("source_not"), row.get("source_port")) \
        + " to " + _side(row.get("destination_net"), row.get("destination_not"), row.get("destination_port"))
    return ", ".join(x for x in (what, where, way, path) if x)


def _finding_text(f: Mapping[str, Any], by_uuid: Mapping[str, Any] | None) -> str:
    """The finding for the "Because of" list: the rule's name and what it allows."""
    name = _finding_name(f, by_uuid)
    row = (by_uuid or {}).get(str(f.get("uuid"))) if f.get("description") else None
    detail = _rule_detail(row)
    return name + " (" + detail + ")" if detail else name


def _ipv4_fixable(findings, by_uuid: Mapping[str, Any]) -> list[dict[str, str]]:
    """The rules behind the IPv6 finding that one change fixes: an enabled pass rule set to IPv4 and IPv6, made IPv4 only.
    Not an IPv6-only rule (made IPv4 it would let new traffic through) and not the country block's own two exception rules
    (they have their own button). At most ten."""
    out: list[dict[str, str]] = []
    for f in findings or []:
        uuid = str(f.get("uuid") or "")
        row = by_uuid.get(uuid)
        if not uuid or not isinstance(row, Mapping):
            continue
        if str(row.get("ipprotocol") or "").strip().lower() != "inet46" or str(row.get("action") or "").strip().lower() != "pass":
            continue
        if str(row.get("description") or "").startswith("Pazuzu: let the "):
            continue
        out.append({"uuid": uuid, "name": _finding_name(f, by_uuid)})
        if len(out) >= 10:
            break
    return out


def _off_fixable(findings, by_uuid: Mapping[str, Any]) -> list[dict[str, str]]:
    """The person's own enabled pass rules behind a drift finding, each of which can be switched off from the card. Never
    Pazuzu's own rules (the plan handles those) nor the stock allow-all rules (the plan's own stage switches them off).
    At most ten."""
    out: list[dict[str, str]] = []
    for f in findings or []:
        uuid = str(f.get("uuid") or "")
        row = by_uuid.get(uuid)
        if not uuid or not isinstance(row, Mapping):
            continue
        desc = str(row.get("description") or "")
        if desc.startswith("PAZUZU:") or desc.startswith("Default allow") or desc.startswith("Pazuzu: "):
            continue
        if str(row.get("action") or "").strip().lower() != "pass":
            continue
        out.append({"uuid": uuid, "name": _finding_name(f, by_uuid)})
        if len(out) >= 10:
            break
    return out


def _control_rows(report: Mapping[str, Any], services: Mapping[str, Any] | None = None,
                  rows: Iterable[Mapping[str, Any]] | None = None) -> list[dict[str, Any]]:
    meanings = dict(UNREADABLE_SETTINGS)
    by_uuid = {str(r.get("uuid")): r for r in (rows or []) if isinstance(r, Mapping)}
    out = []
    for item in report["controls"]:
        name = item["control"]
        status = item["status"]
        if name in TITLES:
            title = TITLES[name]
            text = TODAY_TEXT[name] if status == DRIFTED else (
                "Meets its target." if status == ENFORCED else item["detail"])
        else:
            title = meanings.get(name, name)
            title = title[:1].upper() + title[1:]
            text = ("Needs a read the firewall does not offer yet, so you confirm it."
                    if status == UNVERIFIED else item["detail"] + ".")
        row_out = {
            "id": name, "title": title, "status": status, "text": text,
            "findings": [_finding_name(f, by_uuid) for f in item["findings"]],
            "finding_groups": _group([_finding_text(f, by_uuid) for f in item["findings"]]),
        }
        if name == "ipv6":
            row_out["ipv4_fixable"] = _ipv4_fixable(item["findings"], by_uuid)
        if name in ("dns_bypass", "client_ntp", "quic"):
            row_out["off_fixable"] = _off_fixable(item["findings"], by_uuid)
            # The rules it could not judge (a destination list whose contents it could not read): named, so the card can
            # offer to switch one off, or let the person say they checked it.
            unchecked = item.get("unchecked") or []
            row_out["unchecked"] = [_finding_text(f, by_uuid) for f in unchecked][:10]
            row_out["unchecked_off"] = _off_fixable(unchecked, by_uuid)
        out.append(row_out)
    seen = admin_session_verdict(services)
    if seen is None:
        out.append({
            "id": "admin_session", "title": "Admin session idle timeout is 15 minutes",
            "status": UNVERIFIED,
            "text": "The firewall default is hours. The app could not read it, so you confirm it.",
            "findings": [],
            "finding_groups": [],
        })
    else:
        status, detail, found = seen
        texts = [f["description"] for f in found]
        out.append({
            "id": "admin_session", "title": "Admin session idle timeout is 15 minutes",
            "status": status, "text": "Meets its target." if status == ENFORCED else detail + ".",
            "findings": texts, "finding_groups": _group(texts),
        })
    for cid, title, status, detail, found in box_controls.rows(services):
        out.append({
            "id": cid, "title": title, "status": status,
            "text": "Meets its target." if status == ENFORCED else detail + ".",
            "findings": found, "finding_groups": _group(found),
        })
    return out


def _group(texts: list[str]) -> list[dict[str, Any]]:
    """Same cause named several times (one per rule) shows once, with a count."""
    counts: dict[str, int] = {}
    for text in texts:
        counts[text] = counts.get(text, 0) + 1
    return [{"text": t, "count": n} for t, n in counts.items()]


# ------------------------------------------------------------------- access
def _link(status: str) -> str:
    status = status.strip().lower()
    return status if status in ("up", "no carrier") else "down"


def backup_candidates(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Ports that could carry a backup internet connection, by what they are."""
    return backup_plan.candidates(report)


def access_state(inventory: Mapping[str, Any], interfaces: Mapping[str, Any] | None,
                 zones: Mapping[str, Any] | None, down_counts: dict[str, int] | None,
                 *, ports_error: str | None = None, gateways: Any = None) -> dict[str, Any]:
    """Live facts for the Access board. Addresses are never copied.

    The firewall's own status can flicker, so a port that reads down is shown
    as "checking" until it has read down SETTLE_READS times in a row.
    `down_counts` is the caller's memory of those readings (None: no waiting)."""
    ports = None
    backup = None
    backup_steps = None
    if interfaces is not None:
        ports = []
        report = build_interface_report(dict(interfaces))
        backup = backup_candidates(report)
        backup_steps = backup_plan.plan(report, gateways)
        for item in report["interfaces"]:
            if item["system"] or not item["assigned"] or item["device"] in SYSTEM_DEVICES:
                continue
            link = _link(item["status"])
            if down_counts is not None:
                key = item["device"]
                if link == "up":
                    down_counts[key] = 0
                else:
                    down_counts[key] = down_counts.get(key, 0) + 1
                    if down_counts[key] < SETTLE_READS:
                        link = "checking"
            ports.append({"name": item["description"] or item["identifier"],
                          "device": item["device"], "link": link})
    zone_rows = None
    if isinstance(zones, Mapping) and isinstance(zones.get("assignments"), Mapping):
        zone_rows = []
        for zone, a in zones["assignments"].items():
            state = str((a or {}).get("state") or "")
            zone_rows.append({"zone": zone, "state": (
                "mapped" if state in ("bound", "pending_assignment", "pending_creation")
                else "not set up" if state == "unconfigured" else state or "unknown")})
    found = detect_stock_rules(inventory)["found"]
    lifeline = any(i["role"].startswith("lifeline_") and i["enabled"] for i in found)
    return {"ports": ports, "ports_error": ports_error, "zones": zone_rows,
            "lifeline": lifeline, "backup": backup, "backup_plan": backup_steps}


def build_state(inventory: Mapping[str, Any], aliases: Mapping[str, Any], *,
                source: str, scenario: str | None = None,
                journal: Path | str | None = DEFAULT_JOURNAL,
                access: Mapping[str, Any] | None = None,
                lab: bool = False, can_change: bool = False,
                trial: bool = False, settings: Mapping[str, Any] | None = None,
                services: Mapping[str, Any] | None = None,
                confirmed: Iterable[str] = ()) -> dict[str, Any]:
    report = evaluate(inventory, aliases, settings, services)
    controls = _control_rows(report, services, inventory.get("rows") if isinstance(inventory, Mapping) else None)
    said = set(confirmed or ())
    for c in controls:                      # a control the firewall cannot be asked about, confirmed by the person
        c["confirmed"] = c["status"] == UNVERIFIED and c["id"] in said
    counts = {s: sum(1 for c in controls if c["status"] == s)
              for s in (ENFORCED, DRIFTED, UNVERIFIED)}
    if counts[DRIFTED]:
        hero = "Not happy yet"
    elif any(c["status"] == UNVERIFIED and not c["confirmed"] for c in controls):
        hero = "Almost there"
    else:
        hero = "Happy"
    labels = {str(r.get("uuid")): str(r.get("description") or "")
              for r in inventory.get("rows", []) if isinstance(r, dict)}
    families = {"inet": "IPv4", "inet6": "IPv6", "inet46": "IPv4 and IPv6"}
    details = {str(r.get("uuid")): families.get(str(r.get("ipprotocol") or "").lower(), "")
               for r in inventory.get("rows", []) if isinstance(r, dict)}
    plan = build_plan(inventory, lab_lifeline=lab)
    copies = rule_copies.find(inventory.get("rows", []) if isinstance(inventory, Mapping) else [])
    return {
        "copies": {"extra": copies["extra"], "rules": len(copies["groups"]),
                   "names": [rule_copies.plain_name(g["name"]) for g in copies["groups"]][:8]},
        "read_only": not can_change,
        "can_change": can_change,
        "lab": lab,
        "trial": bool(trial),
        "details": details,
        "source": source,
        "scenario": scenario,
        "generated_at": time.strftime("%H:%M:%S"),
        "hero": hero,
        "counts": counts,
        "controls": controls,
        "confirmed_ids": sorted(c["id"] for c in controls if c["confirmed"]),
        "plan": plan,
        "blocker_kinds": {st["id"]: [blocker_kind(b) for b in st.get("blockers", [])]
                          for st in plan["stages"]},
        "shield": shield_level(inventory),
        "labels": labels,
        "access": dict(access) if access is not None else access_state(
            inventory, None, None, None),
        "change": _change_snapshot(journal),
    }


def _change_snapshot(journal: Path | str | None) -> dict[str, Any]:
    if journal is None or not Path(journal).exists():
        return {"active": False}
    try:
        return ChangeGuard(None, journal).snapshot()
    except GuardError as exc:
        return {"active": False, "error": str(exc)}


def _why_no_answer(exc: Exception) -> str:
    """A failed knock at the plugin, in words a person can act on. Never includes the token."""
    import socket as _socket
    code = getattr(exc, "code", None)
    if isinstance(code, int):
        return "the plugin refused this device's code" if code == 401 else f"the plugin answered with an error ({code})"
    reason = getattr(exc, "reason", None) or exc
    text = str(reason)
    low = text.lower()
    if isinstance(reason, (_socket.timeout, TimeoutError)) or "timed out" in low:
        return "no answer: timed out, so something may be blocking port 8787"
    if isinstance(reason, ConnectionRefusedError) or "refused" in low:
        return "nothing is listening on port 8787 yet"
    if "unreachable" in low or "no route" in low:
        return "no route to the firewall from this device"
    return text.splitlines()[0][:80] if text else type(exc).__name__


_NAMES = rdns.Names()


def _ap_find(source) -> dict:
    """Look for an OpenWrt access point among the devices the firewall already knows. Read-only."""
    clients: list = []
    try:
        got = source.box.read()
        status = got.get("status") if got.get("connected") else None
        if status is None and source.api_feed is not None:
            status = source.api_feed.sample()
        clients = (status or {}).get("clients") or []
    except Exception:
        clients = []
    # BUILD 488 (the maintainer, 10 Nov 2026: prod "didnt find the gale on its network"): every device the box knows, the likely
    # ones first, as the phone's Wi-Fi step does; a fixed-address access point with no name was not on the short list
    out = ap_openwrt.find(clients, oui.vendor, everyone=True)
    out["devices_known"] = len(clients)
    return out


class BoxLink:
    """The link to the box plugin's feed. Held in memory only. It reads, and it may ask for one thing: the
    Pazuzu Wi-Fi back door to be set up (after a passkey approval, which the caller has already had)."""

    def __init__(self, fetcher: Callable[[str, str, str], Any] | None = None,
                 poster: Callable[[str, str, str, dict], Any] | None = None,
                 updater: Callable[..., Any] | None = None):
        self._updater = updater
        self.url: str | None = None
        self.token: str | None = None
        self.last_error = ""           # why the last knock got no answer, in plain words
        self._fetch = fetcher or self._http
        self._poster = poster

    @staticmethod
    def _http(url: str, token: str, path: str) -> Any:
        req = urllib.request.Request(url.rstrip("/") + path,
                                     headers={"Authorization": "Bearer " + token})
        wait = 12 if path == "/internet" else 5           # the internet check takes a few seconds on purpose
        if path in ("/time_zone", "/hardware"):
            wait = 12                                    # the time zone list is asked of PHP the first time; the hardware is read by a few commands
        with feed_pin.urlopen(req, timeout=wait) as r:  # noqa: S310 (private address only)
            return json.loads(r.read(2_000_000))

    def connect(self, url: Any, token: Any) -> None:
        if not isinstance(url, str) or not isinstance(token, str) or not token \
                or len(token) > 200 or len(url) > 200:
            raise ValueError("Give the box's address and its token.")
        parsed = urlparse(url.strip())
        host = parsed.hostname or ""
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            raise ValueError("Use the box's address as numbers, for example http://192.168.1.1:8787")
        if parsed.scheme not in ("http", "https") or not (addr.is_private or addr.is_loopback):
            raise ValueError("The box must be on a private address, with http or https.")
        self.url, self.token = url.strip().rstrip("/"), token
        if self._fetch is self._http:                    # BUILD 565: the feed's key pin on first use (feed_pin.py)
            try:
                feed_pin.learn_soon(self.url)
            except Exception:  # noqa: BLE001 - plain HTTP as before
                pass

    @staticmethod
    def _http_post(url: str, token: str, path: str, body: dict) -> Any:
        raw = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url.rstrip("/") + path, data=raw, method="POST",
                                     headers={"Authorization": "Bearer " + token,
                                              "Content-Type": "application/json"})
        with feed_pin.urlopen(req, timeout=130 if path == "/ipv6_none" else 45 if path in ("/report", "/otp_switch") else 20 if path in ("/otp_server", "/gateway_switch", "/hotspot_standby", "/time_zone") else 5) as r:  # noqa: S310 (private address only)
            return json.loads(r.read(65536))

    def post(self, path: str, body: dict) -> Any:
        """Tell the box how a pause request went, its "Sent to Pazuzu" line, which setup step the wizard is on, or
        the access card (BUILD 438). The only writes the box feed accepts this way."""
        if not self.url or path not in ("/pause_state", "/sent_line", "/setup_step", "/access_card"):
            raise ValueError("not connected")
        return (self._poster or self._http_post)(self.url, self.token, path, body)

    def ap_watch(self, ip: str, password: str = "", forget: bool = False) -> dict:
        """0.6.97: ask the box to look after an access point by key (its password used once, passed on to the box only
        and kept nowhere), or to forget it. {"error": ...} in the box's own words when it would not."""
        if not self.url:
            return {"error": "The manager is not linked to the box."}
        path = "/ap/forget" if forget else "/ap/enroll"
        body = {"ip": ip} if forget else {"ip": ip, "password": password}
        req = urllib.request.Request(self.url.rstrip("/") + path, data=json.dumps(body).encode("utf-8"), method="POST",
                                     headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
        try:
            with feed_pin.urlopen(req, timeout=60) as r:  # noqa: S310 (the box's own private address)
                return json.loads(r.read(65536))
        except urllib.error.HTTPError as exc:
            try:
                got = json.loads(exc.read(4096) or b"{}")
            except ValueError:
                got = {}
            return {"error": str((got or {}).get("error") or f"The box said no ({exc.code}).")}
        except Exception as exc:  # noqa: BLE001
            return {"error": f"The box did not answer ({type(exc).__name__})."}

    def can(self, what: str) -> bool:
        """Does the plugin on the box say it will do `what`? An older plugin does not say, so the answer is no."""
        if not self.url:
            return False
        try:
            return what in (self._fetch(self.url, self.token, "/ping").get("can") or [])
        except Exception:
            return False

    def wifi_setup(self, ssid: str, passphrase: str, close_after_use: bool = False) -> bool:
        """Ask the plugin to set the Wi-Fi up. The only request of this kind; nothing else is sent this way."""
        if not self.url:
            raise ValueError("not connected")
        body = {"ssid": ssid, "passphrase": passphrase}
        if close_after_use:
            body["close_after_use"] = True
        got = (self._poster or self._http_post)(self.url, self.token, "/wifi_setup", body)
        return bool(got) and got.get("state") == "running"

    def otp_server_status(self) -> dict | None:
        """What the plugin reads about the one-time-code login server. None when it cannot say (no plugin, an
        older plugin, or no answer)."""
        if not self.url or not self.can("otp_server"):
            return None
        try:
            got = self._fetch(self.url, self.token, "/otp_server")
        except Exception:
            return None
        return got if isinstance(got, dict) and got.get("state") else None

    def otp_server(self, action: str) -> dict:
        """Ask the plugin to add (or take away) the one-time-code login server. Only those two words are sent."""
        if not self.url:
            raise ValueError("not connected")
        if action not in ("add", "remove"):
            raise ValueError("unknown action")
        got = (self._poster or self._http_post)(self.url, self.token, "/otp_server", {"action": action})
        return got if isinstance(got, dict) else {"ok": False, "error": "The plugin gave no answer."}

    def otp_switch_status(self) -> dict | None:
        """Is the web page's sign-in being switched to the code server, and how long is left. None when the plugin
        cannot say (an older plugin, or no answer)."""
        if not self.url or not self.can("otp_switch"):
            return None
        try:
            got = self._fetch(self.url, self.token, "/otp_switch")
        except Exception:
            return None
        return got if isinstance(got, dict) and got.get("state") else None

    def otp_switch(self, action: str, user: str | None = None) -> dict:
        """Ask the plugin to point the web page at the code server ("on", for one named user), to keep that
        ("keep") or to put it back ("undo"). Nothing else is sent this way."""
        if not self.url:
            raise ValueError("not connected")
        if action not in ("on", "keep", "undo"):
            raise ValueError("unknown action")
        body: dict = {"action": action}
        if action == "on":
            if not isinstance(user, str) or not user:
                raise ValueError("a user is needed")
            body["user"] = user
        got = (self._poster or self._http_post)(self.url, self.token, "/otp_switch", body)
        return got if isinstance(got, dict) else {"ok": False, "error": "The plugin gave no answer."}

    def gateway_switch_status(self) -> dict | None:
        """Is "allow default gateway switching" ticked on the firewall, read by the plugin. None when the plugin cannot
        say (an older plugin, or no answer)."""
        if not self.url or not self.can("gateway_switch"):
            return None
        try:
            got = self._fetch(self.url, self.token, "/gateway_switch")
        except Exception:
            return None
        return got if isinstance(got, dict) and got.get("state") else None

    def gateway_switch(self, action: str) -> dict:
        """Ask the plugin to tick that box ("on") or, if the plugin was the one that ticked it, untick it ("undo").
        Nothing else is sent this way."""
        if not self.url:
            raise ValueError("not connected")
        if action not in ("on", "undo"):
            raise ValueError("unknown action")
        got = (self._poster or self._http_post)(self.url, self.token, "/gateway_switch", {"action": action})
        return got if isinstance(got, dict) else {"ok": False, "error": "The plugin gave no answer."}

    def hotspot_standby_status(self) -> dict | None:
        """0.7.1: is the plugin keeping the phone's hotspot in reserve? None when it cannot say."""
        if not self.url or not self.can("hotspot_standby"):
            return None
        try:
            got = self._fetch(self.url, self.token, "/hotspot_standby")
        except Exception:
            return None
        return got if isinstance(got, dict) else None

    def hotspot_standby(self, action: str, data: dict | None = None) -> dict:
        """0.7.1: ask the plugin to keep the phone's hotspot in reserve ("on": the Wi-Fi port's link stays off until the
        main gateway stops answering) or to stop ("off": the link is left on). An older plugin cannot: said plainly."""
        if not self.url:
            raise ValueError("not connected")
        if action not in ("on", "off"):
            raise ValueError("unknown action")
        if not self.can("hotspot_standby"):
            return {"ok": False, "error": "The plugin on the firewall is older than 0.7.1, so it cannot keep the hotspot "
                                          "in reserve yet; the firewall stays joined to it. Update the plugin, then "
                                          "press Finish again."}
        body = {"action": action}
        body.update({k: str(v) for k, v in (data or {}).items() if k in ("device", "gateway", "monitor")})
        got = (self._poster or self._http_post)(self.url, self.token, "/hotspot_standby", body)
        return got if isinstance(got, dict) else {"ok": False, "error": "The plugin gave no answer."}

    def hardware_status(self) -> dict | None:
        """What the firewall is made of (processor, memory, disks, network cards), read by the plugin. None when the plugin
        cannot say (an older plugin, or no answer)."""
        if not self.url or not self.can("hardware"):
            return None
        try:
            got = self._fetch(self.url, self.token, "/hardware")
        except Exception:
            return None
        return got if isinstance(got, dict) and got.get("state") == "ok" else None

    def time_zone_status(self) -> dict | None:
        """The firewall's time zone and the zones it offers, read by the plugin. None when the plugin cannot say (an older
        plugin, or no answer)."""
        if not self.url or not self.can("time_zone"):
            return None
        try:
            got = self._fetch(self.url, self.token, "/time_zone")
        except Exception:
            return None
        return got if isinstance(got, dict) and got.get("state") == "ok" else None

    def admin_session_change(self, action: str) -> dict:
        """Ask the plugin to set the admin session timeout to the baseline's 15 minutes ("set"), or to put it back ("undo",
        only if the plugin set it). Only the word goes; the value is fixed on the firewall."""
        if not self.url:
            raise ValueError("not connected")
        if action not in ("set", "undo"):
            raise ValueError("unknown action")
        got = (self._poster or self._http_post)(self.url, self.token, "/admin_session", {"action": action})
        return got if isinstance(got, dict) else {"ok": False, "error": "The plugin gave no answer."}

    def time_zone(self, action: str, zone: str | None = None) -> dict:
        """Ask the plugin to set the time zone ("set", with the zone's name) or to put it back ("undo", only if the plugin was
        the one that set it). Nothing else is sent this way."""
        if not self.url:
            raise ValueError("not connected")
        if action not in ("set", "undo"):
            raise ValueError("unknown action")
        body: dict = {"action": action}
        if action == "set":
            if not isinstance(zone, str) or not zone or len(zone) > 64:
                raise ValueError("a time zone is needed")
            body["zone"] = zone
        got = (self._poster or self._http_post)(self.url, self.token, "/time_zone", body)
        return got if isinstance(got, dict) else {"ok": False, "error": "The plugin gave no answer."}

    def ipv6_none_status(self) -> dict | None:
        """The IPv6 type of the WAN and the LAN, read from the firewall. None when the plugin cannot say."""
        if not self.url or not self.can("ipv6_none"):
            return None
        try:
            got = self._fetch(self.url, self.token, "/ipv6_none")
        except Exception:
            return None
        return got if isinstance(got, dict) and got.get("state") == "ok" else None

    def ssh_status(self) -> dict | None:
        """The firewall's Secure Shell settings, read by the plugin. None when it cannot say."""
        if not self.url or not self.can("ssh"):
            return None
        try:
            got = self._fetch(self.url, self.token, "/ssh")
        except Exception:
            return None
        return got if isinstance(got, dict) and got.get("state") == "ok" else None

    def ssh_change(self, action: str, allowed=None, port=None) -> dict:
        if not self.url:
            raise ValueError("not connected")
        if action not in ("off", "tighten", "undo"):
            raise ValueError("unknown action")
        body = {"action": action}
        if action == "tighten":
            body.update(allowed=list(allowed or []), port=port)
        got = (self._poster or self._http_post)(self.url, self.token, "/ssh", body)
        return got if isinstance(got, dict) else {"ok": False, "error": "The plugin gave no answer."}

    def sudo_status(self) -> dict | None:
        if not self.url or not self.can("sudo"):
            return None
        try:
            got = self._fetch(self.url, self.token, "/sudo")
        except Exception:
            return None
        return got if isinstance(got, dict) and got.get("state") == "ok" else None

    def root_check(self) -> dict | None:
        """Whether root is still on its factory password, checked on the firewall by the plugin. None when it cannot
        say."""
        if not self.url or not self.can("root_check"):
            return None
        try:
            got = self._fetch(self.url, self.token, "/root_check")
        except Exception:
            return None
        return got if isinstance(got, dict) and got.get("state") == "ok" else None

    def admin_session_status(self) -> dict | None:
        """The admin session idle timeout, read from the firewall's configuration by the plugin. None when the plugin
        cannot say (too old to offer it, not answering, or the file was not readable)."""
        if not self.url or not self.can("admin_session"):
            return None
        try:
            got = self._fetch(self.url, self.token, "/admin_session")
        except Exception:
            return None
        return got if isinstance(got, dict) and got.get("state") == "ok" else None

    def ipv6_none(self) -> dict:
        """Ask the plugin to set the IPv6 type of the WAN and the LAN to None. Nothing else is sent this way."""
        if not self.url:
            raise ValueError("not connected")
        got = (self._poster or self._http_post)(self.url, self.token, "/ipv6_none", {"action": "apply"})
        return got if isinstance(got, dict) else {"ok": False, "error": "The plugin gave no answer."}

    def report_status(self) -> dict | None:
        """The daily report and its settings (never the password) as the plugin has them. None when it cannot say."""
        if not self.url or not self.can("report"):
            return None
        try:
            got = self._fetch(self.url, self.token, "/report")
        except Exception:
            return None
        return got if isinstance(got, dict) and isinstance(got.get("settings"), dict) else None

    def report(self, action: str, settings: dict | None = None) -> dict:
        """Ask the plugin to save the report's settings ("save"), switch the email off ("off") or send a test ("test")."""
        if not self.url:
            raise ValueError("not connected")
        if action not in ("save", "off", "test"):
            raise ValueError("unknown action")
        body: dict = {"action": action}
        if action == "save":
            if not isinstance(settings, dict):
                raise ValueError("settings are needed")
            body["settings"] = settings
        got = (self._poster or self._http_post)(self.url, self.token, "/report", body)
        return got if isinstance(got, dict) else {"ok": False, "error": "The plugin gave no answer."}

    def version(self) -> str | None:
        """The plugin's own version, if it says (an older plugin does not)."""
        if not self.url:
            return None
        try:
            got = self._fetch(self.url, self.token, "/ping")
            v = got.get("version") if isinstance(got, dict) else None
            return v if isinstance(v, str) and len(v) <= 20 else None
        except Exception:
            return None

    def platform(self) -> str:
        """Which platform the box presents as: "hanbi" when its plugin says so, else "pazuzu" (an older plugin, or a
        box the wizard set up rather than the factory tool, does not say)."""
        if not self.url:
            return "pazuzu"
        try:
            got = self._fetch(self.url, self.token, "/ping")
            p = got.get("platform") if isinstance(got, dict) else None
            return p if p in ("hanbi", "pazuzu") else "pazuzu"
        except Exception:
            return "pazuzu"

    @staticmethod
    def _http_update(url: str, token: str, data: bytes, version: str, signature: str) -> Any:
        req = urllib.request.Request(url.rstrip("/") + "/update", data=data, method="POST",
                                     headers={"Authorization": "Bearer " + token,
                                              "Content-Type": "application/octet-stream",
                                              "X-Hanbi-Version": version, "X-Hanbi-Signature": signature})
        try:
            with feed_pin.urlopen(req, timeout=60) as r:  # noqa: S310 (private address only)
                return json.loads(r.read(65536))
        except urllib.error.HTTPError as exc:
            try:
                return json.loads(exc.read(4096))
            except Exception:
                return {"error": "The plugin refused the update (" + str(exc.code) + ")."}

    def push_update(self, data: bytes, version: str, signature: str) -> dict:
        """Send the plugin a signed set of newer files. The plugin decides; this only carries them."""
        if not self.url:
            raise ValueError("not connected")
        sender = self._updater or self._http_update
        got = sender(self.url, self.token, data, version, signature)
        return got if isinstance(got, dict) else {"error": "The plugin gave no answer."}

    def internet(self) -> dict | None:
        """Ask the plugin whether the firewall itself can reach the internet. None when it cannot say
        (no plugin, an older plugin, or no answer): the caller then falls back to the firewall's own check."""
        if not self.url or not self.can("internet_check"):
            return None
        try:
            got = self._fetch(self.url, self.token, "/internet")
        except Exception:
            return None
        ok = isinstance(got, dict) and isinstance(got.get("reached"), bool) and isinstance(got.get("lines"), list)
        return got if ok else None

    def wifi_status(self) -> dict:
        if not self.url:
            return {"state": "unreachable"}
        try:
            got = self._fetch(self.url, self.token, "/wifi_status")
            return got if isinstance(got, dict) else {"state": "unreachable"}
        except Exception:
            return {"state": "unreachable"}

    @staticmethod
    def _http_post_ap(url: str, token: str, path: str, body: dict) -> Any:
        """Like _http_post, but waits longer and reads a larger reply: an access point's config dump, carried
        back through the box, is far bigger than the box's own short answers."""
        raw = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url.rstrip("/") + path, data=raw, method="POST",
                                     headers={"Authorization": "Bearer " + token,
                                              "Content-Type": "application/json"})
        with feed_pin.urlopen(req, timeout=20) as r:  # noqa: S310 (private address only)
            return json.loads(r.read(2_000_000))

    def ap_relay(self, ip: str, payload: dict) -> Any:
        """Carry ONE ubus call to an access point THROUGH the box, for a point the firewall joined on a spare
        radio that this PC cannot see. Returns the access point's own ubus answer (the same shape a direct call
        gives), or raises so the reader treats it as no answer. Shaped to be handed to ap_openwrt as its `post`."""
        if not self.url:
            raise OSError("not connected to the box")
        sender = self._poster or self._http_post_ap
        got = sender(self.url, self.token, "/ap_relay", {"ip": ip, "payload": payload})
        if not isinstance(got, dict) or not got.get("ok"):
            raise OSError((got.get("error") if isinstance(got, dict) else "") or "the box could not reach the access point")
        return got.get("body")

    def try_connect(self, url: str, token: str) -> bool:
        """Connect only if the box answers a ping with this token. Quiet either way."""
        try:
            self._fetch(url, token, "/ping")
            self.connect(url, token)
        except Exception as exc:
            self.last_error = _why_no_answer(exc)
            return False
        self.last_error = ""
        return True

    def alive(self) -> bool:
        """Does the box answer right now? Being linked is only what was true when the link was made."""
        if not self.url:
            return False
        try:
            self._fetch(self.url, self.token, "/ping")
        except Exception as exc:
            self.last_error = _why_no_answer(exc)
            return False
        self.last_error = ""
        return True

    def screen_link(self) -> str | None:
        """Where the box's touch screen is, with the code after the # sign (a browser never sends that
        part anywhere). Only handed to the browser as a redirect, never as text the page can read."""
        if not self.url or not self.token:
            return None
        return self.url + "/screen#t=" + quote(self.token, safe="")

    def disconnect(self) -> None:
        self.url = self.token = None

    def read(self) -> dict[str, Any]:
        if not self.url:
            return {"connected": False}
        try:
            return {"connected": True, "url": self.url,
                    "status": self._fetch(self.url, self.token, "/status.json")}
        except Exception as exc:  # shown as text; never the token
            name = type(exc).__name__
            hint = "the token was refused" if "401" in str(exc) else "it did not answer"
            return {"connected": True, "url": self.url, "status": None,
                    "error": f"Could not read the box ({name}): {hint}."}


class Source:
    """Where the rule list comes from. Cached briefly so a page refresh does
    not hammer the firewall."""

    def __init__(self, loader: Callable[[], tuple[Mapping, Mapping]] | None,
                 *, offline: bool, journal: Path | str | None = DEFAULT_JOURNAL,
                 interfaces_loader: Callable[[], Mapping] | None = None,
                 zones_path: Path | str | None = None,
                 gateways_loader: Callable[[], Any] | None = None,
                 settings_loader: Callable[[], Any] | None = None,
                 services_loader: Callable[[], Any] | None = None,
                 confirmed_fn: Callable[[], Any] | None = None):
        self.loader = loader
        self.settings_loader = settings_loader
        self.services_loader = services_loader
        self.confirmed_fn = confirmed_fn
        self.offline = offline
        self.journal = journal
        self.interfaces_loader = interfaces_loader
        self.gateways_loader = gateways_loader
        self.zones_path = zones_path
        self._down_counts: dict[str, int] = {}
        self.box = BoxLink()
        self.api_feed = None            # Data through the firewall's own API, no plugin
        self.actions = None             # the guarded switch-on, when started from the wizard
        self.lab = False                # lab box: the LAN lockout protection is the way in
        self.beta_locked = False        # BUILD 493: beta 1 shows the manager as coming (the setup sets this)
        self.trial_fn = None            # the live CD choice (nothing is kept after a restart)
        self._lock = threading.Lock()
        self._cache: tuple[float, dict[str, Any]] | None = None
        self._last_good: dict[str, Any] | None = None
        self._failed: tuple[float, str] | None = None

    def state(self, scenario: str | None = None) -> dict[str, Any]:
        if self.offline:
            scenario = scenario if scenario in ("today", "after") else "today"
            inventory = sample_inventory(scenario)
            access = access_state(inventory, SAMPLE_INTERFACES, SAMPLE_ZONES, None)
            return build_state(inventory, SAMPLE_ALIASES,
                               source="sample", scenario=scenario,
                               journal=None, access=access)
        with self._lock:
            now = time.monotonic()
            if self._cache and now - self._cache[0] < CACHE_SECONDS:
                return self._cache[1]
            if self._failed and now - self._failed[0] < FAIL_SECONDS:
                return self._unreachable(self._failed[1])
            try:
                state = self._read(now)
            except (RuntimeError, ValueError, OSError) as exc:
                if not getattr(exc, "busy", False):      # busy is not a broken firewall: ask again next time
                    self._failed = (now, str(exc))
                return self._unreachable(str(exc))
            self._failed = None
            self._last_good = state
            return state

    def _unreachable(self, why: str) -> dict[str, Any]:
        """The firewall is not answering. Show what was last seen, marked, instead of freezing or failing."""
        if self._last_good is None:
            raise RuntimeError(why)
        # What a person has just chosen here (the lab tick) is not something the firewall told us,
        # so it is shown as it is now, not as it was when the firewall last answered.
        return {**self._last_good, "lab": self.lab, "unreachable": {"why": why}}

    def _read(self, now: float) -> dict[str, Any]:
        inventory, aliases = self.loader()
        interfaces, ports_error = None, None
        if self.interfaces_loader is not None:
            try:
                interfaces = self.interfaces_loader()
            except (RuntimeError, ValueError, OSError) as exc:
                ports_error = str(exc)
        gateways = None
        if self.gateways_loader is not None and interfaces is not None:
            try:
                gateways = self.gateways_loader()
            except Exception:               # an unread gateway list is shown as "not known", never guessed
                gateways = None
        settings = None
        if self.settings_loader is not None:
            try:
                settings = self.settings_loader()
            except Exception:               # an unread setting stays "you confirm it", never guessed
                settings = None
        services = None
        if self.services_loader is not None:
            try:
                services = self.services_loader()
            except Exception:               # an unread service stays "you confirm it", never guessed
                services = None
        access = access_state(inventory, interfaces, self._read_zones(),
                              self._down_counts, ports_error=ports_error, gateways=gateways)
        state = build_state(inventory, aliases, source="live",
                            journal=self.journal, access=access,
                            lab=self.lab, can_change=self.actions is not None,
                            trial=bool(self.trial_fn and self.trial_fn()), settings=settings, services=services,
                            confirmed=self._confirmed())
        state["beta_locked"] = bool(self.beta_locked)
        self._cache = (now, state)
        return state

    def _confirmed(self) -> list[str]:
        if self.confirmed_fn is None:
            return []
        try:
            return list(self.confirmed_fn() or [])
        except Exception:
            return []

    def retry(self) -> None:
        """Forget a recorded failure, so the next read asks the firewall again."""
        with self._lock:
            self._failed = None
            self._cache = None

    def forget(self) -> None:
        """Drop the cached read, so the next page load sees a change at once."""
        with self._lock:
            self._cache = None

    def _read_zones(self) -> Mapping[str, Any] | None:
        if self.zones_path is None or not Path(self.zones_path).exists():
            return None
        try:
            data = json.loads(Path(self.zones_path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return data if isinstance(data, dict) else None


def _live_loader() -> tuple[Mapping, Mapping]:
    from pazuzu_core.egress_drift_cli import _load_live
    return _load_live()


def _live_settings() -> Mapping:
    from pazuzu_core.opnsense_client import discover_interface_settings
    return discover_interface_settings()


def _live_interfaces() -> Mapping:
    from pazuzu_core.opnsense_client import discover_interfaces
    return discover_interfaces()


# ------------------------------------------------------------------- server
def host_allowed(header: str | None, port: int) -> bool:
    """Only loopback names, and only this server's own port."""
    host = (header or "").strip().lower()
    if host.startswith("["):
        name, _, rest = host.partition("]")
        name, port_text = name + "]", rest.lstrip(":")
    elif host.count(":") == 1:
        name, _, port_text = host.partition(":")
    else:
        name, port_text = host, ""
    return name in LOOPBACK_HOSTS and port_text in ("", str(port))


class ActionError(Exception):
    """A switch-on request that was refused, in words a person can read."""

# ---------------------------------------------------------------- the manager app (beta 2)
# The manager's own code (its page and its web handler) lives in the pazuzu_manager package, which is not part of the
# Apache-licensed beta 1 build (legal chat hand-off, 10 Nov 2026). Everything above — the box link, the state builders,
# the sample data — is the open plumbing the wizard uses. These wrappers keep old imports working where the manager is
# present, and say plainly when it is not.
MANAGER_MISSING = ("The manager is not in this build. It comes with beta 2; "
                   "run the setup again any time to change what it set up.")


def manager_present() -> bool:
    import importlib.util
    try:
        return importlib.util.find_spec("pazuzu_manager") is not None
    except (ImportError, ValueError):
        return False


def _manager_app():
    try:
        from pazuzu_manager import app
    except ImportError:
        raise ActionError(MANAGER_MISSING)
    return app


def render_ui(lang: str = "en") -> bytes:
    return _manager_app().render_ui(lang)


def make_handler(source: Source, port_getter: Callable[[], int]):
    return _manager_app().make_handler(source, port_getter)


def make_server(source: Source, host: str = "127.0.0.1",
                port: int = DEFAULT_PORT) -> ThreadingHTTPServer:
    return _manager_app().make_server(source, host, port)


def main(argv: list[str] | None = None, *, loader=None, serve: bool = True):
    return _manager_app().main(argv, loader=loader, serve=serve)


if __name__ == "__main__":
    raise SystemExit(main())
