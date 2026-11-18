"""The setup wizard as a local web page, on the same address as the passkey page.

    python -m pazuzu_core.wizard_server

Run on the owner's PC only. It answers on http://localhost:8766/ and nothing
else. Set OPNSENSE_BASE_URL (and OPNSENSE_TLS_VERIFY=false for a lab box with
a self-signed certificate) before starting; do not set key variables, because
the wizard reads its own key files and the browser never sees a key.

What it does, each step using the same code the command-line tools use:
* sign in once to make pazuzu-read (and later pazuzu-write), then register a
  passkey;
* read the interfaces and save the zone mapping;
* preview the rules and add them, all switched off.

Every change to the firewall still needs a passkey touch on that exact plan:
the apply and the write-user step call the same gate the command line does,
and the page shows the touch dialog while they wait. Looking never needs it.

The root password is used for one sign-in, held in a local variable during that
call, never stored, logged or sent back to the page. The factory password
("opnsense") is only tried when the person picks the "brand-new firewall"
choice. Guards are the same as the passkey page: the Host header must be
exactly localhost:<port>, every POST must come from the page's own origin and
be JSON, and the page loads nothing from outside.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import hashlib
import hmac
import json
import os
import re
import ipaddress
import secrets
import socket
import sys
import copy
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable

if __name__ == "__main__":
    from pazuzu_core import needs as _needs
    _needs.check_or_exit()                      # a missing package is explained here, not as a traceback
from pazuzu_core import enroll as en
from pazuzu_core import help_tips
from pazuzu_core import management_ports as mports
from pazuzu_core import blocklist_choices, country_block
from pazuzu_core import otp as otp_codes
from pazuzu_core import vpn_peer
from pazuzu_core import write_engine as we
from pazuzu_core import wifi_backup as wb
from pazuzu_core import resolver_choices
from pazuzu_core import passkey as pk
from pazuzu_core import passkey_server as ps
from pazuzu_core.enroll_safety import (
    base_host_port, fetch_fingerprint, load_pin, save_pin, show_fingerprint,
)
from pazuzu_core.zone_assignment import ALL_ZONES, ZONES

FACTORY_PASSWORD = "opnsense"
DEFAULT_MANIFEST = "manifests/security_baseline_v0_4.json"
OLD_FIREWALL_FILES = ("zone_assignment.json", "interface_discovery.json", "firewall_manifest_smoke_receipt.json",
                      "change_journal.json", "stock_rules_plan.json", "interrogation.json",
                      "firewall_drift_report.json", "firewall_rule_audit_v0_4.json")
DEFAULT_ZONES = "scan_results/zone_assignment.json"
DEFAULT_DISCOVERY = "scan_results/interface_discovery.json"
KEY_STAMP = "firewall.json"      # in the key folder: the firewall these keys were made on
SCAN_STAMP = ".firewall"         # in scan_results: the firewall those saved results belong to


def read_stamp(path) -> "tuple[str, int] | None":
    """The firewall a folder belongs to (address, port), or None when it has no name on it yet."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        host, port = str(data["host"]), int(data.get("port") or 443)
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None
    return (host, port) if host else None


def write_stamp(path, host: str, port: int = 443) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps({"host": host, "port": int(port)}), encoding="utf-8")
    os.replace(tmp, path)
APPROVAL_SECONDS = 300
ENV_WAIT_SECONDS = 45.0
IPV6_NONE_WAIT = 3.0                   # seconds between reads after the answer to the IPv6 type change was lost
IPV6_NONE_POLLS = 10  # how long a read waits for the keys before saying the app is busy
DEFAULT_WINDOW_NOTE = 5
JOB_ENV_WAIT_SECONDS = 90.0   # a running job (rules being switched on) waits longer: it must not give up because a page read held the keys
BACKGROUND_ENV_WAIT_SECONDS = 8.0   # the manager's own refreshes never hold the keys up for long, and never make a job wait
RIDE_OUT_READ_SECONDS = 60.0        # but a read that is only waiting on ANOTHER READ waits it out: reads end by themselves
_who = threading.local()      # set on threads that run a job
GRACE_SECONDS = 120      # a passkey touch also covers guarded rule changes for this long
MANAGER_UNLOCK_SECONDS = 15 * 60   # one touch when the manager opens covers its changes while it is in use (idle limit)
SLIDER_KIND = "shield-levels"      # the slider: always its own touch
PHONE_LABEL = "your phone (signed in with its passkey)"   # 0.6.53: the wizard run on the box for the Pazuzu app
PAUSE_COOLDOWN = 60      # seconds that must pass between two pauses that need no passkey
SHIELD_SECONDS = 300     # how long "All off" lasts before the shields go back up by themselves
PASSWORD_MAX = 256
MAX_LINES = 400

# How many manifest rule groups one run may take: all of them (the baseline has fewer than this).
WHOLE_MANIFEST = 50
_ENV_NAMES = ("OPNSENSE_API_KEY", "OPNSENSE_API_SECRET", "OPNSENSE_BASE_URL",
              "OPNSENSE_TLS_VERIFY", "OPNSENSE_CA_BUNDLE", "OPNSENSE_TIMEOUT")
WRITE_TIMEOUT = "60"    # applying rules makes the firewall slow to answer; 10 s was too short
_USERNAME = re.compile(r"[A-Za-z0-9._@-]{1,64}")
_COUNT_NEW = re.compile(r"(\d+) disabled rules from (\d+) manifest rules")
_COUNT_THERE = re.compile(r"(\d+) selected rule\(s\) are already on the firewall")
_COUNT_APPLIED = re.compile(r"Applied (\d+) disabled manifest rules and created (\d+) alias")


def _dig_form(form, path):
    node = form
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _read_words(exc) -> str:
    """Why a board line could not be read, in words (never the error's own text)."""
    if isinstance(exc, PermissionError):
        return "the firewall did not let Pazuzu's account read this page"
    if isinstance(exc, LookupError):
        return "this firewall version does not have that page"
    return "the firewall's answer could not be read"


_MISSING = object()          # the read cache's "nothing kept"

class WizardError(Exception):
    """A problem the person can read. Never carries a password or a key."""


class _FairLock:
    """A lock that hands over in the order people asked. A plain lock lets a loop of short checks take it again and
    again while a page read waits its whole time and gives up ("busy ... held for 4 s")."""

    def __init__(self) -> None:
        self._cond = threading.Condition()
        self._held = False
        self._queue: list = []

    def acquire(self, timeout: float = -1) -> bool:
        ticket = object()
        end = None if timeout is None or timeout < 0 else time.monotonic() + timeout
        with self._cond:
            self._queue.append(ticket)
            try:
                while True:
                    if not self._held and self._queue[0] is ticket:
                        self._held = True
                        return True
                    left = None if end is None else end - time.monotonic()
                    if left is not None and left <= 0:
                        return False
                    self._cond.wait(left)
            finally:
                self._queue.remove(ticket)
                self._cond.notify_all()

    def release(self) -> None:
        with self._cond:
            self._held = False
            self._cond.notify_all()


class BusyError(WizardError, RuntimeError):
    """Another step holds the keys. Also a RuntimeError, so the manager's page shows this sentence
    (and what it last saw) instead of dropping the connection."""
    busy = True


_JSON_SCALAR = re.compile(r"^(-?\d[\d.eE+-]*|true|false|null),?$")


def _is_body(line: str) -> bool:
    """A blank line, or a line of a rule's printed JSON body (as json.dumps with an indent writes it): not a sentence,
    and never wanted."""
    t = line.strip()
    return not t or t[0] in '{}[]"' or bool(_JSON_SCALAR.match(t))


class _Lines(io.TextIOBase):
    """Collects what a tool prints, a line at a time, up to a limit. Only sentences count toward the limit: a dry run
    prints every rule's JSON body first, which used to fill it and cut off the last sentence, the count of what is
    missing."""

    def __init__(self) -> None:
        self.lines: list[str] = []
        self._partial = ""

    def writable(self) -> bool:
        return True

    def write(self, text: str) -> int:
        self._partial += text
        *done, self._partial = self._partial.split("\n")
        for line in done:
            if _is_body(line):
                continue
            if len(self.lines) < MAX_LINES:
                self.lines.append(line.rstrip())
        return len(text)

    def finish(self) -> list[str]:
        if not _is_body(self._partial) and len(self.lines) < MAX_LINES:
            self.lines.append(self._partial.rstrip())
        self._partial = ""
        return self.lines


def _summary_lines(lines: list[str]) -> list[str]:
    """Drop the rule bodies a dry run prints; keep the sentences."""

    return [ln for ln in lines
            if ln.strip() and not ln.startswith(("{", "}", "  \"", "[", "]"))
            and "python -m" not in ln
            and not ln.startswith(("To keep the change", "Check from a client",
                                   "If you do nothing"))]


_GROUP_WORDS = {
    "PZ-WAN-001": ("Block everything coming in from the internet",
                   "Nobody outside can reach your firewall or your network unasked."),
    "PZ-MGMT-010": ("Shut every other way into the settings page",
                    "Only the management network can open it."),
    "PZ-DMZ-001": ("Keep public-facing servers away from your private networks",
                   "If a public server is hacked, it can't reach your own devices."),
    "PZ-QUAR-001": ("Cut off quarantined devices completely",
                    "A quarantined device can't reach the internet or any other device."),
    "PZ-IOT-001": ("Keep smart devices away from your own computers",
                   "A hacked smart plug can't reach your laptop."),
    "PZ-GUEST-001": ("Keep guests away from your own devices",
                     "Guests get the internet and nothing else."),
    "PZ-TRUST-001": ("Keep everyday computers out of the management network",
                     "A compromised laptop can't reach the control side."),
    "PZ-DNS-010": ("Stop devices using outside name servers",
                   "All name lookups go through the firewall, where they can be checked."),
    "PZ-QUIC-010": ("Turn QUIC away at once",
                    "Web traffic over UDP is refused straight away, so apps and browsers use ordinary HTTPS without "
                    "waiting. Without it, a video can stall for half a minute while the app waits on QUIC."),
    "PZ-WG-001": ("Let the VPN connect in",
                  "Opens only the one port the VPN needs."),
    "PZ-WG-002": ("Let the VPN connect in from the internet",          # BUILD 529: these two showed as bare codes
                  "Only the VPN\u2019s one port, to the firewall only. It stays off until the VPN is set up."),
    "PZ-DNS-020": ("A timed allowance for direct OpenDNS lookups",
                   "It stays off. It is switched on by hand for a set time, then goes back off."),
    "PZ-MGMT-001": ("Let the management network reach the settings page",
                    "So you can always get back in."),
    "PZ-MGMT-002": ("Let VPN admins reach the settings page",
                    "Only used once the VPN exists."),
    "PZ-CORE-001": ("Let devices ask the firewall for names, addresses and the time",
                    "Without this, devices could not get online."),
    "PZ-IOT-010": ("Let smart devices use the web, outward only",
                   "Web access only. A device that needs more is let through on its own, one service at a time, "
                   "from the Blocks list. Nothing can start a connection to them."),
    "PZ-DMZ-010": ("Let public servers reach the web, outward only",
                   "Web access only, for updates; your own networks stay out of reach. A server that needs more is let "
                   "through on its own, from the Blocks list."),
    "PZ-IOT-005": ("Let smart devices ping the firewall",
                   "Many check they are online this way; it opens nothing else."),
    "PZ-IOT-011": ("Let smart devices ping the internet",
                   "So their own online check passes; pings only, nothing else."),
    "PZ-GUEST-010": ("Let guests use the internet",
                     "Web access only."),
    "PZ-TRUST-010": ("Let your own computers use the internet",
                     "Everyday browsing, updates and apps keep working."),
}


_OBJECT_ID = re.compile(r"\b(PZ-[A-Z]+-\d+)\b")


def baseline_lines(rows) -> list[str]:
    """The whole baseline as it stands on the firewall: each group in plain words, with how many
    of its rules are on. Rules the person made themselves are not listed."""

    seen: dict[str, list[int]] = {}
    for r in rows:
        if not isinstance(r, dict):
            continue
        m = _OBJECT_ID.search(str(r.get("description") or ""))
        if not m:
            continue
        on = str(r.get("enabled", "0")) in ("1", "true", "True")
        got = seen.setdefault(m.group(1), [0, 0])
        got[0] += 1
        got[1] += 1 if on else 0
    out = []
    for oid in sorted(seen):
        total, on = seen[oid]
        title = _GROUP_WORDS.get(oid, (oid, ""))[0]
        out.append(f"   {title}: {on} of {total} on")
    return out


def _group_explanations(lines: list[str]) -> list[dict]:
    out = []
    for ln in lines:
        m = re.match(r"selected: (PZ-[A-Z]+-\d+)", ln)
        if m:
            title, why = _GROUP_WORDS.get(m.group(1), (m.group(1), ""))
            out.append({"title": title, "why": why})
    return out


def suggest_management(interfaces: list[dict]) -> dict:
    """A spare cabled port if there is one, otherwise a loopback, otherwise nothing."""

    # A Wi-Fi interface is never offered as the way in: the Wi-Fi back door is Pazuzu's own, it is not assigned on the
    # firewall, and a zone cannot use an interface that is not assigned and enabled there.
    spare = [i for i in interfaces if i.get("physical") and not i.get("assigned")
             and not str(i.get("device", "")).lower().startswith("wlan")]
    if spare:
        return {"device": spare[0]["device"], "kind": "spare_port"}
    loops = [i for i in interfaces
             if not i.get("physical") and str(i.get("device", "")).startswith("lo")]
    if loops:
        return {"device": loops[0]["device"], "kind": "loopback"}
    return {"device": None, "kind": "none"}


def _local_ips(host: str) -> list[str]:
    """This device's IPv4 addresses, best effort. Nothing is sent to the firewall."""

    found: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            found.add(info[4][0])
    except OSError:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect((host, 9))
            found.add(probe.getsockname()[0])
    except OSError:
        pass
    return sorted(found)


def reach_hint(host: str, ips: list[str] | None = None) -> str:
    """One plain sentence on why this device may not reach the firewall."""

    try:
        firewall = ipaddress.ip_address(host)
        mine = [ipaddress.ip_address(i) for i in (ips if ips is not None else _local_ips(host))]
    except ValueError:
        return ""
    if firewall.version != 4:
        return ""
    lan = ipaddress.ip_network(f"{firewall}/24", strict=False)
    usable = [i for i in mine if not i.is_loopback]
    real = [i for i in usable if not i.is_link_local]
    if any(i in lan for i in real):
        return ("This device has an address in the firewall’s range but cannot reach it. "
                "Check the cable is in the port labelled LAN (or 1), and turn off Wi-Fi if your home router uses the same range.")
    if usable and not real:
        return ("This device has not been given an address by the firewall yet (it shows 169.254.x.x). "
                "Wait about 30 seconds with the cable in the port labelled LAN (or 1), or set the network adapter to automatic. "
                f"If it stays that way, the firewall may not have DHCP turned on: set a fixed address on this device in the firewall’s range, such as {lan.network_address + 50}. "
                "Or press Find my firewall.")
    shown = ", ".join(str(i) for i in real) or "none"
    return (f"This device is not on {firewall}’s network (its addresses: {shown}). "
            "Your firewall may be at a different address: press Find my firewall. "
            f"Otherwise plug into the port labelled LAN (or 1) and set the adapter to automatic, or to a fixed address such as {lan.network_address + 50}. "
            "If you are using Wi-Fi, connect to the Wi-Fi network your firewall provides.")


_STAGE_WORDS = {
    "lifeline": ("Keep your way into the firewall open",
                 "Switches on the rule that lets you reach the firewall’s settings page, so nothing after this can lock you out."),
    "core_services": ("Let devices get online",
                      "Switches on name lookups, addresses and the time for your devices."),
    "outbound": ("Let your devices use the internet",
                 "Switches on the rules that let your Trusted Network reach the internet, and smart devices and guests "
                 "reach the web (never your own devices)."),
    "stock_disable": ("Switch off the old allow-everything rules",
                      "Turns off OPNsense’s default allow-all rules once Pazuzu’s own rules do the job, and notes why."),
    "blocking": ("Switch on the blocking rules",
                 "Turns on Pazuzu’s own block rules, last of all, once everything that must keep working has been tested without the old allow-all rules."),
}

# The rules go on in three runs, in this order, each tested and undone by itself if a test fails.
USB_WARNING = ("Heads-up: this firewall's ports include USB network adapters ({ports}). Zenarmor takes over the "
               "ports it protects, and on one firewall like this it left the network unreachable.")

STAGE_GROUPS = {
    "allow": ("lifeline", "core_services", "outbound"),
    "stock": ("stock_disable",),
    "block": ("blocking",),
}


_OPEN_WORDS = {
    "ipv6": ("IPv6 traffic isn’t filtered", "Devices can reach the internet over IPv6 without the baseline’s rules."),
    "client_ntp": ("Devices use their own time servers", "They can bypass the firewall’s time service."),
    "dns_bypass": ("Devices can use any DNS server", "Name lookups can happen outside the firewall, where they can’t be checked."),
    "quic": ("QUIC gets around inspection", "Fast web traffic that packet inspection can’t see."),
}


def _name_the_port(text: str, way: dict | None) -> str:
    """Make the 'no way in' reason name the port Pazuzu would use, when it can."""

    if not text.startswith("There is no way in") or not way or not way.get("device"):
        return text
    if way["kind"] == "spare_port":
        return (f"There is no way in to protect yet. The port {way['device']} isn’t used by "
                "anything: on the Ports screen, give it to the Management network, then add "
                "the rules again.")
    if way["kind"] == "loopback":
        return (f"There is no way in to protect yet. On the Ports screen, give the Management "
                f"network the internal address {way['device']}, then add the rules again.")
    return text


def _plain_blocker(text: str) -> str:
    low = text.lower()
    if "no lifeline rule" in low:
        return ("There is no way in to protect yet. Pick a port for the Management network "
                "on the Ports screen (or set up the VPN later), then add the rules again.")
    if "has no rules on the firewall" in low:
        return ("These rules haven’t been added yet. Go back to the Rules screen and add them again.")
    if "no enabled pazuzu allow" in low:
        return ("Waiting for the earlier stages. The old allow-all rules stay on until Pazuzu’s own "
                "allow rule is on, so your home network keeps working.")
    if "no stock allow rules" in low:
        return "The default allow-all rules weren’t found, so there is nothing to switch off."
    return text


def port_label(item: dict) -> str:
    """"LAN (em3)": the firewall's own name for the port, then the device in brackets."""

    ident = str(item.get("identifier") or "")
    name = str(item.get("description") or "")
    if name == "Unassigned Interface":
        name = ""
    if not name and ident:
        name = ident.upper() if re.fullmatch(r"(lan|wan|opt\d+)", ident) else ident
    return f"{name or 'Spare port'} ({item.get('device')})"


VIRTUAL_PREFIXES = ("lo", "enc", "pflog", "pfsync", "wg", "tun", "tap", "ovpn", "gif", "gre", "bridge",
                    "lagg", "vlan", "ipsec", "ppp", "ng", "epair",
                    "zen")          # zen0: Zenarmor's own tunnel (seen on a real firewall: groups "tun zenvpngroup")


PORTS_SKIPPED = ("No ports were chosen for your networks yet (the Ports step was skipped), and the firewall does not "
                 "have both an internet port and a home port set up to use instead. Go back to Ports and choose them.")
PORTS_NOT_SAVED = ("The ports you chose for each network are not saved yet, or no longer match what "
                   "this firewall has. Open the setup page and choose them again (the Ports step).")


def is_virtual_device(device: str) -> bool:
    """Not a port a cable goes into: tunnels, loopbacks, bridges and the like."""

    return str(device or "").lower().startswith(VIRTUAL_PREFIXES)


def _link_word(status: str, device: str = "", physical: bool = True) -> str:
    """"cable plugged in" / "no cable", only for a real port. A tunnel has no cable to talk about."""

    if is_virtual_device(device) or not physical:
        return ""
    low = str(status or "").lower()
    if re.search(r"no carrier|down", low):
        return "no cable"
    if re.search(r"up|active|full|1000|100base|10base", low):
        return "cable plugged in"
    return ""


class Wizard:
    """What the page can ask for. No HTTP in here, so it is easy to test."""
    light = False                     # a new or test firewall: set by the first screen's choice
    phone = False                     # run on the box for a phone signed in with its passkey (plugin 0.6.53, Layer 3)
    engine_secret = ""                # what the box's feed adds to each request it passes on (phone mode only)

    def __init__(self, key_dir: Path, base_url: str, verify, passkeys: ps.Service, *,
                 manifest: str = DEFAULT_MANIFEST, zones_path: str = DEFAULT_ZONES,
                 discovery_path: str = DEFAULT_DISCOVERY,
                 fetch_fp: Callable[[str, int], str] = fetch_fingerprint,
                 enroll_fn=en.enroll, scan_fn=None, apply_fn=None,
                 approval_seconds: float = APPROVAL_SECONDS,
                 journal: str | None = None, inventory_loader=None,
                 stage_main=None, checks=None, unguarded_fn=None, read_fn=None,
                 clock=None, sleep=None, lan_fn=None, plan_wait=300.0, find_fn=None):
        self.key_dir = Path(key_dir)
        self.base_url = base_url
        self._find_fn = find_fn
        self.verify = verify
        self.passkeys = passkeys
        self.manifest = manifest
        self.zones_path = Path(zones_path)
        self.discovery_path = Path(discovery_path)
        self._fetch_fp = fetch_fp
        self._enroll = enroll_fn
        self._scan = scan_fn
        self._apply = apply_fn
        self.approval_seconds = approval_seconds
        # An absolute path, fixed now: a relative one follows the folder the program is in at the moment it is used,
        # so a worker that outlived a test (or a changed folder) wrote the journal somewhere the wizard never looked.
        self.journal = os.path.abspath(journal or os.environ.get("HANBI_JOURNAL",
                                                                  "scan_results/change_journal.json"))
        self._inventory_loader = inventory_loader
        self._stage_main = stage_main
        self._checks = checks
        self._unguarded_fn = unguarded_fn
        self._read_fn = read_fn
        self._env_lock = _FairLock()
        self._bg_lock = threading.RLock()  # the manager's own refreshes queue behind each other here, so they never fight over the keys (and behind a preview: BUILD 437)
        self._job_lock = threading.Lock()
        self._approval_lock = threading.Lock()
        self._approval_cancel = threading.Event()      # set when the person cancels the passkey prompt: the job stops at once
        self._job: dict | None = None
        self.lab_lifeline = False
        self._harder_fn = None
        self._detail_fn = None
        self._probe: dict | None = None     # what the read-only check saw on this firewall (memory only)
        self._last_write = None             # (engine, outcomes) of the last guarded addition, for undo
        self._internet_note = None          # before and after the rules: what the plugin saw
        self._internet_seen = None          # the last answer to "can the firewall itself reach the internet" (None = not asked)
        self.trial = False                # running from the live CD: nothing is kept after a restart
        self.light = False                # a new or test firewall: no passkey, each change still tests itself and undoes itself
        self._clock = clock or time.monotonic
        self._sleep = sleep or time.sleep
        self._lan_fn = lan_fn
        self._plan_wait = plan_wait
        self._grace_until = 0.0
        self._plan_grant: dict | None = None
        self._lan_seen: dict = {}
        self._last_pause: float | None = None
        self._svc_rows = None
        self._auto_lock = threading.Lock()
        self._auto_busy = False
        self._auto_at: float | None = None
        self._svc_ack: set = set()
        self._svc_skip: set = set()          # attention rows the person chose to carry on past
        self._lan_skip: set = set()          # tests the person chose to skip (never keep a change alone)
        self._names: dict = {}
        self._manager_url = None
        self.keys_state = "unknown"           # unknown / ok / stale / unreachable / none (set by check_keys)
        # The first screen's choice is kept, so a restart of this program does not turn a test firewall back into one
        # that asks for a passkey nobody registered.
        kept = self._recall("mode")
        if kept in ("new", "trial", "audit"):
            self.light = kept in ("new", "trial")
            self.trial = kept == "trial"
            self.lab_lifeline = self.light

    # -- the passkey gate the change code calls while a job waits
    def gate(self, digest: str, lines) -> bool:
        # Who is asking: the setup (the wizard: making users, getting to the baseline) asks for no passkey. The manager
        # asks once when it opens, and that covers its changes while it is in use; the slider always asks for its own.
        origin, kind = getattr(_who, "origin", "wizard"), getattr(_who, "kind", "")
        if self.phone:
            # On the box, for the Pazuzu app: the phone's passkey was the way in (the box checked it before passing the
            # request on, and the session ends after 15 idle minutes), like a bank. Nothing more is asked per change.
            from pazuzu_core import activity
            activity.note("Approved by the signed-in phone: " + (str(lines[0]) if lines else digest[:12]))
            return True
        if origin != "manager" and not self.light:
            from pazuzu_core import activity
            activity.note("Approved without a passkey (setup): " + (str(lines[0]) if lines else digest[:12]))
            return True
        if origin == "manager" and kind not in (SLIDER_KIND, "manager-unlock") and self.manager_unlocked()["seconds_left"] > 0:
            self._manager_unlock_until = self._now() + MANAGER_UNLOCK_SECONDS      # in use: the time starts again
            return True
        if self.light:
            # A new or test firewall, chosen by the person on the first screen: the click is the approval.
            # Nothing else changes: each stage is still tested and undone by itself if a test fails.
            from pazuzu_core import activity
            activity.note("Approved without a passkey (test mode): " + (str(lines[0]) if lines else digest[:12]))
            return True
        svc = self.passkeys
        with self._approval_lock:
            with svc._lock:
                svc.approved.clear()
                svc.pending = ps.Pending(digest, tuple(lines))
            self._approval_cancel.clear()
            try:
                # Wait for the touch, but stop as soon as the prompt is cancelled (approval_cancel). Before, a cancelled
                # prompt left the job holding the one job slot for the whole approval time (5 minutes).
                deadline = time.monotonic() + float(self.approval_seconds)
                while True:
                    left = deadline - time.monotonic()
                    if left <= 0:
                        return False
                    if svc.approved.wait(min(0.25, left)):
                        if origin == "manager" and kind != SLIDER_KIND:
                            # BUILD 472, like a bank: the touch for a change from the manager signs it in too, so the
                            # next change needs none (a touch for the certificate, then another to unlock).
                            self._manager_unlock_until = self._now() + MANAGER_UNLOCK_SECONDS
                        return True
                    if self._approval_cancel.is_set():
                        return False
            finally:
                self._approval_cancel.clear()
                with svc._lock:
                    svc.pending = None
                    svc.approved.clear()

    def approval_cancel(self) -> dict:
        """The person cancelled the passkey prompt (or closed it): the waiting change stops now and frees the slot."""
        pending = getattr(self.passkeys, "pending", None) is not None
        if pending:
            self._approval_cancel.set()
        return {"cancelled": pending}

    def _own_platform(self) -> str | None:
        """On the box (phone mode) the plugin is right here: say which brand it is, so the page draws it from the start."""
        if not self.phone:
            return None
        try:
            from hanbi_box import marker
            return marker.platform()
        except Exception:  # noqa: BLE001
            return None

    def _can_change(self) -> bool:
        """A change may start: a passkey is registered, or this is a new or test firewall (light mode)."""
        return self.light or bool(self.status()["passkeys"])

    # -- a passkey touch that holds for a short while, for guarded rule changes only
    def _now(self) -> float:
        return self._clock()

    _manager_unlock_until = 0.0
    _manager_seen = 0.0            # BUILD 496: the manager's window says it is open every few seconds
    _manager_closing = 0.0         # and says when it closes; a reload comes back within the grace
    MANAGER_ALIVE_SECONDS = 45     # no word from the window for this long (a crash, a closed laptop): locked
    MANAGER_CLOSE_GRACE = 8        # a reload says "closing" then "open" again within this; a close does not

    def _manager_session_over(self) -> bool:
        """BUILD 496 (the maintainer, 10 Nov 2026: "it should require passkey if closed like the usual convention"): the sign-in
        lasts while the manager's window is open, and ends when it closes or stops answering, as well as after 15 idle
        minutes."""
        now = self._now()
        if self._manager_closing and now - self._manager_closing > self.MANAGER_CLOSE_GRACE:
            return True
        return bool(self._manager_seen) and now - self._manager_seen > self.MANAGER_ALIVE_SECONDS

    def manager_unlocked(self) -> dict:
        if self._manager_unlock_until and self._manager_session_over():
            self._manager_unlock_until = 0.0
            self._grace_until = 0.0
            self._manager_closing = 0.0
        left = max(0, int(self._manager_unlock_until - self._now()))
        return {"unlocked": left > 0 or self.light or self.phone, "seconds_left": left, "light": bool(self.light),
                "idle_minutes": MANAGER_UNLOCK_SECONDS // 60}

    def manager_alive(self) -> dict:
        """The manager's window is open (it says so every 15 seconds, and once as it loads)."""
        self._manager_seen = self._now()
        self._manager_closing = 0.0
        return self.manager_unlocked()

    def manager_closing(self) -> dict:
        """The manager's window is closing (or reloading): locked unless it says it is open again within seconds."""
        self._manager_closing = self._now()
        return {"closing": True}

    def manager_lock_now(self) -> dict:
        """Lock now, from the manager's own button."""
        self._manager_unlock_until = 0.0
        self._grace_until = 0.0
        return self.manager_unlocked()

    def manager_unlock_start(self) -> dict:
        """The one touch when the manager opens. Its changes then need none while it is in use (15 idle minutes); the
        slider still asks for its own each time."""
        if self.manager_unlocked()["unlocked"]:
            return {"unlocked": True}
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        from pazuzu_core.passkey_gate import plan_digest

        def work() -> dict:
            ok = self.gate(plan_digest("manager-unlock", {"at": int(self._now())}),
                           ["Open the manager for changes",
                            "Changes made from the manager need no further touch while it is in use (15 idle minutes)",
                            "The slider still asks for your passkey each time"])
            if not ok:
                raise WizardError("Not approved with a passkey. The manager shows everything, and asks again for changes.")
            self._manager_unlock_until = self._now() + MANAGER_UNLOCK_SECONDS
            return {"lines": ["Unlocked: changes from the manager need no further touch while it is in use."], "can_undo": False}
        return self._start("manager-unlock", work)

    def window_gate(self, digest: str, lines) -> bool:
        """The ordinary approval: a touch is asked for unless one was given in the last two minutes.
        Accounts, installs and additions use it. Switching root off never does. The slider always asks."""
        if getattr(_who, "kind", "") == SLIDER_KIND and getattr(_who, "origin", "") == "manager":
            return self.gate(digest, lines)
        if self._now() < self._grace_until:
            return True
        if not self.gate(digest, lines):
            return False
        self._grace_until = self._now() + GRACE_SECONDS
        return True

    def change_gate(self, stage_id: str | None = None):
        """The gate for a guarded rule change. A touch is asked for unless one was
        given in the last two minutes, or this stage belongs to a plan the person
        already approved as a whole. Nothing else (accounts, installs) uses it."""

        def gate(digest: str, lines) -> bool:
            now = self._now()
            grant = self._plan_grant
            if grant and stage_id in grant["ids"] and now < grant["until"]:
                return True
            if now < self._grace_until and getattr(_who, "kind", "") != SLIDER_KIND:
                return True
            if not self.gate(digest, lines):
                return False
            self._grace_until = self._now() + GRACE_SECONDS
            return True
        return gate

    def window_state(self) -> dict:
        left = max(0, int(self._grace_until - self._now()))
        return {"active": left > 0, "seconds_left": left}

    def window_end(self) -> dict:
        self._grace_until = 0.0
        return self.window_state()

    # -- keys, loaded only here and only for the length of one action
    def _key_file(self, role: en.Role) -> Path:
        return en.key_path(self.key_dir, role)

    @staticmethod
    def _caller_name() -> str:
        """The function that asked for the keys (skipping this file's own plumbing), so a busy message can name it."""
        try:
            f = sys._getframe(2)
            while f is not None and f.f_code.co_filename.endswith("contextlib.py"):
                f = f.f_back
            return f.f_code.co_name if f is not None else "something"
        except Exception:
            return "something"

    @contextlib.contextmanager
    def _env(self, role: en.Role, wait: float | None = None, ride_out_reads: bool = False):
        who = self._caller_name()
        path = self._key_file(role)
        try:
            pair = en.parse_key(path.read_text(encoding="utf-8"))
        except OSError:
            pair = None
        if pair is None:
            raise WizardError(f"There is no key for {role.name} on this device yet.")
        # Another step may hold the keys for a long time (a change waiting for its passkey, a window
        # counting down). Say so after a short wait instead of leaving the page on "Reading…".
        if wait is None:
            wait = JOB_ENV_WAIT_SECONDS if getattr(_who, "job", False) else ENV_WAIT_SECONDS
        got = self._env_lock.acquire(timeout=wait)
        if not got and ride_out_reads and role is en.READ:
            # Only another read has the keys (the setup page's look at the firewall, a retest): it ends by
            # itself, so wait it out instead of putting an error on the board. A change that is waiting
            # for its passkey is not a read, and still gets the plain sentence below.
            held = getattr(self, "_env_holder", None)
            if held and held[0] == en.READ.name:
                got = self._env_lock.acquire(timeout=max(0.0, RIDE_OUT_READ_SECONDS - wait))
        if not got:
            held = getattr(self, "_env_holder", None)
            named = ""
            if held:
                named = f" Held by: {held[1]} ({held[0]}) for {int(max(0, time.monotonic() - held[2]))} s."
            raise BusyError("Pazuzu is busy with another step on this firewall (a change waiting for "
                            "your passkey, or still running). Finish or cancel that, then try again." + named)
        self._env_holder = (role.name, who, time.monotonic())
        try:
            saved = {n: os.environ.get(n) for n in _ENV_NAMES}
            try:
                os.environ["OPNSENSE_API_KEY"], os.environ["OPNSENSE_API_SECRET"] = pair
                os.environ["OPNSENSE_BASE_URL"] = self.base_url
                if role is en.WRITE and not saved.get("OPNSENSE_TIMEOUT"):
                    os.environ["OPNSENSE_TIMEOUT"] = WRITE_TIMEOUT
                if isinstance(self.verify, str):
                    os.environ["OPNSENSE_CA_BUNDLE"] = self.verify
                else:
                    os.environ.pop("OPNSENSE_CA_BUNDLE", None)
                    os.environ["OPNSENSE_TLS_VERIFY"] = "true" if self.verify else "false"
                yield
            finally:
                for name, value in saved.items():
                    if value is None:
                        os.environ.pop(name, None)
                    else:
                        os.environ[name] = value
        finally:
            self._env_holder = None
            self._env_lock.release()

    # -- what the page shows
    def status(self) -> dict:
        zones = None
        if self.zones_path.exists():
            try:
                report = json.loads(self.zones_path.read_text(encoding="utf-8"))
                zones = {"deployable": bool(report["summary"]["deployable"]),
                         "assignments": {
                             z: {"state": a.get("state"), "device": a.get("device")}
                             for z, a in report["assignments"].items()}}
            except (OSError, ValueError, KeyError, TypeError, AttributeError):
                zones = {"deployable": False, "assignments": {}}
        try:
            passkeys = len(pk.load_credentials(self.key_dir / pk.CREDENTIALS_FILE))
        except pk.PasskeyError:
            passkeys = 0
        if self.phone:
            passkeys = max(passkeys, 1)      # the phone's passkey, checked by the box, stands for the PC's
        host, _port = base_host_port(self.base_url)
        self._check_installer()
        self._vpn_already_there()
        return {
            "firewall": host,
            "firewall_url": self.base_url.rstrip("/"),
            "startup": self.startup,
            "read_user": self._key_file(en.READ).exists(),
            "write_user": self._key_file(en.WRITE).exists(),
            # a key on this device that the firewall no longer accepts (the account closed itself) is not an account
            "installer_user": self._key_file(en.INSTALLER).exists() and not getattr(self, "_installer_dead", False),
            "installer_stale": self._key_file(en.INSTALLER).exists() and bool(getattr(self, "_installer_dead", False)),
            "keys_stale": self.keys_state == "stale",
            "keys_silent": self.keys_state == "unreachable" and not getattr(self, "keys_checking", False),
            "keys_note": getattr(self, "keys_note", ""),
            "keys_checking": bool(getattr(self, "keys_checking", False)),
            # WireGuard's own page sends a phone to its app store
            "phone_app_url": "https://www.wireguard.com/install/",
            "passkeys": passkeys,
            "zones": zones,
            "deployed": Path("scan_results/firewall_manifest_smoke_receipt.json").exists(),
            "job": self._job_view(),
            "guard": self._guard(),
            "manager_url": self._manager_url,
            # BUILD 468: the manager needs the firewall sign-in (Pazuzu's look-only account) and the plugin answering;
            # opened before them it asked for the box's address and token by hand (lab, 3 Nov 2026)
            "manager_ready": bool(self.phone or (self._key_file(en.READ).exists() and self.keys_state != "stale"
                                                 and getattr(getattr(getattr(self, "_acts", None), "source", None),
                                                             "box", None) is not None and self._acts.source.box.url)),
            "manager_open": self._manager_open(),  # BUILD 493: beta 1 is the setup; the manager opens in test mode only
            "plugin_offered": self._plugin_offered(),   # BUILD 513: beta 1 has no plugin; its steps are not shown
            "setup_id": self._setup_id(),
            "trial": self.trial,
            "light": self.light,
            "phone": self.phone,                   # BUILD 450: run on the box for a phone signed in with its passkey
            "platform": self._own_platform(),     # BUILD 450: known before the page draws (it flipped Pazuzu -> Hanbi)
            "window": self.window_state(),
            "legal": self.legal(),
            "access": self.access_info(),
            "resolver": self.resolver_state(),
            "blocklists": blocklist_choices.state(self.key_dir),
            "country_block": {**country_block.state(self.key_dir), "on_firewall": self._country_on_firewall()},
            "writes": self.writes_state(),
            "admin_user": None if self.keys_state in ("stale", "none") else self._recall("admin_user"),
            "root_off": self.keys_state not in ("stale", "none") and bool(self._recall("root_off")),
            "root_pw": self.keys_state not in ("stale", "none") and bool(self._recall("root_pw")),
            "root_secured": self.keys_state not in ("stale", "none") and bool(self._recall("root_off") or self._recall("root_pw")),
            "vpn_instance": None if self.keys_state in ("stale", "none") else self._recall("vpn_instance"),
            "zone_wifi": None if self.keys_state in ("stale", "none") else self._recall("zone_wifi"),
            "tips": [dict(t) for t in help_tips.TIPS],
        }

    # -- the two ports this install is meant to use, and who the firewall asks for names
    def access_info(self) -> dict:
        """Where to reach the firewall now, and the ports planned for later. Planning changes nothing."""
        host, port = base_host_port(self.base_url)
        try:
            plan = mports.load_or_create_plan(self.key_dir, reserved={443, 22, port})
            planned = {"web_port": plan.gui, "ssh_port": plan.ssh}
        except (OSError, ValueError):
            planned = {"web_port": None, "ssh_port": None}
        # "ssh" is not read here (this runs on every status read): the page asks /api/ssh/state, which really checks.
        return {"host": host, "web_port_now": port, "ssh": None, **planned}

    def resolver_state(self) -> dict:
        return {"choice": resolver_choices.load(self.key_dir), "options": resolver_choices.options(),
                "checks": list(resolver_choices.CHECK_LINES)}

    def resolver_set(self, choice) -> dict:
        try:
            resolver_choices.save(self.key_dir, choice)
        except ValueError:
            raise WizardError("That is not one of the choices.")
        except OSError:
            raise WizardError("Could not save that choice.")
        return self.resolver_state()

    # -- one VPN peer for one device: keys made here, shown once, never kept
    def vpn_peer_new(self, d) -> dict:
        try:
            return vpn_peer.make(name=d.get("name"), server_public=d.get("server_public"),
                                 host=d.get("host"), port=d.get("port"), address=d.get("address"),
                                 mode=d.get("mode"), networks=d.get("networks"), dns=d.get("dns"),
                                 use_preshared=d.get("preshared") is True)
        except vpn_peer.PeerError as exc:
            raise WizardError(str(exc))

    def vpn_next(self, instance_address) -> dict:
        try:
            return {"address": vpn_peer.next_address(instance_address)}
        except vpn_peer.PeerError as exc:
            raise WizardError(str(exc))

    def vpn_wan(self, address) -> dict:
        try:
            return vpn_peer.wan_hint(address)
        except vpn_peer.PeerError as exc:
            raise WizardError(str(exc))

    # -- a one-time-password seed: made, shown, checked, never kept
    def otp_new(self, account) -> dict:
        return otp_codes.make(account)

    def otp_check(self, seed, code) -> dict:
        try:
            return {"match": otp_codes.check(seed, code)}
        except otp_codes.OtpError as exc:
            raise WizardError(str(exc))

    def blocklists_set(self, data) -> dict:
        try:
            blocklist_choices.save(self.key_dir, data)
        except ValueError as exc:
            raise WizardError(str(exc))
        except OSError:
            raise WizardError("Could not save that choice.")
        return blocklist_choices.state(self.key_dir)

    # -- terms and the call-home choice: each asked once, kept in the key folder
    LEGAL_FILE = "legal.json"
    CONSENT_KEYS = ("versions", "checks", "problems", "devices")

    # The terms' version is stored with the tick, and a new version asks again.
    # It flips to "2026-11-10" when the 12-clause beta 1 terms text goes in.
    TERMS_VERSION = "2026-11-18"

    def legal(self) -> dict:
        try:
            data = json.loads((self.key_dir / self.LEGAL_FILE).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        consent = data.get("consent") if isinstance(data, dict) else None
        # Answered means every switch has an answer: a switch added in a later build (devices, BUILD 427) is asked for
        # on the next start instead of being skipped because the older three were answered.
        answered = isinstance(consent, dict) and set(self.CONSENT_KEYS) <= set(consent)
        return {"terms": bool(isinstance(data, dict) and data.get("terms") is True
                              and data.get("terms_version") == self.TERMS_VERSION),
                "terms_version": self.TERMS_VERSION,
                "consent_answered": answered, "consent_asked": isinstance(consent, dict),
                "consent": {k: bool(isinstance(consent, dict) and consent.get(k) is True) for k in self.CONSENT_KEYS}}

    def legal_save(self, terms, consent) -> dict:
        now = self.legal()
        if not (now["terms"] or terms is True):
            raise WizardError("Accept the terms to finish.")
        if consent is not None and not (isinstance(consent, dict) and set(consent) <= set(self.CONSENT_KEYS)):
            raise WizardError("That choice was not understood.")
        keep = {"terms": True, "terms_version": self.TERMS_VERSION,
                "terms_accepted_at": time.strftime("%Y-%m-%dT%H:%M:%S")}
        if now["consent_answered"]:
            keep["consent"] = now["consent"]            # asked once: never overwritten here
        elif consent is not None:
            # the switches already answered keep their answer; the new one takes what was just said
            keep["consent"] = {**now["consent"], **{k: consent.get(k) is True for k in self.CONSENT_KEYS if k in consent}}
        self.key_dir.mkdir(parents=True, exist_ok=True)
        (self.key_dir / self.LEGAL_FILE).write_text(json.dumps(keep), encoding="utf-8")
        return self.legal()

    def _job_view(self) -> dict | None:
        job = self._job
        if job is None:
            return None
        view = {k: v for k, v in job.items() if k != "sink"}
        sink = job.get("sink")
        view["lines"] = (_summary_lines(list(sink.lines)) if sink is not None and
                         job.get("state") == "running" else list(job["lines"]))
        return view

    # -- finding the firewall when this device is on another network
    @staticmethod
    def _parse_address(text) -> tuple[str, int]:
        """A private address as numbers, with an optional port. Nothing else is accepted."""
        from pazuzu_core import find_firewall as ff
        raw = str(text or "").strip()
        if raw.lower().startswith("https://"):
            raw = raw[8:]
        raw = raw.rstrip("/")
        host, _, port_text = raw.partition(":")
        try:
            port = int(port_text) if port_text else 443
        except ValueError:
            port = 0
        if not ff.private_only(host) or not 1 <= port <= 65535:
            raise WizardError("Type the firewall’s address as numbers, for example 192.168.1.1 "
                              "(a port can follow, like 192.168.1.1:8443).")
        return host, port

    def find_firewall(self, typed=None) -> dict:
        from pazuzu_core import find_firewall as ff
        hosts, ports, launch = [], [], []
        if typed:
            host, port = self._parse_address(typed)
            hosts.append(host)
            ports.append(port)
        else:                                  # first, the address this wizard was started with
            try:
                lhost, lport = base_host_port(self.base_url)
                if lhost and ff.private_only(lhost):
                    launch.append(lhost)
                    ports.append(lport)
            except (ValueError, TypeError):
                pass
        finder = self._find_fn or ff.find_firewall
        report = finder(typed=hosts, launch=launch, extra_ports=ports)
        out = report.as_dict() if hasattr(report, "as_dict") else dict(report)
        self._describe_found(out.get("found") or [])
        return out

    def _describe_found(self, found: list) -> None:
        """With more than one firewall on the network the addresses alone do not say which is which. Add what
        does: the certificate's own name, the start of its fingerprint, and whether the keys in this key folder
        were made on it. The one that owns these keys goes first. A finder handed in is a test's, and gets no
        look at the network unless a detail function is handed in too."""
        detail = self._detail_fn or (None if self._find_fn is not None else _firewall_detail)
        stamp = read_stamp(self.key_dir / KEY_STAMP)
        for f in found:
            info = {}
            if detail is not None:
                try:
                    info = detail(f.get("host"), int(f.get("port") or 443)) or {}
                except Exception:
                    info = {}
            f["fingerprint_start"] = str(info.get("fingerprint_start") or "")
            f["cert_name"] = str(info.get("cert_name") or "")
            f["keys_here"] = bool(stamp and stamp[0] == f.get("host"))
        found.sort(key=lambda f: not f["keys_here"])

    def find_harder(self, address) -> dict:
        """The opt-in full port search, on one address."""
        from pazuzu_core import find_firewall as ff
        if not address or not str(address).strip():
            raise WizardError("Type the firewall's address first, like 192.168.1.1.")
        host, _port = self._parse_address(address)
        searcher = self._harder_fn or ff.search_harder
        report = searcher(host)
        return report.as_dict() if hasattr(report, "as_dict") else dict(report)

    def check_keys(self, timeout: float = 6.0) -> str:
        """Does the firewall still accept the saved look-only key? One harmless read, once at start.
        A refusal (401) means the firewall was reset since: the saved keys are from an older one."""
        try:
            return self._check_keys(timeout)
        finally:
            self.keys_checking = False

    keys_looks = 2          # a "refused" is only believed when it is said this many times in a row
    keys_pause = 0.8        # seconds between looks

    def _one_look(self, timeout: float) -> tuple[str, str]:
        """One harmless read with the saved look-only key. Returns (verdict, what answered)."""
        host, port = base_host_port(self.base_url)
        try:
            session = self._role_session(en.READ, "")
            r = session.get(self.base_url.rstrip("/") + "/api/core/system/status",
                            timeout=timeout, headers={"X-Requested-With": "XMLHttpRequest"},
                            allow_redirects=False)
            if r.status_code == 401:
                return "stale", f"The firewall at {host} answered and refused the saved keys."
            return "ok", f"The firewall at {host} answered (code {r.status_code})."
        except Exception as exc:
            # A certificate that no longer matches the pin means a different (reset) firewall answers.
            ssl_trouble = any("SSL" in type(e).__name__ or "certificate" in str(e).lower()
                              for e in (exc, exc.__cause__, exc.__context__) if e)
            if ssl_trouble:
                seen = ""
                try:
                    seen = " (it starts " + str(self._fetch_fp(host, port))[:8] + ")"
                except Exception:
                    pass
                return "stale", f"Something at {host} answered with a different certificate than the one saved{seen}."
            return "unreachable", f"Nothing answered at {host}: {_plain(exc)}"

    def _check_keys(self, timeout: float) -> str:
        """Look, and look again before blaming the keys: a box that is still starting, or a cable that is
        loose, must not read as a reset firewall. The page says what answered."""
        self.keys_note = ""
        if not self._key_file(en.READ).exists():
            self.keys_state = "none"
            return self.keys_state
        verdict, note = self._one_look(timeout)
        looks = 1
        while verdict == "stale" and looks < self.keys_looks:
            time.sleep(self.keys_pause)
            again, note2 = self._one_look(timeout)
            looks += 1
            if again != "stale":
                verdict, note = again, note2          # it did not say it twice: not believed
                if again == "unreachable":
                    note = "It answered once and then went quiet, so the keys are not blamed. " + note2
        self.keys_state, self.keys_note = verdict, note
        return self.keys_state

    def keys_aside(self) -> dict:
        """Move this firewall's saved keys (and its certificate pin) into a dated folder, so sign-in starts
        again. Nothing is deleted, and the passkey and the other choices stay where they are."""
        from pazuzu_core.enroll_safety import PIN_FILE
        if self._job is not None and self._job.get("state") == "running":
            raise WizardError("Something is already running. Wait for it to finish.")
        files = ([self._key_file(r) for r in (en.READ, en.WRITE, en.INSTALLER)]
                 + [self.key_dir / PIN_FILE, self.key_dir / KEY_STAMP])
        files = [f for f in files if f.exists()]
        if not files:
            self.keys_state = "none"
            return {"moved": [], "folder": None}
        dest = self.key_dir / ("old-keys-" + time.strftime("%Y%m%d-%H%M%S"))
        try:
            dest.mkdir(mode=0o700, parents=True, exist_ok=False)
            for f in files:
                os.replace(f, dest / f.name)
        except OSError as exc:
            raise WizardError("Could not move the old keys: " + _plain(exc))
        # What was found out about the old firewall (its ports, zones and what was switched on) is
        # not true of this one, so it is set aside too and discovery starts from the beginning.
        left = []
        scan = Path("scan_results")
        for name in OLD_FIREWALL_FILES:
            f = scan / name
            if f.exists():
                try:
                    os.replace(f, dest / ("scan-" + name))
                    left.append(name)
                except OSError:
                    pass
        self._probe = None
        self._last_write = None
        self.keys_state = "none"
        self._forget_firewall_choices()
        return {"moved": [f.name for f in files] + left, "folder": dest.name}

    def use_firewall(self, url) -> dict:
        """Point this wizard at another firewall. Only before it has made any keys here."""
        host, port = self._parse_address(url)
        if any(self._key_file(r).exists() for r in (en.READ, en.WRITE, en.INSTALLER)):
            raise WizardError("This device already holds keys for the firewall it first connected to. "
                              "To use a different one, start the wizard with that firewall’s address.")
        if self._job is not None and self._job.get("state") == "running":
            raise WizardError("Something is already running. Wait for it to finish.")
        self.base_url = f"https://{host}" + ("" if port == 443 else f":{port}")
        return {"firewall_url": self.base_url, "firewall": host}

    # -- one firewall per key folder, and per set of saved results
    def stamp_keys(self, just_made: bool = False) -> None:
        """Write the firewall's name into the key folder, once. Keys that were made before this existed carry no
        name, and a guess could be wrong, so they are left alone unless these keys were made just now."""
        path = self.key_dir / KEY_STAMP
        if read_stamp(path) is not None:
            return
        if not just_made and any(self._key_file(r).exists() for r in (en.READ, en.WRITE, en.INSTALLER)):
            return
        host, port = base_host_port(self.base_url)
        try:
            write_stamp(path, host, port)
        except OSError:
            pass

    startup = None            # what the look around at launch saw (set by main); the sign-in step shows it

    def fresh_check(self, fp: str) -> str:
        """Is this firewall the one the saved keys were made on? A different certificate means it was installed again
        (or replaced) since: the old keys and results are set aside, never deleted, and the wizard starts at sign-in,
        exactly as on a new install. Returns a sentence for the console, or ''."""
        fp = str(fp or "").strip().lower()
        if not fp:
            return ""
        if not any(self._key_file(r).exists() for r in (en.READ, en.WRITE, en.INSTALLER)):
            return "No keys are saved here for this firewall yet, so this starts at sign-in, as on a new install."
        pin = load_pin(self.key_dir)
        if pin is None:
            return ""                       # keys from before the certificate was kept: check_keys looks at them
        if pin == fp:
            return "This is the same firewall the saved keys were made on."
        try:
            moved = self.keys_aside()
        except WizardError as exc:
            return str(exc)
        return ("This firewall shows a different certificate than the one the saved keys were made on, so it was "
                "installed again. The old keys and results were set aside in " + str(moved.get("folder")) +
                ", and the wizard starts at sign-in.")

    def claim_scan_results(self, scan_dir=None) -> str:
        """The saved results (ports, zones, what was switched on, the change journal) belong to one firewall.
        Found there for another firewall, they are set aside in a dated folder, never deleted, so a second firewall
        never starts from the first one's port choices. Returns a sentence for the console, or ''."""
        scan = Path(scan_dir) if scan_dir is not None else Path("scan_results")
        host, port = base_host_port(self.base_url)
        stamp = scan / SCAN_STAMP
        seen = read_stamp(stamp)
        present = [n for n in OLD_FIREWALL_FILES if (scan / n).exists()]
        if seen is None:
            if present:
                return ("The saved results in scan_results have no firewall name on them (an older version made "
                        "them). If they came from a different firewall, rename that folder before going on.")
            try:
                write_stamp(stamp, host, port)
            except OSError:
                pass
            return ""
        if seen[0] == host:
            # BUILD 498: results already lost this way (before this build) come back on the next start too,
            # but only into an empty folder, never mixed into results this firewall has made since
            return self._bring_back_results(scan, host).strip() if not present else ""
        where = ""
        if present:
            dest = scan / ("old-" + seen[0] + "-" + time.strftime("%Y%m%d-%H%M%S"))
            try:
                dest.mkdir(parents=True, exist_ok=False)
                for name in present:
                    os.replace(scan / name, dest / name)
            except OSError as exc:
                return f"The saved results for the firewall at {seen[0]} could not be set aside: {_plain(exc)}"
            where = f", so they were set aside in {dest.name}"
        try:
            write_stamp(stamp, host, port)
        except OSError:
            pass
        back = self._bring_back_results(scan, host)
        return f"The saved results in scan_results were for the firewall at {seen[0]}, not {host}{where}.{back}"

    def _bring_back_results(self, scan: Path, host: str) -> str:
        """BUILD 498 (the Smart devices check never ran, so Tuya's 8886 never went on the list):
        switching the PC from one firewall to another and back set the first one's port choice aside and never brought it back,
        so it came back with no saved ports at all. Coming back to a firewall now brings its own newest set-aside results
        back, file by file, where nothing newer is there, but only to the same install: this key folder must be this
        firewall's, still hold its certificate (fresh_check, which runs first, moves keys and certificate aside when
        the firewall was installed again), and that certificate must be older than the set-aside results, so results
        from before a reinstall never come back to keys made on the new one. A port it no longer has is still dropped
        (_drop_stale_zones)."""
        kept = read_stamp(self.key_dir / KEY_STAMP)
        if kept is None or kept[0] != host or load_pin(self.key_dir) is None:
            return ""
        try:
            from pazuzu_core.enroll_safety import PIN_FILE
            pinned_at = (self.key_dir / PIN_FILE).stat().st_mtime
        except OSError:
            return ""
        try:
            mine = sorted((d for d in scan.iterdir()
                           if d.is_dir() and re.fullmatch(re.escape("old-" + host) + r"-\d{8}-\d{6}", d.name)),
                          key=lambda d: d.name)
        except OSError:
            return ""
        if not mine:
            return ""
        src, moved = mine[-1], []
        try:
            aside_at = time.mktime(time.strptime(src.name[-15:], "%Y%m%d-%H%M%S"))
        except ValueError:
            return ""
        if pinned_at > aside_at + 1:
            return ""                        # keys made since: maybe a new install, so these stay aside
        for name in OLD_FIREWALL_FILES:
            if name == "change_journal.json":
                continue                     # BUILD 500: never; a change left open in it would be undone at start
            if (src / name).exists() and not (scan / name).exists():
                try:
                    os.replace(src / name, scan / name)
                    moved.append(name)
                except OSError:
                    pass
        try:
            src.rmdir()                      # only when nothing else is left in it
        except OSError:
            pass
        if not moved:
            return ""
        return f" Its own saved results from {src.name[-15:-7]} were brought back ({', '.join(moved)})."

    _guard_client_fn = None        # tests give this a fake; the real one is the firewall's change client

    def guard_clear(self) -> dict:
        """Close a change that was left open: a crash, a window that ran out, a journal from another run. Nobody can
        be waiting on it (this is only asked when nothing is running), so what was changed is undone through the
        firewall, newest first, and a journal that never changed anything is just set aside. Nothing is deleted."""
        from pazuzu_core.change_guard import ChangeGuard, GuardError, UNRESOLVED
        if self._job is not None and self._job.get("state") == "running":
            raise WizardError("Something is already running. Wait for it to finish.")
        path = Path(self.journal)
        stamp = time.strftime("%Y%m%d-%H%M%S")

        def aside(why: str) -> dict:
            dest = path.with_name(f"{path.stem}.set-aside-{stamp}{path.suffix}")
            try:
                os.replace(path, dest)
            except OSError as exc:
                raise WizardError("Could not set the change file aside: " + _plain(exc))
            return {"action": "set_aside", "note": f"{why} It was set aside as {dest.name}."}

        try:
            journal = ChangeGuard(None, path).load()
        except GuardError:
            return aside("The file that tracks changes could not be read, so check the firewall's rules by hand.")
        if not journal or journal.get("state") not in UNRESOLVED:
            return {"action": "none", "note": ""}
        label = str(journal.get("label") or "a change")
        touched = [s for s in (journal.get("steps") or [])
                   if isinstance(s, dict) and s.get("status") in ("attempted", "applied", "undo_failed")]
        if not touched:
            return aside(f"An earlier change ({label}) had not changed anything.")
        if not self._key_file(en.WRITE).exists():
            raise WizardError(f"An earlier change ({label}) is still open and the change-making account is not "
                              "made yet, so it cannot be undone from here.")
        factory = self._guard_client_fn
        try:
            if factory is None:
                from pazuzu_core.opnsense_mutation_client import OPNsenseMutationClient as factory
            with self._env(en.WRITE):
                result = ChangeGuard(factory(), path).recover(dry_run=False, after_reboot=True)
        except WizardError:
            raise
        except Exception as exc:
            raise WizardError(f"An earlier change ({label}) is still open and could not be undone now: "
                              + _plain_firewall(exc))
        if result.get("state") == "revert_failed":
            raise WizardError(f"An earlier change ({label}) could not be fully undone. Check the firewall's rules.")
        return {"action": "undone" if result.get("state") != "confirmed" else "kept",
                "note": f"An earlier change ({label}) was left open by a previous run, and is now closed."}

    def recover_stale_guard(self) -> str:
        """At start nothing can be waiting on a change, so one left open by an earlier run is closed now rather
        than trapping this run. Returns a sentence for the console, or ''."""
        try:
            return self.guard_clear().get("note", "")
        except WizardError as exc:
            return str(exc)
        except Exception:
            return ""

    def _drop_stale_zones(self, discovery: dict) -> str:
        """A saved port choice that names a port or an interface name the firewall does not have is from another
        firewall. It is set aside, so the ports are chosen again, and 'Option [opt1] not in list' never happens."""
        if not self.zones_path.exists():
            return ""
        try:
            saved = json.loads(self.zones_path.read_text(encoding="utf-8"))
            from pazuzu_core.zone_assignment import selectable_interfaces
            have = {i["device"]: i["identifier"] for i in selectable_interfaces(discovery)}
            odd = []
            for zone, a in (saved.get("assignments") or {}).items():
                if not isinstance(a, dict) or a.get("method") != "existing":
                    continue
                dev, ident = a.get("device"), a.get("identifier")
                if dev not in have or (ident and have[dev] != ident):
                    odd.append(str(dev))
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            return ""
        if not odd:
            return ""
        dest = self.zones_path.with_name(f"{self.zones_path.stem}.other-firewall-{time.strftime('%Y%m%d-%H%M%S')}"
                                         f"{self.zones_path.suffix}")
        try:
            os.replace(self.zones_path, dest)
        except OSError:
            return ""
        return ("The saved port choices named " + ", ".join(sorted(set(odd))) + ", which this firewall does not "
                "have. They are from another firewall, so they were set aside and the ports are chosen again.")

    # -- the certificate the person is asked to compare
    def fingerprint(self) -> dict:
        if self.phone:
            return {"needed": False}      # BUILD 477: on the box the wizard talks to the firewall it runs on: no compare
        return self._fingerprint_read()

    def _fingerprint_read(self) -> dict:
        if not (self.base_url.startswith("https://") and self.verify is False):
            return {"needed": False}
        host, port = base_host_port(self.base_url)
        try:
            fp = self._fetch_fp(host, port)
        except OSError:
            hint = reach_hint(host)
            raise WizardError("Could not reach the firewall. " + (hint or
                "Check the cable is in the port labelled LAN (or 1), and that this device’s address is in the firewall’s range."))
        saved = load_pin(self.key_dir)
        name = ""
        if self._fetch_fp is fetch_fingerprint:
            from pazuzu_core.enroll_safety import fetch_cert_name
            name = fetch_cert_name(host, port)
        return {"needed": True, "fingerprint": show_fingerprint(fp), "raw": fp,
                "host": host, "cert_name": name,
                "known": saved == fp, "changed": bool(saved and saved != fp)}

    # -- jobs: one at a time, output kept for the page
    def _start(self, kind: str, work: Callable[[], dict | None]) -> dict:
        if not self._job_lock.acquire(blocking=False):
            # BUILD 471: the manager's sign-in waiting for its touch is not "something running": wait for it (the touch
            # it waits for is the one the person is about to give), then go on. Prod pressed a button twice into it.
            j = getattr(self, "_job", None) or {}
            if not (j.get("kind") == "manager-unlock" and j.get("state") == "running"
                    and self._job_lock.acquire(timeout=float(self.approval_seconds) + 5)):
                raise WizardError("Something is already running. Wait for it to finish.")
        self._job_seq = getattr(self, "_job_seq", 0) + 1
        self._job = {"kind": kind, "state": "running", "lines": [], "error": None,
                     "result": None, "id": self._job_seq}
        from pazuzu_core import activity
        activity.note(f"Started: {kind}")

        origin = getattr(_who, "origin", "wizard")          # who started it: the manager or the setup
        job = self._job                                     # this job's own record, even once a next one has started

        def run() -> None:
            _who.job = True
            _who.origin, _who.kind = origin, kind
            sink = _Lines()
            job["sink"] = sink
            final: dict = {"state": "failed", "error": "It stopped."}
            try:
                with contextlib.redirect_stdout(sink):
                    result = work()
                lines = _summary_lines(sink.finish())
                if not lines and isinstance(result, dict):
                    lines = list(result.get("lines") or [])
                final = {"lines": lines, "result": result, "state": "done"}
                from pazuzu_core import activity
                activity.note(f"Finished: {kind}")
            except WizardError as exc:
                final = {"lines": _summary_lines(sink.finish()), "state": "failed", "error": str(exc)}
                from pazuzu_core import activity
                activity.note(f"Stopped: {kind} ({str(exc)[:120]})")
                self.telemetry_problem(kind, str(exc))
            except Exception as exc:                     # shown as text, never a trace
                final = {"lines": _summary_lines(sink.finish()), "state": "failed", "error": _plain(exc)}
                self.telemetry_problem(kind, _plain(exc))
            finally:
                job.pop("sink", None)
                self._read_cache_clear()                 # a job may have written: the next read sees the firewall, not the cache
                # BUILD 489: the lock goes first, then the job says it has finished, so whoever sees "done" or "failed"
                # can start the next one at once. It said so first, and a next job started on seeing it was turned away
                # with "Something is already running" now and then (found 10 Nov 2026 by a test that chains two).
                self._job_lock.release()
                job.update(final)

        threading.Thread(target=run, daemon=True).start()
        return {"started": kind}

    # -- sign in and make a user
    def enroll(self, role_name: str, use_default: bool, password, fingerprint,
               username=None, also_installer: bool = False) -> dict:
        role = {"read": en.READ, "write": en.WRITE, "installer": en.INSTALLER}.get(role_name)
        if role is None:
            raise WizardError("Unknown user.")
        if self._key_file(role).exists():
            if role is en.INSTALLER and getattr(self, "_installer_dead", False):
                # The old key no longer works: keep it aside (never deleted) and make the account again
                old_key = self._key_file(role)
                try:
                    old_key.replace(old_key.with_name(old_key.name + ".closed"))
                except OSError:
                    raise WizardError("The old installer key could not be moved aside. Delete it by hand: " + str(old_key))
            else:
                raise WizardError(f"{role.name} already has a key on this device.")
        if role is en.WRITE or role is en.INSTALLER:
            if not self._key_file(en.READ).exists():
                raise WizardError("Make the read user first.")
            if not self._can_change():
                raise WizardError("Register your passkey first.")
        who = "root" if use_default or not username else username
        if not isinstance(who, str) or not _USERNAME.fullmatch(who):
            raise WizardError("That user name is not allowed. Use letters, digits and . _ - @ only.")
        secret = FACTORY_PASSWORD if use_default else password
        if not isinstance(secret, str) or not secret or len(secret) > PASSWORD_MAX:
            raise WizardError("Type the firewall's password.")
        pin = None
        confirmed = None
        if self.base_url.startswith("https://") and self.verify is False:
            # BUILD 479: read it here even on the phone (the page no longer shows it there, BUILD 477, and enroll then
            # failed with "that request was not understood": the lab box, 3 Nov 2026). On the box the wizard talks to
            # the firewall it runs on, so what it reads is what it pins; the person is not asked to compare.
            fresh = self._fingerprint_read()
            if role is en.READ and self.phone:
                fingerprint = fresh["raw"]
            if role is en.READ:
                if fingerprint != fresh["raw"]:
                    raise WizardError("The firewall's certificate is not the one "
                                      "you confirmed. Start the check again.")
                pin, confirmed = fresh["raw"], fresh["raw"]
            else:
                pin = load_pin(self.key_dir)
                if pin is None or pin != fresh["raw"]:
                    raise WizardError("The firewall's certificate is not the one "
                                      "you trusted before. Nothing was sent.")

        def work() -> dict:
            extra = {} if who == "root" else {"username": who}
            lines = self._enroll(
                self.base_url, secret, self.verify, self.key_dir,
                lambda perms, exists=False: True, pin=pin, role=role,
                gate=self.window_gate if role.needs_passkey else None, **extra)
            for line in lines:
                print(line)
            saved = any(line == "key file saved" for line in lines)
            if not saved:
                raise WizardError(_plain_enroll(lines))
            if role is en.INSTALLER:
                self._installer_dead = False
                self._probe = None
                self._sync_accounts()
            self.stamp_keys(just_made=True)          # these keys belong to this firewall from now on
            if role is en.READ or self.keys_state == "none":
                # The firewall has just taken these keys. Without this, a first sign-in on a clean key folder left the
                # state at "none" for the whole session, and the saved admin, root and VPN choices were hidden.
                self.keys_state, self.keys_note = "ok", ""
            if saved and confirmed and load_pin(self.key_dir) != confirmed:
                save_pin(self.key_dir, confirmed)
            result = {"saved": saved}
            if self.light and role is en.READ:
                # A new or test firewall: the one sign-in makes the change account and the installer account too,
                # so nothing later asks for the password again. If one of them is refused (a one-time code that
                # cannot be used twice, say) the look-only user is still made and the page asks for the rest.
                for more_role in (en.WRITE, en.INSTALLER):
                    try:
                        more = self._enroll(
                            self.base_url, secret, self.verify, self.key_dir,
                            lambda perms, exists=False: True, pin=load_pin(self.key_dir) or pin,
                            role=more_role, gate=self.window_gate, **extra)
                    except Exception as exc:
                        print(f"the {more_role.name} account was not made now ({_plain(exc)}); it can be made later")
                        break
                    ok = any(line == "key file saved" for line in more)
                    print(f"{more_role.name} account made" if ok else f"the {more_role.name} account was not made now; it can be made later")
                    if not ok:
                        break
                    if more_role is en.INSTALLER:
                        self._probe = None
            if also_installer and role is en.WRITE and not self._key_file(en.INSTALLER).exists():
                # The same one sign-in makes the installer account too (the password is used once, here),
                # inside the same passkey window, so nothing later has to ask for the password again.
                more = self._enroll(
                    self.base_url, secret, self.verify, self.key_dir,
                    lambda perms, exists=False: True, pin=load_pin(self.key_dir) or pin, role=en.INSTALLER,
                    gate=self.window_gate, **extra)
                result["installer"] = any(line == "key file saved" for line in more)
                if result["installer"]:
                    self._probe = None      # what was checked before was seen by a smaller account
                print("installer account made" if result["installer"]
                      else "the installer account was not made; you can make it later")
            return result

        return self._start(f"enroll-{role_name}", work)

    def trial_set(self, on) -> dict:
        self.trial = on is True
        return {"trial": self.trial}

    def mode_set(self, mode) -> dict:
        """The first screen's choice. A new or test firewall (and the live-CD test flight) is set up the light
        way: no passkey, and the lab lifeline on because the LAN is the only way in. A firewall that is already
        running keeps the careful way: passkey, and a look before any change."""
        if mode not in ("new", "trial", "audit"):
            raise WizardError("Pick one of the three.")
        self.light = mode in ("new", "trial")
        self.trial = mode == "trial"
        self.lab_lifeline = self.light
        self._remember("mode", mode)
        acts = getattr(self, "_acts", None)
        if acts is not None and getattr(acts, "source", None) is not None:
            acts.source.lab = self.light
            acts.source.beta_locked = not self._manager_open()
            acts.source.forget()
        return {"mode": mode, "light": self.light, "trial": self.trial}

    def _setup_id(self) -> str:
        """BUILD 510 (the maintainer, a factory box, 11 Nov 2026: "still skipped version"): which setup this is, from the
        certificate Pazuzu's keys were made on (a firewall installed again has a new one, and its old keys are set
        aside). The page keeps the steps it has done in the browser tab, and must not carry "plugin and version: done"
        over from the old setup. Empty before the first sign-in."""
        import hashlib
        try:
            pin = load_pin(self.key_dir)
        except Exception:  # noqa: BLE001
            pin = None
        return hashlib.sha256(str(pin).encode()).hexdigest()[:12] if pin else ""

    def _manager_open(self) -> bool:
        """BUILD 493 (the maintainer, 10 Nov 2026: the manager is "greyed for all unless in test mode (for me)"; it is the paid part,
        in beta release 2). Test mode is the new/testing way (light); the phone is Hanbi's own setup. The manager's engine
        still starts behind the setup (the box link runs through it); only its window is closed."""
        from pazuzu_core.console import manager_present
        return bool((self.light or self.phone or getattr(self, "manager_override", False)
                     or not BETA_MANAGER_TEST_ONLY) and manager_present())

    def _plugin_offered(self) -> bool:
        """BUILD 513 (the maintainer, 12 Nov 2026: "we keep it closed for now and show off what we can do with the api"; "no real
        value for a beta user to have plugin access yet"). Beta 1 is the wizard over the firewall's own API: the plugin
        is not in the public build, and its steps (the plugin, the Wi-Fi back door, the phone hotspot backup) are not
        shown. They are shown on Hanbi's own setup (the phone), with the maker's switch (--manager), and on a firewall
        this PC already has the plugin on."""
        if not plugin_present():
            return False
        return bool(self.phone or getattr(self, "manager_override", False) or not BETA_PLUGIN_HIDDEN
                    or isinstance(self._recall("box_link"), dict))

    # -- the manager (the Hanbi console), started from here, looking only
    def manager_start(self) -> dict:
        from pazuzu_core import console as cn
        if getattr(self, "_manager_url", None):
            return {"url": self._manager_url}
        if getattr(self, "_acts", None) is not None and not self._manager_open():
            return {"url": None}                 # BUILD 494: the engine is up already; there is no window to open

        def loader():
            with self._bg_lock, self._env(en.READ, wait=BACKGROUND_ENV_WAIT_SECONDS, ride_out_reads=True):
                return cn._live_loader()

        def ifaces():
            with self._bg_lock, self._env(en.READ, wait=BACKGROUND_ENV_WAIT_SECONDS, ride_out_reads=True):
                return cn._live_interfaces()

        def gateways():
            getter = self._api_getter()
            return getter("/api/routing/settings/search_gateway") if getter else None

        def settings():
            with self._bg_lock, self._env(en.READ, wait=BACKGROUND_ENV_WAIT_SECONDS, ride_out_reads=True):
                return cn._live_settings()

        def services():
            from pazuzu_core import service_reads
            getter = self._api_getter()
            out = dict(service_reads.read(getter)) if getter else {}
            try:
                status = (source.box.read() or {}).get("status")
            except Exception:
                status = None
            held = self._ipv6_ports(source, status)
            if held is not None:
                out["ipv6_global"] = held
            zen = (status or {}).get("zenarmor") if isinstance(status, dict) else None
            if isinstance(zen, dict) and isinstance(zen.get("installed"), bool):
                out["zenarmor"] = {"installed": zen["installed"], "running": zen.get("engine_running"),
                                   "source_only": bool(zen.get("source_only"))}
            ours_fw = None
            if country_block.load(self.key_dir) is None:     # BUILD 486: a block put on from another device counts too
                fw_cb = self._country_on_firewall()
                ours_fw = bool(fw_cb and fw_cb.get("ours") and fw_cb.get("codes"))
            if country_block.load(self.key_dir) is not None or ours_fw:
                out["country_picked"] = True                 # only then is the country list judged
                got = None
                if getter:
                    try:                                     # the same number the firewall's Aliases page shows as Loaded
                        got = service_reads.table_count(getter(service_reads.TABLES), country_block.ALIAS)
                    except Exception:
                        got = None
                cb = got or ((status or {}).get("country_block") if isinstance(status, dict) else None)
                if isinstance(cb, dict):
                    out["country_block"] = {"present": cb.get("present"), "entries": cb.get("entries")}
            unread: dict = {}                                # a line the firewall would not let us read: shown, never dropped
            if getter:
                try:                                         # packet inspection's rulesets: the baseline's set switched on
                    from pazuzu_core import ids_rulesets
                    rows = ids_rulesets.rows_of(getter(ids_rulesets.LIST))
                    if ids_rulesets.wanted(rows):
                        out["ids_rulesets"] = {"wanted": len(ids_rulesets.wanted(rows)),
                                               "missing": [f for f in ids_rulesets.missing(rows) if f not in self._ids_refused()]}
                except Exception as exc:
                    unread["ids_rulesets"] = _read_words(exc)
                try:                                         # every zone's network hands out addresses
                    out["dhcp_zones"] = self._dhcp_state(getter)
                except Exception:
                    pass
                try:                                         # a certificate for the home's name, renewed by the firewall
                    out["cert"] = self._cert_read(getter)
                except Exception:
                    pass
                try:                                         # DNS redirects on isolated networks; DNS over TLS
                    out["dns_guard"] = self._dns_guard(getter)
                except Exception as exc:
                    unread["dns_redirects"] = unread["dns_tls"] = unread["ntp_redirects"] = _read_words(exc)
                try:                                         # what smart devices need from the internet (BUILD 424)
                    ic = self._iot_cloud(getter)
                    if ic is not None:
                        out["iot_cloud"] = ic
                except Exception as exc:
                    unread["iot_cloud"] = _read_words(exc)
                try:                                         # the person's own port forwards (BUILD 430)
                    fw = self._forwards(getter)
                    if fw is not None:
                        out["forwards"] = fw
                except Exception as exc:
                    unread["forwards"] = _read_words(exc)
                try:                                         # what the VPN may reach (full tunnel)
                    va = self._vpn_access(getter)
                    if va is not None:
                        out["vpn_access"] = {"missing": [r["description"] for r in va["missing"]]
                                             + (["Pazuzu: VPN DNS answers"] if va.get("acl_missing") else []), "net": va["net"]}
                except Exception as exc:
                    unread["vpn_access"] = _read_words(exc)
                try:                                         # the downloaded lists' nightly refresh
                    from pazuzu_core import list_refresh
                    jobs = (getter(list_refresh.CRON + "/search_jobs?rowCount=-1&searchPhrase=") or {}).get("rows")
                    if isinstance(jobs, list):
                        out["list_refresh"] = {"missing": list_refresh.missing(jobs)}
                except Exception as exc:
                    unread["lists_refresh"] = _read_words(exc)
                out["unread"] = unread
            try:
                admin = source.box.admin_session_status()
            except Exception:
                admin = None
            if admin is not None:
                out["admin_session"] = admin
            try:                                             # sign-in with a one-time code: the login server in use
                otp = source.box.otp_server_status() if source.box.can("otp_server") else None
                if isinstance(otp, dict) and otp.get("state") == "ok":
                    out["otp"] = {"in_use": bool(otp.get("in_use")), "present": bool(otp.get("present")),
                                  "skipped": "otp" in self.confirmed_controls()}
            except Exception:
                pass
            try:                                             # root: switched off, its own password, or the factory one
                root = source.box.root_check()
                if isinstance(root, dict):
                    out["root"] = {"factory": root.get("root") == "default", "off": root.get("root") == "off"}
            except Exception:
                pass
            try:                                             # Secure Shell: off, or tight
                ssh = source.box.ssh_status() if source.box.can("ssh") else None
                if isinstance(ssh, dict):
                    out["ssh"] = dict(ssh, allowed=self._ssh_allowed(getter), port_plan=self._ssh_port())
            except Exception:
                pass
            try:                                             # your own sign-in also works at the console
                con = self._console_state(getter)
                if con is not None:
                    sd = source.box.sudo_status() if source.box.can("sudo") else None
                    if isinstance(sd, dict):
                        con["sudo"] = bool(sd.get("allowed"))
                    out["console"] = con
            except Exception:
                pass
            return out or None

        source = cn.Source(loader, offline=False, journal=self.journal,
                           interfaces_loader=ifaces, zones_path=self.zones_path,
                           gateways_loader=gateways, settings_loader=settings, services_loader=services,
                           confirmed_fn=self.confirmed_controls)
        source.lab = bool(self.lab_lifeline)
        source.beta_locked = not self._manager_open()      # BUILD 493: the manager's window says it comes in beta 2
        source.api_feed = self._api_feed()
        source.trial_fn = lambda: self.trial
        acts = ManagerActions(self)
        acts.source = source
        source.actions = acts
        self._acts = acts
        if not self._manager_open():
            # BUILD 494: the engine above (the box link, the checks) always runs; the manager's own window is beta 2,
            # and the beta 1 build does not carry its code at all (pazuzu_manager/).
            self._manager_url = None
            from pazuzu_core.box_pause import BoxPauseBridge
            BoxPauseBridge(source.box, self.pause_now).start()
            threading.Thread(target=self._reconnect_box, daemon=True).start()
            return {"url": None}
        try:
            server = cn.make_server(source, "127.0.0.1", cn.DEFAULT_PORT)
        except OSError:
            raise WizardError("The manager's port (8765) is already in use. "
                              "Close any other manager window and try again.")
        except cn.ActionError as exc:
            raise WizardError(str(exc))                  # the manager is not in this build (beta 2)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        from pazuzu_core.box_pause import BoxPauseBridge
        BoxPauseBridge(source.box, self.pause_now).start()      # the box console's F key
        def box_then_clear():
            self._reconnect_box()
            # BUILD 459: the manager is open, so the setup page leaves the box's screen. The wizard's page tells the box
            # its step as it draws; opened on its way to the manager it left "step 2 of 4" holding the screen (the
            # dashboard only came after a key press).
            # BUILD 477: not on the phone, where the manager is started quietly behind the setup (the first box_state
            # call starts it); "done" here marked the setup finished on page 2 and the screen never showed a step.
            if self.phone:
                return
            try:
                self._box_step_said = None
                self.box_setup_step({"done": True})
            except Exception:  # noqa: BLE001 - the box not hearing it never stops the manager
                pass
        self._handoff = threading.Thread(target=box_then_clear, daemon=True)   # the plugin is already on the box: no new line
        self._handoff.start()                         # kept so a test can wait for it before its folder goes
        self._manager_url = f"http://localhost:{server.server_address[1]}/"
        # The manager may show the passkey approval itself, so nobody is sent back here for it.
        self.passkeys.approve_origins = (self._manager_url.rstrip("/"),)
        return {"url": self._manager_url}

    # -- the plugin stays on the box and starts again after a restart, so its link is kept here and reused
    def _save_box_link(self, url, token, fresh: bool = False) -> None:
        self._remember("box_link", {"url": str(url), "token": str(token)})
        # BUILD 565 (HTTPS step 2): learn the feed's key pin on first use, in the background. `fresh`: this device
        # has just put the plugin on, so a new key (a reset firewall) replaces the one kept before.
        try:
            from pazuzu_core import feed_pin
            feed_pin.learn_soon(str(url), replace=fresh)
        except Exception:  # noqa: BLE001 - plain HTTP as before
            pass

    def _reconnect_box(self) -> None:
        """Knock on the box with the link kept from last time. Quiet either way; at most once every 15 seconds."""
        acts = getattr(self, "_acts", None)
        saved = self._recall("box_link")
        if acts is None or not isinstance(saved, dict) or acts.source.box.url:
            return
        if self.keys_state == "stale" or self._now() - getattr(self, "_box_try", -1e9) < 15:
            return
        self._box_try = self._now()
        try:
            acts.source.box.try_connect(saved.get("url"), saved.get("token"))
        except Exception:
            pass

    # -- the plugin and the Wi-Fi back door, from the wizard's "safe way back in" step
    def box_offer(self) -> dict:
        from pazuzu_core.console import ActionError
        if self.phone:
            # On the box itself the plugin is what runs this wizard: there is nothing to put on, and the install line
            # would restart the plugin under a new code (lab box, 2 Nov 2026: the phone was shown "Show me the line").
            raise WizardError("The plugin is already on this Hanbi: it is what is running this setup.")
        if not plugin_present():             # BUILD 513
            raise WizardError("This build has no plugin. It comes with beta 2.")
        self.manager_start()
        try:
            return self._acts.box_offer()
        except ActionError as exc:
            raise WizardError(str(exc))

    # BUILD 551 (the maintainer, 17 Nov 2026: "they should all be the same barring the tiers of paid vs free - open and closed"; "go"):
    # the plugin goes on with the firewall's root password, as the Pazuzu app does it, with no line pasted at the
    # console. pazuzu_core/root_install.py has the steps. The pasted line stays as the other way.
    def _root_install_ready(self) -> bool:
        if self.phone or not plugin_present():
            return False
        try:
            from pazuzu_core import root_install
            return root_install.available()
        except ImportError:                      # a copy without the closed file (the public one)
            return False

    def box_root_install(self, d) -> dict:
        password = (d or {}).get("password") if isinstance(d, dict) else None
        if not isinstance(password, str) or not password:
            raise WizardError("Type the firewall's root password.")
        if not self._root_install_ready():
            raise WizardError("This copy can't install with the root password. Use the line instead.")
        from pazuzu_core import root_install
        from pazuzu_core.enroll_safety import load_pin, make_session
        forget = d.get("reinstalled") is True

        def work() -> dict:
            self.box_offer()                                     # the same offer the pasted line uses
            offer = getattr(self._acts, "_offer", None)
            if offer is None:
                raise WizardError("The plugin could not be offered to the firewall.")
            # BUILD 557: the Secure Shell key this device saw from this firewall before, kept beside the web
            # certificate it was seen with. A firewall installed again has a new certificate, so its old key is not
            # held against it; "It was reinstalled" drops it by hand.
            pin = load_pin(self.key_dir) or ""
            kept = self._recall("ssh_host_key")
            known = ""
            if isinstance(kept, dict) and kept.get("key") and kept.get("pin") == pin and not forget:
                known = str(kept["key"])
            session = make_session(self.verify, pin or None)
            try:
                got = root_install.install(self.base_url, password, offer.command(), session, known=known)
            except root_install.RootInstallError as exc:
                raise WizardError(str(exc))
            finally:
                session.close()
            if got.get("feed_pin"):                  # BUILD 565: said over the Secure Shell whose key was checked
                from pazuzu_core import feed_pin
                from pazuzu_core import box_install as _bi
                if feed_pin.keep(f"http://{offer.firewall_ip}:{_bi.FEED_PORT}", got["feed_pin"]):
                    print("The plugin's key is kept: this device speaks to it over HTTPS from now on.")
            if got.get("host_key"):
                self._remember("ssh_host_key", {"key": got["host_key"], "pin": pin})
                self._ssh_seen = {"key": got["host_key"], "state": got.get("key_state") or "first",
                                  "name": got.get("name") or ""}
                print("Secure Shell key of " + (got.get("name") or "the firewall") + ": " + got["host_key"]
                      + (" (the same key as last time)." if got.get("key_state") == "same"
                         else " (the first time this device has seen it)."))
            print("Secure Shell is " + ("as it was before (on)." if got.get("ssh_was_on") else "off again."))
            return {"lines": ["The plugin is on the firewall."]}
        return self._start("box-root-install", work)

    def _aboard(self) -> dict | None:
        """BUILD 550 (the maintainer's screenshot, 17 Nov 2026: the PC's plugin step on a firewall the Pazuzu app had set up sat at
        "Waiting for the plugin" and offered a line to install it). A plugin that this device is not linked to can still
        be seen: it says its version and whether a phone holds its key at /phone/state, with no code. Asked at most every
        15 seconds; reads only. None when nothing answers there."""
        now = time.monotonic()
        kept = getattr(self, "_aboard_kept", None)
        if kept and now - kept[0] < 15:
            return kept[1]
        got = self._open_box_state()
        out = None
        if isinstance(got, dict) and got.get("version"):
            out = {"version": str(got.get("version"))[:20], "enrolled": bool(got.get("enrolled")),
                   "setup_done": bool(got.get("setup_done"))}
            try:
                from hanbi_box import VERSION
                out["ours"] = VERSION
            except Exception:  # noqa: BLE001 - a build with no plugin in it has no copy to offer
                out["ours"] = ""
        self._aboard_kept = (now, out)
        return out

    def box_state(self) -> dict:
        out = self._box_state()
        if not out.get("connected") and not self.phone and plugin_present():
            seen = self._aboard()
            if seen:
                out["aboard"] = seen
            out["root_install"] = self._root_install_ready()
        seen = getattr(self, "_ssh_seen", None)
        if seen:                                 # BUILD 557: shown plainly once the install has run in this visit
            out["ssh_seen"] = dict(seen)
        return out

    def _box_state(self) -> dict:
        acts = getattr(self, "_acts", None)
        if not plugin_present() and not self.phone:
            # BUILD 517: no plugin in this build. A link remembered from an older install made this start the manager's
            # engine, which needs the plugin's code: "Something unexpected stopped this step (ModuleNotFoundError)".
            return {"state": "none", "connected": False}
        if acts is None and isinstance(self._recall("box_link"), dict):
            try:
                self.manager_start()                 # starts the link back up from the kept address and code
            except WizardError:
                pass
            acts = getattr(self, "_acts", None)
        if acts is None and self.phone:
            # BUILD 465: on the box, the plugin is what runs this wizard. Before Pazuzu's own accounts exist (a box
            # just reset to factory) the manager's link cannot start, and the phone was shown "Show me the line" to
            # put on a plugin that was already there (lab box, 3 Nov 2026). It is there: say so.
            return {"state": "running", "connected": True, "platform": self._own_platform_from_link() or "hanbi"}
        if acts is None:
            return {"state": "none", "connected": False}
        box = acts.source.box
        if box.url and hasattr(box, "alive") and not box.alive():
            box.disconnect()                         # a reset or a restart: it no longer answers, so it is not "connected"
        self._reconnect_box()
        out = dict(acts.box_state())
        out["connected"] = bool(box.url)
        if box.url and hasattr(box, "version"):          # BUILD 483: the plugin card says which version is aboard
            try:
                out["version"] = str(box.version() or "")
            except Exception:  # noqa: BLE001
                out["version"] = ""
        out["platform"] = (box.platform() if box.url and hasattr(box, "platform") else "") or self._own_platform() or "pazuzu"
        if box.url:
            # The plugin's own page (the touch screen). The code goes after the # sign, which a browser never sends anywhere.
            from urllib.parse import quote
            tok = getattr(box, "token", "") or ""
            out["page"] = box.url.rstrip("/") + "/screen" + ("#t=" + quote(str(tok), safe="") if tok else "")
        if not out["connected"] and out.get("state") == "running":
            # The line was run and the plugin said it started, but this device has not reached it. Say why.
            why = getattr(box, "last_error", "") or ""
            out["note"] = ("The plugin is on the firewall, but this device has not reached it yet"
                           + (f" ({why})" if why else "") + ". It keeps trying by itself.")
        if not out["connected"]:
            # The firewall's own rules can stop this device reaching the plugin's port. The page then offers one
            # button for that; it needs an address to knock at, and a line that was run (or run once before).
            out["can_open_port"] = bool(self._plugin_target() and out.get("state") != "waiting")
            if getattr(self, "_port", None):
                out["port"] = dict(self._port)
        return out

    def _own_platform_from_link(self) -> str:
        """The platform the box's own feed says it is (hanbi or pazuzu), read with the link it started this wizard
        with. "" when it cannot be read."""
        link = self._recall("box_link")
        if not isinstance(link, dict) or not link.get("url"):
            return ""
        import urllib.request
        try:
            req = urllib.request.Request(str(link["url"]).rstrip("/") + "/status.json",
                                         headers={"Authorization": "Bearer " + str(link.get("token") or "")})
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            from pazuzu_core import feed_pin                 # BUILD 565: HTTPS with the key's pin once it is known
            with feed_pin.urlopen(req, timeout=3, plain=opener.open) as r:
                return str(json.loads(r.read()).get("platform") or "")
        except Exception:  # noqa: BLE001
            return ""

    def ssh_state(self) -> dict:
        """Is Secure Shell on, and on which port? The plugin reads the firewall's own setting when it is on the box
        ("how": "plugin"). Without it, a plain connection test from this device to port 22 and to the port planned for
        this install ("how": "port check"): nothing is sent, no password is tried. A test that finds nothing on those
        ports cannot rule out another port, and says so with "sure": False."""
        host, _port = base_host_port(self.base_url)
        try:
            box = getattr(getattr(getattr(self, "_acts", None), "source", None), "box", None)
            got = box.ssh_status() if box is not None and self._box_up() and box.can("ssh") else None
        except Exception:  # noqa: BLE001
            got = None
        if isinstance(got, dict):
            on = bool(got.get("enabled"))
            return {"host": host, "on": on, "port": got.get("port") if on else None, "how": "plugin", "sure": True,
                    "root_login": bool(got.get("root_login")), "password_login": bool(got.get("password_login"))}
        ports = [22]
        try:
            planned = self._ssh_port()
            if planned and planned not in ports:
                ports.append(planned)
        except Exception:  # noqa: BLE001
            pass
        found = None
        if host:
            for p in ports:
                try:
                    with socket.create_connection((host, p), timeout=1.5):
                        found = p
                        break
                except OSError:
                    continue
        return {"host": host, "on": found is not None, "port": found, "how": "port check", "sure": found is not None}

    # -- the firewall's own rules can block the plugin's port; one guarded rule opens it, and is taken out again if it did not help
    PORT_KNOCKS = 8                     # after the rule: how many times to knock, two seconds apart

    def _plugin_target(self):
        """Where the plugin should answer and the code to knock with: (url, token), or None when no line was ever offered."""
        from urllib.parse import urlparse
        from pazuzu_core import box_install as bi
        acts = getattr(self, "_acts", None)
        box = getattr(getattr(acts, "source", None), "box", None)
        found = []
        if box is not None and box.url and getattr(box, "token", None):
            found.append((box.url, box.token))
        offer = getattr(acts, "_offer", None)
        if offer is not None:
            found.append((f"http://{offer.firewall_ip}:{bi.FEED_PORT}", offer.feed_token))
        saved = self._recall("box_link")
        if isinstance(saved, dict) and saved.get("url") and saved.get("token"):
            found.append((str(saved["url"]), str(saved["token"])))
        for url, tok in found:
            try:
                if urlparse(url).hostname:
                    return url, tok
            except ValueError:
                continue
        return None

    def plugin_port_open(self) -> dict:
        """Approved exception to "nothing is added until the plugin is on": one pass rule, that network to the firewall
        itself, the plugin's one TCP port. The plugin still needs its code. Needs a passkey like every change."""
        from pazuzu_core.console import ActionError
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        self.box_state()                                  # starts the link back up from a kept address, if there is one
        target = self._plugin_target()
        if target is None:
            raise WizardError("Run the plugin line on the firewall first; there is no plugin address to open a way to yet.")
        if (getattr(self, "_port", None) or {}).get("state") == "working":
            raise WizardError("That is already being done. Wait for it to finish.")
        url, token = target
        self._port = {"state": "working", "message": "Checking whether the plugin answers\u2026", "manual": []}
        try:
            return self._start("plugin-port", lambda: self._open_port(url, token))
        except WizardError:
            self._port = None
            raise

    def _open_port(self, url: str, token: str) -> dict:
        from urllib.parse import urlparse
        from pazuzu_core import plugin_link
        from pazuzu_core.passkey_gate import plan_digest
        box = self._acts.source.box
        parsed = urlparse(url)
        host, port = parsed.hostname or "", parsed.port or 8787
        state = {"manual": plugin_link.manual_fields(None, port)}

        def say(kind: str, message: str) -> dict:
            self._port = {"state": kind, "message": message, "manual": state["manual"]}
            return dict(self._port)

        def hand() -> str:
            return " The rule is in the box below if you would rather add it yourself."

        for _ in range(2):                                # a merely slow plugin must not get a rule it does not need
            if box.try_connect(url, token):
                self._save_box_link(url, token)
                return say("answering", "The plugin already answers, so nothing was changed.")
        if self._probe is None:
            return say("failed", "Check what this firewall supports first, then try again. Nothing was changed." + hand())
        try:
            engine = we.Engine(self._installer_session(), self.base_url.rstrip("/"), self._probe)
        except WizardError as exc:
            return say("failed", str(exc) + " Nothing was changed." + hand())
        undo = None
        try:
            iface = engine.interface_for(host)
            if not iface:
                return say("failed", f"None of the firewall's networks holds {host}, so no rule was added. "
                                     "Add one by hand on the network the plugin is on." + hand())
            state["manual"] = plugin_link.manual_fields(iface, port)
            rows = [r for r in engine._rows(we.CAPS["fw_rule"], plugin_link.DESCRIPTION)
                    if str(r.get("description")) == plugin_link.DESCRIPTION]
            if rows and str(rows[0].get("enabled", "1")) != "0":
                return say("rule_present", "Pazuzu's rule for the plugin is already on the firewall and switched on, "
                                           "yet the plugin does not answer. Something else is in the way: a rule of "
                                           "your own above it, or the plugin is not running. Nothing was changed.")
            if rows:                                      # there but switched off: switch it on, and back off to undo
                uuid = str(rows[0].get("uuid", ""))
                if not we._UUID.match(uuid):
                    return say("failed", "The firewall's rule list was not in the usual shape. Nothing was changed." + hand())
                lines = ["Switch on the rule that lets this network reach the Pazuzu plugin",
                         f"{iface} net to the firewall itself, TCP port {port} only"]
                if not self.window_gate(plan_digest("plugin-port-on", {"uuid": uuid}), lines):
                    return say("failed", "Not approved with a passkey. Nothing was changed.")
                engine._req("post", f"/api/firewall/filter/toggle_rule/{uuid}/1", json={})
                engine._reconfigure(we.CAPS["fw_rule"])

                def undo():
                    engine._req("post", f"/api/firewall/filter/toggle_rule/{uuid}/0", json={})
                    engine._reconfigure(we.CAPS["fw_rule"])
                    return True
            else:
                plans = plugin_link.build_plans(engine, host, port)
                if not plans:
                    return say("failed", "The rule could not be built for this firewall. Nothing was changed." + hand())
                outs = engine.apply_many(plans, self.window_gate)

                def undo():
                    return all(engine.undo(o) for o in reversed(outs))
        except Exception as exc:
            return say("failed", _plain_firewall(exc) + " Nothing was left changed." + hand())
        say("working", "The rule is in. Checking that the plugin answers\u2026")
        for i in range(self.PORT_KNOCKS):
            if box.try_connect(url, token):
                self._save_box_link(url, token)
                return say("done", "The rule is on and the plugin answers.")
            if i < self.PORT_KNOCKS - 1:
                self._sleep(2.0)
        why = getattr(box, "last_error", "") or ""
        try:
            removed = bool(undo())
        except Exception:
            removed = False
        gone = ("The rule did not help, so it was taken out again." if removed else
                "The rule did not help and could not be taken out: look for \u201c" + plugin_link.DESCRIPTION +
                "\u201d in the firewall's rules and delete it.")
        if "nothing is listening" in why:
            reason = ("The firewall lets the traffic through, but nothing is listening on the port: the plugin is not "
                      "running. Run the line again.")
        elif "timed out" in why:
            reason = ("Still no answer after the rule, so something else is blocking the port: a rule of your own "
                      "that matches first, or a different address than the plugin listens on.")
        else:
            reason = "Still no answer after the rule" + (f" ({why})." if why else ".")
        return say("failed", reason + " " + gone + hand())

    def _box_up(self) -> bool:
        try:
            return bool(self.box_state().get("connected"))
        except Exception:
            return False

    def _set_wifi(self, rec: dict) -> None:
        """Make this the current Wi-Fi attempt, keeping the older ones so a failure report is not lost."""
        old = getattr(self, "_wifi", None)
        if old is not None:
            self._wifi_past = (getattr(self, "_wifi_past", []) + [old])[-5:]
        self._wifi = rec

    def wifi_prepare(self) -> dict:
        import secrets
        from pazuzu_core import box_install as bi, qr
        from pazuzu_core.passkey_gate import plan_digest
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        if not self.box_state()["connected"]:
            raise WizardError("Put the Pazuzu plugin on the firewall first.")
        host, _p = base_host_port(self.base_url)
        alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        ssid = "Pz-" + "".join(secrets.choice(alphabet) for _ in range(6))
        phrase = "".join(secrets.choice(alphabet) for _ in range(20))

        box = getattr(getattr(getattr(self, "_acts", None), "source", None), "box", None)
        direct = bool(box is not None and box.can("wifi_setup"))   # a newer plugin sets it up itself; an older one needs the line once

        def work() -> dict:
            lines = ["Set up a Wi-Fi way in to your firewall's web page",
                     "Hidden network, one long password, nothing else reachable",
                     "The plugin on the firewall sets it up now" if direct else
                     "A one-time line is then pasted on the firewall (it also updates the plugin)"]
            if not self.window_gate(plan_digest("wifi-backdoor", {}), lines):
                raise WizardError("Not approved with a passkey; nothing was set up.")
            qr_text = f"WIFI:T:WPA;S:{ssid};P:{phrase};H:true;;"
            pic = qr.svg(qr.encode(qr_text, "M"), label="Wi-Fi sign-in QR code")

            def finished():
                # Whichever line the firewall ran, its report counts, even if a newer line was made since.
                self._wifi_done = {"ssid": ssid, "passphrase": phrase, "qr": pic}
                self._remember("wifi_backdoor", ssid)

            if direct:
                offer = bi.BoxWifi(box, ssid, phrase, on_done=finished, close_after_use=True).start()
                self._set_wifi({"offer": offer, "ssid": ssid, "passphrase": phrase, "qr": pic})
                return {"ready": True}
            try:
                offer = bi.ScriptOffer(host, ssid, phrase, on_done=finished, update_pub=self._update_pub())
            except (ValueError, OSError) as exc:
                raise WizardError("Could not offer the script: " + str(exc))
            # Older lines are left to run out on their own (ten minutes), so a late success is still heard.
            self._set_wifi({"offer": offer, "ssid": ssid, "passphrase": phrase, "qr": pic})
            return {"ready": True}

        return self._start("wifi-backdoor", work)

    # -- the test Wi-Fi password on an OpenWrt access point (one network only; see ap_openwrt.py)
    def _ap_store(self) -> dict:
        """{ip: {"ssid", "passphrase", "qr", "previous"}} for what this run changed. In memory only: never written to disk."""
        store = getattr(self, "_ap_wifi", None)
        if store is None:
            store = self._ap_wifi = {}
        return store

    def ap_passphrase(self, data) -> dict:
        from pazuzu_core import ap_openwrt as ap, qr
        from pazuzu_core.passkey_gate import plan_digest
        data = data if isinstance(data, dict) else {}
        ip = ap.private_address(data.get("ip"))
        phrase = data.get("passphrase")
        if ip is None:
            raise WizardError("Only an address on your own network can be changed.")
        bad = ap.passphrase_problem(phrase)
        if bad:
            raise WizardError(bad)
        if not self._can_change():
            raise WizardError("Register your passkey first.")

        def work() -> dict:
            lines = [f"Set a Wi-Fi password on the network {ap.TEST_SSID} (WPA2)",
                     f"On the access point at {ip}",
                     "Its Wi-Fi restarts for a few seconds; devices on it reconnect",
                     f"If it does not check out, the access point puts it back by itself within {ap.APPLY_TIMEOUT} seconds"]
            # The password itself is never part of the approval's name or lines; its length is.
            if not self.window_gate(plan_digest("ap-passphrase", {"ip": ip, "ssid": ap.TEST_SSID, "length": len(phrase)}), lines):
                raise WizardError("Not approved with a passkey; nothing was changed.")
            try:
                got = ap.set_passphrase(ip, phrase)
            except ap.ApError as exc:
                raise WizardError(str(exc))
            pic = qr.svg(qr.encode(ap.wifi_qr_text(got["ssid"], phrase, got["hidden"]), "M"), label="Wi-Fi join QR code")
            self._ap_store()[ip] = {"ssid": got["ssid"], "passphrase": phrase, "qr": pic, "previous": got["previous"]}
            return {"lines": [f"{got['ssid']} now has a password."]}

        return self._start("ap-passphrase", work)

    def ap_revert(self, data) -> dict:
        from pazuzu_core import ap_openwrt as ap
        from pazuzu_core.passkey_gate import plan_digest
        data = data if isinstance(data, dict) else {}
        ip = ap.private_address(data.get("ip"))
        if ip is None:
            raise WizardError("Only an address on your own network can be changed.")
        mine = self._ap_store().get(ip)
        if not mine:
            raise WizardError("This run did not change that access point, so it has nothing to put back.")
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        prev = mine["previous"]

        def work() -> dict:
            was = sorted({ap.security_words(x.get("encryption")) for x in prev.values()})
            lines = [f"Put the Wi-Fi network {mine['ssid']} back as it was: " + " / ".join(was),
                     f"On the access point at {ip}",
                     "Its Wi-Fi restarts for a few seconds; devices on it reconnect"]
            if not self.window_gate(plan_digest("ap-revert", {"ip": ip, "ssid": mine["ssid"], "was": was}), lines):
                raise WizardError("Not approved with a passkey; nothing was changed.")
            try:
                ap.restore(ip, prev)
            except ap.ApError as exc:
                raise WizardError(str(exc))
            self._ap_store().pop(ip, None)
            return {"lines": [f"{mine['ssid']} is back as it was."]}

        return self._start("ap-revert", work)

    def ap_fix_start(self, data) -> dict:
        """One of the access point's baseline fixes: IPv6 off, or Pazuzu's own leftovers removed. The access point's
        password, when it has one, is used for this one change and kept nowhere."""
        from pazuzu_core import ap_openwrt as ap
        from pazuzu_core.passkey_gate import plan_digest
        data = data if isinstance(data, dict) else {}
        ip = ap.private_address(data.get("ip"))
        action = data.get("action")
        if ip is None:
            raise WizardError("Only an address on your own network can be changed.")
        if action not in ("ipv6_off", "tidy", "dhcp_off"):
            raise WizardError("That was not understood.")
        password = data.get("password") if isinstance(data.get("password"), str) else ""
        if not self._can_change():
            raise WizardError("Register your passkey first.")

        def work() -> dict:
            lines = {"ipv6_off": [f"Switch IPv6 off on the access point at {ip}",
                                  "No local IPv6 prefix, no IPv6 connection of its own, nothing IPv6 handed out"],
                     "tidy": [f"Remove what an earlier Pazuzu change left on the access point at {ip}",
                              "Only its own unused networks (pz_v...); nothing else"],
                     "dhcp_off": [f"Stop the access point at {ip} handing out addresses on its main network",
                                  "The firewall keeps handing them out there; devices keep the address they have"]}[action]
            lines += ["Its network restarts for a few seconds; devices on it reconnect",
                      f"If it does not check out, the access point puts it all back by itself within {ap.APPLY_TIMEOUT} seconds"]
            if not self.window_gate(plan_digest("ap-" + action, {"ip": ip}), lines):
                raise WizardError("Not approved with a passkey; nothing was changed.")
            post = self._ap_post()                 # PC-direct, or through the box for a radio-joined access point
            try:
                got = {"ipv6_off": ap.ipv6_off, "tidy": ap.tidy, "dhcp_off": ap.dhcp_off}[action](ip, password, post=post, say=print)
            except ap.ApError as exc:
                raise WizardError(str(exc))
            if action == "ipv6_off":
                out = ["IPv6 is off on the access point." if got.get("changed") else "IPv6 was already off."]
            elif action == "dhcp_off":
                out = ["The access point no longer hands out addresses; the firewall does." if got.get("changed")
                       else "The access point was not handing out addresses."]
            else:
                out = ["Removed: " + ", ".join(got["removed"]) + "." if got.get("removed") else "Nothing was left over."]
            print("Reading the access point back to check it.")
            try:                                   # read back with the same password, so the list shows what is there now
                unit = ap.read(ip, post=post, password=password)
            except ap.ApError as exc:
                return {"lines": out + [f"It could not be read back just now ({exc}). Read it again in a minute."], "ip": ip}
            row = next((c for c in unit.get("checks") or [] if c.get("fix") == action or
                        (action == "ipv6_off" and str(c.get("text", "")).startswith("IPv6")) or
                        (action == "tidy" and "earlier Pazuzu change" in str(c.get("text", ""))) or
                        (action == "dhcp_off" and "addresses" in str(c.get("text", "")))), None)
            if row is not None:
                out.append("Read back: " + (row["text"] + "." if row.get("ok") else "still not right: " + row["text"] + "."))
            return {"lines": out, "ip": ip, "unit": unit}

        return self._start("ap-fix", work)

    # -- a certificate for the home's name (cert_acme): HTTP-01, port 80 open only while Let's Encrypt checks
    def _cert_name(self) -> str:
        return str(self._recall("cert_name") or self._recall("ddns_name")
                   or (self._recall("vpn_host") if self._recall("host_choice") == "ddns" else "") or "")

    def _cert_choices(self, getter) -> dict:
        """BUILD 471: the names a certificate can be for: the Dynamic DNS names on the firewall, {name: service}."""
        from pazuzu_core import ddns_setup as dd
        out: dict = {}
        try:
            for r in (getter("/api/dyndns/accounts/search_item") or {}).get("rows") or []:
                if isinstance(r, dict):
                    for n in dd.shown_name(r.get("hostnames")).split(","):
                        n = n.strip().lower()
                        if n and n not in out:
                            out[n] = str(r.get("service") or "")
        except Exception:  # noqa: BLE001
            pass
        own = self._cert_name()
        if own and own not in out:
            out[own] = ""
        return out

    def _cert_read(self, getter) -> dict:
        from pazuzu_core import cert_acme
        name = self._cert_name()
        out = {"name": name, "plugin": None, "issued": False, "renews": False, "words": "", "behind": False,
               "method": "", "port80_taken": []}
        if not name:
            return out
        try:
            name = cert_acme.clean_name(name)
        except we.WriteError:
            out["name"] = ""
            return out
        choices = self._cert_choices(getter)
        out["names"] = sorted(choices)                              # BUILD 471: the person picks which name
        out["method"] = cert_acme.method_for(name, choices.get(name, ""))   # dns01 / dns01gd: nothing opened
        out["page_name"] = self._recall("gui_name") or ""           # the name the admin page answers to, once set
        out["on_page"] = out["page_name"] == name                  # BUILD 473: a "Use it on the admin page" button otherwise
        if out["method"] == "http01":
            try:                                                 # a forward of 80 or 443 would catch the HTTP check
                out["port80_taken"] = cert_acme.port80_taken(self._forwards(getter) or [])
            except Exception:
                pass
        got = cert_acme.read(getter, name)
        out["plugin"] = got["plugin"]
        c = got.get("cert")
        if c:
            out.update(issued=c["issued"], renews=c["renews"], words=c["words"], made=True, made_method=c.get("method", ""))
        try:
            for r in (getter("/api/interfaces/overview/interfaces_info/true") or {}).get("rows") or []:
                if isinstance(r, dict) and str(r.get("identifier")) == "wan":
                    vals = r.get("addr4") if isinstance(r.get("addr4"), list) else [r.get("addr4")]
                    out["behind"] = any(cert_acme.behind_another_router(str(v)) for v in vals if v)
        except Exception:
            pass
        return out

    def advanced_state(self) -> dict:
        """BUILD 477: user mode or developer mode in the manager. Developer mode shows the control ids, the rule dumps, the
        request log, the Plan screen and the rest of the verbose parts; user mode leaves them out. Off by default on a
        Hanbi, on elsewhere, until the person flips it (kept in the key folder)."""
        saved = self._recall("advanced")
        if isinstance(saved, bool):
            return {"advanced": saved, "chosen": True}
        try:
            plat = self._acts.source.platform() if self._acts is not None else "pazuzu"
        except Exception:  # noqa: BLE001
            plat = "pazuzu"
        return {"advanced": plat != "hanbi", "chosen": False}

    def advanced_set(self, d) -> dict:
        d = d if isinstance(d, dict) else {}
        self._remember("advanced", bool(d.get("advanced")))
        return self.advanced_state()

    def cert_state(self) -> dict:
        getter = self._api_getter()
        if getter is None:
            return {"name": self._cert_name(), "plugin": None}
        return self._cert_read(getter)

    def cert_install(self) -> dict:
        """Put the certificate plugin (os-acme-client) on the firewall, with a passkey."""
        from pazuzu_core import cert_acme, plugin_install as pi
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        session = self._installer_session()
        base = self.base_url.rstrip("/")

        def work() -> dict:
            from pazuzu_core.passkey_gate import plan_digest
            lines = [f"Install the plugin {cert_acme.PLUGIN} on your firewall (it gets and renews certificates)",
                     self._uses_words()]
            if not self.window_gate(plan_digest("install-plugin", {"plugin": cert_acme.PLUGIN}), lines):
                raise WizardError("Not approved with a passkey; nothing was installed.")
            try:
                pi.install(session, base, cert_acme.PLUGIN)
            except pi.PluginError as exc:
                raise WizardError(str(exc))
            except Exception as exc:
                raise WizardError(f"The install stopped: {_plain_firewall(exc)}")
            return {"installed": cert_acme.PLUGIN, "lines": ["The certificate plugin is on the firewall."]}

        return self._start("cert-install", work)

    def cert_start(self, data) -> dict:
        """Set up the certificate for the home's name (cert_acme) under one passkey, then ask Let's Encrypt for it and
        wait. An e-mail address is optional (Let's Encrypt can write to it about the account)."""
        from pazuzu_core import cert_acme
        data = data if isinstance(data, dict) else {}
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        try:
            name = cert_acme.clean_name(self._cert_name())
        except we.WriteError as exc:
            raise WizardError(str(exc))
        email = str(data.get("email") or "").strip()
        token = str(data.get("token") or "").strip()
        gd_key, gd_secret = str(data.get("gd_key") or "").strip(), str(data.get("gd_secret") or "").strip()
        getter0 = self._api_getter()
        choices = self._cert_choices(getter0) if getter0 is not None else {}
        picked = str(data.get("name") or "").strip().lower()
        if picked:
            if picked not in choices:
                raise WizardError("Pick one of the names on the firewall. Nothing was changed.")
            self._remember("cert_name", picked)
            try:
                name = cert_acme.clean_name(picked)
            except we.WriteError as exc:
                raise WizardError(str(exc))
        service = choices.get(name, "")
        if email and not re.match(r"^[^@\s]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$", email):
            raise WizardError("That e-mail address does not look right. Leave it empty if you would rather not give one.")
        getter = self._api_getter()
        if getter is not None and cert_acme.method_for(name, service) == "http01":
            cr = self._cert_read(getter)
            if cr.get("behind"):
                raise WizardError("The firewall's internet side has a private address, so it sits behind another router. "
                                  "Let's Encrypt has to reach port 80 on it, which needs a forward on that router first. "
                                  "Nothing was changed.")
            if cr.get("port80_taken"):
                raise WizardError("Port 80 or 443 is forwarded to " + ", ".join(cr["port80_taken"]) + ", so Let's Encrypt's "
                                  "check over port 80 would land there, not on the firewall. A DuckDNS name is proved "
                                  "through DNS instead and needs no port; with this name, the forward would have to "
                                  "step aside while the certificate is asked for. Nothing was changed.")
        session = self._installer_session()
        base = self.base_url.rstrip("/")
        probe = self._probe

        def work() -> dict:
            cs = cert_acme.CertSetup(we.Engine(session, base, probe),
                                     trace_to=Path("scan_results") / time.strftime("cert_trace_%Y%m%d-%H%M%S.json"))
            try:
                plan = cs.plan(name, email, token, service, gd_key, gd_secret)
                plan.lines.append("Once issued: the firewall's admin page uses it, and answers to " + name
                                  + " (it restarts once; the old certificate is kept to put back)")
                outs = cs.apply(plan, lambda digest, lines: self.window_gate(digest, list(lines)))
                if outs:
                    self._last_write = (wb.Undoer(), outs)
                got = cs.request(plan.facts)
            except we.WriteError as exc:
                raise WizardError(str(exc) + self._trace_note(cs))
            finally:
                cs.save_trace()
            lines = list(cs.said) + cert_acme.outcome_words(name, got)
            if got.get("issued"):
                lines += self._gui_use_cert(got.get("refid") or "", name)
            return {"lines": lines, "can_undo": bool(outs), "issued": got.get("issued")}

        return self._start("write-cert", work)

    def _gui_use_cert(self, refid: str, name: str) -> list:
        """BUILD 471: the firewall's admin page uses the new certificate and answers to its name, through the plugin
        (the page's own Save for two fields). This computer then trusts the page by that certificate, and follows its
        renewals by the name (enroll_safety.refresh_pin)."""
        from pazuzu_core.enroll_safety import save_pin
        manual = ["To use it on the admin page by hand: System, Settings, Administration: SSL Certificate = the new one, "
                  "and add " + name + " to Alternate Hostnames. Save."]
        if not refid:
            return ["The certificate's place in the firewall's store could not be read, so the admin page was left as it "
                    "was."] + manual
        got = self._box_post("/gui_cert", {"action": "use", "refid": refid, "name": name}, timeout=90)
        if not isinstance(got, dict) or not got.get("ok"):
            why = (got or {}).get("error") if isinstance(got, dict) else "the plugin did not answer (it needs 0.6.71)"
            return [f"The admin page was left as it was: {why}"] + manual
        fp = str(got.get("fingerprint") or "")
        if len(fp) == 64:
            save_pin(self.key_dir, fp)
        self._remember("gui_name", name)
        host, port = base_host_port(self.base_url)
        return ["The admin page uses it now and answers to " + name + f": https://{name}:{port}/ shows no warning. "
                "It restarted once; this computer trusts the new certificate."]

    def gui_cert_undo(self, d=None) -> dict:
        """Put the admin page's certificate and names back as they were (the plugin kept them)."""
        from pazuzu_core.enroll_safety import save_pin
        got = self._box_post("/gui_cert", {"action": "undo"}, timeout=90)
        if not isinstance(got, dict) or not got.get("ok"):
            raise WizardError(str((got or {}).get("error") or "The plugin did not answer."))
        fp = str(got.get("fingerprint") or "")
        if len(fp) == 64:
            save_pin(self.key_dir, fp)
        self._remember("gui_name", "")
        return {"lines": ["The admin page uses its earlier certificate again."]}

    def gui_cert_use(self, d=None) -> dict:
        """BUILD 473: put a certificate that is already issued on the admin page, without asking Let's Encrypt again
        (the manager read a stale "refused" and skipped this step while the run went on to issue it)."""
        from pazuzu_core import cert_acme
        from pazuzu_core.passkey_gate import plan_digest
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        getter = self._api_getter()
        if getter is None:
            raise WizardError("Sign in to the firewall first.")
        try:
            name = cert_acme.clean_name(self._cert_name())
        except we.WriteError as exc:
            raise WizardError(str(exc))
        got = cert_acme.read(getter, name)
        c = got.get("cert") or {}
        if not c.get("issued"):
            raise WizardError(f"The certificate for {name} is not issued yet. Nothing was changed.")
        try:
            refid = str(((getter(f"{cert_acme.A}/certificates/get/{c['uuid']}") or {}).get("certificate") or {})
                        .get("certRefId") or "").strip()
        except Exception as exc:  # noqa: BLE001
            raise WizardError(f"The certificate could not be read ({_plain_firewall(exc)}). Nothing was changed.")

        def work() -> dict:
            lines = [f"The firewall's admin page uses the certificate for {name}, and answers to {name}",
                     "It restarts once; the old certificate is kept to put back"]
            if not self.window_gate(plan_digest("gui-cert-use", {"name": name, "refid": refid}), lines):
                raise WizardError("Not approved with a passkey. Nothing was changed.")
            return {"lines": self._gui_use_cert(refid, name), "can_undo": False}

        return self._start("gui-cert", work)

    def gui_cert_undo_start(self, d=None) -> dict:
        """The admin page's earlier certificate back, with a passkey."""
        from pazuzu_core.passkey_gate import plan_digest
        if not self._can_change():
            raise WizardError("Register your passkey first.")

        def work() -> dict:
            if not self.window_gate(plan_digest("gui-cert-undo", {}), ["Put the admin page's earlier certificate and names "
                                                                       "back (it restarts once)"]):
                raise WizardError("Not approved with a passkey. Nothing was changed.")
            return self.gui_cert_undo()

        return self._start("gui-cert", work)

    def iot_suggestions(self) -> dict:
        """Devices on the Trusted Network that look like smart devices (iot_guess), to suggest moving them. Reads only."""
        from pazuzu_core import iot_guess, oui
        if not self._box_up():
            return {"devices": [], "why": "The plugin is not answering, so the devices cannot be listed here."}
        st = (self._acts.source.box.read() or {}).get("status") or {}
        zones = self._zone_devices()
        trusted = [zones[z] for z in ("trusted",) if zones.get(z)]
        got = iot_guess.suggest(st.get("clients") or [], trusted, oui.label)
        return {"devices": got, "why": "", "iot": bool(zones.get("iot")), "iot_port": zones.get("iot", "")}

    def ap_vlan_options(self) -> dict:
        """The firewall's VLANs, each with the zone it carries: what an access point's Wi-Fi networks can be put on."""
        from pazuzu_core.address_plan import zone_word
        getter = self._api_getter()
        if getter is None:
            return {"vlans": [], "why": "The firewall's VLANs could not be read (no sign-in yet)."}
        try:
            rows = (getter("/api/interfaces/vlan_settings/search_item?rowCount=-1&searchPhrase=") or {}).get("rows") or []
        except Exception as exc:  # noqa: BLE001
            return {"vlans": [], "why": f"The firewall's VLANs could not be read ({_plain_firewall(exc)})."}
        zones = (self.status().get("zones") or {}).get("assignments") or {}
        by_dev = {(a or {}).get("device"): z for z, a in zones.items() if (a or {}).get("device")}
        out = []
        for r in rows:
            try:
                tag = int(str(r.get("tag")))
            except (TypeError, ValueError):
                continue
            from pazuzu_core.zone_vlans import device_of
            dev = device_of(r.get("vlanif"))
            zone = by_dev.get(dev, "")
            out.append({"tag": tag, "device": dev, "parent": str(r.get("if") or ""), "zone": zone,
                        "word": zone_word(zone) if zone else str(r.get("descr") or "")})
        return {"vlans": sorted(out, key=lambda x: x["tag"]), "why": ""}

    def ap_vlans_start(self, data) -> dict:
        """Put an access point's Wi-Fi networks on the firewall's VLANs (ap_openwrt.set_vlans). The access point's
        password, when it has one, is used for this one change and kept nowhere."""
        from pazuzu_core import ap_openwrt as ap
        from pazuzu_core.passkey_gate import plan_digest
        data = data if isinstance(data, dict) else {}
        ip = ap.private_address(data.get("ip"))
        if ip is None:
            raise WizardError("Only an address on your own network can be changed.")
        offered = {v["tag"]: v for v in self.ap_vlan_options()["vlans"]}
        mapping: dict = {}
        for sec, tag in (data.get("map") or {}).items() if isinstance(data.get("map"), dict) else []:
            if tag in (None, "", 0):
                mapping[str(sec)] = None
                continue
            try:
                tag = int(tag)
            except (TypeError, ValueError):
                raise WizardError("That VLAN number was not understood.")
            if tag not in offered:
                raise WizardError(f"VLAN {tag} is not one of the firewall's VLANs.")
            mapping[str(sec)] = tag
        if not any(t is not None for t in mapping.values()):
            raise WizardError("Pick a VLAN for at least one Wi-Fi network.")
        password = data.get("password") if isinstance(data.get("password"), str) else ""
        if not self._can_change():
            raise WizardError("Register your passkey first.")

        def work() -> dict:
            names = data.get("names") if isinstance(data.get("names"), dict) else {}
            lines = [f"Set up VLAN tagging on the access point at {ip}"]
            for sec, tag in mapping.items():
                if tag is not None:
                    v = offered[tag]
                    lines.append(f"{str(names.get(sec) or sec)[:40]}: on VLAN {tag}" + (f" ({v['word']})" if v["word"] else ""))
            lines += ["Everything else stays on the untagged network, and the access point is reached as before",
                      "Its network and Wi-Fi restart for a few seconds; devices on it reconnect",
                      f"If it does not check out, the access point puts it all back by itself within {ap.APPLY_TIMEOUT} seconds"]
            if not self.window_gate(plan_digest("ap-vlans", {"ip": ip, "map": sorted((k, v or 0) for k, v in mapping.items())}), lines):
                raise WizardError("Not approved with a passkey; nothing was changed.")
            try:
                got = ap.set_vlans(ip, mapping, password, post=self._ap_post(), say=print)
            except ap.ApError as exc:
                raise WizardError(str(exc))
            return {"lines": [f"Tagged VLAN {', '.join(map(str, got['tags']))} on {', '.join(got['ports'])} of {got['bridge']}; "
                              "the Wi-Fi networks you picked are on them now.",
                              "Devices on those networks now get their addresses from the firewall's VLAN."]}

        return self._start("ap-vlans", work)

    def ap_find(self) -> dict:
        """Look through the devices the firewall already knows (its DHCP clients) for an OpenWrt access point, and ask each
        candidate whether it answers like OpenWrt. Reads only; nothing is changed. Scans, never a hardcoded address."""
        from pazuzu_core import ap_openwrt as ap, oui
        if not self._box_up():
            return {"found": [], "tried": 0, "why": "The plugin is not answering, so the devices on your network cannot be listed yet."}
        st = self._box_status_view()
        clients = st.get("clients") or []
        try:
            res = ap.find(clients, oui.label, everyone=True)   # BUILD 482: every device on the phone; BUILD 488: on the PC too
        except Exception as exc:  # noqa: BLE001
            return {"found": [], "tried": 0, "why": f"Could not scan for an access point ({_plain(exc)})."}
        return {"found": res.get("found") or [], "tried": res.get("tried") or 0, "why": "",
                "silent": res.get("silent") or []}          # BUILD 556: called OpenWrt, gave no answer

    def _box_status_view(self) -> dict:
        """BUILD 482: the box plugin's status (its devices among it): through the manager's link when it is up, else (the
        phone's setup, no manager yet) with the link the box started this wizard with. {} when neither answers."""
        try:
            if self._acts is not None:
                return (self._acts.source.box.read() or {}).get("status") or {}
        except Exception:  # noqa: BLE001
            pass
        link = self._recall("box_link")
        if not isinstance(link, dict) or not link.get("url"):
            return {}
        import urllib.request
        try:
            req = urllib.request.Request(str(link["url"]).rstrip("/") + "/status.json",
                                         headers={"Authorization": "Bearer " + str(link.get("token") or "")})
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            from pazuzu_core import feed_pin                 # BUILD 565: HTTPS with the key's pin once it is known
            with feed_pin.urlopen(req, timeout=5, plain=opener.open) as r:
                got = json.loads(r.read())
            return got if isinstance(got, dict) else {}
        except Exception:  # noqa: BLE001
            return {}

    # BUILD 482 (the maintainer, 5 Nov 2026): Hanbi's own Wi-Fi. With an OpenWrt access point on the Home port, the phone's setup
    # makes three networks on it: Home (Trusted, untagged), Smart devices and Guest (each on its zone's scrambled VLAN),
    # with names in the Hanbi_Setup style and passwords the box makes. The person types nothing but, at most, the access
    # point's own password once. The names and passwords are kept on the box (home_wifi.json, owner-only) so its screen
    # can show the join code again later.
    HOME_WIFI_FILE = "home_wifi.json"
    HOME_WIFI_ZONES = ("trusted", "iot", "guest")

    def _home_wifi_names(self, rng=None) -> dict:
        import secrets as _secrets
        rng = rng or _secrets.SystemRandom()
        tail = "".join(rng.choice("abcdefghjkmnpqrstuvwxyz23456789") for _ in range(4))
        base = "Hanbi-" + tail
        return {"trusted": base, "iot": base + " Smart", "guest": base + " Guest"}

    @staticmethod
    def _home_wifi_key(rng=None) -> str:
        import secrets as _secrets
        rng = rng or _secrets.SystemRandom()
        return "".join(rng.choice("abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(16))

    def home_wifi_plan(self, d) -> dict:
        """Read the access point (its own password if it has one, used for this read only) and plan the three networks:
        their names, and which radio each goes on. Reads only; nothing is changed."""
        from pazuzu_core import ap_openwrt as ap
        d = d if isinstance(d, dict) else {}
        ip = ap.private_address(d.get("ip"))
        if ip is None:
            raise WizardError("That is not an address on your own network.")
        pw = str(d.get("password") or "")
        post = self._ap_post()
        try:
            got = ap.read(ip, post=post, password=pw)
        except ap.ApError as exc:
            return {"ok": False, "needs_password": str(exc) == ap.NEEDS_PASSWORD, "why": str(exc)}
        why = ap.can_carry(ip, pw, post=post)
        if why:
            return {"ok": False, "needs_password": False, "why": why, "model": got.get("model") or ""}
        radios = [r for r in got.get("radios") or [] if isinstance(r, dict) and r.get("name")]
        if not radios:
            return {"ok": False, "needs_password": False, "why": "It has no Wi-Fi radio to put a network on."}
        all_r = [str(r["name"]) for r in radios]
        low = [str(r["name"]) for r in radios if r.get("band") == "2.4 GHz"] or all_r[:1]
        names = self._home_wifi_names()
        plan = {"ip": ip, "names": names, "keys": {z: self._home_wifi_key() for z in self.HOME_WIFI_ZONES},
                "radios": {"trusted": all_r, "iot": low[:1], "guest": all_r}}
        self._hw_plan = plan
        return {"ok": True, "model": got.get("model") or "", "release": got.get("release") or "",
                "networks": [{"zone": z, "ssid": names[z], "radios": plan["radios"][z]} for z in self.HOME_WIFI_ZONES]}

    def home_wifi_start(self, d) -> dict:
        """Make the Smart devices and Guest zones (VLANs on the Home port, scrambled) and the three networks on the access
        point, in the one zone job (write-zone-vlans), with the access point's IPv6 and its own DHCP switched off."""
        from pazuzu_core import ap_openwrt as ap
        d = d if isinstance(d, dict) else {}
        plan = getattr(self, "_hw_plan", None)
        ip = ap.private_address(d.get("ip"))
        if not plan or ip != plan.get("ip"):
            raise WizardError("Read the access point first.")
        nets = [{"zone": "trusted", "ssid": plan["names"]["trusted"], "passphrase": plan["keys"]["trusted"],
                 "radios": plan["radios"]["trusted"], "encryption": "sae-mixed"},
                {"zone": "iot", "ssid": plan["names"]["iot"], "passphrase": plan["keys"]["iot"],
                 "radios": plan["radios"]["iot"], "encryption": "psk2", "isolate": True},
                {"zone": "guest", "ssid": plan["names"]["guest"], "passphrase": plan["keys"]["guest"],
                 "radios": plan["radios"]["guest"], "encryption": "sae-mixed", "isolate": True}]
        self._home_wifi_save({"ip": ip, "names": plan["names"], "keys": plan["keys"], "made": False})
        import secrets as _secrets
        admin = "".join(_secrets.choice("abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(24))
        return self.zone_vlans_start({"zones": ["iot", "guest"], "scramble": True,
                                      "ap": {"ip": ip, "password": str(d.get("password") or ""), "networks": nets,
                                             "ipv6_off": True, "dhcp_off": True, "new_password": admin}})

    def _home_wifi_save(self, rec: dict) -> None:
        path = self.key_dir / self.HOME_WIFI_FILE
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(rec), encoding="utf-8")
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except OSError:
            pass

    def home_wifi_state(self) -> dict:
        """The networks made (names, and the join code for each: the standard WIFI: text a phone camera reads), for the
        page to put on the box's screen. {} before any were made."""
        from pazuzu_core import ap_openwrt as ap
        try:
            rec = json.loads((self.key_dir / self.HOME_WIFI_FILE).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        if not isinstance(rec, dict) or not isinstance(rec.get("names"), dict):
            return {}
        names, keys = rec["names"], rec.get("keys") or {}
        return {"made": bool(rec.get("made")), "networks": [
            {"zone": z, "ssid": names.get(z, ""), "join": ap.wifi_qr_text(names.get(z, ""), keys.get(z, ""))}
            for z in self.HOME_WIFI_ZONES if names.get(z)]}

    def _box_post(self, path: str, body: dict, timeout: float = 40):
        """A POST to the box's own plugin: through the manager's link when it is up, else (the phone's setup, before
        Pazuzu's accounts exist) with the link the box started this wizard with. None when neither answers."""
        try:
            if self._acts is not None and self._box_up():
                return self._acts.source.box.post(path, body)
        except Exception:  # noqa: BLE001
            pass
        link = self._recall("box_link")
        if not isinstance(link, dict) or not link.get("url"):
            return None
        import urllib.request
        try:
            req = urllib.request.Request(str(link["url"]).rstrip("/") + path, data=json.dumps(body).encode(),
                                         method="POST", headers={"Authorization": "Bearer " + str(link.get("token") or ""),
                                                                 "Content-Type": "application/json"})
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            from pazuzu_core import feed_pin                 # BUILD 565: HTTPS with the key's pin once it is known
            with feed_pin.urlopen(req, timeout=timeout, plain=opener.open) as r:
                return json.loads(r.read())
        except Exception:  # noqa: BLE001
            return None

    def ap_wifi_scan(self) -> dict:
        """Nearby Wi-Fi networks this computer can see (name + signal), strongest first, so the access point's network is
        picked from a list instead of typed. Reads only, from this computer's own Wi-Fi radio. BUILD 467: on the box (the
        phone's setup) the box looks with a spare radio, never the one serving the setup Wi-Fi; on a PC that sees none,
        the box is asked too."""
        own = ("hanbi_setup",)          # BUILD 468: the box's own setup network is never the access point's
        if self.phone:
            got = self._box_post("/wifi_scan", {})
            if isinstance(got, dict):
                nets = [n for n in (got.get("networks") or []) if str(n.get("name") or "").lower() not in own]
                return {"networks": nets, "why": str(got.get("why") or "")
                        or ("" if nets else "The box sees no Wi-Fi networks nearby.")}
            return {"networks": [], "why": "The box did not answer the scan. Type the network's name instead."}
        from pazuzu_core import find_firewall as ff
        try:
            nets = ff.wifi_signals(prefix="")
        except Exception as exc:  # noqa: BLE001
            return {"networks": [], "why": f"Could not scan for Wi-Fi from this device ({_plain(exc)})."}
        out = [{"name": str(n.get("name") or ""), "signal": n.get("signal")} for n in (nets or [])
               if n.get("name") and str(n.get("name")).lower() not in own]
        if not out:
            got = self._box_post("/wifi_scan", {}) if (self._acts is not None and self._box_up()) else None
            boxed = [n for n in ((got or {}).get("networks") or []) if str(n.get("name") or "").lower() not in own] \
                if isinstance(got, dict) else []
            if boxed:
                return {"networks": boxed, "why": ""}
        return {"networks": out, "why": "" if out else "No Wi-Fi networks seen from this device — is its Wi-Fi switched on, and does it have a Wi-Fi adapter?"}

    def _ap_post(self):
        """A ubus transport for ap_openwrt. It tries THIS PC directly first (a wired access point, or one on the
        same LAN, answers straight away). If the PC cannot reach it — the usual case once the firewall has joined
        the access point on a spare radio, which only the firewall can see — it carries the same call through the
        box (BoxLink.ap_relay). The box's support is asked at most once, and only after a direct miss, so a wired
        access point never pays for the box round-trip."""
        from pazuzu_core import ap_openwrt as ap
        src = getattr(getattr(self, "_acts", None), "source", None)
        box = getattr(src, "box", None)
        state = {"relay": None}          # None = not asked yet; then True/False once a direct call has missed

        def post(ip, payload):
            try:
                return ap._post(ip, payload)                 # this PC -> the access point, directly
            except Exception:
                if state["relay"] is None:
                    state["relay"] = bool(box is not None and getattr(box, "url", None) and box.can("ap_relay"))
                if state["relay"]:
                    return box.ap_relay(ip, payload)         # the firewall -> the access point, for the radio-join case
                raise
        return post

    def ap_read(self, d) -> dict:
        """Read one access point's Wi-Fi, network and DHCP, with its weak-password / IPv6 checks. Reads only.
        d = {"ip", "password"}. The password (when it has one) is used for this read only and kept nowhere."""
        from pazuzu_core import ap_openwrt as ap
        d = d if isinstance(d, dict) else {}
        ip = ap.private_address(d.get("ip"))
        if ip is None:
            raise WizardError("Only an address on your own network can be read.")
        try:
            return ap.read(ip, post=self._ap_post(), password=str(d.get("password") or ""))
        except ap.ApError as exc:
            raise WizardError(str(exc))

    def ap_join(self, d) -> dict:
        """Join an access point's own Wi-Fi with a spare radio on this firewall, so the app can reach it to read and roll it
        onto our VLANs — no cable. A transient reach, torn down once the access point is on our scheme. Reuses the proven
        Wi-Fi client join; one passkey touch (none in light mode). d = {ssid, passphrase}."""
        d = d if isinstance(d, dict) else {}
        try:
            ssid, passphrase = wb.Hotspot.clean(d.get("ssid"), d.get("passphrase"))
        except we.WriteError as exc:
            raise WizardError(str(exc))
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        # BUILD 512 (the maintainer, dev, 12 Nov 2026, no plugin aboard): this join adds no gateway and leaves default gateway
        # switching alone, so it does not need the plugin. It was refused for want of it.
        link = self._hotspot_link() if self._box_up() else None
        session = self._installer_session()
        base = self.base_url.rstrip("/")
        probe = self._probe

        def work() -> dict:
            hs = wb.Hotspot(we.Engine(session, base, probe), switch=link, trace_to=self._hotspot_trace_path(),
                            **getattr(self, "_hotspot_timing", {}))
            try:
                plan = hs.plan_client(ssid, passphrase)   # management-only station: no gateway, no routing change
                outs = hs.apply(plan, lambda digest, lines: self.window_gate(digest, list(lines)))
            except we.WriteError as exc:
                raise WizardError(str(exc) + self._trace_note(hs))
            finally:
                hs.save_trace()
            if outs:
                self._last_write = (wb.Undoer(), outs)
            return {"lines": list(hs.said) + [f"Joined “{ssid}” with a spare radio (no gateway added). Now read the access point’s address below to roll it onto your VLANs; undo this link once it’s on your scheme."],
                    "can_undo": bool(outs)}

        return self._start("ap-join", work)

    def ap_join_network(self, d) -> dict:
        """Make the access point a clean member of our zones in ONE action: tag its Wi-Fi onto the zone VLANs (so it rides
        each zone's scrambled VLAN and subnet), and — unless turned off — switch IPv6 off and stop it handing out
        addresses (the firewall's Kea serves the VLAN). Reuses the OpenWrt pieces (set_vlans / ipv6_off / dhcp_off); one
        passkey touch (none in light). d = {ip, password, map:{section:tag}, names, ipv6_off, dhcp_off}."""
        from pazuzu_core import ap_openwrt as ap
        from pazuzu_core.passkey_gate import plan_digest
        d = d if isinstance(d, dict) else {}
        ip = ap.private_address(d.get("ip"))
        if ip is None:
            raise WizardError("Only an address on your own network can be changed.")
        password = str(d.get("password") or "")
        offered = {v["tag"]: v for v in self.ap_vlan_options().get("vlans", [])}
        mapping: dict = {}
        for sec, tag in (d.get("map") or {}).items() if isinstance(d.get("map"), dict) else []:
            if tag in (None, "", 0):
                continue
            try:
                tag = int(tag)
            except (TypeError, ValueError):
                raise WizardError("That VLAN number was not understood.")
            if tag not in offered:
                raise WizardError(f"VLAN {tag} is not one of the firewall's zone VLANs.")
            mapping[str(sec)] = tag
        if not mapping:
            raise WizardError("Pick a zone VLAN for at least one of the access point's Wi-Fi networks.")
        names = d.get("names") if isinstance(d.get("names"), dict) else {}
        want_ipv6 = d.get("ipv6_off") is not False
        want_dhcp = d.get("dhcp_off") is not False
        if not self._can_change():
            raise WizardError("Register your passkey first.")

        def work() -> dict:
            steps = [f"Make the access point at {ip} a clean member of your zones"]
            for sec, tag in mapping.items():
                v = offered[tag]
                steps.append(f"{str(names.get(sec) or sec)[:40]}: onto zone VLAN {tag}" + (f" ({v['word']})" if v.get("word") else ""))
            if want_ipv6:
                steps.append("Switch IPv6 off on the access point")
            if want_dhcp:
                steps.append("Stop the access point handing out addresses (the firewall does, on the VLAN)")
            steps.append(f"If a step does not check out, the access point puts it back by itself within {ap.APPLY_TIMEOUT} seconds")
            if not self.window_gate(plan_digest("ap-join-network",
                                                {"ip": ip, "map": sorted(mapping.items()), "ipv6": want_ipv6, "dhcp": want_dhcp}), steps):
                raise WizardError("Not approved with a passkey; nothing was changed.")
            lines: list = []
            post = self._ap_post()
            try:
                got = ap.set_vlans(ip, mapping, password, post=post, say=print)
                lines.append(f"Tagged VLAN {', '.join(map(str, got.get('tags') or []))} on {got.get('bridge') or 'the access point'} "
                             "— its Wi-Fi is on your zones now, and scrambles with them.")
                if want_ipv6:
                    ap.ipv6_off(ip, password, post=post)
                    lines.append("IPv6 is off on the access point.")
                if want_dhcp:
                    ap.dhcp_off(ip, password, post=post)
                    lines.append("The access point no longer hands out addresses; the firewall does, on the VLAN.")
            except ap.ApError as exc:
                raise WizardError(str(exc))
            lines.append("It is a member of your zones now. Set a strong Wi-Fi password on it, then hand the radio back.")
            return {"lines": lines}

        return self._start("ap-join-network", work)

    def ap_wifi_state(self, ip) -> dict:
        from pazuzu_core import ap_openwrt as ap
        address = ap.private_address(ip)
        got = self._ap_store().get(address) if address else None
        if not got:
            return {"done": False}
        prev = got["previous"]
        return {"done": True, "ssid": got["ssid"], "passphrase": got["passphrase"], "qr": got["qr"],
                "was": sorted({ap.security_words(x.get("encryption")) for x in prev.values()})}

    # -- the plugin keeping itself current (signed; see plugin_update.py)
    def _signer(self):
        from pazuzu_core.plugin_update import Signer
        sg = getattr(self, "_plugin_signer", None)
        if sg is None:
            sg = self._plugin_signer = Signer(self.key_dir)
        return sg

    def _update_pub(self) -> str | None:
        try:
            return self._signer().public_hex()
        except OSError:
            return None

    # BUILD 485 / plugin 0.6.89 (the maintainer, 5 Nov 2026: "wizard didnt update lab plugin"): a reset to factory clears the plugin's
    # link code, so after one this PC had no link and could not update the plugin by itself. The box now takes a newer
    # plugin signed with a key it trusts from its home network with no code (it keeps that key through a reset), and says
    # its version on /phone/state, so the PC finds it by the firewall's own address and sends the update before sign-in.
    def _open_box_url(self) -> str | None:
        from pazuzu_core import box_install as bi
        try:
            host, _p = base_host_port(self.base_url)
        except Exception:  # noqa: BLE001
            return None
        return f"http://{host}:{bi.FEED_PORT}" if host else None

    def _open_box_state(self) -> dict | None:
        """The box's /phone/state, asked with no code: {enrolled, setup_done, version, signed_update}, or None."""
        url = self._open_box_url()
        if not url:
            return None
        import urllib.request
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(url + "/phone/state", timeout=4) as r:
                got = json.loads(r.read(4096))
            return got if isinstance(got, dict) else None
        except Exception:  # noqa: BLE001
            return None

    def _signed_plugin(self) -> tuple:
        """(the plugin's bytes, its version, its signature): the signed release this build carries (BUILD 552, a tester
        build: Hanbi's release key, as the apps send), else this checkout's plugin signed with this device's own key."""
        from hanbi_box import VERSION
        from pazuzu_core import box_install as bi
        rel = bi.released()
        if rel:
            return rel["data"], rel["version"], rel["signature"]
        data = bi.bundle()[0]
        try:
            return data, VERSION, self._signer().sign_bundle(data, VERSION)
        except OSError:
            raise WizardError("Could not read or make the signing key in your key folder.")

    def _open_update(self, sleep=time.sleep) -> dict:
        """Send the box this PC's plugin, signed, with no link code; then see it come back as the new version."""
        import urllib.error
        import urllib.request
        data, VERSION, sig = self._signed_plugin()
        url = self._open_box_url()
        req = urllib.request.Request(url + "/update", data=data, method="POST",
                                     headers={"Content-Type": "application/octet-stream",
                                              "X-Hanbi-Version": VERSION, "X-Hanbi-Signature": sig})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(req, timeout=90) as r:
                got = json.loads(r.read(65536))
        except urllib.error.HTTPError as exc:
            try:
                got = json.loads(exc.read(4096))
            except Exception:  # noqa: BLE001
                got = {"error": f"The box refused the update ({exc.code})."}
        except Exception as exc:  # noqa: BLE001
            raise WizardError(f"The box did not take the update ({type(exc).__name__}).")
        if not isinstance(got, dict) or got.get("state") != "restarting":
            raise WizardError(self._other_key_words(str((got or {}).get("error") or "The box did not take the update.")))
        for _ in range(40):                          # it restarts its plugin; see it come back as the new one
            sleep(1.5)
            back = self._open_box_state()
            if back and str(back.get("version") or "") == VERSION:
                return {"state": "updated", "version": VERSION, "open": True}
        raise WizardError("The box took the update but has not come back yet. Look again in a minute.")

    def plugin_state(self) -> dict:
        """none (nothing answering) / old (answers, cannot take updates: one more line, once) / current / behind.
        BUILD 485: with no link, the box is asked by the firewall's own address ("open": True)."""
        if not plugin_present():             # BUILD 513: the public beta 1 build has no plugin to compare with
            return {"state": "none"}
        from hanbi_box import VERSION
        if not self._box_up():
            if not getattr(self, "phone", False):
                got = self._open_box_state()
                theirs = str((got or {}).get("version") or "")
                if got and got.get("signed_update") and theirs:
                    try:
                        newer = tuple(map(int, VERSION.split("."))) > tuple(map(int, theirs.split(".")))
                    except ValueError:
                        newer = False
                    return {"state": "behind" if newer else "current", "mine": VERSION, "theirs": theirs, "open": True}
            return {"state": "none", "mine": VERSION}
        box = self._acts.source.box
        theirs = box.version()
        if not box.can("update"):
            return {"state": "old", "mine": VERSION, "theirs": theirs}
        try:
            newer = tuple(map(int, VERSION.split("."))) > tuple(map(int, (theirs or "0.0.0").split(".")))
        except ValueError:
            newer = False
        if not newer and theirs == VERSION and not box.can("wizard"):
            newer = True                      # 0.6.53 without its wizard engine: the second half is still to send
        return {"state": "behind" if newer else "current", "mine": VERSION, "theirs": theirs}

    def plugin_update(self, sleep=time.sleep) -> dict:
        """Send the plugin the files this app carries, signed with the key only this device holds. The plugin checks
        the signature itself; it is the one that decides."""
        from hanbi_box import VERSION
        from pazuzu_core import box_install as bi
        st = self.plugin_state()
        if st.get("open"):                       # BUILD 485: no link (a reset cleared its code): signed, by address
            return {"state": "current", "version": st["theirs"]} if st["state"] == "current" else self._open_update(sleep)
        if st["state"] == "none":
            raise WizardError("The plugin is not answering, so there is nothing to update.")
        if st["state"] == "old":
            raise WizardError("This plugin is too old to update itself. Put it on once more with the Wi-Fi or plugin "
                              "line; that line also lets it take updates from then on.")
        if st["state"] == "current":
            return {"state": "current", "version": st["theirs"]}
        box = self._acts.source.box
        try:
            before = tuple(map(int, (st.get("theirs") or "0.0.0").split(".")))
        except ValueError:
            before = (0, 0, 0)
        if before < (0, 6, 55):
            # Older plugins cannot take the wizard engine in one go: 0.6.52 and older take only small .py files, and up
            # to 0.6.54 the feed refused any update over 1.6 MB (the lab box, 1 Nov 2026: "bad request"). First the plugin
            # without the engine (which brings the new updater and feed), then the same version again with it.
            self._push_plugin(box, bi.bundle(engine=False)[0], sleep, lambda: box.version() == VERSION)
        data, ver, sig = self._signed_plugin()
        self._push_plugin(box, data, sleep, lambda: box.version() == ver and box.can("wizard"), version=ver, sig=sig)
        return {"state": "updated", "version": ver}

    OTHER_KEY = ("This firewall's plugin only takes updates signed by where it was set up: the Pazuzu app (Hanbi's signed "
                 "releases), or the device that first put it on. This copy of the wizard signs with this device's own key, "
                 "so the firewall turned its update down. That is the firewall being careful, not a fault, and nothing was "
                 "changed. Update it from the Pazuzu app. To have it take updates from this device instead, put the plugin "
                 "on again from here with the plugin line.")

    @classmethod
    def _other_key_words(cls, error: str) -> str:
        """BUILD 538 (the maintainer, 14 Nov 2026, a firewall the iPhone app had set up, the wizard run from another folder: "The
        update's signature did not check against the key this plugin trusts"): what that means, in plain words."""
        return cls.OTHER_KEY if "did not check against the key this plugin trusts" in error else error

    def _push_plugin(self, box, data: bytes, sleep, back, version: str | None = None, sig: str | None = None) -> None:
        from hanbi_box import VERSION
        if sig is None:
            try:
                sig = self._signer().sign_bundle(data, VERSION)
            except OSError:
                raise WizardError("Could not read or make the signing key in your key folder.")
        got = box.push_update(data, version or VERSION, sig)
        if got.get("state") != "restarting":
            raise WizardError(self._other_key_words(str(got.get("error") or "The plugin did not take the update.")))
        for _ in range(20):                      # the plugin restarts itself; see that it comes back as the new one
            sleep(1.5)
            if back():
                return
        raise WizardError("The plugin took the update but has not come back yet. Look again in a minute; its old files "
                          "are kept on the firewall in /root/hanbi_box/hanbi_box.old.")

    # -- the one-time-code login server (added by the plugin; the sign-in switch is never done for the person)
    def otp_server_state(self) -> dict:
        """What the plugin reads: is the server there, and does the web page sign in with it. Reads only."""
        if not self._plugin_offered():       # BUILD 519 (the maintainer: "plugin in beta 2"): beta 1 has no plugin to be "not answering"
            return {"can": False, "beta2": True,
                    "why": "Adding this server for you comes with the Hanbi plugin, in beta 2. In beta 1 you add it by hand: "
                           "six short steps, below."}
        if not self._box_up():
            return {"can": False, "why": "The plugin is not answering, so Pazuzu cannot see or add the server."}
        box = self._acts.source.box
        if not box.can("otp_server"):
            return {"can": False, "why": "The plugin on the firewall is older than this step needs. Update it in the plugin step."}
        got = box.otp_server_status()
        if got is None:
            return {"can": False, "why": "The plugin did not answer about login servers just now."}
        if got.get("state") != "ok":
            return {"can": False, "why": "The firewall's configuration file did not look as expected, so Pazuzu will not touch it."}
        out = {"can": True, "present": bool(got.get("present")), "type_ok": bool(got.get("type_ok")),
               "in_use": bool(got.get("in_use")), "login": [str(x) for x in (got.get("login") or [])][:8],
               "name": str(got.get("name") or "Pazuzu OTP")}
        sw = box.otp_switch_status() if box.can("otp_switch") else None
        if sw is not None:                  # a plugin that can switch the page itself, with its safety timer
            out["switch"] = {"state": str(sw.get("state") or "idle"), "seconds_left": int(sw.get("seconds_left") or 0)}
        return out

    def otp_switch_change(self, d) -> dict:
        """Point the web page at the code server through the plugin (with the plugin's own timer to put it back), keep
        that, or put it back. The plugin refuses unless the user is there with a code seed."""
        from pazuzu_core.passkey_gate import plan_digest
        d = d if isinstance(d, dict) else {}
        action = d.get("action")
        if action not in ("on", "keep", "undo"):
            raise WizardError("That was not understood.")
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        st = self.otp_server_state()
        if not st["can"]:
            raise WizardError(st["why"])
        if "switch" not in st:
            raise WizardError("The plugin on the firewall is older than this step needs. Update it in the plugin step.")
        user = str(self._recall("admin_user") or "")
        if action == "on" and not user:
            raise WizardError("Make your own sign-in first.")
        box = self._acts.source.box

        def work() -> dict:
            lines = {"on": ["Point the firewall's web page at the one-time-code server (Pazuzu OTP) for " + user,
                            "The page then asks for your password followed by the code; root has no code",
                            "The firewall puts the old setting back by itself after 5 minutes unless you keep it"],
                     "keep": ["Keep the web page signing in with the one-time-code server"],
                     "undo": ["Put the web page's sign-in back as it was"]}[action]
            if not self.window_gate(plan_digest("otp-switch-" + action, {"user": user}), lines):
                raise WizardError("Not approved with a passkey. Nothing was changed.")
            try:
                got = box.otp_switch(action, user if action == "on" else None)
            except Exception as exc:
                raise WizardError("The plugin did not answer: " + _plain_firewall(exc))
            if not got.get("ok"):
                raise WizardError(str(got.get("error") or "The plugin did not do it."))
            done = {"on": "The web page now asks for your password followed by the code. Sign in from a second window "
                          "within 5 minutes, then keep it.",
                    "keep": "Kept. The web page signs in with the one-time-code server.",
                    "undo": "Put back as it was."}[action]
            return {"lines": [done], "can_undo": False}

        return self._start("write-otp-switch", work)

    def otp_server_change(self, d) -> dict:
        """Add (or take away) the login server through the plugin, after a passkey. It never switches the sign-in."""
        from pazuzu_core.passkey_gate import plan_digest
        d = d if isinstance(d, dict) else {}
        action = d.get("action")
        if action not in ("add", "remove"):
            raise WizardError("That was not understood.")
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        st = self.otp_server_state()
        if not st["can"]:
            raise WizardError(st["why"])
        box = self._acts.source.box

        def work() -> dict:
            lines = (["Add a login server called Pazuzu OTP (Local + Timebased One Time Password)",
                      "The plugin on the firewall adds it and keeps a backup of the old settings",
                      "It does not change how the web page signs in. That stays your step"] if action == "add" else
                     ["Take away the login server called Pazuzu OTP",
                      "Refused if the web page signs in with it"])
            if not self.window_gate(plan_digest("otp-server-" + action, {}), lines):
                raise WizardError("Not approved with a passkey. Nothing was changed.")
            try:
                got = box.otp_server(action)
            except Exception as exc:
                raise WizardError("The plugin did not answer: " + _plain_firewall(exc))
            if not got.get("ok"):
                raise WizardError(str(got.get("error") or "The plugin did not do it."))
            done = ("Added." if got.get("added") else "It was already there.") if action == "add" else \
                   ("Taken away." if got.get("removed") else "It was not there.")
            return {"lines": [done], "can_undo": False}

        return self._start("write-otp-server", work)

    # -- the firewall's time zone (set by the plugin, the way the General settings page's Save does it)
    def time_zone_state(self) -> dict:
        """What the plugin reads: the firewall's time zone, whether this app set it, and the zones the firewall offers.
        Reads only."""
        up = self._box_up()
        for _ in range(3):                           # the link to the plugin may be coming back up: give it a moment
            if up:
                break
            time.sleep(1.0)
            up = self._box_up()
        if not up:
            return {"can": False, "retry": True,
                    "why": "The plugin is not answering yet\u2026 this page tries again by itself."}
        box = self._acts.source.box
        if not box.can("time_zone"):
            return {"can": False, "why": "The plugin on the firewall is older than this step needs. Update it in the plugin step."}
        got = box.time_zone_status()
        if got is None:
            return {"can": False, "why": "The plugin did not answer about the time zone just now."}
        zones = [str(z) for z in (got.get("zones") or []) if isinstance(z, str)][:1000]
        if not zones:
            return {"can": False, "why": "The firewall did not give its list of time zones."}
        return {"can": True, "zone": str(got.get("zone") or ""), "saved": bool(got.get("saved")),
                "ours": bool(got.get("ours")), "was": str(got.get("was") or ""), "zones": zones}

    def time_zone_change(self, d) -> dict:
        """Set the firewall's time zone through the plugin (one zone name, taken from the firewall's own list), or put it back
        if the plugin was the one that set it. Nothing else on the General settings page is touched."""
        from pazuzu_core.passkey_gate import plan_digest
        d = d if isinstance(d, dict) else {}
        action = d.get("action")
        zone = d.get("zone")
        if action not in ("set", "undo"):
            raise WizardError("That was not understood.")
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        st = self.time_zone_state()
        if not st["can"]:
            raise WizardError(st["why"])
        if action == "set" and (not isinstance(zone, str) or zone not in st["zones"]):
            raise WizardError("The firewall does not offer that time zone.")
        box = self._acts.source.box

        def work() -> dict:
            lines = (["Set the firewall's time zone to " + str(zone) + " (it is " + st["zone"] + " now)",
                      "Only the time zone changes: the plugin writes that one setting and has the firewall apply it",
                      "The firewall keeps a backup of its old settings"] if action == "set" else
                     ["Put the firewall's time zone back to " + (st["was"] or "what it was")])
            if not self.window_gate(plan_digest("time-zone-" + action, {"zone": str(zone or "")}), lines):
                raise WizardError("Not approved with a passkey. Nothing was changed.")
            try:
                got = box.time_zone(action, zone if action == "set" else None)
            except Exception as exc:
                raise WizardError("The plugin did not answer: " + _plain_firewall(exc))
            if not got.get("ok"):
                raise WizardError(str(got.get("error") or "The plugin did not do it."))
            if action == "set":
                done = ("The firewall is already on " + str(zone) + "." if not got.get("changed") else
                        "The firewall's time zone is now " + str(zone) + "."
                        + ("" if got.get("applied", True) else " The firewall has not switched its clock over yet; that happens at its next restart."))
            else:
                done = "The time zone is back to " + str(got.get("zone") or "what it was") + "." if got.get("undone") \
                    else "The time zone was not one Pazuzu set, so it was left as it is."
            return {"lines": [done], "can_undo": False}

        return self._start("write-time-zone", work)

    # -- will the firewall's hardware be happy with Zenarmor (the plugin reads the facts; the judging is here)
    def hardware_state(self) -> dict:
        """What the plugin reads about the processor, memory, disk and network cards, judged against what Zenarmor publishes.
        Reads only."""
        if not self._box_up():
            return {"can": False, "why": "The plugin is not answering, so the hardware cannot be read."}
        box = self._acts.source.box
        if not box.can("hardware"):
            return {"can": False, "why": "The plugin on the firewall is older than this check needs. Update it in the plugin step."}
        got = box.hardware_status()
        if got is None:
            return {"can": False, "why": "The plugin did not answer about the hardware just now."}
        from pazuzu_core import hardware_check
        return {"can": True, **hardware_check.judge(got)}

    # -- the daily report, made on the firewall by the plugin; emailed only if the person turned that on
    REPORT_KEYS = ("enabled", "to", "from", "host", "port", "security", "username", "password", "clear_password", "hour", "minute")

    def report_state(self) -> dict:
        """What the plugin says about the daily report: today's headline and lines, the saved settings (never the
        password) and how the last send went. Reads only."""
        if not self._box_up():
            return {"can": False, "why": "The plugin is not answering, so the daily report cannot be read."}
        box = self._acts.source.box
        if not box.can("report"):
            return {"can": False, "why": "The plugin on the firewall is older than the daily report needs. Update it first."}
        got = box.report_status()
        if got is None:
            return {"can": False, "why": "The plugin did not answer about the report just now."}
        return {"can": True, **got}

    def report_change(self, d) -> dict:
        """Save the report's email settings, switch the email off, or send a test now. Saving and switching off need the
        passkey (the email is a way for the firewall to talk to the outside); a test only uses what is already saved."""
        import hashlib
        from pazuzu_core.passkey_gate import plan_digest
        d = d if isinstance(d, dict) else {}
        action = d.get("action")
        if action not in ("save", "off", "test"):
            raise WizardError("That was not understood.")
        st = self.report_state()
        if not st["can"]:
            raise WizardError(st["why"])
        box = self._acts.source.box
        if action == "test":
            try:
                got = box.report("test")
            except Exception as exc:
                raise WizardError("The plugin did not answer: " + _plain_firewall(exc))
            if not got.get("ok"):
                raise WizardError(str(got.get("error") or "The test mail did not go."))
            return {"ok": True, "sent": True}
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        fields = d.get("settings") if isinstance(d.get("settings"), dict) else {}
        fields = {k: fields[k] for k in self.REPORT_KEYS if k in fields}
        if action == "save" and not fields:
            raise WizardError("There was nothing to save.")

        def work() -> dict:
            if action == "off":
                lines = ["Switch the daily report email off", "The report is still made and can be read here and on the phone page"]
                digest = plan_digest("report-off", {})
            else:
                on = fields.get("enabled") is True
                lines = ["Save the daily report settings on the firewall",
                         ("Email it every day at %02d:%02d to %s" % (int(fields.get("hour", 7) or 0), int(fields.get("minute", 0) or 0),
                                                                    fields.get("to") or "the address you gave")) if on else "The email stays off",
                         "It goes only to that address, through your own mail server (%s)" % (fields.get("host") or "the one you named"),
                         "The password stays on the firewall and is never shown again"]
                shown = {k: v for k, v in fields.items() if k not in ("password",)}
                shown["password_sha"] = hashlib.sha256(str(fields.get("password") or "").encode()).hexdigest()[:16]
                digest = plan_digest("report-save", shown)
            if not self.window_gate(digest, lines):
                raise WizardError("Not approved with a passkey. Nothing was changed.")
            try:
                got = box.report(action, fields if action == "save" else None)
            except Exception as exc:
                raise WizardError("The plugin did not answer: " + _plain_firewall(exc))
            if not got.get("ok"):
                raise WizardError(str(got.get("error") or "The plugin did not save it."))
            return {"lines": ["Saved. The email is off." if action == "off" or not fields.get("enabled") else
                              "Saved. The report will be emailed every day at %02d:%02d." % (int(fields.get("hour", 7) or 0), int(fields.get("minute", 0) or 0))],
                    "can_undo": False}

        return self._start("write-report", work)

    def _wifi_closed_itself(self) -> bool:
        """The plugin says the Wi-Fi back door was used and then closed itself, as it was set up to."""
        try:
            return bool(self._acts.source.box.wifi_status().get("closed_after_use"))
        except Exception:
            return False

    def wifi_state(self) -> dict:
        got = getattr(self, "_wifi_done", None)
        # The Wi-Fi lives on the box and is set up through the plugin: with no plugin answering
        # (a reset box, say) what was remembered is not true any more, so it is not shown as done.
        up = self._box_up()
        if up and self._wifi_closed_itself():
            self._wifi_done = None
            return {"state": "none", "done": False, "closed_after_use": True,
                    "direct": bool(self._acts and self._acts.source.box.can("wifi_setup"))}
        if got and up:
            return {"state": "done", "done": True, **got}
        w = getattr(self, "_wifi", None)
        done = bool(self._recall("wifi_backdoor")) and up
        direct = False
        if up and not done:
            try:
                direct = bool(self._acts.source.box.can("wifi_setup"))
            except Exception:
                direct = False
        if w is None:
            return {"state": "done" if done else "none", "done": done, "direct": direct}
        st = w["offer"].state()
        out = {"state": st, "done": done or st == "done", "ssid": w["ssid"], "direct": direct}
        out.update(passphrase=w["passphrase"], qr=w["qr"])
        if st == "failed":
            out["report"] = w["offer"].report
            out["no_card"] = _no_wifi_card(out["report"])
            out["no_beacon"] = _no_beacon(out["report"])
            cant = _cannot_host(out["report"])
            if cant:
                out["cannot_host"] = cant
                known = [c for c in (self._recall("wifi_cannot_host") or []) if isinstance(c, str)]
                if any(c not in known for c in cant):
                    self._remember("wifi_cannot_host", sorted(set(known) | set(cant)))
                out["other_card"] = self._wifi_can_host()     # a card plugged in since: worth trying again
        else:
            for old in reversed(getattr(self, "_wifi_past", [])):
                rep = getattr(old["offer"], "report", None)
                if rep:
                    out["earlier_report"] = rep     # kept after "Start over", so what went wrong is still readable
                    break
        if st in ("waiting", "fetched", "closed") and not out["done"]:
            out.update(command=w["offer"].command(),
                       seconds_left=max(0, int(w["offer"].expires - w["offer"].clock())))
        return out

    # -- the phone's hotspot as the backup internet (a Wi-Fi device, a port, the gateways), one passkey touch
    def _hotspot_link(self):
        """The plugin, as the Wi-Fi backup step needs it: read whether default gateway switching is on, and switch it on."""
        if not self._box_up():
            raise WizardError("The plugin is not answering, so Pazuzu cannot switch on default gateway switching. "
                              "Put the plugin on first (the plugin step).")
        box = self._acts.source.box
        if not box.can("gateway_switch"):
            raise WizardError("The plugin on the firewall is older than this step needs. Update it in the plugin step.")

        class Link:
            def status(self_):
                return box.gateway_switch_status()

            def gateway_switch(self_, action):
                try:
                    return box.gateway_switch(action)
                except Exception as exc:
                    return {"ok": False, "error": "The plugin did not answer: " + _plain_firewall(exc)}

            def hotspot_standby(self_, action, data=None):
                # BUILD 505 ("hotspot still connected on phone"): the link the hotspot step is given
                # had no way to ask for the reserve, so Finish never switched it on
                try:
                    return box.hotspot_standby(action, data)
                except Exception as exc:
                    return {"ok": False, "error": "The plugin did not answer: " + _plain_firewall(exc)}
        return Link()

    @staticmethod
    def _hotspot_trace_path() -> Path:
        """Where a run of the Wi-Fi backup keeps what the firewall was asked and answered (next to the saved scan results)."""
        return Path("scan_results") / "hotspot_trace.json"

    def _trace_note(self, hs) -> str:
        """For a refusal: where the record of the run was saved, so it can be sent along with the message."""
        path = hs.save_trace()
        return f" (What the firewall was asked and answered is saved in {path}.)" if path else ""

    @staticmethod
    def _gateway_facts(row) -> dict | None:
        if not isinstance(row, dict):
            return None
        return {k: str(row.get(k) or "") for k in ("name", "priority", "monitor", "monitor_disable", "status")}

    def hotspot_state(self) -> dict:
        """What the card needs: can it be done here, and how far it has got. Reads only."""
        out = {"can": False, "why": "", "stage": "none", "done": bool(self._recall("wifi_backup")), "ssid": "",
               "device": "", "identifier": "", "joined": False, "reuse": False, "gateway": None, "main": None}
        try:
            link = self._hotspot_link()
            session = self._installer_session()
            hs = wb.Hotspot(we.Engine(session, self.base_url.rstrip("/"), self._probe), switch=link)
            cur = hs.look()
        except WizardError as exc:
            out["why"] = str(exc)
            return out
        except we.WriteError as exc:
            out["why"] = str(exc)
            return out
        out.update(can=True, stage=cur["stage"], ssid=cur["ssid"], device=cur["device"], identifier=cur["identifier"],
                   joined=bool(cur["joined"]), reuse=bool(cur["reuse"]), gateway=self._gateway_facts(cur["gateway"]),
                   main=self._gateway_facts(cur["main"]))
        try:                                       # BUILD 504: plugin 0.7.1's reserve, so "Offline" is said as "in reserve"
            sb = self._acts.source.box.hotspot_standby_status()
        except Exception:  # noqa: BLE001
            sb = None
        if isinstance(sb, dict):
            out["standby"] = {"on": bool(sb.get("on")) and str(sb.get("device") or "") == str(cur["device"] or ""),
                              "joined_for_outage": bool(sb.get("joined_for_outage"))}
        return out

    def hotspot_set(self, d) -> dict:
        """Set the hotspot up (or change which phone), with one passkey touch. The password is held for this call only."""
        d = d if isinstance(d, dict) else {}
        try:
            ssid, passphrase = wb.Hotspot.clean(d.get("ssid"), d.get("passphrase"))
        except we.WriteError as exc:
            raise WizardError(str(exc))
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        link = self._hotspot_link()
        session = self._installer_session()
        base = self.base_url.rstrip("/")
        probe = self._probe

        def work() -> dict:
            hs = wb.Hotspot(we.Engine(session, base, probe), switch=link, trace_to=self._hotspot_trace_path(),
                            **getattr(self, "_hotspot_timing", {}))
            try:
                plan = hs.plan(ssid, passphrase)
                outs = hs.apply(plan, lambda digest, lines: self.window_gate(digest, list(lines)))
            except we.WriteError as exc:
                raise WizardError(str(exc) + self._trace_note(hs))
            finally:
                hs.save_trace()
            if outs:
                self._last_write = (wb.Undoer(), outs)
                self._remember("wifi_backup", True)
            return {"lines": list(hs.said), "can_undo": bool(outs)}

        return self._start("write-hotspot", work)

    def hotspot_finish(self) -> dict:
        """The last part again for a port that is already on: wait for the phone, then set the order of the two connections."""
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        link = self._hotspot_link()
        session = self._installer_session()
        base = self.base_url.rstrip("/")
        probe = self._probe

        def work() -> dict:
            hs = wb.Hotspot(we.Engine(session, base, probe), switch=link, trace_to=self._hotspot_trace_path(),
                            **getattr(self, "_hotspot_timing", {}))
            try:
                plan = hs.finish_plan()
                outs = hs.finish_apply(plan, lambda digest, lines: self.window_gate(digest, list(lines)))
            except we.WriteError as exc:
                raise WizardError(str(exc) + self._trace_note(hs))
            finally:
                hs.save_trace()
            if outs:
                self._last_write = (wb.Undoer(), outs)
            return {"lines": list(hs.said), "can_undo": bool(outs)}

        return self._start("write-hotspot", work)

    def zone_vlans_start(self, d) -> dict:
        """Zones with no port: each given a spare port (put on the firewall with its own network) or a VLAN of its own
        (zone_vlans), then saved to it on this device. d = {"zones": [VLAN zones], "ports": {zone: device}}."""
        from pazuzu_core import zone_vlans as zv
        from pazuzu_core.zone_assignment import BLOCKING_STATES
        d = d if isinstance(d, dict) else {}
        if not kids_present():                      # BUILD 539: a copy without KidsNet makes no network for it
            d = {**d, **{k: ({z: v for z, v in d[k].items() if z != "kids"} if isinstance(d.get(k), dict)
                             else [z for z in d[k] if z != "kids"] if isinstance(d.get(k), list) else d[k])
                         for k in ("zones", "ports", "wifi") if k in d}}
        scramble = d.get("scramble") is not False   # random subnets + VLAN IDs are the baseline; off = fixed, repeatable (for testing only)
        ports_in = d.get("ports") if isinstance(d.get("ports"), dict) else {}
        spare = {p["device"] for p in self.spare_ports()}
        ports = {z: dev for z, dev in ports_in.items() if z in zv.PORT_ZONES and isinstance(dev, str) and dev}
        bad = [dev for dev in ports.values() if dev not in spare]
        if bad:
            raise WizardError("Not a spare port: " + ", ".join(bad) + ". Nothing was changed.")
        wifi_in = d.get("wifi") if isinstance(d.get("wifi"), dict) else {}
        free = {r["card"] for r in self._radios() if r["free"]}
        wifi = {}
        for z, w in wifi_in.items():
            if z not in zv.WIFI_ZONES or not isinstance(w, dict) or z in ports:
                continue
            card = str(w.get("card") or "")
            if card not in free:
                raise WizardError(f"{card or 'That card'} cannot host a Wi-Fi network right now. Nothing was changed.")
            wifi[z] = {"card": card, "ssid": str(w.get("ssid") or ""), "passphrase": w.get("passphrase")}
        zones = [z for z in (d.get("zones") or []) if isinstance(z, str) and z in zv.OFFERED and z not in ports
                 and z not in wifi]
        current = (self.status().get("zones") or {}).get("assignments") or {}
        # BUILD 556 (the maintainer's run, 17 Nov 2026: a firewall that already had its zones could not put their Wi-Fi on an
        # access point found afterwards, "it used to"): a zone that already has a VLAN keeps it, and its Wi-Fi is made
        # on the access point on that VLAN. A zone that lives on a port or a Wi-Fi card of the firewall's own has no
        # VLAN to ride, so it is left where it is and said.
        ap_ask = d.get("ap") if isinstance(d.get("ap"), dict) else None
        ap_named = [str(n.get("zone")) for n in (ap_ask.get("networks") or []) if isinstance(n, dict)] if ap_ask else []
        homed = {z: str(current[z].get("device")) for z in ap_named
                 if isinstance(current.get(z), dict) and current[z].get("device")
                 and current[z].get("state") not in ("unconfigured", None, *BLOCKING_STATES)}
        kept_tag, left_alone = {}, []
        if homed:
            by_zone = {str(v.get("zone")): int(v["tag"]) for v in (self.ap_vlan_options().get("vlans") or []) if v.get("zone")}
            for z, dev in homed.items():
                if z == "trusted":
                    continue
                if z in by_zone:
                    kept_tag[z] = by_zone[z]
                else:
                    left_alone.append(f"{zv.WORDS.get(z, z)} is on {dev}, not on a VLAN, so its Wi-Fi was left where it is.")
            zones = [z for z in zones if z not in homed]
        if not zones and not ports and not wifi and not kept_tag:
            raise WizardError(" ".join(left_alone) if left_alone else "Pick at least one zone that has no port.")
        busy = [z for z in [*zones, *ports, *wifi] if isinstance(current.get(z), dict) and current[z].get("device")
                and current[z].get("state") not in ("unconfigured", None, *BLOCKING_STATES)]
        if busy:
            raise WizardError("These zones already have a port: " + ", ".join(busy) + ". Nothing was changed.")
        trusted = str((current.get("trusted") or {}).get("device") or "")
        if not trusted and re.fullmatch(r"[a-z]{2,10}\d{1,3}", str(d.get("trusted") or "")):
            # BUILD 450: the Trusted port as picked in the table above it, before Save and continue was pressed (lab
            # box, 2 Nov 2026: "No port is known for the Trusted Network" with igc0 showing as Trusted on the page).
            trusted = str(d["trusted"])
        dhcp = d.get("dhcp") if d.get("dhcp") in ("kea", "dnsmasq") else None    # BUILD 499: the person's pick
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        session = self._installer_session()
        base = self.base_url.rstrip("/")
        probe = self._probe

        def work() -> dict:
            import random as _rnd
            _rng = None if scramble else (lambda _r=_rnd.Random(13337): (lambda lo, hi: _r.randint(lo, hi)))()   # off: fixed sequence => predictable, repeatable addresses for testing
            made, outs, lines = [], [], []
            if zones or ports or wifi:               # BUILD 556: nothing to make when only kept zones go on the access point
                zvl = zv.ZoneVlans(we.Engine(session, base, probe), rng=_rng, trace_to=Path("scan_results") / time.strftime("vlan_trace_%Y%m%d-%H%M%S.json"))
                try:
                    named = [str((a or {}).get("device")) for a in current.values() if isinstance(a, dict) and (a or {}).get("device")]
                    plan = zvl.plan(zones, trusted, ports, in_use=named, wifi=wifi, dhcp=dhcp)   # any port a zone names, whatever its state
                    outs = zvl.apply(plan, lambda digest, lines: self.window_gate(digest, list(lines)))
                except we.WriteError as exc:
                    raise WizardError(str(exc) + self._trace_note(zvl))
                finally:
                    zvl.save_trace()
                if outs:
                    self._last_write = (wb.Undoer(), outs)
                lines = list(zvl.said)
                made = list(plan.facts["made"])
            elif kept_tag:
                # Only the access point is changed: it has its own approval, since no zone change asked for one.
                from pazuzu_core.passkey_gate import plan_digest
                want = [n for n in (ap_ask.get("networks") or []) if isinstance(n, dict) and n.get("zone") in kept_tag]
                shown = [f"Make Wi-Fi networks on the access point at {ap_ask.get('ip')}"]
                shown += [f"{zv.WORDS.get(n['zone'], n['zone'])}: \u201c{str(n.get('ssid') or '')[:32]}\u201d on VLAN {kept_tag[n['zone']]}"
                          for n in want]
                shown += ["The zones and their VLANs on the firewall are not changed",
                          "Its network and Wi-Fi restart for a few seconds; devices on it reconnect"]
                if not self.window_gate(plan_digest("ap-zone-wifi", {"ip": str(ap_ask.get("ip")),
                                                                     "nets": sorted((n["zone"], kept_tag[n["zone"]]) for n in want)}), shown):
                    raise WizardError("Not approved with a passkey; nothing was changed.")
            lines += left_alone
            for f in made:
                try:
                    self.zone_set(f["zone"], f["device"])
                    how = (f"Wi-Fi \u201c{f['ssid']}\u201d" if f.get("wifi") else f"VLAN {f['tag']}" if f.get("tag") else "its own port")
                    lines.append(f"Saved {zv.WORDS[f['zone']]} to {f['device']} ({how}). "
                                 + ("Pick its family DNS filter next; until then nothing there reaches the internet."
                                    if f["zone"] == "kids" else "The rules step adds its rules."))
                    if f.get("wifi") and f.get("ssid"):
                        self._note_zone_wifi({f["zone"]: {"ssid": str(f["ssid"]), "where": "firewall"}})
                except WizardError as exc:
                    lines.append(f"{zv.WORDS[f['zone']]}: made, but not saved to the zone yet ({exc}). Pick {f['device']} "
                                 "for it on the ports page.")
            if made:
                self._remember("zone_vlans", [[f["zone"], f["tag"], f["device"]] for f in made])
                self._remember("network_scrambled", scramble)   # posture flags a not-scrambled network as not-done
            if made and not scramble:
                lines.append("Network NOT scrambled (testing): fixed, repeatable subnets and VLAN numbers. The manager flags this until you scramble.")
            ap_in = d.get("ap") if isinstance(d.get("ap"), dict) else None   # same pass: fold an OpenWrt access point onto the zones just made
            if ap_in:
                from pazuzu_core import ap_openwrt as apx
                ap_ip = apx.private_address(ap_in.get("ip"))
                ap_pw = str(ap_in.get("password") or "")
                ap_post = self._ap_post()        # PC-direct, or through the box when the firewall joined it on a radio
                zone_tag = {**kept_tag, **{f["zone"]: f["tag"] for f in made if f.get("tag")}}   # BUILD 556: a VLAN a zone already had counts
                # Preferred: CREATE the firewall's zone Wi-Fi on the access point, each on the zone's just-chosen (scrambled)
                # VLAN. networks = [{zone, ssid, passphrase, radio}]. Management is never among them (the wizard leaves it out).
                nets_in = ap_in.get("networks") if isinstance(ap_in.get("networks"), list) else []
                specs = []
                for n in nets_in:
                    if not isinstance(n, dict):
                        continue
                    extra = {k: n[k] for k in ("radios", "encryption", "isolate") if k in n}   # BUILD 482
                    if n.get("zone") == "trusted" and str(n.get("ssid") or "").strip():      # BUILD 482: Home, untagged
                        specs.append(dict({"ssid": str(n.get("ssid")).strip(), "passphrase": str(n.get("passphrase") or ""),
                                           "tag": None, "home": True, "radio": str(n.get("radio") or "")}, **extra))
                        continue
                    tag = zone_tag.get(n.get("zone"))
                    if tag and str(n.get("ssid") or "").strip():
                        specs.append(dict({"ssid": str(n.get("ssid")).strip(), "passphrase": str(n.get("passphrase") or ""),
                                           "tag": int(tag), "radio": str(n.get("radio") or "")}, **extra))
                # Fallback (manager-style): retag the access point's EXISTING networks onto zones. zones = {section: zone}.
                zmap = ap_in.get("zones") if isinstance(ap_in.get("zones"), dict) else {}
                section_tag = {str(s): int(zone_tag[z]) for s, z in zmap.items() if zone_tag.get(z)}

                def _ap_cleanup():
                    if ap_in.get("ipv6_off") is not False:
                        apx.ipv6_off(ap_ip, ap_pw, post=ap_post)
                        lines.append("Access point: IPv6 switched off.")
                    if ap_in.get("dhcp_off") is not False:
                        apx.dhcp_off(ap_ip, ap_pw, post=ap_post)
                        lines.append("Access point: it no longer hands out addresses; the firewall does, on the VLAN.")

                if ap_ip and specs:
                    try:
                        got = apx.add_networks(ap_ip, specs, ap_pw, post=ap_post, say=print)
                        lines.append("Access point: created " + ", ".join(sorted({("“%s” on the home network" % m["ssid"]) if m["tag"] is None
                                     else ("“%s” on VLAN %s" % (m["ssid"], m["tag"])) for m in got.get("made") or []}))
                                     + " — your zone Wi-Fi broadcasts from it now, scrambled with the "
                                     "zones; it stays reachable on its own network for admin, and never broadcasts management.")
                        _ap_cleanup()
                        tag_zone = {int(t): z for z, t in zone_tag.items()}
                        self._note_zone_wifi({("trusted" if m["tag"] is None else tag_zone.get(int(m["tag"]))):
                                              {"ssid": str(m["ssid"]), "where": "ap"} for m in got.get("made") or []})
                        if any(m["tag"] is None for m in got.get("made") or []):                # BUILD 482: Hanbi's Wi-Fi made
                            try:
                                rec = json.loads((self.key_dir / self.HOME_WIFI_FILE).read_text(encoding="utf-8"))
                            except (OSError, ValueError):
                                rec = None
                            if isinstance(rec, dict) and rec.get("ip") == ap_ip:
                                rec = dict(rec, made=True)
                                new_pw = str(ap_in.get("new_password") or "")
                                if new_pw:                         # last: every call above signed in with the old one
                                    try:
                                        apx.set_root_password(ap_ip, new_pw, ap_pw, post=ap_post)
                                        rec["admin"] = new_pw
                                        lines.append("Access point: its own web page now has a password your Hanbi made "
                                                     "and keeps; you never need to type it.")
                                    except apx.ApError as exc:
                                        lines.append("Access point: its password was not changed (" + str(exc) + ").")
                                self._home_wifi_save(rec)
                    except apx.ApError as exc:
                        lines.append("Access point not fully set up (" + str(exc) + "); your zones are made — finish it from the OpenWrt card below.")
                elif ap_ip and section_tag:
                    try:
                        got = apx.set_vlans(ap_ip, section_tag, ap_pw, post=ap_post, say=print)
                        lines.append("Access point: moved its existing Wi-Fi onto VLAN " + ", ".join(map(str, got.get("tags") or []))
                                     + " — it rides your scrambled zones now.")
                        _ap_cleanup()
                    except apx.ApError as exc:
                        lines.append("Access point not fully set up (" + str(exc) + "); your zones are made — finish it from the OpenWrt card below.")
                elif ap_ip and (nets_in or zmap):
                    lines.append("Access point: the zones you chose for it did not get a VLAN to ride; set them to a VLAN and set up again.")
            return {"lines": lines, "can_undo": bool(outs)}

        return self._start("write-zone-vlans", work)

    def _ssh_port(self) -> int:
        """The random SSH port this install was given (the same one the printed page shows)."""
        port = mports.gui_port_from_base_url(self.base_url) or 443
        return mports.load_or_create_plan(self.key_dir, reserved={443, 22, port}).ssh

    def _ssh_allowed(self, getter) -> list:
        """The ports SSH may listen on: the management port and the VPN's, by the firewall's own names (opt3, ...)."""
        zones = (self.status().get("zones") or {}).get("assignments") or {}
        out = []
        mg = zones.get("management") or {}
        if mg.get("state") == "bound" and mg.get("identifier"):
            out.append(str(mg["identifier"]))
        try:
            rows = (getter("/api/interfaces/overview/interfaces_info/true") or {}).get("rows") or [] if getter else []
        except Exception:  # noqa: BLE001
            rows = []
        for r in rows:
            if isinstance(r, dict) and str(r.get("device", "")).startswith("wg") and r.get("identifier"):
                out.append(str(r["identifier"]))
        return sorted(set(out))

    _REAL_SHELLS = ("/bin/sh", "/bin/csh", "/bin/tcsh")

    def _console_state(self, getter):
        """Can your own admin sign in at the firewall's console? It needs a login shell (not nologin), then a proof that
        it worked. None when there is no admin user known yet or it cannot be read."""
        name = self._recall("admin_user")
        if not name or getter is None:
            return None
        rows = (getter("/api/auth/user/search?searchPhrase=" + str(name)) or {}).get("rows") or []
        row = next((r for r in rows if isinstance(r, dict) and str(r.get("name")) == name), None)
        if row is None or not we._UUID.match(str(row.get("uuid", ""))):
            return None
        body = getter("/api/auth/user/get/" + str(row["uuid"])) or {}
        form = next(iter(body.values()), {}) if isinstance(body, dict) and len(body) == 1 else {}
        node = form.get("shell") if isinstance(form, dict) else None
        shell = (we._value_of(node) if we._option_labels(node) is not None else str(node or "")) if node is not None else ""
        return {"user": name, "shell": str(shell or ""), "real": str(shell or "") in self._REAL_SHELLS,
                "proved": "console" in self.confirmed_controls()}

    def console_facts(self) -> dict:
        """BUILD 477: what the box itself can vouch for about your admin's console sign-in: a login shell (read from the
        firewall) and sudo allowed for admins (read from the firewall's own sudo rules by the plugin). On a Hanbi these
        stand for the "I signed in at the console" tick: there is no keyboard console to sign in at."""
        getter = self._api_getter()
        try:
            con = self._console_state(getter)
        except Exception:  # noqa: BLE001
            con = None
        if not con:
            return {"user": self._recall("admin_user") or "", "known": False, "real": False, "sudo": None, "ok": False}
        sudo = None
        try:
            box = self._acts.source.box if (self._acts is not None and self._box_up()) else None
            sd = box.sudo_status() if box is not None and box.can("sudo") else None
            if isinstance(sd, dict):
                sudo = bool(sd.get("allowed"))
            con["can_sudo_set"] = bool(box is not None and box.can("sudo_set"))
        except Exception:  # noqa: BLE001
            pass
        con.update(known=True, sudo=sudo, ok=bool(con.get("real") and sudo))
        return con

    def console_shell_start(self) -> dict:
        """Give your own admin a login shell, so it can sign in at the console (the factory root is the only one that can
        until then). One field on one user; the Undo puts the old one back."""
        name = self._recall("admin_user")
        if not name:
            raise WizardError("There is no admin user of your own yet. Make one on the setup page's Admin step.")

        def run(engine, gate):
            form = engine._template(we.CAPS["user"])[1]
            offered = we._option_labels(form.get("shell")) or {}
            pick = next((s for s in self._REAL_SHELLS if s in offered), None)
            if pick is None:
                raise we.WriteError("The firewall's user form offers no ordinary shell, so nothing was changed.")
            out = engine.change_text("user", name, "shell", pick, gate, say=f"Let {name} sign in at the console ({pick})")
            if out is None:
                raise we.WriteError(f"The firewall has no user called {name}. Nothing was changed.")
            return [out], list(out.lines) + [f"{name} can now sign in at the firewall's console."]
        return self._engine_job("console-shell", run)

    def console_sudo_start(self, d=None) -> dict:
        """BUILD 473 / plugin 0.6.72: let the admins group use sudo, asking for its password, so your own admin can open
        the console menu (sudo opnsense-shell). System, Settings, Administration, Sudo, through the plugin; the Undo
        puts it back exactly as it was."""
        from pazuzu_core.passkey_gate import plan_digest
        d = d if isinstance(d, dict) else {}
        action = d.get("action") or "allow"
        if action not in ("allow", "undo"):
            raise WizardError("That was not understood.")
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        if not self._box_up() or not self._acts.source.box.can("sudo_set"):
            raise WizardError("The plugin on the firewall is older than this needs (0.6.72). Update it in the plugin step, "
                              "or set it by hand: System, Settings, Administration, Sudo: Ask password, group admins, Save.")

        def work() -> dict:
            lines = (["Let the admins group use sudo, asking for its password (System, Settings, Administration, Sudo)",
                      "Then your own admin opens the console menu with  sudo opnsense-shell"] if action == "allow"
                     else ["Put the firewall's sudo setting back as it was before Pazuzu changed it"])
            if not self.window_gate(plan_digest("console-sudo-" + action, {}), lines):
                raise WizardError("Not approved with a passkey. Nothing was changed.")
            got = self._box_post("/sudo_set", {"action": action}, timeout=90)
            if not isinstance(got, dict) or not got.get("ok"):
                raise WizardError(str((got or {}).get("error") if isinstance(got, dict) else "") or "The plugin did not answer.")
            said = ("Admins may use sudo now (it asks for the password). At the console: sign in as your admin, then "
                    "sudo opnsense-shell." if action == "allow" else "Sudo is back as it was.")
            return {"lines": [said], "can_undo": False}

        return self._start("console-sudo", work)

    def ssh_fix_start(self, d) -> dict:
        """Secure Shell to the baseline, through the plugin: off, or tight (root login off, listening only on the
        management and VPN ports, on this install's random port). Password login is left as it is."""
        from pazuzu_core.passkey_gate import plan_digest
        d = d if isinstance(d, dict) else {}
        action = d.get("action")
        if action not in ("off", "tighten", "undo"):
            raise WizardError("That was not understood.")
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        if not self._box_up() or not self._acts.source.box.can("ssh"):
            raise WizardError("The plugin on the firewall is older than this needs. Update it in the plugin step.")
        box = self._acts.source.box
        getter = self._api_getter()
        allowed = self._ssh_allowed(getter) if action == "tighten" else []
        port = self._ssh_port() if action == "tighten" else None
        warn = self._ssh_warnings(getter, allowed) if action == "tighten" else []

        def work() -> dict:
            lines = {"off": ["Switch Secure Shell off (the baseline: nothing listens for SSH)"],
                     "tighten": ["Keep Secure Shell on, tightened: root may not log in",
                                 "It listens only on " + (", ".join(allowed) or "nothing") + " (management and the VPN)",
                                 f"On this install's own port, {port}",
                                 "Password login is left as it is: add a key to your user before you switch it off"] + warn,
                     "undo": ["Put the Secure Shell settings back as they were before Pazuzu changed them"]}[action]
            if not self.window_gate(plan_digest("ssh-" + action, {"allowed": allowed, "port": port}), lines):
                raise WizardError("Not approved with a passkey. Nothing was changed.")
            got = box.ssh_change(action, allowed, port)
            if not got.get("ok"):
                raise WizardError(str(got.get("error") or "The plugin did not change it."))
            said = {"off": "Secure Shell is off.", "tighten": f"Secure Shell now listens only on {', '.join(allowed)}, port {port}, "
                    "and root may not log in.", "undo": "Secure Shell is back as it was." if got.get("undone") else
                    "Nothing to put back: Pazuzu had not changed it."}[action]
            return {"lines": [said], "can_undo": False}

        return self._start("ssh-fix", work)

    def _ssh_warnings(self, getter, allowed) -> list:
        """BUILD 475: said before the passkey for Tighten: which network this computer reaches the firewall on, when that
        one loses SSH, and when the VPN is not among the ports (Tighten took SSH from the PC on LAN
        without a word, and only management was listed because the VPN's interface was not assigned)."""
        import ipaddress
        out = []
        try:
            rows = (getter("/api/interfaces/overview/interfaces_info/true") or {}).get("rows") or [] if getter else []
        except Exception:  # noqa: BLE001
            rows = []
        host, _p = base_host_port(self.base_url)
        here = None
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        for r in rows:
            if ip is None or not isinstance(r, dict):
                break
            vals = r.get("addr4") if isinstance(r.get("addr4"), list) else [r.get("addr4")]
            for v in vals:
                try:
                    if v and ip in ipaddress.ip_interface(str(v).strip()).network:
                        here = r
                except ValueError:
                    continue
        if here is not None and str(here.get("identifier") or "") not in allowed:
            name = str(here.get("description") or here.get("identifier") or "")
            out.append(f"This computer reaches the firewall on {name} ({here.get('identifier')}): SSH from here stops "
                       "after this. It answers only from the ports listed above")
        if not any(str(r.get("device", "")).startswith("wg") and str(r.get("identifier") or "") in allowed
                   for r in rows if isinstance(r, dict)):
            out.append("The VPN is not among them: its WireGuard interface is not assigned on the firewall (Interfaces, "
                       "Assignments), so SSH is reachable from management only")
        return out

    def dns_trace(self, name) -> dict:
        """Did the DNS block lists turn this name away? From the firewall's own DNS log. Reads only."""
        from pazuzu_core import dns_allow
        getter = self._api_getter()
        if getter is None:
            raise WizardError("Sign in to the firewall first.")
        try:
            return dns_allow.trace(getter, name)
        except we.WriteError as exc:
            raise WizardError(str(exc))

    def dns_allow_start(self, d) -> dict:
        """Let one name (and the names under it) through the DNS block lists, with one passkey; the Undo takes it back."""
        from pazuzu_core import dns_allow
        d = d if isinstance(d, dict) else {}
        try:
            name = dns_allow.clean(d.get("name"))
        except we.WriteError as exc:
            raise WizardError(str(exc))
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        session = self._installer_session()
        base = self.base_url.rstrip("/")
        probe = self._probe

        def work() -> dict:
            da = dns_allow.DnsAllow(we.Engine(session, base, probe))
            try:
                plan = da.plan(name)
                outs = da.apply(plan, lambda digest, lines: self.window_gate(digest, list(lines)))
            except we.WriteError as exc:
                raise WizardError(str(exc))
            if outs:
                self._last_write = (wb.Undoer(), outs)
            return {"lines": list(da.said), "can_undo": bool(outs)}

        return self._start("dns-allow", work)

    def _zone_devices(self) -> dict:
        zones = (self.status().get("zones") or {}).get("assignments") or {}
        return {z: str(a.get("device")) for z, a in zones.items()
                if isinstance(a, dict) and a.get("device") and a.get("state") == "bound"}

    def _dhcp_state(self, getter) -> dict:
        """{"missing", "incomplete", "strays"}: zone networks with no handout, Pazuzu's subnets handing out no router or
        name server, and Pazuzu's subnets on none of the firewall's ports. Reads only."""
        from pazuzu_core import zone_dhcp
        out = {"missing": self._dhcp_missing(getter), "incomplete": [], "strays": []}
        gen = (getter("/api/kea/dhcpv4/get") or {}).get("dhcpv4") or {}
        en_ = (gen.get("general") or {}).get("enabled") if isinstance(gen, dict) else None
        if str(en_ if not isinstance(en_, dict) else "") in ("1", "true", "True"):
            details = zone_dhcp.kea_details(getter)
            if details is not None:
                rows = (getter("/api/interfaces/overview/interfaces_info/true") or {}).get("rows") or []
                out["incomplete"] = [{"label": x["label"], "subnet": x["subnet"]} for x in zone_dhcp.incomplete(details, rows)]
                out["strays"] = [{"label": x["label"], "subnet": x["subnet"]} for x in zone_dhcp.strays(details, rows)]
        return out

    def _dhcp_missing(self, getter) -> list:
        """The zone networks with no address handout, read from the firewall (Kea first, else dnsmasq)."""
        from pazuzu_core import zone_dhcp
        rows = (getter("/api/interfaces/overview/interfaces_info/true") or {}).get("rows") or []
        gen = (getter("/api/kea/dhcpv4/get") or {}).get("dhcpv4") or {}
        en_ = (gen.get("general") or {}).get("enabled") if isinstance(gen, dict) else None
        kea = str(en_ if not isinstance(en_, dict) else "") in ("1", "true", "True")
        if kea:
            subnets = [str(r.get("subnet") or "") for r in
                       ((getter("/api/kea/dhcpv4/search_subnet?rowCount=-1") or {}).get("rows") or [])]
            got = zone_dhcp.missing(self._zone_devices(), rows, subnets, None)
        else:
            ranges = [str(r.get("interface") or "") for r in
                      ((getter("/api/dnsmasq/settings/search_range?rowCount=-1") or {}).get("rows") or [])]
            got = zone_dhcp.missing(self._zone_devices(), rows, None, ranges)
        return [{"zone": m["zone"], "network": m["network"]} for m in got]

    def dhcp_zones_start(self) -> dict:
        """An address handout for every zone network that has none (zone_dhcp), with one passkey; each takeable back."""
        from pazuzu_core import zone_dhcp
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        zones = self._zone_devices()
        session = self._installer_session()
        base = self.base_url.rstrip("/")
        probe = self._probe

        def work() -> dict:
            zd = zone_dhcp.ZoneDhcp(we.Engine(session, base, probe),
                                    trace_to=Path("scan_results") / time.strftime("dhcp_trace_%Y%m%d-%H%M%S.json"))
            try:
                plan = zd.plan(zones)
                outs = zd.apply(plan, lambda digest, lines: self.window_gate(digest, list(lines)))
            except we.WriteError as exc:
                raise WizardError(str(exc) + self._trace_note(zd))
            finally:
                zd.save_trace()
            if outs:
                self._last_write = (wb.Undoer(), outs)
            return {"lines": list(zd.said), "can_undo": bool(outs)}

        return self._start("write-zone-dhcp", work)

    def spare_ports(self, found: list | None = None) -> list:
        """Real ports no zone uses yet, that are not the internet or home port, not a Wi-Fi card and not the USB backup:
        [{"device", "label", "assigned", "link"}]. Reads only."""
        from pazuzu_core.backup_plan import kind_of
        found = found if found is not None else self.interfaces()["interfaces"]
        zones = (self.status().get("zones") or {}).get("assignments") or {}
        taken = {(a or {}).get("device") for z, a in zones.items()
                 if (a or {}).get("device") and (a or {}).get("state") == "bound"}
        usb = self._recall("usb_backup")
        out = []
        for i in found:
            dev, ident = i["device"], str(i.get("identifier") or "").lower()
            if (not i.get("physical") or is_virtual_device(dev) or kind_of(dev) == "wifi" or ident in ("wan", "lan")
                    or dev in taken or dev == usb):
                continue
            out.append({"device": dev, "label": port_label(i), "assigned": bool(i.get("assigned")),
                        "link": _link_word(i.get("status"), dev, True)})
        return out

    def usb_backup_set(self, d, finish: bool = False) -> dict:
        """A USB network port (a phone's tethering, or an adapter to a second router) as the backup internet: the checklist's
        steps done here, with one passkey touch, each one takeable back. `finish` does only the last part again."""
        d = d if isinstance(d, dict) else {}
        device = str(d.get("device") or "")
        if not re.fullmatch(r"[a-z]{2,8}\d{1,3}", device):
            raise WizardError("Say which USB port (for example ue0).")
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        link = self._hotspot_link()
        session = self._installer_session()
        base = self.base_url.rstrip("/")
        probe = self._probe

        def work() -> dict:
            try:
                ub = wb.UsbBackup(we.Engine(session, base, probe), device, switch=link, trace_to=self._hotspot_trace_path(),
                                  **getattr(self, "_hotspot_timing", {}))
            except we.WriteError as exc:
                raise WizardError(str(exc))
            try:
                if finish:
                    plan = ub.finish_plan()
                    outs = ub.finish_apply(plan, lambda digest, lines: self.window_gate(digest, list(lines)))
                else:
                    plan = ub.plan()
                    outs = ub.apply(plan, lambda digest, lines: self.window_gate(digest, list(lines)))
            except we.WriteError as exc:
                raise WizardError(str(exc) + self._trace_note(ub))
            finally:
                ub.save_trace()
            if outs:
                self._last_write = (wb.Undoer(), outs)
                self._remember("usb_backup", device)
            return {"lines": list(ub.said), "can_undo": bool(outs)}

        return self._start("write-usb-backup", work)

    def _api_getter(self):
        """A GET through the firewall's API, with the installer key if there is
        one (it may read more pages), else the look-only key. None if neither.
        The installer account closes itself after a day: when the firewall refuses its key (401), that key is marked
        as no longer accepted and the read is tried again with the look-only key, so nothing goes quietly unread."""
        from pazuzu_core.enroll_safety import make_session
        pairs = []
        for role in (en.INSTALLER, en.READ):
            if role is en.INSTALLER and getattr(self, "_installer_dead", False):
                continue
            try:
                pair = en.parse_key(self._key_file(role).read_text(encoding="utf-8"))
            except OSError:
                pair = None
            if pair:
                pairs.append((role, pair))
        if not pairs:
            return None
        pin = load_pin(self.key_dir) if (self.base_url.startswith("https://")
                                         and self.verify is False) else None
        base = self.base_url.rstrip("/")
        sessions = []
        for role, pair in pairs:
            session = make_session(self.verify, pin)
            session.auth = pair
            sessions.append((role, session))

        def getter(path):
            # BUILD 436: one read per page per cycle. The board's readers each fetched interfaces_info (seven times a
            # cycle) and every Kea subnet twice; a cycle took ~35 s and the preview queued behind it.
            # Kept READ_CACHE_SECONDS, cleared when any job ends (a write may have changed what is read).
            cached = getattr(self, "_read_cache_get", None)          # a bare test double has no cache: read through
            hit = cached(path) if cached else _MISSING
            if hit is not _MISSING:
                return hit
            got = fetch(path)
            if cached:
                self._read_cache_put(path, got)
            return got

        def fetch(path):
            last = None
            for role, session in sessions:
                if role is en.INSTALLER and getattr(self, "_installer_dead", False):
                    continue
                r = session.get(base + path, timeout=8)
                if r.status_code == 401 and role is en.INSTALLER:
                    self._installer_dead = True            # closed itself; the look-only key carries on
                    last = r.status_code
                    continue
                if r.status_code in (401, 403):
                    raise PermissionError(f"{r.status_code}")
                if r.status_code == 404:
                    raise LookupError("this firewall version does not have that page")
                try:
                    return r.json()
                except ValueError:
                    raise ValueError(f"the firewall's answer was not understood (HTTP {r.status_code})")
            raise PermissionError(f"{last or 401}")
        return getter

    READ_CACHE_SECONDS = 20.0

    def _read_cache_get(self, path):
        cache = getattr(self, "_read_cache", None)
        if not cache:
            return _MISSING
        with self._read_cache_lock:
            hit = cache.get(path)
        if hit is None or time.monotonic() - hit[0] > self.READ_CACHE_SECONDS:
            return _MISSING
        return copy.deepcopy(hit[1])

    def _read_cache_put(self, path, value) -> None:
        if not hasattr(self, "_read_cache_lock"):
            self._read_cache_lock = threading.Lock()
        with self._read_cache_lock:
            cache = getattr(self, "_read_cache", None)
            if cache is None:
                cache = self._read_cache = {}
            if len(cache) > 400:
                cache.clear()
            cache[path] = (time.monotonic(), copy.deepcopy(value))

    def _read_cache_clear(self) -> None:
        cache = getattr(self, "_read_cache", None)
        if cache:
            with self._read_cache_lock:
                cache.clear()

    def _api_feed(self):
        from pazuzu_core.api_data import ApiFeed
        getter = self._api_getter()
        return ApiFeed(getter, dns_state=str(Path(self.key_dir) / "dns_hist.json")) if getter else None

    # -- the four service checks and the tests from this device
    def _network_devices(self) -> list[str]:
        zones = (self.status().get("zones") or {}).get("assignments") or {}
        return sorted({a.get("device") for z, a in zones.items()
                       if z not in ("wan", "wireguard_admin") and a.get("device")})

    AUTO_CHECK_EVERY = 60.0            # seconds between the app's own re-tests while a check step has not passed

    def auto_checks_start(self) -> bool:
        """The plan's two check steps (the LAN check and the firewall services) test themselves: once when nothing has
        been tested yet (a restart forgets the last answer), then again every minute while they have not passed, so a
        fix made on the firewall shows without a button. Only tests and reads; one run at a time, in the background.
        Nothing runs until the app is signed in to the firewall. True when a run is under way."""
        if self._api_getter() is None:
            return False
        with self._auto_lock:
            if self._auto_busy:
                return True
            state = self.services_state()
            if state["ok"] and state["lan_ok"]:
                return False
            due = self._auto_at is None or time.monotonic() - self._auto_at >= self.AUTO_CHECK_EVERY
            if not due and state["rows"]:
                return False
            self._auto_busy = True
        threading.Thread(target=self._auto_checks_work, daemon=True).start()
        return True

    def _auto_checks_work(self) -> None:
        try:
            state = self.services_state()
            if not state["ok"]:
                try:
                    self.services_test()
                except Exception:
                    pass                      # a failed read stays "not tested"; the next round tries again
            if not self.services_state()["lan_ok"]:
                try:
                    self.lan_test(["dns_firewall", "time_firewall"])
                except Exception:
                    pass
        finally:
            with self._auto_lock:
                self._auto_busy = False
                self._auto_at = time.monotonic()

    def services_test(self) -> dict:
        from pazuzu_core import service_checks as sc
        host, _p = base_host_port(self.base_url)
        getter = self._api_getter()
        self._svc_rows = sc.run(getter, self._network_devices(), host)
        keep = {r["id"] for r in self._svc_rows if r["status"] == "unknown"}
        self._svc_ack &= keep
        self._svc_skip &= {r["id"] for r in self._svc_rows if r["status"] != "good"}
        return self.services_state()

    def services_ack(self, ids) -> dict:
        rows = getattr(self, "_svc_rows", None)
        if not rows:
            raise WizardError("Run the checks first.")
        unknown = {r["id"] for r in rows if r["status"] == "unknown"}
        if not isinstance(ids, list) or not set(ids) <= unknown:
            raise WizardError("Only a check the app could not read can be confirmed by hand.")
        self._svc_ack = set(ids)
        return self.services_state()

    def _skip_log(self, kind: str, ids) -> None:
        """Every skip is written down, so it can be seen later who carried on past what."""
        try:
            path = Path(self.journal).with_name("skip_log.jsonl")
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({"at": time.strftime("%Y-%m-%dT%H:%M:%S"), "kind": kind,
                                     "ids": sorted(ids)}) + "\n")
        except OSError:
            pass

    def services_skip(self, ids) -> dict:
        """Carry on past a service check that did not pass. Only a check that was read and did
        not pass can be skipped; it stays marked as skipped and never counts as done."""
        rows = getattr(self, "_svc_rows", None)
        if not rows:
            raise WizardError("Run the checks first.")
        skippable = {r["id"] for r in rows if r["status"] == "attention"}
        if not isinstance(ids, list) or not set(ids) <= skippable:
            raise WizardError("Only a check that did not pass can be skipped.")
        new = set(ids) - self._svc_skip
        self._svc_skip = set(ids)
        if new:
            self._skip_log("service", new)
        return self.services_state()

    def lan_skip(self, ids) -> dict:
        names = {"dns_firewall", "time_firewall", "dns_outside", "web", "no_ipv6"}
        if not isinstance(ids, list) or not set(ids) <= names:
            raise WizardError("That test was not understood.")
        new = set(ids) - self._lan_skip
        self._lan_skip = set(ids)
        if new:
            self._skip_log("lan", new)
        return self.services_state()

    def services_state(self) -> dict:
        from pazuzu_core import service_checks as sc
        rows = getattr(self, "_svc_rows", None)
        ok = bool(rows) and sc.passed(rows, self._svc_ack, self._svc_skip)
        need = ("dns_firewall", "time_firewall")
        lan_ok = all(self._lan_seen.get(i) == "good" or (i in self._lan_skip and i in self._lan_seen)
                     for i in need)
        svc_skipped = bool(rows) and any(r["id"] in self._svc_skip and r["status"] != "good" for r in rows)
        lan_skipped = any(self._lan_seen.get(i) != "good" and i in self._lan_skip for i in need)
        return {"rows": rows, "acked": sorted(self._svc_ack), "skipped": sorted(self._svc_skip),
                "lan_skipped_ids": sorted(self._lan_skip),
                "ok": ok, "lan_ok": lan_ok,
                "handled": {"lan_check": lan_ok, "firewall_services": ok},
                "carried_on": {"lan_check": lan_ok and lan_skipped,
                               "firewall_services": ok and svc_skipped}}

    CONFIRMABLE = ("admin_session", "ntp_service", "ntp_dhcp_option", "dns_bypass", "client_ntp", "quic", "otp", "console")   # the last three: only while a rule cannot be judged (console marks confirmed only for "can't check")

    def confirmed_controls(self) -> list[str]:
        """Controls the firewall cannot be asked about that the person has said are done. The two time controls also
        count once the plan's firewall-services step was handled."""
        ids = {i for i in (self._recall("confirmed_controls") or []) if i in self.CONFIRMABLE}
        try:
            if self.services_state()["handled"]["firewall_services"]:
                ids |= {"ntp_service", "ntp_dhcp_option"}
        except Exception:
            pass
        return sorted(ids)

    def control_confirm(self, d) -> dict:
        d = d if isinstance(d, dict) else {}
        cid = str(d.get("id") or "")
        if cid not in self.CONFIRMABLE:
            raise WizardError("That control cannot be confirmed by hand.")
        now = {i for i in (self._recall("confirmed_controls") or []) if i in self.CONFIRMABLE}
        (now.add if d.get("on") is not False else now.discard)(cid)
        self._remember("confirmed_controls", sorted(now))
        acts = getattr(self, "_acts", None)
        if acts is not None and getattr(acts, "source", None) is not None:
            acts.source.forget()
        return {"confirmed": self.confirmed_controls()}

    def lan_test(self, only=None) -> dict:
        from pazuzu_core import lan_tests as lt
        host, _p = base_host_port(self.base_url)
        names = {"dns_firewall", "time_firewall", "dns_outside", "web", "no_ipv6"}
        if only is not None and (not isinstance(only, list) or not set(only) <= names):
            raise WizardError("That test was not understood.")
        if self._lan_fn:
            rows = self._lan_fn(host, only=tuple(only) if only else None)
        else:
            rows = lt.run(host, only=tuple(only) if only else None, lenient=bool(self.light))
        for r in rows:
            self._lan_seen[r["id"]] = r["status"]
        state = self.services_state()
        return {"rows": rows, "lan_ok": state["lan_ok"], "carried_on": state["carried_on"],
                "lan_skipped_ids": state["lan_skipped_ids"]}

    # -- plugins, through the installer account
    def _sync_accounts(self) -> list[str]:
        """Right after the installer account is made (it may change users): give pazuzu-read and pazuzu-write the pages
        the board and Finish getting to Happy use, so the morning the installer closes the board still reads them
        (13 of 15 enforced at night, 7 the next morning, every service page refused). Asked under
        the same two-minute passkey window as the installer. Best effort: a refusal leaves the accounts as they were."""
        lines = ["Give pazuzu-read and pazuzu-write the pages for DNS, VPN, DHCP, scheduled jobs, packet inspection "
                 "and source NAT", "Read: " + ", ".join(en.SERVICE_PERMISSIONS),
                 "pazuzu-read stays look-only (the firewall refuses its changes)"]
        try:
            if not self.window_gate(hashlib.sha256("\n".join(lines).encode()).hexdigest(), lines):
                print("the accounts' pages were left as they were (not approved)")
                return []
            got = en.sync_permissions(self._installer_session(), self.base_url)
        except Exception as exc:      # never in the way of the installer account itself
            got = [f"the accounts' pages were not brought up to date ({_plain(exc)})"]
        for line in got:
            print(line)
        return got

    def _installer_session(self):
        """The session for a change. The installer while it is open. Once it has closed itself (401), the change account
        (pazuzu-write) carries on: its pages cover what Finish getting to Happy changes (0.6.42). Plugin installs still
        need the installer's every-page access; with the change account the firewall refuses them and the page says so."""
        if getattr(self, "_installer_dead", False) and self._key_file(en.WRITE).exists():
            return self._role_session(en.WRITE, "Make the installer account first.")
        return self._role_session(en.INSTALLER, "Make the installer account first.")

    def _uses_words(self) -> str:
        """The approval's last line: which account the change goes through."""
        if getattr(self, "_installer_dead", False) and self._key_file(en.WRITE).exists():
            return "It uses the change account (pazuzu-write); the installer account has closed itself"
        return "It uses the installer account, which can open every page"

    def _role_session(self, role, missing: str):
        if getattr(self, "_session_fn", None):
            return self._session_fn()
        from pazuzu_core.enroll_safety import make_session
        path = self._key_file(role)
        try:
            pair = en.parse_key(path.read_text(encoding="utf-8"))
        except OSError:
            pair = None
        if pair is None:
            raise WizardError(missing)
        pin = load_pin(self.key_dir) if (self.base_url.startswith("https://")
                                         and self.verify is False) else None
        session = make_session(self.verify, pin)
        session.auth = pair
        if role is en.INSTALLER:
            session.hooks["response"].append(self._installer_seen)
        return session

    INSTALLER_CHECK_EVERY = 120.0

    def _check_installer(self) -> None:
        """Ask the firewall, at most every two minutes, whether it still takes the installer's key. Until something read
        with it, a key the firewall had closed overnight still counted as an account, so the setup page walked past
        "make it again". One small read; a 401 marks it closed (_installer_seen)."""
        import time as _t
        if getattr(self, "_session_fn", None) or not self._key_file(en.INSTALLER).exists():
            return
        now = _t.monotonic()
        if now - getattr(self, "_installer_checked", -1e9) < self.INSTALLER_CHECK_EVERY:
            return
        self._installer_checked = now
        try:
            self._role_session(en.INSTALLER, "").get(self.base_url.rstrip("/") + "/api/core/firmware/status", timeout=4)
        except Exception:
            pass
        threading.Thread(target=self._telemetry_tick, daemon=True).start()     # weekly reports, off the page's thread

    def _telemetry_tick(self) -> None:
        self.telemetry_weekly()
        self.telemetry_devices()

    def _installer_seen(self, resp, *args, **kwargs):
        """The firewall answers 401 to a key it does not accept (an account that has closed itself, or a deleted one).
        Remember that, so the page asks for the account to be made again instead of failing step after step."""
        code = getattr(resp, "status_code", 0)
        if code == 401:
            self._installer_dead = True
        elif code == 200:
            self._installer_dead = False
        return resp

    def _usb_ports(self) -> list:
        """The firewall's USB network adapters (ue0, ue1...), read only; empty when none or when it could not be read."""
        import re
        scan = self._scan
        if scan is None:
            if self._inventory_loader is not None or self._read_fn is not None:
                return []
            from pazuzu_core.opnsense_scanner import scan_interfaces as scan
        try:
            with self._env(en.READ):
                report = scan()
        except Exception:
            return []
        return sorted({str(i.get("device")) for i in report.get("interfaces") or []
                       if isinstance(i, dict) and not i.get("system") and re.fullmatch(r"ue\d+", str(i.get("device") or ""))})

    def plugins(self) -> dict:
        from pazuzu_core import plugin_install as pi
        session = self._installer_session()
        usb = self._usb_ports()
        try:
            return {"plugins": pi.list_plugins(session, self.base_url.rstrip("/")), "usb_ports": usb}
        except pi.PluginError as exc:
            # The package list is large and some firewalls (a live CD) cut it off. Say so, and still
            # offer the two installs: the firewall itself decides whether it has them.
            # BUILD 527 (the maintainer, dev, 12 Nov 2026: Zenarmor's card said "Installed" with its log, then "Could not read the
            # firewall's package list ... you can still press Install" and an Install button): right after a large
            # install the firewall is too busy to list its packages. What this run just installed is said as installed.
            mine = sorted(getattr(self, "_installed_now", set()))
            return {"plugins": [{"name": n, "installed": True, "locked": False} for n in mine], "unread": str(exc),
                    "usb_ports": usb, "just_installed": mine}
        except Exception as exc:
            raise WizardError(f"Could not read the plugin list: {_plain_firewall(exc)}")

    def plugin_install(self, name) -> dict:
        from pazuzu_core import plugin_install as pi
        from pazuzu_core.passkey_gate import plan_digest
        chain = pi.ZENARMOR_CHAIN if name == "zenarmor" else None
        if chain is None and (not isinstance(name, str) or not pi._allowed(name)):
            raise WizardError("That plugin is not on the list Pazuzu can install.")
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        session = self._installer_session()

        def work() -> dict:
            what = ("Install Zenarmor on your firewall" if chain
                    else f"Install the plugin {name} on your firewall")
            lines = [what]
            if chain:
                lines.append("First the vendor's package source (os-sunnyvalley), then Zenarmor (os-sensei)")
                usb = self._usb_ports()
                if usb:
                    lines.append(USB_WARNING.format(ports=", ".join(usb)))
            lines.append(self._uses_words())
            if not self.window_gate(plan_digest("install-plugin", {"plugin": name}), lines):
                raise WizardError("Not approved with a passkey; nothing was installed.")
            try:
                if chain:
                    pi.install_chain(session, self.base_url.rstrip("/"), chain)
                else:
                    pi.install(session, self.base_url.rstrip("/"), name)
            except pi.PluginError as exc:
                # BUILD 519 (the maintainer, live disc, 12 Nov 2026: Zenarmor's install "reported a problem"; "sharpen the error
                # message for live cd"): a live disc runs from memory, with little room and nothing kept, and a large
                # add-on like Zenarmor does not fit there. Said as that, not as a fault to chase in a log.
                live = (" This firewall is running from a live disc, which has little room and keeps nothing: a large "
                        "add-on like this one is for a firewall installed to disk. Install OPNsense to disk, run this "
                        "setup again, and install it then. Nothing else in the setup depends on it."
                        if self.trial else "")
                raise WizardError(str(exc) + live)
            except Exception as exc:
                raise WizardError(f"The install stopped: {_plain_firewall(exc)}")
            # BUILD 527: kept for this run, so the card still says Installed while the firewall is too busy to list packages
            self._installed_now = set(getattr(self, "_installed_now", set())) | set(chain or (name,))
            return {"installed": name}

        return self._start("plugin-install", work)

    def firmware_update(self) -> dict:
        """Run the firewall's own update (minor versions only) and follow it. A restart, if one is asked for, is a
        separate button (firmware_reboot): nothing here restarts the firewall."""
        from pazuzu_core import plugin_install as pi
        from pazuzu_core.passkey_gate import plan_digest
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        session = self._installer_session()
        base = self.base_url.rstrip("/")

        def work() -> dict:
            lines = ["Update the firewall's software to the newest version it offers",
                     "It does not restart the firewall; if one is needed, that is a separate button",
                     self._uses_words()]
            if not self.window_gate(plan_digest("firmware-update", {}), lines):
                raise WizardError("Not approved with a passkey; nothing was updated.")
            was = str(getattr(self, "_fw_version", "") or "")
            try:
                got = pi.update(session, base)
            except pi.PluginError as exc:
                got = self._update_landed(was)
                if got is None:
                    raise WizardError(str(exc))
            except Exception as exc:
                got = self._update_landed(was)
                if got is None:
                    raise WizardError(f"The update stopped: {_plain_firewall(exc)}")
            self._firmware_updated = True          # from now on a "needs a restart" from the firewall is about this update
            return got

        return self._start("firmware-update", work)

    UPDATE_LANDED_POLLS = 60          # times the version is read after an update that lost its own report
    UPDATE_LANDED_WAIT = 5.0          # seconds between them (five minutes in all: a restart takes a couple)

    def _update_landed(self, was: str, sleep=time.sleep) -> dict | None:
        """BUILD 522 (the maintainer, an installed 26.7 updating to 26.7.9, 12 Nov 2026: "The update did not finish. The
        firewall's own Firmware page has the log", with the page already showing version 26.7.9). An update with a new
        kernel restarts the firewall by itself. The sign-in the update was followed with does not outlive the restart,
        so the report was lost and the update was called unfinished. What counts is the version the firewall is on once
        it answers again, read with Pazuzu's own look-only key, which does outlive a restart. None when it is still on
        the version it was on (or cannot be read): the update's own refusal then stands."""
        for _ in range(self.UPDATE_LANDED_POLLS):
            try:
                st = self.firmware_state()
            except Exception:  # noqa: BLE001 - not answering yet: it may be restarting
                st = None
            now = str((st or {}).get("version") or "")
            if now and was and now != was:
                return {"reboot": bool((st or {}).get("needs_reboot")), "version": now,
                        "lines": [f"The firewall restarted by itself to finish the update. It is now on version {now}."]}
            if now and not (st or {}).get("offline") and was and now == was and (st or {}).get("state") == "update":
                return None                      # answering, same version, the update still waiting: it did not land
            sleep(self.UPDATE_LANDED_WAIT)
        return None

    def firmware_check(self) -> dict:
        """Ask the firewall to look for updates (what Check for updates does on its own Firmware page). Without this its
        answer to "is there a newer version" is whatever it found last, which on a fresh firewall is nothing."""
        from pazuzu_core import plugin_install as pi
        session = self._installer_session()
        base = self.base_url.rstrip("/")

        def work() -> dict:
            try:
                pi.refresh(session, base, wait=300)
            except pi.PluginError:
                return {"checked": False, "lines": ["The firewall could not check for updates. It may have no internet "
                                                    "right now."]}
            except Exception as exc:
                raise WizardError(f"The check stopped: {_plain_firewall(exc)}")
            return {"checked": True, "lines": ["The firewall looked for updates."]}

        return self._start("firmware-check", work)

    def firmware_reboot(self) -> dict:
        """Restart the firewall, on the person's own button. It is off for a minute or two."""
        from pazuzu_core import plugin_install as pi
        from pazuzu_core.passkey_gate import plan_digest
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        session = self._installer_session()
        base = self.base_url.rstrip("/")

        def work() -> dict:
            if not self.window_gate(plan_digest("firmware-reboot", {}),
                                    ["Restart the firewall now", "It is off for a minute or two, and every connection through it drops"]):
                raise WizardError("Not approved with a passkey; nothing was restarted.")
            try:
                pi.reboot(session, base)
            except pi.PluginError as exc:
                raise WizardError(str(exc))
            except Exception as exc:
                raise WizardError(f"The restart did not start: {_plain_firewall(exc)}")
            return {"restarting": True}

        return self._start("firmware-reboot", work)

    # -- what this firewall supports (reads only), and the guarded additions that depend on it
    def writes_state(self) -> dict:
        rep = self._probe
        return {"checked": bool(rep), "version": (rep or {}).get("version"),
                "account": (rep or {}).get("account"), "role": (rep or {}).get("role"), "caps": we.readiness(rep),
                "can_undo": bool(self._last_write)}

    def auto_check(self, force: bool = False) -> bool:
        """The manager never shows the setup page, so nothing there would ever run the firewall check, and every
        control that depends on it stayed greyed. Run it here, by itself, when it has not been run (or when asked
        again). True while it is running or was just started; reads only."""
        if force:
            self._probe = None
        if self._probe is not None:
            return False
        if self._job and self._job.get("kind") == "probe" and self._job.get("state") == "running":
            return True
        if not (self._key_file(en.INSTALLER).exists() or self._key_file(en.READ).exists()):
            return False
        last = getattr(self, "_auto_check_at", None)
        if not force and last is not None and self._now() - last < 30:
            return False                     # it was tried a moment ago and did not finish; do not hammer the firewall
        self._auto_check_at = self._now()
        try:
            self.probe_run()
        except Exception:
            return False
        return True

    def probe_run(self) -> dict:
        role = en.INSTALLER if self._key_file(en.INSTALLER).exists() else en.READ
        session = self._role_session(role, "Sign in first.")
        return self._start("probe", lambda: self._look(session, role))

    def _look(self, session, role) -> dict:
        """Read what this firewall supports (reads only) and keep the answer."""
        from pazuzu_core import probe, probe_cli
        report = probe.run_probe(probe_cli.session_fetch(session, self.base_url))
        report["account"] = role.name
        report["role"] = "installer" if role is en.INSTALLER else "read"
        self._probe = report
        try:
            out = Path("scan_results")
            out.mkdir(parents=True, exist_ok=True)
            name = "probe_" + str(report.get("version") or "unknown").replace("/", "_") + (
                "_installer" if role is en.INSTALLER else "") + ".json"
            (out / name).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        except OSError:
            pass
        got = [r for r in report["results"] if r["kind"] == "answered"]
        lines = [f"{len(got)} of {len(report['results'])} pages answered. Nothing was changed."]
        if role is en.INSTALLER:
            lines += self._check_remembered_admin(session, report)
        return {"lines": lines}

    def _write_job(self, kind: str, make_plans, extra: dict | None = None, after=None, notes=None,
                   nothing=None) -> dict:
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        if self._probe is None:
            raise WizardError("Check what this firewall supports first. It only reads.")
        session = self._installer_session()
        base = self.base_url.rstrip("/")
        report = self._probe

        def work() -> dict:
            engine = we.Engine(session, base, report)

            def gate(digest, lines):
                return self.window_gate(digest, list(lines) + [self._uses_words()])
            try:
                plans = make_plans(engine)
                outs = engine.apply_many(plans, gate) if (plans or not nothing) else []
            except we.WriteError as exc:
                raise WizardError(str(exc))
            if outs:
                self._last_write = (engine, outs)
            lines = [ln for o in outs for ln in o.lines]
            info = False
            if not plans and nothing:
                lines, info = list(nothing(engine)), True            # nothing to add: a plain note, not a failure
            if notes:
                try:
                    lines += [ln for ln in notes(engine) if ln]      # things the firewall still needs, said plainly
                except Exception:
                    pass
            result = {"lines": lines, "can_undo": any(o.undo_path for o in outs), "info": info, **(extra or {})}
            if after:
                after(result)
            return result

        return self._start(kind, work)

    def _note_zone_wifi(self, made) -> None:
        """BUILD 525 (the maintainer, 12 Nov 2026: "wifi info if set up on access card"): the Wi-Fi names this setup made, by zone,
        and where each lives (the firewall's own card or the access point), kept for the access card. Names only: no
        password is kept."""
        try:
            had = self._recall("zone_wifi")
            had = dict(had) if isinstance(had, dict) else {}
            for z, w in (made or {}).items():
                if isinstance(z, str) and z and isinstance(w, dict) and str(w.get("ssid") or "").strip():
                    had[z] = {"ssid": str(w["ssid"]).strip()[:32], "where": "ap" if w.get("where") == "ap" else "firewall"}
            if had:
                self._remember("zone_wifi", had)
        except Exception:
            pass

    def _remember(self, key: str, value) -> None:
        from pazuzu_core import choices_file          # one lock and an atomic write for the shared file (10 Nov 2026)
        try:
            choices_file.update(self.key_dir, lambda data: data.__setitem__(key, value))
        except OSError:
            pass

    def _forget(self, key: str) -> None:
        from pazuzu_core import choices_file
        if key not in choices_file.read(self.key_dir):
            return
        try:
            choices_file.update(self.key_dir, lambda data: data.pop(key, None))
        except OSError:
            pass

    def _check_remembered_admin(self, session, report) -> list[str]:
        """Reads only. The wizard remembers that it made an admin user and switched root off; the firewall may have been
        changed since (put back from a backup, users edited by hand). Where the firewall's own user list shows that
        is no longer true, forget it, so no page claims it. Where the list cannot be read, nothing is touched."""
        keep = self._recall("admin_user")
        if not (keep or self._recall("root_off")):
            return []
        try:
            rows = we.Engine(session, self.base_url.rstrip("/"), report)._rows(we.CAPS["user"])
        except Exception:                                   # noqa: BLE001 (any trouble reading: say nothing, change nothing)
            return []
        users = {str(r.get("name")): r for r in rows if isinstance(r, dict)}
        if "root" not in users:
            return []
        said = []
        if keep and (keep not in users or str(users[keep].get("disabled", "0")) in ("1", "true")):
            for key in ("admin_user", "root_off", "root_pw"):
                self._forget(key)
            return [f"The firewall has no switched-on user called {keep} any more, so the wizard no longer says it made one."]
        if self._recall("root_off") and str(users["root"].get("disabled", "0")) not in ("1", "true"):
            self._forget("root_off")
            said.append("Root can sign in on the firewall again, so the wizard no longer says it is off.")
        return said

    # BUILD 483 (the maintainer, 5 Nov 2026: "we had the wizard auto updating the plugin, where did it go"): box_link is kept. The
    # plugin and its code live in /root and outlive a reset to factory, so after one the link still answers, and the
    # plugin step sends a newer plugin by itself again instead of asking for the line. Forgetting it here was what
    # stopped that on the lab box, reset after every run. A different box at the same address refuses its code.
    FIREWALL_CHOICES = ("admin_user", "root_off", "root_pw", "vpn_instance", "vpn_host", "wifi_backdoor",
                        "host_choice", "ddns_name", "shield_types", "zones_later", "wifi_backup")

    def _forget_firewall_choices(self) -> None:
        """What was done to an older firewall (its admin, root switched off, its VPN) is not true of a new one."""
        from pazuzu_core import choices_file

        def drop(data: dict) -> None:
            for k in [k for k in data if k in self.FIREWALL_CHOICES or k.startswith(("country", "blocklist", "resolver"))]:
                data.pop(k)
        if not choices_file.read(self.key_dir):
            return
        try:
            choices_file.update(self.key_dir, drop)
        except OSError:
            pass

    def _recall(self, key: str):
        from pazuzu_core import choices_file
        return choices_file.read(self.key_dir).get(key)

    def write_admin(self, d) -> dict:
        if not isinstance(d, dict):
            raise WizardError("Give a user name and a password.")
        values = {"name": str(d.get("name") or "").strip(), "password": d.get("password"),
                  "group_memberships": "admins", "descr": "Made by Pazuzu"}
        seed = d.get("otp_seed")
        if isinstance(seed, str) and seed.strip():
            values["otp_seed"] = seed.strip().upper()
        if not isinstance(values["password"], str):
            raise WizardError("Type a password for the new user.")

        def plans(e):
            # A login shell, so this user can sign in at the console too (root is the only one that can otherwise, and
            # root goes off later). Taken from the firewall's own list.
            vals = dict(values)
            offered = we._option_labels(e._template(we.CAPS["user"])[1].get("shell")) or {}
            pick = next((s for s in self._REAL_SHELLS if s in offered), None)
            if pick:
                vals["shell"] = pick
            return [e.build("user", vals)]
        return self._write_job("write-user", plans,
                               after=lambda r: self._remember("admin_user", values["name"]))

    def admin_forget(self) -> dict:
        """Forget the admin user Pazuzu remembers, to make and test another. Nothing on the firewall changes (the user
        stays there), and the console proof goes with it."""
        self._remember("admin_user", "")
        now = [i for i in (self._recall("confirmed_controls") or []) if i != "console"]
        self._remember("confirmed_controls", now)
        return {"admin_user": ""}

    def adopt_admin(self, d) -> dict:
        """The user is already on the firewall (an earlier try made it). Check it is there and remember it as
        the admin. Reads only; nothing is changed on the firewall."""
        d = d if isinstance(d, dict) else {}
        name = str(d.get("name") or "").strip()
        if not re.match(r"^[a-z][a-z0-9_.-]{0,31}$", name) or name == "root" or name.startswith("pazuzu-"):
            raise WizardError("Type the user name you made.")
        if self._probe is None:
            raise WizardError("Check what this firewall supports first. It only reads.")
        engine = we.Engine(self._installer_session(), self.base_url.rstrip("/"), self._probe)
        try:
            there = engine.exists("user", name)
        except we.WriteError as exc:
            raise WizardError(str(exc))
        if not there:
            raise WizardError(f"The firewall has no user called {name}. Nothing was changed.")
        self._remember("admin_user", name)
        return {"admin_user": name}

    def write_root_off(self, d) -> dict:
        """Switch root's own sign-in off, after the person has proved the new admin works. Always asks."""
        d = d if isinstance(d, dict) else {}
        keep = str(d.get("keep") or "").strip()
        if self.phone:
            # BUILD 477: on a Hanbi set up from the app there is no second window and no keyboard console. The box
            # vouches instead: the admin has a login shell and admins may use sudo (both read, not ticked), and the
            # web page already asks for the one-time code (read back at the step before).
            facts = self.console_facts()
            if not facts.get("ok"):
                raise WizardError("Not yet: " + ("your admin has no login shell" if not facts.get("real")
                                                 else "admins may not use sudo on this firewall")
                                  + ". The buttons above fix it; then root can go off. Nothing was changed.")
        else:
            if d.get("proved") is not True:
                raise WizardError("Sign in from a second window with the new user first, then tick the box.")
            if d.get("console") is not True and "console" not in self.confirmed_controls():
                raise WizardError("Sign in at the firewall's console with the new user first (then sudo opnsense-shell for "
                                  "the menu), and tick that box too. Root is the only way in at the console until then.")
        self.control_confirm({"id": "console", "on": True})
        if not keep:
            raise WizardError("Type the name of the new admin user who stays on.")
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        if self._probe is None:
            raise WizardError("Check what this firewall supports first. It only reads.")
        session = self._installer_session()
        base = self.base_url.rstrip("/")
        report = self._probe

        def work() -> dict:
            engine = we.Engine(session, base, report)
            try:
                out = engine.disable_root(keep, lambda digest, lines: self.gate(
                    digest, list(lines) + [self._uses_words()]))
            except we.WriteError as exc:
                raise WizardError(str(exc))
            self._last_write = (engine, [out])
            if out.saved:
                self._remember("root_off", True)
            return {"lines": out.lines, "can_undo": True}

        return self._start("write-root-off", work)

    def admin_finish(self, d) -> dict:
        """BUILD 480, the app on a Hanbi: your own admin, all of it in one go, once the code from the box's screen matched.
        On a PC this is eight steps with a second window and the firewall's console; a phone has neither, so the box
        does each step and checks it:
          1. the user, in the admins group, with its password, its code seed and a login shell (skipped when it is there);
          2. the login server for codes (Pazuzu OTP), through the plugin;
          3. the proof: the firewall's own login code lets this user in with the password followed by the current code
             (the plugin asks it, like the Tester page). Nothing after this happens unless it says yes;
          4. the web page signs in with the code from now on (the plugin's switch, kept straight away: step 3 proved it);
          5. admins may use sudo, so your admin can open the console menu;
          6. root off.
        The password is used for steps 1 and 3 and is not kept."""
        if not self.phone:
            raise WizardError("This is for the app on a Hanbi. On a computer the Admin step walks through it.")
        d = d if isinstance(d, dict) else {}
        name = str(d.get("name") or "").strip()
        password, seed = d.get("password"), str(d.get("seed") or "").strip().upper()
        if not re.match(r"^[a-z][a-z0-9_.-]{0,31}$", name) or name == "root" or name.startswith("pazuzu-"):
            raise WizardError("Choose a user name: lower-case letters and digits, not root.")
        if not isinstance(password, str) or len(password) < 12:
            raise WizardError("Choose a password of at least 12 characters.")
        if len(password) > 128:
            raise WizardError("Choose a password of at most 128 characters.")
        try:
            if not otp_codes.check(seed, d.get("code")):
                raise WizardError("That code does not match. Wait for the next one and type it again.")
        except otp_codes.OtpError as exc:
            raise WizardError(str(exc))
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        if self._probe is None:
            raise WizardError("Check what this firewall supports first. It only reads.")
        if not self._box_up():
            raise WizardError("The plugin is not answering just now. Try again in a moment.")
        box = self._acts.source.box
        for word, need in (("otp_server", "0.6.40"), ("otp_switch", "0.6.40"), ("sudo_set", "0.6.72"), ("otp_test", "0.6.78")):
            if not box.can(word):
                raise WizardError("The plugin on your Hanbi is older than this needs. Update it from the app, then try again.")
        session = self._installer_session()
        base = self.base_url.rstrip("/")
        report = self._probe

        def work() -> dict:
            engine = we.Engine(session, base, report)
            done: list[str] = []

            def note(text: str) -> None:
                done.append(text)
                print(text)                                   # the job's own lines, for the busy card

            def stop(why: str):
                raise WizardError(why + (" Done so far: " + " ".join(done) if done else " Nothing was changed."))

            def gate(digest, lines):
                return self.gate(digest, list(lines) + [self._uses_words()])
            try:
                # 1. the user
                if not engine.exists("user", name):
                    vals = {"name": name, "password": password, "group_memberships": "admins", "descr": "Made by Pazuzu",
                            "otp_seed": seed}
                    offered = we._option_labels(engine._template(we.CAPS["user"])[1].get("shell")) or {}
                    pick = next((x for x in self._REAL_SHELLS if x in offered), None)
                    if pick:
                        vals["shell"] = pick
                    engine.apply_many([engine.build("user", vals)], gate)
                    note(f"Made {name}, in the admins group, with its code.")
                else:
                    note(f"{name} is already on the firewall.")
                self._remember("admin_user", name)
            except we.WriteError as exc:
                stop("The user could not be made: " + str(exc))
            # 2. the login server for codes
            try:
                got = box.otp_server("add")
            except Exception as exc:  # noqa: BLE001
                stop("The plugin did not answer about the login server: " + _plain_firewall(exc) + ".")
            if not got.get("ok"):
                stop(str(got.get("error") or "The plugin did not add the login server."))
            note("The login server for codes is there.")
            # 3. the proof, before anything depends on it (a code at a step boundary gets one more try with the next)
            said = None
            for attempt in range(2):
                said = self._box_post("/otp_test", {"user": name, "password": password + otp_codes.code_at(seed, time.time())},
                                      timeout=40)
                if not isinstance(said, dict) or not said.get("ok") or said.get("authenticated") or attempt:
                    break
                self._sleep(31.0 - (time.time() % 30.0))
            if not isinstance(said, dict) or not said.get("ok"):
                stop("The firewall could not check the sign-in" + (": " + str(said.get("error")) if isinstance(said, dict)
                                                                   and said.get("error") else ".") +
                     " The web page still signs in as before.")
            if not said.get("authenticated"):
                stop(f"The firewall did not let {name} in with that password and code, so the web page still signs in as "
                     "before. If the user was made on an earlier try with another password, choose another user name.")
            note("The firewall let your admin in with the password and the code.")
            # 4. the web page asks for the code from now on. A switch still on its 5-minute timer (an earlier try whose
            # answer was lost) is kept, not skipped: skipped, the timer would put the old sign-in back by itself.
            def switch(action, user=None) -> dict:
                try:
                    return box.otp_switch(action, user)
                except Exception as exc:  # noqa: BLE001
                    return {"ok": False, "error": "The plugin did not answer: " + _plain_firewall(exc)}

            def switch_state() -> str:
                try:
                    return str((box.otp_switch_status() or {}).get("state") or "idle")
                except Exception:  # noqa: BLE001
                    return "idle"
            in_use = bool((box.otp_server_status() or {}).get("in_use"))
            state = switch_state()
            if not in_use or state == "waiting":
                if state != "waiting":
                    got = switch("on", name)
                    if not got.get("ok") and switch_state() != "waiting":     # a slow answer can still have switched it
                        stop(str(got.get("error") or "The plugin did not switch the web page's sign-in."))
                got = switch("keep")
                if not got.get("ok") and switch_state() != "kept":
                    switch("undo")
                    stop(str(got.get("error") or "The plugin did not keep the switch, so it was put back."))
            note("The web page asks for the password followed by the code.")
            # 5. the console: a login shell (given when the user was made) and sudo for admins
            facts = self.console_facts()
            if facts.get("known") and not facts.get("real"):
                try:
                    form = engine._template(we.CAPS["user"])[1]
                    offered = we._option_labels(form.get("shell")) or {}
                    pick = next((x for x in self._REAL_SHELLS if x in offered), None)
                    if pick:
                        engine.change_text("user", name, "shell", pick, gate, say=f"Let {name} sign in at the console ({pick})")
                except we.WriteError as exc:
                    stop("Your admin could not be given a login shell: " + str(exc))
            if facts.get("sudo") is not True:
                got = self._box_post("/sudo_set", {"action": "allow"}, timeout=90)
                if not isinstance(got, dict) or not got.get("ok"):
                    stop(str((got or {}).get("error") if isinstance(got, dict) else "") or "The plugin did not let admins use sudo.")
            self._read_cache_clear()                          # read what was just written, not the cache from before
            facts = self.console_facts()
            if not facts.get("ok"):
                stop("The box could not confirm that your admin can sign in at its console (login shell and sudo), so root "
                     "stays on.")
            note("Your admin can open the console menu (sudo).")
            # 6. root off
            self.control_confirm({"id": "console", "on": True})
            try:
                out = engine.disable_root(name, gate)
            except we.WriteError as exc:
                stop("Root could not be switched off: " + str(exc))
            self._last_write = (engine, [out])
            if out.saved:
                self._remember("root_off", True)
            note("Root is off.")
            return {"lines": done, "can_undo": False}

        return self._start("write-admin-finish", work)

    def write_root_password(self, d) -> dict:
        """Give root a new password: the other way to stop the factory one working, for a person who wants root kept.
        Always asks. The password is held only for this call and is never saved or shown."""
        d = d if isinstance(d, dict) else {}
        new = d.get("password")
        if not isinstance(new, str) or len(new) < 12:
            raise WizardError("Type a new password of at least 12 characters.")
        if d.get("again") != new:
            raise WizardError("The two passwords are not the same. Type it again.")
        if new.lower() in ("opnsense", "password", "root"):
            raise WizardError("That is a password anyone tries first. Choose another.")
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        if self._probe is None:
            raise WizardError("Check what this firewall supports first. It only reads.")
        session = self._installer_session()
        base = self.base_url.rstrip("/")
        report = self._probe

        def work() -> dict:
            engine = we.Engine(session, base, report)
            try:
                out = engine.set_root_password(new, lambda digest, lines: self.gate(
                    digest, list(lines) + [self._uses_words()]))
            except we.WriteError as exc:
                raise WizardError(str(exc))
            if out.saved:
                self._remember("root_pw", True)
            return {"lines": out.lines, "can_undo": False}

        return self._start("write-root-password", work)

    def write_vpn_instance(self, d) -> dict:
        d = d if isinstance(d, dict) else {}
        try:
            private, public = vpn_peer.new_keypair()
        except Exception:
            raise WizardError("This device cannot make VPN keys. Install the cryptography package.")
        try:                                   # the firewall takes no spaces in a name: "home vpn" becomes "home-vpn" (BUILD 435)
            name = vpn_peer.device_name(d.get("name") or "home")
        except ValueError as exc:
            raise WizardError(str(exc))
        values = {"name": name, "port": str(d.get("port") or "51820").strip(),
                  "tunneladdress": str(d.get("tunneladdress") or "10.91.5.1/24").strip(),
                  "pubkey": public, "privkey": private, "enabled": "1"}

        def plans(e):
            return [e.build("wg_general", {"enabled": True}), e.build("wg_server", values)]
        info = {"public_key": public, "tunneladdress": values["tunneladdress"], "port": values["port"]}
        return self._write_job("write-vpn", plans, info,
                               after=lambda r: self._remember("vpn_instance", {
                                   "public_key": public, "tunneladdress": values["tunneladdress"],
                                   "port": values["port"]}))

    # -- how devices find home: a name of their own, a free changing-address name, or the current address
    def ddns_state(self) -> dict:
        from pazuzu_core import ddns_setup as dd
        caps = we.readiness(self._probe)
        ready = bool(caps["ddns_general"]["ready"] and caps["ddns_account"]["ready"])
        out = {"choice": self._recall("host_choice") or "", "host": self._recall("vpn_host") or "",
               "providers": dd.public_providers(), "checked": bool(self._probe),
               "plugin_there": ready, "can_write": ready,
               "why": next((caps[c]["why"] for c in ("ddns_general", "ddns_account") if not caps[c]["ready"]), ""),
               "existing": [], "ddns_name": self._recall("ddns_name") or ""}
        getter = self._api_getter() if self._probe else None   # BUILD 461: read even when writing is not ready (a
        if getter is not None:                                   # closed installer: the look-only key still reads)
            try:
                rows = getter("/api/dyndns/accounts/search_item").get("rows") or []
                out["existing"] = [str(r.get("hostnames") or "") for r in rows
                                   if isinstance(r, dict) and r.get("hostnames")]
                # BUILD 453: what is on the firewall, as its own Dynamic DNS page shows it (no username, no password)
                out["accounts"] = [{"service": str(r.get("service") or ""), "names": dd.shown_name(r.get("hostnames")),
                                    "on": str(r.get("enabled") or "") in ("1", "True", "true"),
                                    "address": str(r.get("current_ip") or ""), "updated": str(r.get("current_mtime") or ""),
                                    "pazuzu": str(r.get("description") or "").startswith(dd.DESCRIPTION_PREFIX)}
                                   for r in rows if isinstance(r, dict)]
            except Exception:
                pass
            try:
                general = (getter("/api/dyndns/settings/get").get("ddclient") or {}).get("general") or {}
                picked = [k for k, o in (general.get("backend") or {}).items() if isinstance(o, dict) and o.get("selected")]
                if picked:
                    out["backend"] = "ddclient" if picked[0] == "ddclient" else "native"
            except Exception:
                pass
        return out

    def ddns_manual(self, d) -> dict:
        from pazuzu_core import ddns_setup as dd
        d = d if isinstance(d, dict) else {}
        try:
            host = dd.clean_hostname(dd.full_name(d.get("provider"), d.get("hostname"))) if d.get("hostname") else ""
        except dd.DdnsError as exc:
            raise WizardError(str(exc))
        return {"steps": dd.manual_steps(str(d.get("provider") or ""), host)}

    def ddns_choose(self, d) -> dict:
        """Remember how devices will find home. A name is only remembered (and put in the VPN's address
        box); nothing is sent to the firewall here."""
        from pazuzu_core import ddns_setup as dd
        d = d if isinstance(d, dict) else {}
        choice = str(d.get("choice") or "")
        if choice not in ("domain", "ddns", "current"):
            raise WizardError("Pick one of the three ways.")
        if choice == "current":
            self._remember("host_choice", "current")
            self._remember("vpn_host", "")
            return self.ddns_state()
        try:
            host = dd.clean_hostname(dd.full_name(d.get("provider") if choice == "ddns" else "", d.get("hostname")))
        except dd.DdnsError as exc:
            raise WizardError(str(exc))
        self._remember("host_choice", choice)
        self._remember("vpn_host", host)
        return self.ddns_state()

    def ddns_change(self) -> dict:
        """Open the question again."""
        self._remember("host_choice", "")
        return self.ddns_state()

    def ddns_install(self) -> dict:
        """Put the changing-address plugin on the firewall (installer account, passkey), then look again
        at what the firewall now supports."""
        from pazuzu_core import plugin_install as pi, ddns_setup as dd
        from pazuzu_core.passkey_gate import plan_digest
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        role = en.INSTALLER
        session = self._installer_session()
        base = self.base_url.rstrip("/")

        def work() -> dict:
            lines = [f"Install the plugin {dd.PLUGIN} on your firewall (it keeps a name pointing at your home)",
                     self._uses_words()]
            if not self.window_gate(plan_digest("install-plugin", {"plugin": dd.PLUGIN}), lines):
                raise WizardError("Not approved with a passkey; nothing was installed.")
            try:
                pi.install(session, base, dd.PLUGIN)
            except pi.PluginError as exc:
                raise WizardError(str(exc))
            except Exception as exc:
                raise WizardError(f"The install stopped: {_plain_firewall(exc)}")
            try:
                self._look(session, role)
            except Exception as exc:
                raise WizardError(f"It was installed, but looking at the firewall again failed: {_plain_firewall(exc)}")
            return {"installed": dd.PLUGIN}

        return self._start("ddns-install", work)

    def write_ddns(self, d) -> dict:
        """Give the firewall the name service's login, with a passkey. The password goes to the firewall
        in this one request and is not kept, shown, or written to any file or log."""
        from pazuzu_core import ddns_setup as dd
        d = d if isinstance(d, dict) else {}
        prov = dd.BY_ID.get(str(d.get("provider") or ""))
        if prov is None:
            raise WizardError("Pick a name service from the list.")
        try:
            host = dd.clean_hostname(dd.full_name(prov["id"], d.get("hostname")))
        except dd.DdnsError as exc:
            raise WizardError(str(exc))
        username = str(d.get("username") or "").strip()
        password = d.get("password")
        if prov["needs_login"] and not username:
            raise WizardError("Give the user name your provider gave you.")
        if not isinstance(password, str) or not password:
            raise WizardError("Give the password or token your provider gave you.")
        if prov["id"] == "duckdns":                 # BUILD 535: the token's length and shape, before the firewall is asked
            password = password.strip()
            bad = dd.duckdns_token_problem(password)
            if bad:
                raise WizardError(bad)
        extra_key = (prov["extra"] or {}).get("key")
        extra = str(d.get(extra_key) or "").strip() if extra_key else ""
        if extra_key and not extra:
            raise WizardError(prov["extra"]["label"] + ".")
        port_ip = self._wan_address()          # BUILD 455: a public address on the port is read there

        def plans(e):
            try:
                service = dd.resolve_service(e.choices("ddns_account", "service"), prov["id"])
            except dd.DdnsError:
                if prov["id"] not in dd.DDCLIENT_ONLY:
                    raise
                service = switch_backend(e)
            checkip = dd.pick_checkip(e.choices("ddns_account", "checkip"), bool(port_ip))
            values = {"enabled": "1", "service": service, "hostnames": dd.firewall_hostname(prov["id"], host, extra),
                      "password": password,
                      "checkip": checkip, "description": dd.DESCRIPTION_PREFIX + host}
            if checkip == dd.CHECKIP_PORT:
                values["interface"] = dd.PORT_INTERFACE
            if prov["id"] in dd.MIN_TTL:                  # BUILD 456: GoDaddy takes 600 s at least
                values["ttl"] = str(dd.MIN_TTL[prov["id"]])
            if username:
                values["username"] = username
            if extra_key:
                values[extra_key] = extra
            # The account first: it is the one the firewall can refuse, and a refusal then leaves nothing behind.
            plans_out = [e.build("ddns_account", values), e.build("ddns_general", {"general.enabled": True})]
            try:                                       # BUILD 461: its update host and the lookups, past the block lists
                plans_out += self._allow_plans(e, self._every_allow_host(e, [prov["id"]], [host]))
            except we.WriteError:
                pass
            return plans_out
        def switch_backend(e):
            """BUILD 453: the native updater has no GoDaddy: switch the firewall to ddclient first (one passkey touch
            covers it and the account), then read the list again. If the account is then refused, it goes back."""
            line = dd.BACKEND_LINE.format(name=prov["name"])
            switch = e.build("ddns_general", {"general.backend": "ddclient"})
            switch.lines[:] = [line]
            account_words = [f"Add a changing-address name: {host} at {prov['name']}"]
            done = e.apply(switch, lambda dg, ln: self.window_gate(dg, list(ln) + account_words + [self._uses_words()]))
            try:
                return dd.resolve_service(e.choices("ddns_account", "service"), prov["id"])
            except (dd.DdnsError, we.WriteError):
                try:
                    e.apply(e.build("ddns_general", {"general.backend": "opnsense"}), lambda dg, ln: True)
                except we.WriteError:
                    pass
                raise
            finally:
                del done

        if prov["id"] == "godaddy" and extra and not (host == extra or host.endswith("." + extra)):
            raise WizardError(f"{host} is not in the domain {extra}: the name is the domain itself or a name under it.")
        also = d.get("also") is True        # BUILD 451: another name too (a second domain); the VPN keeps its name

        def remember(_r):
            if not also:
                self._remember("host_choice", "ddns")
                self._remember("vpn_host", host)
                self._remember("ddns_name", host)
        return self._write_job("write-ddns", plans, {"hostname": host, "provider": prov["name"]}, after=remember)

    def _every_allow_host(self, e, services=(), names=()) -> tuple:
        """BUILD 464: every name the block lists must let through, at once: the address lookups, each name service's
        update host and site, and every Dynamic DNS name on the firewall (plus any being added now). Each change to an
        allow list reloads every list (names stop for a minute or more), so a box pays for that once, not per name."""
        from pazuzu_core import ddns_setup as dd
        rows = []
        try:
            if e.ready("ddns_account")[0]:
                rows = e._rows(we.CAPS["ddns_account"], "")
        except we.WriteError:
            rows = []
        return dd.allow_hosts([str(r.get("service") or "") for r in rows] + list(services),
                              [str(r.get("hostnames") or "") for r in rows] + list(names))

    def _allow_plans(self, e, hosts) -> list:
        """BUILD 461: the names `hosts` on the allow list of every switched-on block-list entry that lacks them, the
        person's own entries too (an allow list only covers its own entry, and the lists can be in one of the person's).
        Only ever adds. On the older single setting (no entry grid), its whitelist."""
        from pazuzu_core import ddns_setup as dd
        out = []
        if e.ready("dnsbl_entry")[0]:
            cap = we.CAPS["dnsbl_entry"]
            for r in e._rows(cap, ""):
                if str(r.get("enabled", "1")) not in ("1", "True", "true"):
                    continue
                uuid = str(r.get("uuid") or "")
                body = e._req("get", we._derive(cap.read, "get") + "/" + uuid)
                form = next(iter(body.values()), {}) if isinstance(body, dict) and len(body) == 1 else {}
                if not isinstance(form, dict) or "allowlists" not in form:
                    continue
                now = we._value_of(form.get("allowlists"))
                want = dd.merge_allow(now, hosts)
                if want != now:
                    out.append(e.change("dnsbl_entry", uuid, {"allowlists": want},
                                        "Let the name service and address lookups through the block list",
                                        anyone=True))
        elif e.ready("unbound_dnsbl")[0]:
            unb = e._template(we.CAPS["unbound_dnsbl"])[1]
            if str(_dig_form(unb, "dnsbl.enabled")) == "1" and _dig_form(unb, "dnsbl.whitelists") is not None:
                now = we._value_of(_dig_form(unb, "dnsbl.whitelists"))
                want = dd.merge_allow(now, hosts)
                if want != now:
                    out.append(e.build("unbound_dnsbl", {"dnsbl.whitelists": want}))
        return out

    def ddns_force(self, d=None) -> dict:
        """BUILD 461: one ddclient round now, through the box (OPNsense's API has none for ddclient). The manager asks
        when Reach home from outside is opened while a name waits; the box allows one every ten minutes."""
        try:
            if self._acts is not None and self._box_up() and self._acts.source.box.can("ddns_force"):
                got = self._acts.source.box.post("/ddns_force", {})
                return got if isinstance(got, dict) else {"forced": False}
        except Exception:  # noqa: BLE001 - the box not answering never stops the page
            pass
        return {"forced": False, "why": "no box with the plugin 0.6.65 or newer"}

    def ddns_fix_address(self, d=None) -> dict:
        """BUILD 455: let the firewall learn its own address again, for the names already there. Pazuzu's names read it
        off the internet port when the port holds a public address; the block lists Pazuzu turned on let the web
        lookups through (their names go on the lists' allow list). One passkey touch; each change can be undone."""
        from pazuzu_core import ddns_setup as dd
        port_ip = self._wan_address()

        def plans(e):
            out = []
            if port_ip and e.ready("ddns_account")[0]:
                for r in e._rows(we.CAPS["ddns_account"], dd.DESCRIPTION_PREFIX.strip()):
                    if not str(r.get("description") or "").startswith(dd.DESCRIPTION_PREFIX):
                        continue
                    want = {"checkip": dd.CHECKIP_PORT, "interface": dd.PORT_INTERFACE}
                    svc = str(r.get("service") or "").lower()
                    if svc in dd.MIN_TTL:                     # BUILD 456: and a time-to-live GoDaddy takes
                        want["ttl"] = str(dd.MIN_TTL[svc])
                    if svc in dd.ZONE_ROOT:                   # BUILD 463: the domain itself is "@.<domain>"
                        uuid = str(r.get("uuid") or "")
                        body = e._req("get", we._derive(we.CAPS["ddns_account"].read, "get") + "/" + uuid)
                        form = next(iter(body.values()), {}) if isinstance(body, dict) and len(body) == 1 else {}
                        zone = we._value_of((form or {}).get("zone")).strip()
                        hostnames = we._value_of((form or {}).get("hostnames")).strip()
                        fixed = dd.firewall_hostname(svc, hostnames, zone)
                        if fixed != hostnames:
                            want["hostnames"] = fixed
                    p = e.change("ddns_account", str(r.get("uuid") or ""), want,
                                 "Read the address off the internet port for")
                    if e._previous.get(p.digest, {}).get(p.wrapper) != p.payload[p.wrapper]:
                        out.append(p)
            rows = e._rows(we.CAPS["ddns_account"], "") if e.ready("ddns_account")[0] else []
            out += self._allow_plans(e, self._every_allow_host(e))
            return out

        def nothing(_e):
            return ["Nothing to change: the names already read the address where they can, and the block lists "
                    "already let the lookups through."]
        return self._write_job("ddns-fix", plans, {"port": port_ip}, nothing=nothing)

    # -- "Reach home from outside": a name that follows the home address, then the VPN behind it
    _NAME_WORDS = (("quiet", "calm", "bright", "swift", "gentle", "amber", "cedar", "misty", "silver", "mossy"),
                   ("maple", "river", "harbor", "meadow", "falcon", "lantern", "pebble", "willow", "comet", "orchard"))

    def ddns_suggest(self) -> dict:
        """A name to try at the free name service, like quiet-maple-4821. Made here, nothing is sent anywhere."""
        import secrets as _s
        first, second = self._NAME_WORDS
        label = "%s-%s-%d" % (_s.choice(first), _s.choice(second), 1000 + _s.randbelow(9000))
        return {"label": label, "host": label + ".duckdns.org"}

    def reach_state(self) -> dict:
        """Everything the one 'Reach home from outside' step needs: the name, the VPN, and whether the firewall
        can reach the internet at all (the name service and its plugin both need it)."""
        vpn = self.vpn_state()
        down = self._wan_link_down()
        seen = getattr(self, "_internet_seen", None)
        net = "down" if down else "no" if seen is False else "yes" if seen else "unknown"
        return {"internet": net, "ddns": vpn.get("find") or {}, "name": self._recall("ddns_name") or "",
                "vpn": {k: v for k, v in vpn.items() if k != "find"}}

    # -- the five protection levels (packet inspection, block lists, ad lists)
    def levels_state(self) -> dict:
        from pazuzu_core import shield_levels as sl
        checking = self.auto_check()
        caps = we.readiness(self._probe)
        grid = caps["dnsbl_entry"]["ready"]               # newer firewalls keep the block lists as a grid of entries
        need = [caps[c] for c in ("ids_general", "dnsbl_entry" if grid else "unbound_dnsbl")]
        out = {"ready": all(c["ready"] for c in need), "level": None, "flags": None, "lists": None,
               "why": next((c["why"] for c in need if not c["ready"]), ""),
               "can_set": False, "names": list(sl.LEVELS), "checking": checking}
        if checking:
            out["why"] = "Checking what this firewall supports. This takes a few seconds."
        if not out["ready"]:
            return out
        getter = self._api_getter()
        if getter is None:
            out.update(ready=False, why="Not signed in to the firewall yet.")
            return out
        try:
            ids = next(iter(getter("/api/ids/settings/get").values()))
            if grid:
                form = next(iter(getter("/api/unbound/settings/get_dnsbl").values()))
                rows = getter("/api/unbound/settings/search_dnsbl?rowCount=-1").get("rows") or []
                flags = sl.read_flags_grid(ids, form.get("type") if isinstance(form, dict) else None, rows)
            else:
                unb = next(iter(getter("/api/unbound/settings/get").values()))
                flags = sl.read_flags(ids, unb)
        except Exception as exc:
            out.update(ready=False, why="Could not read the shields from the firewall: " + _plain_firewall(exc))
            return out
        idx = sl.level_index(flags)
        out.update(level=idx, flags={k: flags[k] for k in ("ips", "block", "ads")}, lists=sl.describe(flags),
                   can_set=self._can_change())
        return out

    def _ids_plan(self, e, on):
        """The plan that switches packet inspection. This firewall's own form is read first: if it has no IPS
        switch (a newer release may have renamed or moved it), say what it does have instead of guessing."""
        form = e._template(we.CAPS["ids_general"])[1]
        gen = form.get("general") if isinstance(form, dict) else None
        gen = gen if isinstance(gen, dict) else {}
        vals = {"general.enabled": on}
        if "ips" in gen:
            vals["general.ips"] = on
            return e.build("ids_general", vals)
        if "mode" in gen:
            # 26.7: no IPS tick, a capture mode instead. Blocking is divert (chosen by the person). Turning it off
            # only switches inspection off; the mode is left as it was, so the undo puts it back exactly.
            if on:
                from pazuzu_core import shield_levels as sl
                divert, _alerts = sl.divert_choice(gen["mode"])
                if divert is None:
                    offered = ", ".join(v for v, _s in sl._options(gen["mode"]).values()) or "nothing it showed"
                    raise WizardError("This firewall's capture mode has no single choice called divert, so Pazuzu did "
                                      "not guess. It offers: " + offered + ". Nothing was changed.")
                vals["general.mode"] = divert
            plan = e.build("ids_general", vals)
            if on:
                plan.lines.append("Divert only sees traffic that firewall rules send to it. This sets the mode; it does "
                                  "not add those rules.")
            return plan
        offered = ", ".join(sorted(str(k) for k in gen)[:30]) or "nothing it showed"
        raise WizardError("This firewall's packet-inspection form has no IPS switch and no capture mode, so Pazuzu did "
                          "not guess. Its form has: " + offered + ". Nothing was changed.")

    @staticmethod
    def _ipv6_ports(source, status=...):
        """[{iface, addr}] for every port holding a usable IPv6 address, from the plugin's own reading of the firewall.
        None when the plugin is not answering or is too old to report it, in which case the check stays unverified.
        `status` is the plugin's status reading when the caller already has it."""
        try:
            if status is ...:
                status = (source.box.read() or {}).get("status")
            ifaces = (status or {}).get("ifaces")
        except Exception:
            return None
        if not isinstance(ifaces, list) or not any(isinstance(i, dict) and "addrs6" in i for i in ifaces):
            return None
        return [{"iface": str(i.get("name")), "addr": str(a)} for i in ifaces if isinstance(i, dict)
                for a in (i.get("addrs6") or [])]

    def _time_option_plan(self, e):
        """The DHCP option that hands the firewall out as the time server, built from the firewall's own empty form.
        A field the form lacks is named and nothing is sent."""
        form = e._template(we.CAPS["dhcp_time_option"])[1]
        want = ("type", "option", "description")
        missing = [k for k in want if k not in form]
        if missing:
            raise WizardError("This firewall's DHCP option form has no " + ", ".join(missing) + " field, so Pazuzu did "
                              "not guess. Its form has: " + ", ".join(sorted(str(k) for k in form)[:30])
                              + ". Nothing was changed.")
        values = {"type": "set", "description": "Pazuzu: time server"}
        node = form.get("option")
        labels = {k: (v.get("value") if isinstance(v, dict) else str(v)) for k, v in node.items()} \
            if isinstance(node, dict) and node and all(isinstance(v, dict) for v in node.values()) else None
        if labels is None:
            values["option"] = "42"                       # a plain field: option 42 is the time server
        else:
            # Option 42 is the NTP server. Option 4 is the old "time server" (a different, obsolete protocol): not that one.
            # Most exact first: the key 42 itself, then a label that carries [42], then any label that names NTP.
            tiers = [[k for k in labels if k == "42"],
                     [k for k, lab in labels.items() if "[42]" in str(lab)],
                     [k for k, lab in labels.items() if "ntp" in (k + " " + str(lab)).lower()]]
            hit = next((t for t in tiers if t), [])
            if len(hit) != 1:
                if hit:
                    said = "It matches more than one: " + ", ".join(str(labels[k]) for k in hit[:15]) + "."
                else:
                    said = ("It has none that says 42 or NTP. Its list starts: "
                            + ", ".join(sorted({str(x) for x in labels.values()})[:15]) + ".")
                raise WizardError("This firewall's DHCP option list has no single time-server choice, so Pazuzu did not "
                                  "guess. " + said + " Nothing was changed.")
            values["option"] = hit[0]
        plan = e.build("dhcp_time_option", values)
        plan.lines.append("With no address given the DHCP server hands out its own, so devices use the firewall for time.")
        return plan

    def _happy_extras(self, e) -> list:
        """What the top step adds to the shields: the DHCP time option, when the firewall says it is missing and the stock
        DHCP server can take it. A time service that is stopped is its own button (it is not a settings change)."""
        from pazuzu_core import service_reads
        getter = self._api_getter()
        if getter is None or not e.ready("dhcp_time_option")[0]:
            return []
        reads = service_reads.read(getter)
        return [self._time_option_plan(e)] if reads.get("dhcp_ntp") is False else []

    def _firewall_address_in(self, subnet: str, getter) -> str:
        """The firewall's own IPv4 address on the network `subnet` (like "192.168.50.0/24"), from its interface list;
        "" when it has none there."""
        import ipaddress
        try:
            net = ipaddress.ip_network(subnet, strict=False)
            rows = getter("/api/interfaces/overview/interfaces_info/true").get("rows") or []
        except Exception:
            return ""
        for r in rows:
            cand = r.get("addr4") if isinstance(r, dict) and isinstance(r.get("addr4"), list) else [r.get("addr4") if isinstance(r, dict) else None]
            for c in cand:
                try:
                    iface = ipaddress.ip_interface(str(c))
                except ValueError:
                    continue
                if iface.version == 4 and iface.ip in net:
                    return str(iface.ip)
        return ""

    def _ids_refused(self) -> list:
        got = self._recall("ids_refused")
        return [str(x) for x in got] if isinstance(got, list) else []

    def _ids_apply(self, req) -> list:
        """Packet inspection's rulesets on (ids_rulesets.apply), remembering any the firewall keeps off when asked."""
        from pazuzu_core import ids_rulesets
        refused: list = []
        lines = ids_rulesets.apply(req, refused=refused)
        if refused:
            self._remember("ids_refused", sorted(set(self._ids_refused()) | set(refused)))
        return lines

    def _zone_assignments(self) -> dict:
        """The saved port choice by zone ({zone: {"state", "device"}}), as the status shows it; {} when there is none."""
        try:
            report = json.loads(self.zones_path.read_text(encoding="utf-8"))
            return {z: {"state": a.get("state"), "device": a.get("device")} for z, a in report["assignments"].items()}
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            return {}

    def _dns_guard(self, getter) -> dict:
        """DNS redirects on the isolated networks and DNS over TLS (dns_guard.read), read only."""
        from pazuzu_core import dns_guard
        plugin = None
        try:
            if self._acts is not None and self._box_up():
                plugin = dns_guard.box_dot((self._acts.source.box.read() or {}).get("status"))
        except Exception:
            plugin = None
        return dns_guard.read(getter, self._zone_assignments(), resolver_choices.load(self.key_dir), plugin)

    def _iot_cloud(self, getter) -> dict | None:
        """What smart devices need from the internet (iot_cloud.py), read only: None when there is no IoT network.
        The state plus where the rules go: {"iot": (short name, network), "lan": (short name, network) | None}."""
        from pazuzu_core import iot_cloud, nat_audit
        zones, where, _ips = nat_audit.ports(getter, self._zone_assignments())
        def at(zone):
            ident = str((zones.get(zone) or {}).get("identifier") or "")
            nets = [i for i in where.get(zone, []) if getattr(i, "version", 4) == 4]
            return (ident, str(nets[0].network)) if ident and nets else None
        iot = at("iot")
        rules = None
        if iot is None:
            # BUILD 492 (Tuya bulbs offline, no bar): the saved port choice did not name the IoT
            # network, so this check never ran and 8886 never went on the list. The network the smart devices' own
            # rule is on is the IoT network too.
            rules = (getter("/api/firewall/filter/search_rule?rowCount=-1&searchPhrase=Pazuzu") or {}).get("rows") or []
            iot = self._iot_links_net(getter, rules)
        if iot is None:
            return None
        lan = at("trusted")
        aliases = (getter("/api/firewall/alias/search_item?rowCount=-1&searchPhrase=IoT_") or {}).get("rows") or []
        if rules is None:
            rules = (getter("/api/firewall/filter/search_rule?rowCount=-1&searchPhrase=Pazuzu") or {}).get("rows") or []
        status = None
        try:
            if self._acts is not None and self._box_up():
                status = (self._acts.source.box.read() or {}).get("status")
        except Exception:
            status = None
        status = status if isinstance(status, dict) else {}
        cams = iot_cloud.cameras(status.get("clients"), status.get("names"))
        st = iot_cloud.state(aliases, rules, cams, lan is not None)
        st.update(iot=iot, lan=lan)
        return st

    @staticmethod
    def _iot_links_net(getter, rules=None):
        """BUILD 492: (short name, network) of the port the enabled "IoT cloud links" rule is on, read from the firewall,
        or None. A rule written by hand may name its port's network ("opt2") instead of the range."""
        import ipaddress as _ip
        from pazuzu_core import iot_cloud
        if rules is None:
            rules = (getter("/api/firewall/filter/search_rule?rowCount=-1&searchPhrase=Pazuzu") or {}).get("rows") or []
        rule = next((r for r in rules if isinstance(r, dict)
                     and str(r.get("description") or r.get("descr") or "") == iot_cloud.RULE_IOT
                     and str(r.get("enabled", "1")) not in ("0", "false")), None)
        if rule is None:
            return None
        ident = str(rule.get("interface") or "").split(",")[0].strip()
        if not re.match(r"^[a-z][a-z0-9_]{0,31}$", ident):
            return None
        src = str(rule.get("source_net") or "").strip()
        try:
            return ident, str(_ip.ip_network(src, strict=False))
        except ValueError:
            pass
        rows = (getter("/api/interfaces/overview/interfaces_info/true") or {}).get("rows") or []
        want = re.sub(r"ip$", "", src) if src and src != "any" else ident
        for r in rows:
            if not isinstance(r, dict) or str(r.get("identifier")) != want:
                continue
            for c in (r.get("addr4") if isinstance(r.get("addr4"), list) else [r.get("addr4")]):
                try:
                    net = _ip.ip_interface(str(c)).network
                except ValueError:
                    continue
                if net.version == 4:
                    return ident, str(net)
        return None

    def _cloud_gap(self, getter):
        """BUILD 492: {"net": the IoT network, "listed": {ports on IoT_cloud_ports}} when the smart devices' rule and list
        are on the firewall; None otherwise. What the bars need to offer one port to every smart device at once."""
        import ipaddress as _ip
        from pazuzu_core import iot_cloud
        rules = (getter("/api/firewall/filter/search_rule?rowCount=-1&searchPhrase=Pazuzu") or {}).get("rows") or []
        where = self._iot_links_net(getter, rules)
        if where is None:
            return None
        aliases = (getter("/api/firewall/alias/search_item?rowCount=-1&searchPhrase=" + iot_cloud.ALIAS) or {}).get("rows") or []
        alias = next((a for a in aliases if isinstance(a, dict) and a.get("name") == iot_cloud.ALIAS), None)
        if alias is None:
            return None
        return {"net": _ip.ip_network(where[1], strict=False), "listed": set(iot_cloud._list(alias.get("content")))}

    def _forwards(self, getter) -> list | None:
        """The person's port forwards on the internet side (forwards.py), read only: None when there are none."""
        from pazuzu_core import forwards as fwd
        rows = (getter(fwd.PAGE) or {}).get("rows") or []
        got = fwd.forwards(rows)
        return got or None

    def _vpn_access(self, getter) -> dict | None:
        """What the VPN may reach (vpn_access.py), read only: None when there is no VPN instance on the firewall.
        {"net", "missing": [rule values]}."""
        from pazuzu_core import vpn_access
        from pazuzu_core.enroll_safety import base_host_port
        servers = [r for r in (getter("/api/wireguard/server/search_server").get("rows") or [])
                   if isinstance(r, dict) and str(r.get("enabled", "1")) != "0"]
        if not servers:
            return None
        net = vpn_access.tunnel_net(servers[0].get("tunneladdress"))
        if not net:
            return None
        rows = (getter("/api/firewall/filter/search_rule?rowCount=-1&searchPhrase=" + "Pazuzu%3A%20VPN") or {}).get("rows") or []
        want = vpn_access.wanted(net, base_host_port(self.base_url)[1])
        acl = None
        try:
            acl = vpn_access.acl_missing((getter("/api/unbound/settings/search_acl?rowCount=-1&searchPhrase=") or {})
                                         .get("rows") or [], net)
        except Exception:
            acl = None                          # not read: not judged
        return {"net": net, "missing": vpn_access.missing(rows, want), "acl_missing": bool(acl)}

    def happy_todo(self) -> dict:
        """What "Finish getting to Happy" would do now, read only: each Kea subnet with no time server (and the firewall's
        own address there), the stock DHCP server's time option when Kea is not in use, and the admin session timeout."""
        from pazuzu_core import service_reads
        getter = self._api_getter()
        out = {"kea": [], "dnsmasq_option": False, "session": False, "ids": [], "refresh": [], "dnat": [], "dot": [],
               "dot_enable": [], "dot_off": [], "vpn_rules": [], "vpn_acl": "", "iot_cloud": None, "forwards": [],
               "notes": [], "unread": []}
        if getter is None:
            out["unread"].append("everything: Pazuzu is not signed in to the firewall")
            return out

        def unread(part, exc):
            why = ("the firewall did not allow Pazuzu's account to read it" if isinstance(exc, PermissionError)
                   else str(exc) if isinstance(exc, (LookupError, ValueError)) else _plain_firewall(exc))
            out["unread"].append(f"{part} ({why})")
        try:                                       # what the VPN may reach (full tunnel): its rules
            va = self._vpn_access(getter)
            if va and va["missing"] and we.probe_ready(self._probe, we.CAPS["fw_rule"])[0]:
                out["vpn_rules"] = va["missing"]
            if va and va.get("acl_missing") and we.probe_ready(self._probe, we.CAPS["unbound_acl"])[0]:
                out["vpn_acl"] = va["net"]
        except Exception as exc:
            unread("the VPN's rules", exc)
        try:                                       # what smart devices need from the internet, internet only
            from pazuzu_core import iot_cloud
            ic = self._iot_cloud(getter)
            if ic is not None and not iot_cloud.done(ic):
                if all(we.probe_ready(self._probe, we.CAPS[c])[0] for c in ("fw_rule", "cloud_alias")):
                    out["iot_cloud"] = ic
                else:
                    out["notes"].append("The smart devices' cloud links wait for the firewall check to run again "
                                        "(Check the firewall again).")
        except Exception as exc:
            unread("what smart devices need from the internet", exc)
        try:                                       # the person's own forwards, buried under the internet-side deny
            from pazuzu_core import forwards as fwd
            fw = self._forwards(getter)
            if fw and fwd.buried(fw):
                if we.probe_ready(self._probe, we.CAPS["dnat_rule"])[0]:
                    out["forwards"] = fwd.buried(fw)
                else:
                    out["notes"].append("Your port forwards wait for the firewall check to run again (Check the firewall again).")
        except Exception as exc:
            unread("your port forwards", exc)
        try:                                       # DNS redirects on the isolated networks, and DNS over TLS
            guard = self._dns_guard(getter)
            red, dot = guard.get("redirects") or {}, guard.get("dot") or {}
            ntp = guard.get("ntp_redirects") or {}              # time redirects, made with the DNS ones (BUILD 424)
            if red.get("plan") or ntp.get("plan") or dot.get("add") or dot.get("enable") or dot.get("off"):
                ready = {c: we.probe_ready(self._probe, we.CAPS[c])[0] for c in ("dnat_rule", "unbound_dot")}
                if (red.get("plan") or ntp.get("plan")) and ready["dnat_rule"]:
                    out["dnat"] = list(red.get("plan") or []) + list(ntp.get("plan") or [])
                if ready["unbound_dot"]:
                    out["dot"] = [list(x) for x in dot.get("add") or []]
                    out["dot_enable"] = list(dot.get("enable") or [])
                    out["dot_off"] = list(dot.get("off") or [])
                if not all(ready.values()):
                    out["notes"].append("The DNS redirects or DNS over TLS wait for the firewall check to run again "
                                        "(Check the firewall again).")
            out["notes"] += list(red.get("notes") or []) + list(ntp.get("notes") or [])
            if dot.get("why") and not (dot.get("add") or dot.get("enable") or dot.get("off")) and dot.get("on") is False:
                out["notes"].append(dot["why"] + ".")
            if guard.get("redirects") is None:
                out["unread"].append("the DNS redirects (the firewall's port forwards could not be read)")
            if guard.get("dot") is None:
                out["unread"].append("DNS over TLS (the firewall's DNS settings could not be read)")
        except Exception as exc:
            unread("the DNS redirects and DNS over TLS", exc)
        try:                                       # the downloaded lists' nightly refresh, on the firewall's own scheduler
            from pazuzu_core import list_refresh
            out["refresh"] = list_refresh.missing(((getter(list_refresh.CRON + "/search_jobs?rowCount=-1&searchPhrase=") or {})
                                                   .get("rows") or []))
        except Exception as exc:
            out["refresh"] = []
            unread("the nightly refresh", exc)
        try:                                       # packet inspection on, but the baseline's rulesets are not
            from pazuzu_core import ids_rulesets
            out["ids"] = [f for f in ids_rulesets.missing(ids_rulesets.rows_of(getter(ids_rulesets.LIST)))
                          if f not in self._ids_refused()]
        except Exception as exc:
            out["ids"] = []
            unread("packet inspection's rulesets", exc)
        reads = service_reads.read(getter)
        for s in reads.get("kea_subnets") or []:
            if s["has_field"] and not s["ntp"]:
                ip = self._firewall_address_in(s["subnet"], getter)
                if ip:
                    out["kea"].append({"uuid": s["uuid"], "subnet": s["subnet"], "ip": ip})
                else:
                    out["notes"].append(f"The DHCP network {s['subnet']} is not on one of the firewall's own ports, so it was left alone.")
        if not reads.get("kea_subnets") and reads.get("dhcp_ntp") is False:
            out["dnsmasq_option"] = True
        try:
            box = self._acts.source.box if self._box_up() else None
            got = box.admin_session_status() if box is not None and hasattr(box, "admin_session_status") else None
            if box is not None and box.can("admin_session_set") and isinstance(got, dict) and got.get("state") == "ok" \
                    and not (got.get("set") and 0 < int(got.get("minutes") or 0) <= 15):
                out["session"] = True
        except Exception:
            pass
        return out

    HAPPY_COVERS = ("the time server handed out by DHCP", "the admin session timeout", "packet inspection's rulesets",
                    "the nightly list refresh", "DNS redirects", "time redirects", "DNS over TLS", "what the VPN may reach",
                    "what smart devices need from the internet")

    def _still_red(self) -> list[str]:
        """The board's lines that are not green, by title, from the manager's own reading (empty when not at hand)."""
        try:
            st = self._acts.source.state(None)
        except Exception:
            return []
        return [str(c.get("title") or c.get("id")) for c in (st.get("controls") or [])
                if isinstance(c, dict) and c.get("status") == "drifted"]

    # -- telemetry (docs/architecture/telemetry.md): captured here, shown on the Reports page, sent only by a tap
    def _telemetry(self):
        from pazuzu_core import telemetry as tm
        legal = self.legal()
        words = []
        try:
            words.append(socket.gethostname())
            st = (self._acts.source.box.read() or {}).get("status") if (self._acts is not None and self._box_up()) else {}
            words.append(str((st or {}).get("host") or ""))
            words += [str(v) for v in ((st or {}).get("assign") or {}).values()]
        except Exception:
            pass
        host, _port = base_host_port(self.base_url)
        words.append(host)
        # a switch the person has answered counts, even while a newer one is still to be asked; an unanswered one is off
        return tm.Telemetry(self.key_dir, legal.get("consent") if legal.get("consent_asked") else None, words)

    def _plugin_version(self) -> str:
        try:
            st = (self._acts.source.box.read() or {}).get("status") if (self._acts is not None and self._box_up()) else {}
            return str((st or {}).get("version") or (st or {}).get("plugin_version") or "")
        except Exception:
            return ""

    def telemetry_weekly(self) -> None:
        """versions and checks, once a week each, from what the manager already has. Never raises."""
        try:
            from pazuzu_core import telemetry as tm
            t = self._telemetry()
            if t.due("versions"):
                hw = None
                try:
                    hw = self._acts.source.box.hardware_status() if (self._acts is not None and self._box_up()) else None
                except Exception:
                    hw = None
                fw = ""
                try:
                    fw = str((self.firmware_state() or {}).get("version") or "")
                except Exception:
                    fw = ""
                t.capture("versions", tm.versions_payload(BUILD, self._plugin_version(), fw, hw, self._platform_word()))
            if t.due("checks") and self._acts is not None:
                st = self._acts.source.state() if getattr(self._acts, "source", None) is not None else None
                if isinstance(st, dict) and st.get("controls"):
                    t.capture("checks", tm.checks_payload(st["controls"], st.get("hero") or "", st.get("shield"),
                                                           self._days_since_setup(), BUILD))
        except Exception:
            pass

    def _platform_word(self) -> str:
        try:
            box = self._acts.source.box
            return (box.platform() if box.url and hasattr(box, "platform") else "") or "pazuzu"
        except Exception:
            return "pazuzu"

    def _days_since_setup(self):
        try:
            made = (self.key_dir / KEY_STAMP).stat().st_mtime
            return int((time.time() - made) // 86400)
        except OSError:
            return None

    def telemetry_problem(self, kind: str, error: str) -> None:
        """A failed job, as a category. Never raises, never the error's text."""
        try:
            from pazuzu_core import telemetry as tm
            self._telemetry().capture("problems", tm.problem_payload(kind, "", error, BUILD, self._plugin_version()))
        except Exception:
            pass

    def telemetry_devices(self) -> None:
        """What smart devices needed (the Always allows on the firewall and the box's high counts), once a week: the
        maker word and the port, never the address."""
        try:
            from pazuzu_core import oui, telemetry as tm
            t = self._telemetry()
            if not t.due("devices"):
                return
            getter = self._api_getter()
            rows = (getter("/api/firewall/filter/search_rule?rowCount=-1&searchPhrase=" + "Pazuzu%3A%20allow") or {}).get("rows") or [] if getter else []
            allows = []
            for r in rows:
                d = str(r.get("description") or "")
                m = re.match(r"^Pazuzu: allow (home to )?([0-9a-f:]{17}) (tcp|udp)/(\d+)", d)
                if m:
                    allows.append({"mac": m.group(2), "kind": "home" if m.group(1) else "out", "proto": m.group(3), "dport": m.group(4)})
                elif re.match(r"^Pazuzu: allow ([0-9a-f:]{17}) any udp out$", d):
                    allows.append({"mac": d[14:31], "kind": "udp", "proto": "udp", "dport": "0"})
            st = (self._acts.source.box.read() or {}).get("status") if (self._acts is not None and self._box_up()) else {}
            macs = {str(c.get("ip")): str(c.get("mac") or "") for c in (st or {}).get("clients") or [] if isinstance(c, dict)}
            stopped = [{**n, "mac": macs.get(str(n.get("src")), "")} for n in ((st or {}).get("top") or {}).get("needs") or []]
            t.capture("devices", tm.device_needs_payload(allows, [], stopped, oui.vendor))
        except Exception:
            pass

    def telemetry_view(self) -> dict:
        return self._telemetry().view()

    # -- the box's screen follows the setup (BUILD 438, plugin 0.6.49): which step the wizard is on, and the access card
    def box_setup_step(self, d) -> dict:
        """The wizard's page tells the box which step it is on, so the box's own screen (and a phone looking at the
        feed) shows it with what to do; done=True clears it. Nothing when there is no box yet: the page carries on."""
        d = d if isinstance(d, dict) else {}
        body = {"step": int(d.get("step") or 0), "of": int(d.get("of") or 0), "title": str(d.get("title") or "")[:80],
                "do": str(d.get("do") or "")[:240], "done": bool(d.get("done"))}
        if d.get("qr"):                                   # BUILD 477: a code for the box's own screen (the one-time
            body["qr"] = str(d.get("qr"))[:400]           # code's seed on a phone setup: the phone cannot scan itself)
            body["qr_words"] = str(d.get("qr_words") or "")[:80]
        steps = []                                        # plugin 0.6.83: the page's own steps, numbered on the screen
        for item in (d.get("steps") if isinstance(d.get("steps"), list) else [])[:6]:
            if isinstance(item, dict):
                text, state = str(item.get("text") or "")[:90], str(item.get("state") or "todo")
            else:
                text, state = str(item or "")[:90], "todo"
            if text.strip():
                steps.append({"text": text.strip(), "state": state if state in ("todo", "now", "done", "failed") else "todo"})
        if steps:
            body["steps"] = steps
        last = getattr(self, "_box_step_said", None)
        if last == body:
            return {"sent": False, "same": True}
        if not body["done"] and ((getattr(self, "_manager_url", None) and not self.phone) or self._recall("setup_finished")):
            # BUILD 469: past setup (the manager is open, or the setup reached its end) the box's screen no longer
            # follows this page: an old setup tab kept putting "step 1 of 4" back on the box's screen.
            return {"sent": False, "past_setup": True}
        self._box_step_said = body
        if body["done"]:
            try:
                self._remember("setup_finished", True)
            except Exception:  # noqa: BLE001
                pass
        return {"sent": self._box_tell("setup_step", "/setup_step", body)}

    def box_access_card(self, d) -> dict:
        """The access card's lines (no secrets on it by design), kept on the box so the app can show it later."""
        d = d if isinstance(d, dict) else {}
        lines = [{"label": str(r.get("label") or "")[:40], "value": str(r.get("value") or "")[:240]}
                 for r in (d.get("lines") or []) if isinstance(r, dict)]
        if not lines or len(lines) > 12:
            raise WizardError("The card was not understood.")
        body = {"lines": lines, "as_of": str(d.get("as_of") or "")[:40], "brand": str(d.get("brand") or "")[:12]}
        return {"sent": self._box_tell("access_card", "/access_card", body)}

    def _box_tell(self, ability: str, path: str, body: dict) -> bool:
        try:
            if self._acts is not None and self._box_up() and self._acts.source.box.can(ability):
                self._acts.source.box.post(path, body)
                return True
            if self.phone:                            # BUILD 477: before the manager's link exists, the box's own link
                got = self._box_post(path, body)      # (the wizard runs on the box; step 1 was lost without this)
                return isinstance(got, dict)
        except Exception:  # noqa: BLE001 - the box not hearing it never stops the page
            pass
        return False

    def _box_sent_line(self) -> None:
        """Step 5: the box's Report page says what left ("Sent to Pazuzu: 3 reports, last on 30 Oct"). The manager tells
        the box the line after each send; the box keeps it and shows it, nothing more."""
        try:
            if self._acts is not None and self._box_up() and self._acts.source.box.can("sent_line"):
                self._acts.source.box.post("/sent_line", {"line": self._telemetry().view()["box_line"]})
        except Exception:
            pass

    def telemetry_change(self, d) -> dict:
        """Send, discard one or all waiting reports, start a new install id, or change a switch."""
        d = d if isinstance(d, dict) else {}
        t = self._telemetry()
        what = d.get("action")
        if what == "discard":
            if not t.discard(str(d.get("name") or "")):
                raise WizardError("That report is not waiting any more.")
        elif what == "discard_all":
            t.discard_all()
        elif what == "new_id":
            t.new_id()
        elif what == "switch":
            k, on = str(d.get("switch") or ""), d.get("on") is True
            from pazuzu_core import telemetry as tm
            if k not in tm.SWITCHES:
                raise WizardError("That switch was not understood.")
            legal = self.legal()
            consent = dict(legal.get("consent") or {})
            consent[k] = on
            (self.key_dir / self.LEGAL_FILE).write_text(json.dumps({"terms": legal["terms"], "consent": consent}), encoding="utf-8")
        elif what == "send":
            got = t.send(str(d.get("name") or ""))
            if not got.get("ok"):
                raise WizardError(str(got.get("why") or "It was not sent."))
            self._box_sent_line()
        elif what == "send_all":
            left = []
            for r in t.waiting():
                got = t.send(r["name"])
                if not got.get("ok"):
                    left.append(str(got.get("why") or ""))
                    break
            self._box_sent_line()
            if left:
                raise WizardError(left[0] + " The rest stay here.")
        else:
            raise WizardError("That was not understood.")
        return self.telemetry_view()

    def _happy_nothing_words(self, todo: dict) -> str:
        """Why "Finish getting to Happy" had nothing to do, in words that lead somewhere: what could not be read (and
        the way out), what is still red that this button does not do, and the notes."""
        out = ["Finish getting to Happy had nothing to set: everything it does (" + ", ".join(self.HAPPY_COVERS)
               + ") is already done or was not read."]
        if todo.get("unread"):
            out.append("Not read: " + "; ".join(todo["unread"]) + ".")
            if getattr(self, "_installer_dead", False):
                out.append("The installer account has closed itself (it lasts a day). Make it again on the setup page "
                           "(Connection), then press Check the firewall again.")
        red = self._still_red()
        if red:
            out.append("Still red, and not something this button does: " + "; ".join(red)
                       + ". Open each tile for its own fix.")
        out += [n for n in todo.get("notes") or [] if n]
        return " ".join(out)

    def happy_left(self) -> dict:
        """BUILD 477: what the setup's own "Switch protection on" step still has to do, read only: the shields to Normal,
        the Finish-getting-to-Happy settings, IPv6 off. Happy is the setup's last step; leaving it is the person's choice."""
        lv = self.levels_state()
        todo = self.happy_todo()
        finish = bool(todo["kea"] or todo["dnsmasq_option"] or todo["session"] or todo["ids"] or todo["refresh"]
                      or todo["dnat"] or todo["dot"] or todo["dot_enable"] or todo["dot_off"] or todo["vpn_rules"]
                      or todo["vpn_acl"] or todo["iot_cloud"] or todo["forwards"])
        # BUILD 480: on a Hanbi set up from the app, Secure Shell goes off last (it is open from the factory for the prep;
        # the app and the box's screen are the way in). Read by the plugin; on a computer it is left to the manager.
        ssh = False
        if self.phone:
            try:
                sh = self.ssh_state()
                ssh = sh.get("how") == "plugin" and bool(sh.get("on"))
            except Exception:  # noqa: BLE001
                ssh = False
        return {"shields": bool(lv.get("ready")) and lv.get("level") != 4, "shields_ready": bool(lv.get("ready")),
                "shields_why": lv.get("why") or "", "finish": finish, "ipv6": self._ipv6_state() != "off",
                "ssh": ssh, "unread": todo.get("unread") or []}

    def happy_finish_start(self) -> dict:
        """The top step's own settings, all under one passkey: a time server for each Kea DHCP subnet (the firewall's own
        address on it), the stock DHCP server's time option when Kea is not used, and the admin session timeout of 15
        minutes (through the plugin). Each is read back. Rules of the person's own are never changed here."""
        todo = self.happy_todo()
        if not (todo["kea"] or todo["dnsmasq_option"] or todo["session"] or todo["ids"] or todo["refresh"]
                or todo["dnat"] or todo["dot"] or todo["dot_enable"] or todo["dot_off"] or todo["vpn_rules"]
                or todo["vpn_acl"] or todo["iot_cloud"] or todo["forwards"]):
            raise WizardError(self._happy_nothing_words(todo))
        from pazuzu_core.passkey_gate import plan_digest
        box = self._acts.source.box if todo["session"] else None

        def run(engine, gate):
            lines = ["Finish getting to Happy"]
            lines += [f"DHCP network {k['subnet']}: hand out the firewall ({k['ip']}) as the time server" for k in todo["kea"]]
            if todo["dnsmasq_option"]:
                lines.append("The DHCP server hands out the firewall as the time server")
            if todo["session"]:
                lines.append("Sign the firewall's admin pages out after 15 idle minutes")
            if todo["ids"]:
                lines.append(f"Switch on and download packet inspection's rulesets ({len(todo['ids'])})")
            if todo["refresh"]:
                from pazuzu_core import list_refresh
                lines.append("Refresh every night, on the firewall's own scheduler: "
                             + ", ".join(list_refresh.WORDS[k] for k in todo["refresh"]))
            from pazuzu_core import dns_guard
            lines += dns_guard.lines(todo)
            if todo["vpn_rules"]:
                lines.append("Let the VPN reach: " + "; ".join(r["description"][len("Pazuzu: VPN "):] for r in todo["vpn_rules"]))
            if todo["vpn_acl"]:
                lines.append(f"Let the VPN ({todo['vpn_acl']}) ask the firewall's DNS")
            if todo["iot_cloud"]:
                from pazuzu_core import iot_cloud
                lines += iot_cloud.lines(todo)
            if todo["forwards"]:
                from pazuzu_core import forwards as fwd
                lines += fwd.lines(todo)
            if not gate(plan_digest("happy-finish", todo), lines):
                raise we.WriteError("Not approved with a passkey. Nothing was changed.")
            outs, said = [], []
            for k in todo["kea"]:
                body = engine._req("get", "/api/kea/dhcpv4/get_subnet/" + k["uuid"])
                if not isinstance(body, dict) or len(body) != 1:
                    raise we.WriteError("The firewall's DHCP network form was not in the usual shape. Nothing more was changed.")
                (wrapper, _form), = body.items()
                res = engine._req("post", "/api/kea/dhcpv4/set_subnet/" + k["uuid"], json={wrapper: {"option_data": {"ntp_servers": k["ip"]}}})
                if not (isinstance(res, dict) and str(res.get("result")) == "saved"):
                    raise we.WriteError(f"The firewall did not save the time server for {k['subnet']}. Nothing more was changed.")
                outs.append(we.Outcome("kea_subnet", k["uuid"], saved=True,
                                       undo_path="/api/kea/dhcpv4/set_subnet/" + k["uuid"],
                                       undo_body={wrapper: {"option_data": {"ntp_servers": ""}}}))
                said.append(f"{k['subnet']}: the firewall ({k['ip']}) is now handed out as the time server.")
            if todo["kea"]:
                try:
                    engine._req("post", "/api/kea/service/reconfigure", json={})
                except we.WriteError:
                    said.append("Saved, but the DHCP server did not apply it yet: press Apply on Services, Kea DHCP.")
                from pazuzu_core import service_reads
                left = [s for s in (service_reads.kea_subnets(self._api_getter()) or []) if s["has_field"] and not s["ntp"]]
                said.append("Read the DHCP networks back: each now names a time server." if not left else
                            f"Read back: {len(left)} DHCP network(s) still name no time server. Look at Services, Kea DHCP.")
            if todo["dnsmasq_option"]:
                out = engine.apply(self._time_option_plan(engine), gate)
                outs.append(out)
                said += list(out.lines)
            if todo["session"]:
                got = box.admin_session_change("set")
                if not got.get("ok"):
                    said.append(str(got.get("error") or "The plugin did not set the session timeout."))
                else:
                    said.append("Admin pages now sign out after 15 idle minutes." if got.get("changed") else
                                "The session timeout was already 15 minutes.")
            if todo["ids"]:
                said += self._ids_apply(engine._req)
            if todo["refresh"]:
                from pazuzu_core import list_refresh
                lr = list_refresh.ListRefresh(engine)
                try:
                    lr.apply(lr.plan(), lambda d, l: True)           # approved above, with the rest
                    said += list(lr.said) + ["To take a nightly job back, remove it on System, Settings, Cron (each is "
                                             "called \u201cPazuzu: ...\u201d)."]
                except we.WriteError as exc:
                    said.append(f"The nightly refresh was not set: {exc}")
            if todo["dnat"] or todo["dot"] or todo["dot_enable"] or todo["dot_off"]:
                got, words = dns_guard.apply(engine, todo)
                outs += got
                said += words
            if todo["vpn_rules"]:
                try:
                    got = engine.apply_many([engine.build("fw_rule", r) for r in todo["vpn_rules"]], lambda d_, l_: True)
                    outs += got
                    said.append("The VPN can now reach the firewall's page, the box's feed, its DNS and the internet, "
                                "and asks the firewall for names and time (no outside DNS, time servers or QUIC).")
                except we.WriteError as exc:
                    said.append(f"The VPN's rules were not made: {exc}")
            if todo["vpn_acl"]:
                from pazuzu_core import vpn_access
                try:
                    outs.append(engine.apply(engine.build("unbound_acl", vpn_access.acl_values(todo["vpn_acl"])),
                                             lambda d_, l_: True))
                    said.append("The firewall's DNS now answers the VPN, with your block lists, like at home.")
                except we.WriteError as exc:
                    said.append(f"The VPN's DNS entry was not made: {exc}")
            if todo["iot_cloud"]:
                got, words = self._iot_cloud_apply(engine, todo["iot_cloud"])
                outs += got
                said += words
            if todo["forwards"]:
                got, words = self._forwards_apply(engine, todo["forwards"])
                outs += got
                said += words
            return outs, said + todo["notes"]
        return self._engine_job("happy-finish", run)

    def _forwards_apply(self, engine, buried: list) -> tuple[list, list[str]]:
        """Set each buried forward's "Firewall rule" to Pass (its traffic admitted with the translation, ahead of every
        rule). Only that one setting, only on a forward that holds the value just read, and each put back by Undo."""
        from pazuzu_core import forwards as fwd
        outs, said = [], []
        for f in buried:
            who = f.get("descr") or f.get("target") or "?"
            try:
                out = engine.change_by_uuid("dnat_rule", f["uuid"], "pass", fwd.PASS, lambda d_, l_: True,
                                            f"The forward to {who} ({f.get('ports') or 'its ports'}) admits its own traffic",
                                            expect=f.get("pass", ""))
                outs.append(out)
                said.append(f"The forward to {who} ({f.get('ports') or 'its ports'}) now admits its own traffic (Pass): "
                            "the internet reaches it again, whatever the rule order.")
            except we.WriteError as exc:
                said.append(f"The forward to {who} was not changed: {exc}")
        return outs, said

    def forwards_state(self) -> dict:
        """The Reaching-in sheet: each forwarded box, its ports, whether its traffic is admitted, and the override (if
        any) that names it inside the house. Reads only."""
        from pazuzu_core import forwards as fwd
        getter = self._api_getter()
        if getter is None:
            return {"boxes": [], "why": "Pazuzu is not signed in to the firewall."}
        try:
            fw = self._forwards(getter) or []
        except Exception as exc:  # noqa: BLE001
            return {"boxes": [], "why": "The forwards could not be read (" + _plain_firewall(exc) + ")."}
        try:
            hosts = (getter("/api/unbound/settings/search_host_override?rowCount=-1&searchPhrase=") or {}).get("rows") or []
        except Exception:  # noqa: BLE001
            hosts = None
        boxes = []
        for g in fwd.by_target(fw):
            mine = [h for h in (hosts or []) if isinstance(h, dict) and str(h.get("server") or "").strip() == g["target"]]
            names = sorted({".".join(p for p in (str(h.get("hostname") or ""), str(h.get("domain") or "")) if p) for h in mine})
            boxes.append({**g, "names": names, "overrides_read": hosts is not None})
        return {"boxes": boxes, "why": ""}

    def forwards_name(self, d) -> dict:
        """Name a forwarded box inside the house: a host override (that public name -> the box's inside address) in the
        firewall's resolver, under the passkey, read back, with Undo. The resolver reloads, which takes a minute or
        two with block lists on."""
        from pazuzu_core import forwards as fwd
        d = d if isinstance(d, dict) else {}
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        try:
            name = fwd.clean_public_name(d.get("name"))
            values = fwd.override_values(name, str(d.get("target") or ""))
        except ValueError as exc:
            raise WizardError(str(exc))
        getter = self._api_getter()
        fw = (self._forwards(getter) if getter is not None else None) or []
        if values["server"] not in {f["target"] for f in fw}:
            raise WizardError("That address is not the target of one of your forwards. Nothing was changed.")

        def run(engine, gate):
            rows = engine._rows(we.CAPS["unbound_host"])
            if fwd.override_there(rows, name):
                raise we.WriteError(f"{name} is already answered inside the house. Nothing was changed.")
            out = engine.apply(engine.build("unbound_host", values), gate)
            return [out], [f"Inside the house, {name} now answers with {values['server']}. The resolver is reloading; "
                           "give it a minute or two, then the name works from any device at home."]
        return self._engine_job("write-forward-name", run)

    # ------------------------------------------------------------------ KidsNet (BUILD 537, kids_net.py)
    def _kids_port(self, getter):
        """(short name, network, the firewall's address) of the KidsNet port, as the firewall shows it; None when there
        is no KidsNet, or the firewall did not show its port whole."""
        from pazuzu_core import kids_net, nat_audit
        zones, where, _ips = nat_audit.ports(getter, self._zone_assignments())
        a = zones.get(kids_net.ZONE) or {}
        nets = [i for i in where.get(kids_net.ZONE, []) if getattr(i, "version", 4) == 4]
        port = (str(a.get("identifier") or ""), str(nets[0].network), str(nets[0].ip)) if nets else None
        return port if kids_net.port_ok(port) else None

    def _kids_read(self, getter, want=None) -> dict:
        from pazuzu_core import kids_net
        port = self._kids_port(getter)
        if port is None:
            return kids_net.state(None, None, None, None, want)
        nat = (getter("/api/firewall/d_nat/search_rule?rowCount=-1&searchPhrase=KidsNet") or {}).get("rows") or []
        rules = (getter("/api/firewall/filter/search_rule?rowCount=-1&searchPhrase=KidsNet") or {}).get("rows") or []
        aliases = (getter("/api/firewall/alias/search_item?rowCount=-1&searchPhrase=KidsNet_") or {}).get("rows") or []
        return kids_net.state(port, nat, rules, aliases, want)

    def kids_state(self) -> dict:
        """The KidsNet card: the family DNS services offered, and what is on the firewall. Reads only.
        the maintainer, 14 Nov 2026: "if the user picks to build a KidsNet allow the choice tree ... default to OpenDNS FamilyShield"."""
        if not kids_present():
            return {"offered": False, "choices": [], "state": {"built": False, "done": False}, "why": "", "plugin": False}
        from pazuzu_core import kids_net
        out = {"offered": True, "choices": kids_net.choices(), "state": {"built": False, "want": kids_net.DEFAULT, "done": False},
               "why": "", "plugin": bool(getattr(self, "_acts", None) is not None and self._box_up())}
        getter = self._api_getter()
        if getter is None:
            out["why"] = "Pazuzu is not signed in to the firewall."
            return out
        try:
            out["state"] = self._kids_read(getter, self._recall("kids_provider"))
        except Exception as exc:  # noqa: BLE001 - said, never guessed
            out["why"] = "KidsNet could not be read (" + _plain_firewall(exc) + ")."
        return out

    def kids_apply(self, d) -> dict:
        """Make the KidsNet network a KidsNet: its DNS sent to the family service picked, and its rules. One passkey
        approval for the lot; each write is read back by the engine; Undo takes them back."""
        if not kids_present():
            raise WizardError("KidsNet is not in this copy of Pazuzu. Nothing was changed.")
        from pazuzu_core import kids_net
        from pazuzu_core.passkey_gate import plan_digest
        d = d if isinstance(d, dict) else {}
        pid = d.get("provider") or kids_net.DEFAULT
        if pid not in kids_net.PROVIDERS:
            raise WizardError("That family DNS service was not understood. Nothing was changed.")
        getter = self._api_getter()
        if getter is None:
            raise WizardError("Pazuzu is not signed in to the firewall.")
        if self._kids_port(getter) is None:
            raise WizardError("There is no KidsNet network on the firewall yet. Give KidsNet a home on the ports page "
                              "first (a VLAN, a spare port or a Wi-Fi name), then come back. Nothing was changed.")

        def run(engine, gate):
            st = self._kids_read(getter, pid)
            if st.get("done"):
                self._remember("kids_provider", pid)
                return [], ["KidsNet is already set up with " + kids_net.PROVIDERS[pid]["name"] + ". Nothing was changed."]
            port = st["port"]
            if not gate(plan_digest("kids-net", {"provider": pid, "port": port, "nat": st["nat"], "old": st["nat_old"],
                                                 "alias": st["alias"], "home": st["home_alias"],
                                                 "rules": st["rules_missing"]}), kids_net.lines(st)):
                raise we.WriteError("Not approved with a passkey. Nothing was changed.")
            yes = lambda _d, _l: True                            # noqa: E731 - approved above, with the rest
            outs, said = [], []
            if not st["home_alias"]:
                outs.append(engine.apply(engine.build("kids_alias", kids_net.home_alias_values()), yes))
            if st["alias"] == "missing":
                outs.append(engine.apply(engine.build("kids_alias", kids_net.alias_values(pid)), yes))
            elif st["alias"] == "stale":
                outs.append(engine.change_text("kids_alias", kids_net.BYPASS_ALIAS, "content",
                                               "\n".join(kids_net.bypass_for(pid)), yes))
            there = {str(r.get("description") or "") for r in engine._rows(we.CAPS["fw_rule"], "KidsNet")}
            new = [n for n in st["rules_missing"] if n not in there]
            if new:
                outs += engine.apply_many([engine.build("fw_rule", kids_net.rule_values(n, port["interface"], port["network"],
                                                                                        port["ip"])) for n in new], yes)
            off = [n for n in st["rules_missing"] if n in there]
            if st["nat_old"]:
                engine.remove_named("kids_dnat", st["nat_old"], yes)
            if st["nat"] != "ok":
                outs.append(engine.apply(engine.build("kids_dnat", kids_net.nat_values(pid, port["interface"])), yes))
            self._remember("kids_provider", pid)
            said += kids_net.said({"want": pid})
            if off:
                said.append("Switched off on the firewall, and left that way: " + ", ".join(off)
                            + ". Switch them on under Firewall, Rules for KidsNet to work as set up.")
            return [o for o in outs if o is not None], said
        return self._engine_job("write-kids-net", run)

    def _iot_cloud_apply(self, engine, st) -> tuple[list, list[str]]:
        """Make what iot_cloud.state found missing: the port list (or the ports it lacks), the camera list (or the
        cameras it lacks), and the rules. Approved above with the rest; each read back by the engine. A part the firewall
        refuses is said, and the others still go."""
        from pazuzu_core import iot_cloud
        yes = lambda _d, _l: True                                # noqa: E731
        outs, said = [], []
        try:
            if not st.get("alias"):
                outs.append(engine.apply(engine.build("cloud_alias", iot_cloud.port_alias_values([p for p, _w in iot_cloud.PORTS])), yes))
            elif st.get("ports_missing"):
                outs.append(engine.change_text("cloud_alias", iot_cloud.ALIAS, "content",
                                               "\n".join(list(st.get("alias_ports") or []) + list(st["ports_missing"])), yes))
            if st.get("cams_missing"):
                if not st.get("cam_alias"):
                    outs.append(engine.apply(engine.build("cloud_alias", iot_cloud.cam_alias_values(st["cams"])), yes))
                else:
                    outs.append(engine.change_text("cloud_alias", iot_cloud.CAM_ALIAS, "content",
                                                   "\n".join(sorted(set(st.get("cam_macs") or []) | set(st["cams_missing"]))), yes))
            iot_if, iot_net = st["iot"]
            lan = st.get("lan") or ("", "")
            rules = [iot_cloud.rule_values(k, iot_if if k != "app" else lan[0], iot_net if k != "app" else lan[1])
                     for k in st.get("rules_missing") or []]
            if rules:
                outs += engine.apply_many([engine.build("fw_rule", r) for r in rules], yes)
            said.append("Smart devices can now reach their clouds, internet only: "
                        + ", ".join(f"{p} ({w})" for p, w in iot_cloud.PORTS) + ".")
            if st.get("cams"):
                said.append("Doorbells and cameras can send live video, internet only (" + ", ".join(st["cams"]) + ").")
        except we.WriteError as exc:
            said.append(f"The smart devices' cloud links were not all made: {exc}")
        return [o for o in outs if o is not None], said

    def firewall_services(self) -> dict:
        """The firewall's own service list, as it shows it (Configd, Unbound, Zenarmor Engine, ...), each running or
        not, read through its service page rather than guessed from process names. Read only."""
        getter = self._api_getter()
        if getter is None:
            raise WizardError("Not signed in to the firewall yet.")
        try:
            body = getter("/api/core/service/search")
        except Exception as exc:
            raise WizardError("Could not read the firewall's service list: " + _plain_firewall(exc))
        rows = body.get("rows") if isinstance(body, dict) else None
        if not isinstance(rows, list):
            raise WizardError("The firewall's service list was not in the usual shape.")
        out = []
        for r in rows:
            if not isinstance(r, dict):
                continue
            name = str(r.get("description") or r.get("name") or r.get("id") or "").strip()
            if name:
                out.append({"name": name, "running": str(r.get("running")).strip().lower() in ("1", "true", "yes"),
                            "locked": str(r.get("locked")).strip().lower() in ("1", "true", "yes"),
                            "key": str(r.get("name") or ""), "sid": str(r.get("id") or "")})
        out.sort(key=lambda x: x["name"].lower())
        notes = []
        if any("zen" in x["name"].lower() and not x["running"] for x in out):
            notes.append("Zenarmor is installed but not running. It does not start until its own setup is finished: "
                         "open Zenarmor on the firewall, tick the terms and go through its steps.")
        return {"rows": out, "notes": notes}

    # -- quarantine a device where it is (quarantine.py): its MAC on PZ_quarantine, one block rule per inside port
    # -- what each device is, and where it belongs (device_zones, BUILD 431)
    KINDS_FILE = "device_kinds.json"

    def _said_kinds(self) -> dict:
        """What the person said each device is, by hardware address ("you said the Samsung is a phone")."""
        try:
            got = json.loads((self.key_dir / self.KINDS_FILE).read_text(encoding="utf-8"))
            return {str(k).lower(): str(v) for k, v in got.items()} if isinstance(got, dict) else {}
        except (OSError, ValueError):
            return {}

    def _zone_nets(self) -> list:
        """[(ip_network, zone key)] for every zone with a port, from the firewall; [] when it cannot be read."""
        from pazuzu_core import nat_audit
        getter = self._api_getter()
        if getter is None:
            return []
        try:
            _zones, where, _ips = nat_audit.ports(getter, self._zone_assignments())
        except Exception:  # noqa: BLE001
            return []
        return [(i.network, z) for z, ifs in where.items() for i in ifs if getattr(i, "version", 4) == 4]

    @staticmethod
    def _zone_of_ip(nets, ip) -> str | None:
        try:
            addr = ipaddress.ip_address(str(ip or ""))
        except ValueError:
            return None
        for net, zone in nets:
            if addr in net:
                return zone
        return None

    def devices_state(self) -> dict:
        """The Devices page: each device with what it is (the box's word, or yours), where it sits, where it belongs
        and how to move it; the quarantine offers; Zenarmor's store state. Reads only."""
        from pazuzu_core import device_zones as dz, forwards as fwd
        if not (self._acts is not None and self._box_up()):
            return {"devices": [], "offers": [], "zen": {"ok": None, "why": "The box plugin is not answering."}, "why": "The box plugin is not answering, so the devices cannot be listed."}
        st = (self._acts.source.box.read() or {}).get("status") or {}
        said = self._said_kinds()
        nets = self._zone_nets()
        targets: set = set()
        getter = self._api_getter()
        try:
            targets = {f["target"] for f in (self._forwards(getter) or [])} if getter is not None else set()
        except Exception:  # noqa: BLE001
            targets = set()
        zone_of = lambda d: self._zone_of_ip(nets, d.get("ip"))
        out = []
        for c in st.get("clients") or []:
            if not isinstance(c, dict):
                continue
            kind, why = dz.kind_of(c, said)
            zone = zone_of(c)
            forward = str(c.get("ip") or "") in targets
            rec = dz.recommend(kind, zone, forward)
            if forward and kind != "server":
                kind, why = "server", "a port forward from the internet points at it"
            wifi = str(c.get("iface") or "").startswith(("wlan", "ath", "rtwn", "run", "iwn", "iwm"))
            out.append({"mac": c.get("mac"), "ip": c.get("ip"), "name": c.get("name") or "", "vendor": c.get("vendor") or "",
                        "here": bool(c.get("here")), "kind": kind, "why": why, "said": (c.get("mac") or "").lower() in said,
                        "zone": zone, "zone_word": dz.ZONE_WORDS.get(zone, zone or ""), "forward": forward,
                        "recommend": rec, "how": dz.how_to_move(rec["zone"], "wifi" if wifi else "wired" if c.get("iface") else "") if rec.get("move") else "",
                        "zen": c.get("zen") or None})
        held = []
        try:
            held = self.quarantine_state().get("macs") or []
        except Exception:  # noqa: BLE001
            pass
        offers = dz.quarantine_offers(st.get("clients") or [], zone_of, said, held)
        zen = st.get("zen_devices") if isinstance(st.get("zen_devices"), dict) else {"ok": None, "why": ""}
        return {"devices": out, "offers": offers, "zen": zen, "why": ""}

    def device_kind_set(self, d) -> dict:
        """You say what a device is (or take it back with an empty kind). Kept on this PC by hardware address; no
        firewall change, so no passkey."""
        from pazuzu_core import device_zones as dz, quarantine
        d = d if isinstance(d, dict) else {}
        try:
            mac = quarantine.clean_mac(d.get("mac"))
            kind = dz.clean_kind(d.get("kind"))
        except ValueError as exc:
            raise WizardError(str(exc))
        said = self._said_kinds()
        if kind:
            said[mac] = kind
        else:
            said.pop(mac, None)
        try:
            self.key_dir.mkdir(parents=True, exist_ok=True)
            (self.key_dir / self.KINDS_FILE).write_text(json.dumps(said, indent=1, sort_keys=True), encoding="utf-8")
        except OSError:
            raise WizardError("Could not save that.")
        self._suggest_at = None
        return self.devices_state()

    def quarantine_suggestions(self) -> list:
        """The devices worth cutting off now, as bars at the top of the board: one tap, the passkey (device_zones)."""
        from pazuzu_core import device_zones as dz
        try:
            st = (self._acts.source.box.read() or {}).get("status") or {}
            nets = self._zone_nets()
            held = self.quarantine_state().get("macs") or []
            offers = dz.quarantine_offers(st.get("clients") or [], lambda d: self._zone_of_ip(nets, d.get("ip")), self._said_kinds(), held)
        except Exception:  # noqa: BLE001
            return []
        return [{"text": f"{o['name']} {o['why']}. Cut it off from everything until you have looked?", "label": "Quarantine",
                 "critical": o["score"] >= 3, "quarantine": {"mac": o["mac"], "name": o["name"]}} for o in offers[:3]]

    def quarantine_state(self) -> dict:
        """{"macs": [...], "ready": bool, "why"}. Reads only."""
        from pazuzu_core import quarantine
        getter = self._api_getter()
        if getter is None:
            return {"macs": [], "ready": False, "why": "Not signed in to the firewall yet."}
        try:
            rows = (getter("/api/firewall/alias/search_item?rowCount=-1&searchPhrase=" + quarantine.ALIAS) or {}).get("rows") or []
        except Exception as exc:  # noqa: BLE001
            return {"macs": [], "ready": False, "why": "The quarantine list could not be read: " + _plain_firewall(exc)}
        row = next((r for r in rows if isinstance(r, dict) and r.get("name") == quarantine.ALIAS), None)
        ready = we.probe_ready(self._probe, we.CAPS["q_alias"])[0] and self._can_change()
        return {"macs": quarantine.macs_in(row.get("content")) if row else [], "ready": ready, "why": ""}

    def quarantine_add(self, d) -> dict:
        from pazuzu_core import quarantine
        d = d if isinstance(d, dict) else {}
        try:
            mac = quarantine.clean_mac(d.get("mac"))
        except ValueError as exc:
            raise WizardError(str(exc))
        label = re.sub(r"[^\w .:()'-]", "", str(d.get("name") or ""))[:40].strip() or mac
        zones = self._zone_assignments()

        def run(engine, gate):
            cap = we.CAPS["q_alias"]
            row = engine._one_row(cap, quarantine.ALIAS)
            have = quarantine.macs_in(row.get("content")) if row else []
            if mac in have:
                return [], [f"{label} is already in quarantine."]
            ports = quarantine.ports(zones, engine.interface_id)
            if not ports:
                raise we.WriteError("Pazuzu does not know the firewall's inside ports yet (the setup page's Ports step), "
                                    "so nothing was changed.")
            rules = [engine.build("fw_rule", quarantine.rule_values(i, w)) for i, w in ports
                     if not engine.exists("fw_rule", quarantine.rule_values(i, w)["description"])]
            head = [f"Quarantine {label} ({mac})"]
            if row is None:
                outs = engine.apply_many([engine.build("q_alias", quarantine.alias_values([mac]))] + rules,
                                         lambda dg, ln: gate(dg, head + list(ln)))
            else:
                outs = [engine.change_text("q_alias", quarantine.ALIAS, "content", "\n".join(have + [mac]), gate,
                                           say=head[0] + ": it can reach nothing until you release it")]
                if rules:
                    outs += engine.apply_many(rules, lambda dg, ln: True)          # approved above, with the rest
            return outs, quarantine.held_words(label)

        return self._engine_job("quarantine", run)

    def quarantine_release(self, d) -> dict:
        from pazuzu_core import quarantine
        d = d if isinstance(d, dict) else {}
        try:
            mac = quarantine.clean_mac(d.get("mac"))
        except ValueError as exc:
            raise WizardError(str(exc))
        label = re.sub(r"[^\w .:()'-]", "", str(d.get("name") or ""))[:40].strip() or mac

        def run(engine, gate):
            row = engine._one_row(we.CAPS["q_alias"], quarantine.ALIAS)
            have = quarantine.macs_in(row.get("content")) if row else []
            if mac not in have:
                return [], [f"{label} is not in quarantine."]
            out = engine.change_text("q_alias", quarantine.ALIAS, "content", "\n".join(m for m in have if m != mac),
                                     gate, say=f"Release {label} ({mac}) from quarantine")
            return [out], [f"{label} is out of quarantine and back to its network's normal rules."]

        return self._engine_job("quarantine", run)

    # -- a tap on the box's screen asks for a change (hanbi_box/asks.py); it is approved here, with the passkey
    def box_ask(self) -> dict | None:
        """The box screen's open request, as the plugin shows it: {"id", "kind", "what", "words", "age_s"}, or None."""
        if not self._box_up():
            return None
        try:
            got = ((self._acts.source.box.read() or {}).get("status") or {}).get("ask")
        except Exception:
            return None
        if not isinstance(got, dict) or got.get("kind") not in ("allow30", "quarantine", "start") or not isinstance(got.get("id"), str):
            return None
        return got

    def _box_answer(self, rid: str, ok: bool, message: str) -> None:
        try:
            self._acts.source.box.post("/ask_state", {"id": rid, "ok": ok, "message": str(message or "")[:160]})
        except Exception:
            pass                                       # the box drops an unanswered request by itself

    def box_ask_answer(self, d) -> dict:
        """Approve (the same change the manager makes from its own lists, with the passkey) or turn down the box screen's
        request. The box is told how it went once the change is done."""
        d = d if isinstance(d, dict) else {}
        ask = self.box_ask()
        if ask is None or d.get("id") != ask["id"]:
            raise WizardError("That request is no longer open on the box.")
        if d.get("ok") is not True:
            self._box_answer(ask["id"], False, "turned down")
            return {"answered": True}
        w = ask.get("what") or {}
        if ask["kind"] == "allow30":
            started = self.block_allow({"src": w.get("src"), "proto": w.get("proto"), "dport": w.get("dport"),
                                        "device": w.get("iface"), "temp": True})
        elif ask["kind"] == "start":
            keys = [str(k) for k in (w.get("keys") or [])]
            rows = self.firewall_services()["rows"]
            pick = next((r for k in keys for r in rows if r.get("key") == k and not r.get("locked")), None)
            if pick is None:
                self._box_answer(ask["id"], False, "the firewall has no such service to start")
                raise WizardError(f"The firewall's service list has nothing called {', '.join(keys)}, so nothing was started.")
            if pick["running"]:
                self._box_answer(ask["id"], True, f"{pick['name']} is already running")
                return {"answered": True}
            started = self.service_start({"key": pick["key"], "sid": pick.get("sid") or ""})
        else:
            started = self.quarantine_add({"mac": w.get("mac"), "name": w.get("name") or w.get("ip")})

        def report():
            for _ in range(400):                        # up to ten minutes, for the passkey and the change
                time.sleep(1.5)
                job = self._job or {}
                if job.get("state") in ("done", "failed"):
                    ok = job.get("state") == "done"
                    lines = (job.get("result") or {}).get("lines") or []
                    self._box_answer(ask["id"], ok, (lines[0] if ok and lines else str(job.get("error") or "not done")))
                    return
            self._box_answer(ask["id"], False, "no answer in time")
        threading.Thread(target=report, daemon=True, name="box-ask").start()
        return started

    _SVC_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,40}$")
    _SVC_ID = re.compile(r"^[A-Za-z0-9_.:-]{0,64}$")

    def service_start(self, d) -> dict:
        """Start one stopped service from the firewall's own list (the manager's Start button), with the passkey, through
        the firewall's own service call; then read the list back. Only a service the list shows as stopped, by the
        name and id the list gives; nothing is ever stopped here."""
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        d = d if isinstance(d, dict) else {}
        key, sid = str(d.get("key") or ""), str(d.get("sid") or "")
        if not self._SVC_NAME.match(key) or not self._SVC_ID.match(sid):
            raise WizardError("That is not a service on the firewall's list.")
        return self._start("service-start", lambda: self._service_start_work(key, sid))

    def _service_start_work(self, key: str, sid: str) -> dict:
        from pazuzu_core.passkey_gate import plan_digest

        def find():
            return next((x for x in self.firewall_services()["rows"] if x["key"] == key and x["sid"] == sid), None)
        row = find()
        if row is None:
            raise WizardError("That service is not on the firewall's list any more.")
        if row["running"]:
            return {"lines": [f"{row['name']} is already running."], "can_undo": False, "info": True}
        session = self._installer_session()
        engine = we.Engine(session, self.base_url.rstrip("/"), self._probe or {})
        if not self.window_gate(plan_digest("start-service", {"key": key, "sid": sid}),
                                [f"Start {row['name']} on the firewall",
                                 self._uses_words()]):
            raise WizardError("Not approved with a passkey. Nothing was changed.")
        try:
            engine._req("post", "/api/core/service/start/" + key + ("/" + sid if sid else ""), json={})
        except we.WriteError as exc:
            raise WizardError(str(exc))
        running = False
        for _ in range(8):
            time.sleep(1.5)
            try:
                got = find()
            except WizardError:
                got = None
            if got and got["running"]:
                running = True
                break
        acts = getattr(self, "_acts", None)
        if acts is not None and getattr(acts, "source", None) is not None:
            acts.source.forget()
        if running:
            return {"lines": [f"{row['name']} is running."], "can_undo": False}
        return {"lines": [f"The firewall was asked to start {row['name']} but it does not read as running. Its own page "
                          "on the firewall usually says why (a setting it still needs, say)."], "can_undo": False}

    def time_service_start(self) -> dict:
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        return self._start("time-service", self._time_service_work)

    def zenarmor_start(self) -> dict:
        """Start Zenarmor's engine through the firewall's own service call, then read it back. The engine does not run
        until Zenarmor's own setup is finished (its terms are accepted by the person, on the firewall), so a start that
        does not take says so and the manager points to that setup."""
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        return self._start("zenarmor-start", self._zenarmor_start_work)

    def _zenarmor_start_work(self) -> dict:
        from pazuzu_core import service_reads
        from pazuzu_core.passkey_gate import plan_digest
        getter = self._api_getter()
        if getter is None:
            raise WizardError("Not signed in to the firewall yet.")
        try:
            body = getter(service_reads.SERVICES)
        except Exception as exc:
            raise WizardError("Could not read the firewall's service list: " + _plain_firewall(exc))
        row, why = service_reads.zenarmor_pick(body)
        if row is None:
            raise WizardError(why + " Start it on the firewall: open Zenarmor in its menu.")
        if service_reads._flag(row, "running"):
            return {"running": True, "setup": False, "lines": ["Zenarmor is already running."], "can_undo": False}
        name = str(row.get("name") or row.get("id"))
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", name):
            raise WizardError("Zenarmor's service name was not understood. Start it on the firewall: open Zenarmor in its menu.")
        session = self._installer_session()
        engine = we.Engine(session, self.base_url.rstrip("/"), self._probe or {})
        if not self.window_gate(plan_digest("start-zenarmor", {"name": name}),
                                ["Start Zenarmor's engine", self._uses_words()]):
            raise WizardError("Not approved with a passkey. Nothing was changed.")
        try:
            engine._req("post", "/api/core/service/start/" + name)
        except we.WriteError as exc:
            raise WizardError(str(exc))
        running = None
        for _ in range(8):
            time.sleep(1.5)
            try:
                running = service_reads.zenarmor_running(getter(service_reads.SERVICES))
            except Exception:
                running = None
            if running:
                break
        acts = getattr(self, "_acts", None)
        if acts is not None and getattr(acts, "source", None) is not None:
            acts.source.forget()
        if running:
            return {"running": True, "setup": False, "lines": ["Zenarmor is running."], "can_undo": False}
        return {"running": False, "setup": True, "can_undo": False,
                "lines": ["The firewall was asked to start Zenarmor but it does not read as running. It does not run until its "
                          "own setup is finished: open that setup, accept its terms and go through its steps."]}

    GEOIP_SET = "/api/firewall/alias/set"
    GEOIP_RECONFIGURE = "/api/firewall/alias/reconfigure"
    GEOIP_WAIT = 600.0                 # the firewall downloads the ranges and loads millions of them in this one call

    def geoip_set_start(self, d) -> dict:
        """Give the firewall its country-range source from the manager, the way the firewall's own GeoIP settings page
        does it: save the link, then Apply (the firewall downloads the ranges and loads them). The link usually holds the
        person's own key, so it goes only to the firewall, only inside the approved job, and is never shown or kept."""
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        try:
            link = country_block.clean_source((d or {}).get("url") if isinstance(d, dict) else None)
        except ValueError as exc:
            raise WizardError(str(exc))
        return self._start("geoip-set", lambda: self._geoip_set_work(link))

    def _geoip_set_work(self, link: str) -> dict:
        from urllib.parse import urlparse
        from pazuzu_core import service_reads
        from pazuzu_core.passkey_gate import plan_digest
        getter = self._api_getter()
        if getter is None:
            raise WizardError("Not signed in to the firewall yet.")
        host = country_block.source_host(link)
        bits = urlparse(link).query.split("&") + [urlparse(link).username or "", urlparse(link).password or ""]
        secrets_ = sorted({link, *(b for b in bits if len(b) > 5), *(b.split("=", 1)[-1] for b in bits if len(b.split("=", 1)[-1]) > 5)},
                          key=len, reverse=True)

        def plain(msg: str) -> str:
            for bit in secrets_:
                msg = msg.replace(bit, "[your link]")
            return msg
        session = self._installer_session()
        engine = we.Engine(session, self.base_url.rstrip("/"), self._probe or {}, timeout=self.GEOIP_WAIT)
        if not self.window_gate(plan_digest("geoip-set", {"host": host}),
                                ["Set where the firewall gets its country ranges", "Your link goes to the firewall, from this device, and nowhere else (site: " + host + ")",
                                 "The firewall then downloads and loads the ranges, which can take a few minutes",
                                 self._uses_words()]):
            raise WizardError("Not approved with a passkey. Nothing was changed.")
        print("Saving the link on the firewall.")
        try:
            got = engine._req("post", self.GEOIP_SET, json={"alias": {"geoip": {"url": link}}})
        except we.WriteError as exc:
            raise WizardError(plain(str(exc)))
        if not (isinstance(got, dict) and str(got.get("result")).lower() == "saved"):
            raise WizardError("The firewall did not say it saved the link, so nothing more was done.")
        print("Loading the country ranges. This takes a few minutes.")
        try:
            engine._req("post", self.GEOIP_RECONFIGURE, json={})
        except we.WriteError as exc:
            raise WizardError("The link was saved, but loading the ranges did not finish: " + plain(str(exc))
                              + " Press Apply on the firewall's GeoIP settings page to load them.")
        try:
            ranges = service_reads.geoip_ranges(getter(service_reads.GEOIP))
        except Exception:
            ranges = None
        try:
            listed = (service_reads.table_count(getter(service_reads.TABLES), country_block.ALIAS) or {}).get("entries")
        except Exception:
            listed = None
        acts = getattr(self, "_acts", None)
        if acts is not None and getattr(acts, "source", None) is not None:
            acts.source.forget()
        lines = []
        if ranges:
            lines.append("The firewall loaded %s country ranges." % format(ranges, ","))
        else:
            lines.append("The link was saved and the firewall was told to load it, but it does not show any ranges yet. "
                         "Check the link is the country file, then try again.")
        if listed:
            lines.append("The blocked-countries list now holds %s of them, so the block is working." % format(listed, ","))
        elif ranges and country_block.load(self.key_dir) is not None:
            lines.append("The blocked-countries list does not show any yet. The board reads it again in a minute.")
        return {"ranges": ranges, "listed": listed, "loaded": bool(ranges), "lines": lines, "can_undo": False}

    def ipv6_off_start(self) -> dict:
        """IPv6 off from the manager's levels, for the top step: the same two things the setup page's first stage does (the
        IPv6 type None on the WAN and the LAN through the plugin, then the firewall-wide box), each read back, on this
        one passkey. It is not a rules change, so it has no timer and no undo; the firewall's own pages undo it."""
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        return self._start("ipv6-off", self._ipv6_off_work)

    def _ipv6_off_work(self) -> dict:
        from pazuzu_core import ipv6_off
        from pazuzu_core.passkey_gate import plan_digest
        ifaces = self._ipv6_iface_todo()
        glob = self._ipv6_state() != "off"                 # unreadable counts as "look": the step reads it again itself
        if not ifaces and not glob:
            raise WizardError("IPv6 is already off. Nothing was changed.")
        lines = ["Turn IPv6 off"]
        if ifaces:
            lines.append(ipv6_off.IFACES_LINE)
        lines.append("Turn IPv6 off for the whole firewall (Interfaces, Settings, the Turn off IPv6 box).")
        lines.append("Each is read back to check. Nothing else is touched.")
        if not self.window_gate(plan_digest("ipv6-off", {"interfaces": bool(ifaces)}), lines):
            raise WizardError("Not approved with a passkey. Nothing was changed.")
        entry: dict = {}
        ok = self._ipv6_stage(entry)
        acts = getattr(self, "_acts", None)
        if acts is not None and getattr(acts, "source", None) is not None:
            acts.source.forget()
        if not ok:
            raise WizardError(str(entry.get("detail") or "IPv6 could not be switched off."))
        return {"lines": [str(entry.get("detail") or "IPv6 is off.")], "can_undo": False}

    def _time_service_work(self) -> dict:
        """Start the firewall's time service through the firewall's own service call, then read it back. Not a
        settings change: nothing is saved, so there is nothing to undo."""
        from pazuzu_core import service_reads
        from pazuzu_core.passkey_gate import plan_digest
        session = self._installer_session()
        engine = we.Engine(session, self.base_url.rstrip("/"), self._probe or {})
        getter = self._api_getter()
        if getter is None:
            raise WizardError("Not signed in to the firewall yet.")
        try:
            rows = getter("/api/core/service/search").get("rows") or []
        except Exception as exc:
            raise WizardError("Could not read the firewall's service list: " + _plain_firewall(exc))
        mine = [r for r in rows if isinstance(r, dict) and "ntpd" in (str(r.get("name")) + " " + str(r.get("id"))).lower()]
        if len(mine) != 1:
            raise WizardError("The firewall's service list has no single time service, so Pazuzu did not guess. "
                              "Start it on the firewall: Services, Network Time.")
        name = str(mine[0].get("name") or mine[0].get("id"))
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", name):
            raise WizardError("The time service's name was not understood. Start it on the firewall: Services, Network Time.")
        if not self.window_gate(plan_digest("start-time-service", {"name": name}),
                                ["Start the firewall's time service", self._uses_words()]):
            raise WizardError("Not approved with a passkey. Nothing was changed.")
        try:
            engine._req("post", "/api/core/service/start/" + name)
        except we.WriteError as exc:
            raise WizardError(str(exc))
        running = None
        for _ in range(5):
            time.sleep(1.0)
            running = service_reads.ntp_state(getter)
            if running:
                break
        acts = getattr(self, "_acts", None)
        if acts is not None and getattr(acts, "source", None) is not None:
            acts.source.forget()
        line = ("The time service is running." if running else
                "The firewall was asked to start it but it does not read as running. Look at Services, Network Time.")
        return {"running": bool(running), "read": running is not None, "lines": [line], "can_undo": False}

    def levels_set(self, level) -> dict:
        from pazuzu_core import shield_levels as sl
        try:
            idx = int(level)
        except (TypeError, ValueError):
            raise WizardError("That level was not understood.")
        if idx not in sl.SETTABLE:
            raise WizardError("Only Warning, Caution, Secure and Normal can be set here.")
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        if not self.levels_state()["ready"]:
            raise WizardError(self.levels_state()["why"] or "This firewall has not been checked for this yet.")

        def plans(e):
            try:
                out = shield_plans(e)
            except WizardError as exc:
                if "already at that level" not in str(exc) or idx != 4:
                    raise
                out = []
            if idx == 4:                                   # Happy: the rest of what a green board needs
                out += self._happy_extras(e)
            if not out:
                raise WizardError("The shields are already at that level.")
            return out

        def shield_plans(e):
            ids = e._template(we.CAPS["ids_general"])[1]
            grid = e.ready("dnsbl_entry")[0]
            if grid:
                entry_form = e._template(we.CAPS["dnsbl_entry"])[1]
                flags = sl.read_flags_grid(ids, entry_form.get("type"), e._rows(we.CAPS["dnsbl_entry"]))
            else:
                unb = e._template(we.CAPS["unbound_dnsbl"])[1]
                flags = sl.read_flags(ids, unb)
            want = sl.wanted(idx)
            if grid:
                try:
                    adds = sl.entries_to_add(idx, flags, self._recall("shield_types") or {})
                except sl.LevelsError as exc:
                    raise WizardError(str(exc))
                out = []
                if flags["ips"] != want["ips"]:
                    out.append(self._ids_plan(e, want["ips"]))
                for shield, keys in adds:
                    from pazuzu_core import ddns_setup as dd
                    vals = {"enabled": True, "type": ",".join(keys),
                            "description": "Pazuzu: " + ("ad lists" if shield == "ads" else "block lists")}
                    if "allowlists" in entry_form:          # BUILD 455: the address lookups stay reachable
                        vals["allowlists"] = dd.merge_allow("", self._every_allow_host(e))
                    out.append(e.build("dnsbl_entry", vals))
                if adds:
                    self._remember("shield_types", {"ads": [k for k in flags["chosen"] if k in flags["ads_keys"]],
                                                    "block": [k for k in flags["chosen"] if k in flags["block_keys"]]})
                if not out:
                    raise WizardError("The shields are already at that level.")
                return out
            try:
                types = sl.types_for(idx, flags, self._recall("shield_types") or {})
            except sl.LevelsError as exc:
                raise WizardError(str(exc))
            out = []
            if flags["ips"] != want["ips"]:
                out.append(self._ids_plan(e, want["ips"]))
            now = sorted(flags["chosen"])
            dns_on = want["block"] or want["ads"]
            if sorted(types) != now or dns_on != (str(_dig_form(unb, "dnsbl.enabled")) == "1"):
                self._remember("shield_types", {"ads": [k for k in flags["chosen"] if k in flags["ads_keys"]],
                                                "block": [k for k in flags["chosen"] if k in flags["block_keys"]]})
                vals = {"dnsbl.enabled": dns_on, "dnsbl.type": ",".join(types)}
                if dns_on and _dig_form(unb, "dnsbl.whitelists") is not None:   # BUILD 455: the address lookups stay reachable
                    from pazuzu_core import ddns_setup as dd
                    vals["dnsbl.whitelists"] = dd.merge_allow(we._value_of(_dig_form(unb, "dnsbl.whitelists")),
                                                              self._every_allow_host(e))
                out.append(e.build("unbound_dnsbl", vals))
            if not out:
                raise WizardError("The shields are already at that level.")
            return out
        def rulesets(result: dict) -> None:
            # Packet inspection with no rulesets installed has nothing to match: when this level wants it, the
            # baseline's rulesets go on and are downloaded in the same run (the same touch covers it).
            if not sl.wanted(idx)["ips"]:
                return
            from pazuzu_core import ids_rulesets
            try:
                eng = we.Engine(self._installer_session(), self.base_url.rstrip("/"), self._probe)
                result["lines"] = list(result.get("lines") or []) + self._ids_apply(eng._req)
            except Exception as exc:  # noqa: BLE001
                result["lines"] = list(result.get("lines") or []) + [f"Packet inspection's rulesets were not set: {_plain_firewall(exc)}"]
        return self._write_job("shield-levels", plans, {"level": idx}, after=rulesets)

    # -- the VPN tab in the manager: what is there, and the two things it can do
    def vpn_state(self) -> dict:
        from pazuzu_core import wireguard_setup as wgs
        zones = self.status().get("zones") or {}
        caps = we.readiness(self._probe)
        need = [caps[c] for c in ("wg_general", "wg_server", "wg_client")]
        out = {"ports_set": bool(zones.get("deployable")), "checked": bool(self._probe),
               "can_make": bool(caps["wg_general"]["ready"] and caps["wg_server"]["ready"]),
               "can_device": bool(caps["wg_client"]["ready"]),
               "why": next((c["why"] for c in need if not c["ready"]), ""),
               "instance": None, "devices": [], "host": self._recall("vpn_host") or "",
               "suggest": None, "read_error": None, "host_guess": "", "find": self.ddns_state()}
        getter = self._api_getter()
        if getter is not None:
            try:
                servers = [r for r in (getter("/api/wireguard/server/search_server").get("rows") or [])
                           if isinstance(r, dict) and str(r.get("enabled", "1")) != "0"]
                clients = [r for r in (getter("/api/wireguard/client/search_client").get("rows") or [])
                           if isinstance(r, dict)]
                if servers:
                    sv = servers[0]
                    out["instance"] = {"name": str(sv.get("name") or ""), "port": str(sv.get("port") or ""),
                                       "tunneladdress": str(sv.get("tunneladdress") or ""),
                                       "public_key": str(sv.get("pubkey") or "")}
                out["devices"] = [{"name": str(c.get("name") or ""), "address": str(c.get("tunneladdress") or "")}
                                  for c in clients]
                gen = getter("/api/wireguard/general/get") or {}
                en_ = (gen.get("general") or {}).get("enabled") if isinstance(gen, dict) else None
                if en_ is not None:                          # WireGuard itself switched on (System: the VPN's own switch)
                    out["service_on"] = str(en_) in ("1", "true", "True")
            except Exception as exc:
                out["read_error"] = _plain_firewall(exc)
        if not out["host"]:
            out["host_guess"] = self._wan_address()
        if out["instance"] is None:
            if getattr(self, "_vpn_suggest", None) is None:
                import secrets as _s
                plan = wgs.plan_wireguard(tunnel_subnet=f"10.{64 + _s.randbelow(64)}.{1 + _s.randbelow(253)}.0/24",
                                          listen_on=("wan",))
                self._vpn_suggest = {"name": "home", "port": str(plan.listen_port), "address": plan.server_address}
            out["suggest"] = self._vpn_suggest
        return out

    def vpn_device(self, d) -> dict:
        """Make the keys for one device here, start the passkey-approved add, and hand back the phone's
        settings (shown once, never kept)."""
        d = d if isinstance(d, dict) else {}
        st = self.vpn_state()
        inst = st["instance"]
        if not inst or not inst["public_key"]:
            raise WizardError("Make the VPN first. Pazuzu could not read its public key from the firewall.")
        if st.get("service_on") is False:
            raise WizardError("The VPN is made but switched off on the firewall. Switch it on first, then add devices.")
        used = [x["address"] for x in st["devices"]]
        try:
            addr = vpn_peer.next_free_address(inst["tunneladdress"], used)
        except vpn_peer.PeerError as exc:
            raise WizardError(str(exc))
        mode = "full" if d.get("full") is True else "home"
        nets = str(d.get("networks") or "").strip() or self._home_networks()
        host = str(d.get("host") or "").strip()
        r = self.vpn_peer_new({"name": d.get("name"), "server_public": inst["public_key"], "host": host,
                               "port": inst["port"], "address": addr, "mode": mode, "networks": nets,
                               # a full tunnel asks the firewall for names (filtered, like at home): on the address
                               # Pazuzu reaches it by, which Unbound listens on (it is not on the tunnel's own address)
                               "dns": (base_host_port(self.base_url)[0] if mode == "full" else "")})
        self._remember("vpn_host", host)
        self.write_vpn_peer({"name": r["device"], "public": r["public"], "address": r["address"].split("/")[0]})
        return {"device": r["device"], "address": r["address"], "svg": r["svg"], "config": r["config"]}

    def _wan_address(self) -> str:
        """The firewall's own internet-side address, when it is a public one (a private one means another router is in front)."""
        import ipaddress
        getter = self._api_getter()
        if getter is None:
            return ""
        try:
            rows = getter("/api/interfaces/overview/interfaces_info/true").get("rows") or []
        except Exception:
            return ""
        for r in rows:
            if not isinstance(r, dict) or str(r.get("identifier")) != "wan":
                continue
            cand = r.get("addr4") if isinstance(r.get("addr4"), list) else [r.get("addr4")]
            for c in cand:
                try:
                    ip = ipaddress.ip_interface(str(c)).ip
                except ValueError:
                    continue
                if ip.version == 4 and ip.is_global:
                    return str(ip)
        return ""

    def _way_in_words(self) -> str:
        """A way in that is not a management port: the VPN (a switched-on WireGuard instance on the firewall, by the
        wizard's memory or a read), or a bonded Bluetooth door the box reports. "" when there is none. BUILD 434."""
        try:
            self._vpn_already_there()
        except Exception:  # noqa: BLE001
            pass
        words = []
        if self._recall("vpn_instance"):
            words.append("the VPN")
        try:
            st = (self._acts.source.box.read() or {}).get("status") if (self._acts is not None and self._box_up()) else {}
            bt = (st or {}).get("bluetooth") if isinstance(st, dict) else None
            if isinstance(bt, dict) and bt.get("bonded"):
                words.append("the Bluetooth door")
        except Exception:  # noqa: BLE001
            pass
        return " and ".join(words)

    def _bind_vpn_zone(self) -> None:
        """The VPN's zone (wireguard_admin) bound to the firewall's WireGuard interface when one is assigned, so the
        lifeline rule for the VPN (PZ-MGMT-002) can be made instead of skipped as "no configured source zone"."""
        try:
            current = (self.status().get("zones") or {}).get("assignments") or {}
            if (current.get("wireguard_admin") or {}).get("device"):
                return
            wg = [i for i in self.interfaces()["interfaces"]
                  if str(i.get("device") or "").startswith("wg") and i.get("assigned") and i.get("identifier")]
            if wg:
                self.zone_set("wireguard_admin", str(wg[0]["device"]))
        except Exception:  # noqa: BLE001 - a read that did not work changes nothing
            pass

    def _vpn_already_there(self) -> None:
        """Ask the firewall (a read) whether it already has a switched-on VPN, and if so remember it. "Is the VPN set up"
        was answered from this wizard's memory alone, so a VPN made earlier (by hand, or before the memory was cleared)
        was nagged about for ever. A firewall that cannot be read leaves the memory as it is. Asked at most every 30
        seconds, and every two minutes after a failed read."""
        if self.keys_state in ("stale", "none") or self._recall("vpn_instance"):
            return
        now = time.monotonic()
        last = getattr(self, "_vpn_looked", None)
        if last is not None and now - last[0] < (30 if last[1] is not None else 120):
            return
        got = None
        getter = self._api_getter()
        if getter is not None:
            try:
                rows = (getter("/api/wireguard/server/search_server") or {}).get("rows") or []
                got = [r for r in rows if isinstance(r, dict) and str(r.get("enabled", "1")) != "0"]
            except Exception:                                  # noqa: BLE001 (cannot read: change nothing)
                got = None
        self._vpn_looked = (now, got)
        if got:
            sv = got[0]
            self._remember("vpn_instance", {"public_key": str(sv.get("pubkey") or ""),
                                            "tunneladdress": str(sv.get("tunneladdress") or ""),
                                            "port": str(sv.get("port") or "")})
            self._bind_vpn_zone()

    WIFI_LOOK_SECONDS = 120

    def _wifi_card_names(self) -> list:
        """The Wi-Fi cards the plugin sees on this firewall, by name (iwn0, run0...). Empty when it says there is none, and
        also when it cannot say (no plugin answering, or one older than 0.6.1). Read at most every two minutes, so a USB
        card plugged in later still shows up."""
        now = time.monotonic()
        last = getattr(self, "_wifi_looked", None)
        if last is not None and now - last[0] < self.WIFI_LOOK_SECONDS:
            return list(last[1])
        names: list = []
        try:
            if self._box_up():
                box = self._acts.source.box
                got = box.hardware_status() if box.can("hardware") else None
                if isinstance(got, dict) and isinstance(got.get("wifi"), list):
                    names = [str(n) for n in got["wifi"] if isinstance(n, str)]
        except Exception:                                  # noqa: BLE001 (cannot read: no Wi-Fi reminders)
            names = []
        self._wifi_looked = (now, names)
        return list(names)

    def _radios(self) -> list:
        """The Wi-Fi cards that can host a zone's own network: [{"card", "label", "free"}]. A card is offered when its
        driver is one this box has hosted on (run, rtwn), it never refused to host, and it has no Wi-Fi network on the
        firewall yet (each hosts one: the hotspot backup's or the back door's card is taken)."""
        from pazuzu_core import zone_vlans as zv
        cards = [c for c in self._wifi_card_names() if zv.can_host(c)]
        cards.sort(key=lambda c: 0 if c.startswith("run") else 1)     # BUILD 508: Hanbi's own card first, rtwn after it
        cant = set(c for c in (self._recall("wifi_cannot_host") or []) if isinstance(c, str))
        busy: set = set()
        getter = self._api_getter() if cards else None
        if getter is not None:
            try:
                busy = {str(r.get("if") or "") for r in (getter(zv.WL + "/search_item?rowCount=-1&searchPhrase=") or {})
                        .get("rows") or [] if isinstance(r, dict)}
            except Exception:  # noqa: BLE001
                busy = set()
        return [{"card": c, "label": f"Wi-Fi card {c} (2.4 GHz)", "free": c not in cant and c not in busy}
                for c in cards if c not in cant]

    def _wifi_cards_known(self) -> bool:
        """Has the plugin seen a Wi-Fi card on this firewall? The Wi-Fi things need the plugin and a card either way."""
        return bool(self._wifi_card_names())

    def _wifi_can_host(self) -> bool:
        """Is there a card that has not already said it cannot host a network? A card that refused (iwn: "Operation not
        supported") is remembered by name, so the back door reminder stops for it, and a new card plugged in brings it back."""
        names = self._wifi_card_names()
        cant = [c for c in (self._recall("wifi_cannot_host") or []) if isinstance(c, str)]
        return not names or any(n not in cant for n in names)

    def _root_factory(self) -> bool:
        """Root still on the factory password, as the plugin reads it on the firewall. Asked at most every two minutes."""
        now = time.monotonic()
        last = getattr(self, "_root_looked", None)
        if last is not None and now - last[0] < 120:
            return last[1]
        bad = False
        try:
            if self._box_up():
                got = self._acts.source.box.root_check()
                bad = bool(isinstance(got, dict) and got.get("root") == "default")
        except Exception:  # noqa: BLE001
            bad = False
        self._root_looked = (now, bad)
        return bad

    DDNS_LOOK_SECONDS = 120

    def _ddns_from_firewall(self) -> None:
        """A name already kept up to date by the firewall's own DynDNS (set up here, or by hand on the firewall) counts:
        it is remembered as the way home, so the reminder leaves. Read at most every two minutes."""
        now = time.monotonic()
        last = getattr(self, "_ddns_looked", None)
        if last is not None and now - last < self.DDNS_LOOK_SECONDS:
            return
        self._ddns_looked = now
        from pazuzu_core import ddns_setup as dd
        if self._recall("ddns_name"):
            # BUILD 473: a name already known counts as the way home too (three names updating, and the bar still
            # said none was set up, because a known name returned here before the choice was ever set)
            names = [str(self._recall("ddns_name"))]
        else:
            getter = self._api_getter()
            if getter is None:
                return
            try:
                rows = (getter("/api/dyndns/accounts/search_item") or {}).get("rows") or []
            except Exception:  # noqa: BLE001 (no DynDNS plugin, or not allowed: nothing to learn)
                return
            names = [dd.shown_name(r.get("hostnames")).split(",")[0].strip() for r in rows
                     if isinstance(r, dict) and str(r.get("enabled", "1")) != "0" and r.get("hostnames")]
            names = [n for n in names if n]
        if names:
            self._remember("ddns_name", names[0])
            if not self._recall("vpn_host"):
                self._remember("vpn_host", names[0])
            if (self._recall("host_choice") or "") not in ("domain", "ddns"):
                self._remember("host_choice", "ddns")

    SUGGEST_AT = 50                 # blocks of one kind from one device before it is worth a suggestion
    SUGGEST_UDP_PORTS = 8           # different UDP ports to the internet from one device: live video

    def allow_suggestions(self) -> list:
        """What a device keeps being stopped from, turned into one offer each (BUILD 426, from the box's own counts):
        a port to the internet ("out"), your home network reaching a device ("home"), or a doorbell's live video
        ("udp"). Each carries the exact allow it would make, so one tap (and the passkey) does it. Already-allowed ones
        and the baseline's own refusals (QUIC, time, DNS) are left out."""
        from pazuzu_core import block_allow as ba
        from pazuzu_core import iot_cloud
        try:
            from hanbi_box import names as hn
        except ImportError:                  # BUILD 513: no plugin in this build, so no counts to make offers from
            return []
        try:
            st = (self._acts.source.box.read() or {}).get("status") if (self._acts is not None and self._box_up()) else None
        except Exception:
            st = None
        if not isinstance(st, dict):
            return []
        top = st.get("top") or {}
        clients = {str(c.get("ip")): c for c in st.get("clients") or [] if isinstance(c, dict)}
        names = st.get("names") or {}
        wan = st.get("wan_iface")

        def who(ip):
            c = clients.get(ip) or {}
            nm = c.get("name") or names.get(ip)
            if hn.placeholder(nm):              # BUILD 492: "wlan0" names nothing (a plugin older than 0.6.99 still sends it)
                nm = ""
            return str(nm or c.get("vendor") or ip), str(c.get("mac") or "").lower(), str(c.get("iface") or "")

        have = set()
        getter = None
        try:
            getter = self._api_getter()
            rows = (getter("/api/firewall/filter/search_rule?rowCount=-1&searchPhrase=" + "Pazuzu%3A%20allow") or {}).get("rows") or [] if getter else []
            have = {str(r.get("description") or "") for r in rows if isinstance(r, dict)}
        except Exception:
            have = set()
        try:
            cloud = self._cloud_gap(getter) if getter is not None else None
        except Exception:  # noqa: BLE001 - the bars go on without it
            cloud = None
        words = dict(iot_cloud.PORTS)

        def on_iot(ip):
            try:
                return cloud is not None and ipaddress.ip_address(str(ip)) in cloud["net"]
            except ValueError:
                return False

        def port_words(proto, dport):
            return f" ({words[dport]})" if proto == "tcp" and dport in words else ""
        out = []
        ignored = self._ignored_offers()
        # BUILD 492 (Tuya bulbs offline): a smart device's cloud port that the smart devices' list
        # leaves out is one bar for every device on the IoT network asking for it, first, and one tap puts it on the
        # list. Three bulbs had a bar each (one shown, two cut off at six), and each tap fixed one bulb.
        gaps: dict = {}
        for r in top.get("needs") or []:
            proto, dport = str(r.get("proto")), str(r.get("dport"))
            if (str(r.get("where")) == "out" and proto == "tcp" and dport in words and cloud is not None
                    and dport not in cloud["listed"] and on_iot(r.get("src"))):
                g = gaps.setdefault(dport, {"count": 0, "who": []})
                g["count"] += int(r.get("count") or 0)
                g["who"].append(who(str(r.get("src")))[0])
        for dport, g in sorted(gaps.items(), key=lambda kv: -kv[1]["count"]):
            if g["count"] < self.SUGGEST_AT:
                continue
            n, seen = len(g["who"]), sorted(set(g["who"]))
            said = ", ".join(seen[:3]) + (", and more" if len(seen) > 3 else "")
            lead = (f"{n} smart devices on the IoT network keep asking" if n != 1
                    else "A smart device on the IoT network keeps asking")
            app = "Their apps probably show them offline" if n != 1 else "Its app probably shows it offline"
            out.append({"text": (f"{lead} the internet on TCP port {dport} ({words[dport]}), {g['count']} times, blocked: "
                                 f"{said}. {app}. Put {dport} on the smart devices' list, so every smart device there may "
                                 "use it, internet only?"),
                        "label": "Add it", "promote": {"port": dport}})
        for r in top.get("spread") or []:
            if r.get("proto") != "udp" or int(r.get("ports") or 0) < self.SUGGEST_UDP_PORTS:
                continue
            name, mac, iface = who(str(r.get("src")))
            if not mac or not iface or iface == wan or ba.keep_description("udp", mac, "udp", "") in have:
                continue
            if self._offer_key(mac or r["src"], "udp", "*") in ignored:
                continue
            out.append({"text": f"{name} keeps trying many different UDP ports to the internet ({r['count']} times): that is how a "
                                "doorbell or camera sends live video. Let it, to the internet only?",
                        "label": "Allow live video", "allow": {"src": r["src"], "proto": "udp", "dport": "443", "device": iface,
                                                                "kind": "udp", "mac": mac, "name": name}})
        for r in top.get("needs") or []:
            if int(r.get("count") or 0) < self.SUGGEST_AT:
                continue
            proto, dport, where = str(r.get("proto")), str(r.get("dport")), str(r.get("where"))
            if (proto, dport) in (("udp", "443"), ("udp", "123"), ("udp", "53"), ("tcp", "53"), ("tcp", "853"), ("udp", "853")):
                continue                                             # the baseline turns these away on purpose
            name, mac, iface = who(str(r.get("src")))
            if not iface or iface == wan:
                continue
            if self._offer_key(mac or str(r.get("src")), proto, dport) in ignored:
                continue                                             # you said: not this one (Ignore on the bar)
            if where == "home":
                tname, tmac, _ti = who(str(r.get("dst")))
                if not tmac or ba.keep_description("home", tmac, proto, dport) in have:
                    continue
                out.append({"text": f"{name} keeps trying to reach {tname} on your other network ({proto.upper()} {dport}, "
                                    f"{r['count']} times). Let your home network reach {tname} on that port? "
                                    "It still cannot start anything toward your home.",
                            "label": "Allow it", "allow": {"src": r["src"], "proto": proto, "dport": dport, "device": iface,
                                                           "kind": "home", "mac": tmac, "target": r["dst"], "name": tname}})
            elif where == "out":
                if not mac or ba.keep_description("out", mac, proto, dport) in have:
                    continue
                if any(x.get("allow", {}).get("kind") == "udp" and x["allow"]["src"] == r["src"] for x in out):
                    continue                                         # its live-video offer covers this
                if proto == "tcp" and on_iot(r.get("src")) and (dport in gaps or dport in cloud["listed"]):
                    continue                                         # the smart devices' list covers it (BUILD 492)
                out.append({"text": f"{name} keeps asking the internet on {proto.upper()} port {dport}{port_words(proto, dport)} "
                                    f"({r['count']} times, blocked). Its app probably shows it offline. Let it, to the internet only?",
                            "label": "Allow it", "allow": {"src": r["src"], "proto": proto, "dport": dport, "device": iface,
                                                           "kind": "out", "mac": mac, "name": name}})
        return out[:6]

    # -- Ignore on an offer (BUILD 434): kept on this PC by device and port; the bar leaves and stays away
    IGNORED_FILE = "ignored_offers.json"

    @staticmethod
    def _offer_key(who: str, proto: str, dport: str) -> str:
        return f"{str(who or '').lower()}|{str(proto or '').lower()}|{str(dport or '')}"

    def _ignored_offers(self) -> dict:
        try:
            got = json.loads((self.key_dir / self.IGNORED_FILE).read_text(encoding="utf-8"))
            return got if isinstance(got, dict) else {}
        except (OSError, ValueError, AttributeError):          # no key folder (a bare test wizard): nothing ignored
            return {}

    def _save_ignored(self, got: dict) -> None:
        try:
            self.key_dir.mkdir(parents=True, exist_ok=True)
            (self.key_dir / self.IGNORED_FILE).write_text(json.dumps(got, indent=1, sort_keys=True), encoding="utf-8")
        except OSError:
            raise WizardError("Could not save that.")
        self._suggest_at = None

    def ignore_offer(self, d) -> dict:
        """Ignore one offer: {"allow": the offer's allow} (or {"key"} to bring one back with "forget": true)."""
        d = d if isinstance(d, dict) else {}
        got = self._ignored_offers()
        if d.get("forget"):
            got.pop(str(d.get("key") or ""), None)
            self._save_ignored(got)
            return self.ignored_offers()
        al = d.get("allow") if isinstance(d.get("allow"), dict) else {}
        who = str(al.get("mac") or al.get("src") or "")
        proto, dport = str(al.get("proto") or ""), "*" if al.get("kind") == "udp" else str(al.get("dport") or "")
        if not who or not proto:
            raise WizardError("That offer was not understood.")
        key = self._offer_key(who, proto, dport)
        got[key] = {"name": str(al.get("name") or who)[:60], "proto": proto, "dport": dport, "kind": str(al.get("kind") or "out"),
                    "at": int(time.time())}
        self._save_ignored(got)
        return self.ignored_offers()

    def ignored_offers(self) -> dict:
        got = self._ignored_offers()
        return {"ignored": [{"key": k, **v} for k, v in sorted(got.items(), key=lambda kv: -int(kv[1].get("at") or 0))]}

    def promote_suggestions(self) -> list:
        """When Always has been tapped for the same port on two or more devices of the same maker, offer to put that port
        on the smart devices' list (IoT_cloud_ports), so the next such device needs no tap."""
        from pazuzu_core import iot_cloud
        try:
            getter = self._api_getter()
            if getter is None:
                return []
            rows = (getter("/api/firewall/filter/search_rule?rowCount=-1&searchPhrase=" + "Pazuzu%3A%20allow") or {}).get("rows") or []
            aliases = (getter("/api/firewall/alias/search_item?rowCount=-1&searchPhrase=IoT_cloud_ports") or {}).get("rows") or []
            st = (self._acts.source.box.read() or {}).get("status") if (self._acts is not None and self._box_up()) else {}
        except Exception:
            return []
        listed = set(iot_cloud._list(next((a.get("content") for a in aliases if isinstance(a, dict) and a.get("name") == iot_cloud.ALIAS), "")))
        makers = {str(c.get("mac") or "").lower(): str(c.get("vendor") or "") for c in (st or {}).get("clients") or [] if isinstance(c, dict)}
        by_port: dict = {}
        for r in rows:
            m = re.match(r"^Pazuzu: allow ([0-9a-f:]{17}) (tcp)/(\d+) out$", str(r.get("description") or ""))
            if m and m.group(3) not in listed:
                by_port.setdefault(m.group(3), set()).add(makers.get(m.group(1)) or m.group(1))
        out = []
        for port, who in sorted(by_port.items()):
            if len(who) >= 2:
                out.append({"text": f"Two or more devices needed TCP port {port} ({', '.join(sorted(who)[:3])}). Put it on the smart "
                                    "devices' list, so the next one needs no tap?", "label": "Add it",
                            "promote": {"port": port}})
        return out

    def promote_port(self, d) -> dict:
        from pazuzu_core import iot_cloud
        port = str((d or {}).get("port") or "")
        if not (port.isdigit() and 1 <= int(port) <= 65535):
            raise WizardError("That is not a port.")

        def run(engine, gate):
            row = engine._one_row(we.CAPS["cloud_alias"], iot_cloud.ALIAS)
            if row is None:
                raise we.WriteError("The smart devices' list is not on the firewall yet: Finish getting to Happy makes it.")
            have = iot_cloud._list(row.get("content"))
            if port in have:
                return [], [f"Port {port} is already on the list."]
            out = engine.change_text("cloud_alias", iot_cloud.ALIAS, "content", "\n".join(have + [port]), gate,
                                     say=f"Add TCP port {port} to the smart devices' list (internet only)")
            return [out], [f"Port {port} is on the smart devices' list: every device on that network may use it, internet only."]

        return self._engine_job("promote-port", run)

    def feedback_save(self, d) -> dict:
        """BUILD 493 (the maintainer: the feedback button, "offered right after anything fails"). One report, saved on this PC in
        a folder called feedback, holding only what the sheet shows: versions, the mode, the step, the last job's error
        and the person's own words. No screenshot is taken and nothing is sent anywhere; the page offers a mail draft,
        and sending to hanbi.net comes once its endpoint is live."""
        import uuid
        d = d if isinstance(d, dict) else {}
        job = self._job_view() or {}
        plugin = ""
        try:
            st = (self._acts.source.box.read() or {}).get("status") if (self._acts is not None and self._box_up()) else {}
            plugin = str((st or {}).get("version") or (st or {}).get("plugin") or "")
            if not plugin and self._acts is not None:      # BUILD 506: the feed's status has no version; its ping does
                plugin = str(self._acts.source.box.version() or "")
        except Exception:  # noqa: BLE001
            plugin = ""
        ref = uuid.uuid4().hex[:6]
        report = {"report_id": str(uuid.uuid4()), "ref": ref, "app": "pazuzu", "build": str(BUILD), "plugin": plugin,   # BUILD 519: hanbi.net answered "build must be text" (a number was sent)
                  "opnsense": str(d.get("opnsense") or getattr(self, "_fw_version", "") or ""),
                  "mode": "new" if self.light else "running",
                  "step": str(d.get("step") or "")[:120],
                  "error": str(d.get("error") or job.get("error") or "")[:2000],
                  "job": {k: job.get(k) for k in ("kind", "state", "error") if job.get(k)},
                  "note": str(d.get("note") or "")[:4000],
                  "created": time.strftime("%Y-%m-%dT%H:%M:%S")}
        folder = Path("feedback")
        try:
            folder.mkdir(parents=True, exist_ok=True)
            path = folder / f"report-{time.strftime('%Y%m%d-%H%M%S')}-{ref}.json"
            path.write_text(json.dumps(report, indent=1), encoding="utf-8")
        except OSError as exc:
            raise WizardError("The report could not be saved: " + _plain(exc))
        return {"ref": ref, "path": str(path.resolve()),
                "mailto": ("mailto:feedback@hanbi.net?subject=" + f"Pazuzu beta report {ref} (build {BUILD})"
                           + "&body=" + "Please attach the saved report file named above, and a screenshot if one helps."
                           + " Blank out anything on it you would rather keep private.")}

    FEEDBACK_URL = "https://hanbi.net/api/feedback"
    FEEDBACK_SHOT_MAX = 5 * 1024 * 1024

    @staticmethod
    def _beta_token() -> str:
        """The shared beta value the feedback endpoint asks for: not a secret, only there to keep out drive-by spam.
        From PAZUZU_BETA_TOKEN, else pazuzu_core/beta_token.txt, which the beta build puts in (never in git)."""
        tok = os.environ.get("PAZUZU_BETA_TOKEN", "").strip()
        if not tok:
            try:
                # utf-8-sig: a file made by hand in Notepad may start with a byte-order mark (the maintainer, 10 Nov 2026)
                tok = (Path(__file__).with_name("beta_token.txt")).read_text(encoding="utf-8-sig").strip()
            except OSError:
                tok = ""
        return tok if re.fullmatch(r"[A-Za-z0-9._~+/=-]{8,200}", tok or "") else ""

    def feedback_send(self, d) -> dict:
        """BUILD 497: Send report. Consent is asked at each send, on the form,
        apart from the Welcome switches; without the tick nothing is sent. The report is saved here first (its words,
        never the screenshot), then sent to hanbi.net with the screenshot only if the person attached one. With no
        beta token in this build, or no answer from hanbi.net, it stays saved here and a mail draft is offered."""
        import base64
        import urllib.request
        import uuid
        d = d if isinstance(d, dict) else {}
        if d.get("consent") is not True:
            raise WizardError("Tick the box to agree before the report is sent. Nothing was sent.")
        shot, shot_type = b"", ""
        if d.get("screenshot"):
            try:
                shot = base64.b64decode(str(d.get("screenshot")), validate=True)
            except ValueError:
                raise WizardError("The screenshot could not be read. Nothing was sent.")
            if len(shot) > self.FEEDBACK_SHOT_MAX:
                raise WizardError("The screenshot is over 5 MB. Attach a smaller one. Nothing was sent.")
            shot_type = ("image/png" if shot[:8] == b"\x89PNG\r\n\x1a\n" else
                         "image/jpeg" if shot[:3] == b"\xff\xd8\xff" else "")
            if not shot_type:
                raise WizardError("The screenshot must be a PNG or JPEG picture. Nothing was sent.")
        saved = self.feedback_save(d)
        report = json.loads(Path(saved["path"]).read_text(encoding="utf-8"))
        token = self._beta_token()
        if not token:
            return {**saved, "sent": False, "why": "This build has no way to send reports yet."}
        boundary = "pz" + uuid.uuid4().hex
        parts = [("report", "report.json", "application/json", json.dumps(report).encode("utf-8"))]
        if shot:
            parts.append(("screenshot", "screenshot." + ("png" if shot_type == "image/png" else "jpg"), shot_type, shot))
        body = b""
        for name, fname, ctype, data in parts:
            body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{fname}\"\r\n"
                     f"Content-Type: {ctype}\r\n\r\n").encode() + data + b"\r\n"
        body += f"--{boundary}--\r\n".encode()
        req = urllib.request.Request(self.FEEDBACK_URL, data=body, method="POST", headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}", "X-Pazuzu-Beta": token,
            "User-Agent": f"Pazuzu/{BUILD}"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                got = json.loads(r.read().decode("utf-8") or "{}")
            ref = str(got.get("ref") or "")
            if not re.fullmatch(r"[A-Za-z0-9]{4,16}", ref):
                raise ValueError("no ref")
        except Exception as exc:  # noqa: BLE001 - kept here and offered by mail instead
            code = getattr(exc, "code", None)
            why = {400: "hanbi.net did not understand the report", 403: "hanbi.net turned this build away",
                   413: "the report is too big", 429: "too many reports were sent in the last hour"}.get(code,
                   "hanbi.net could not be reached")
            said = ""
            try:                                       # BUILD 506 (the maintainer, 11 Nov 2026): say what hanbi.net said, if it did
                raw = exc.read(2048) if hasattr(exc, "read") else b""
                got = json.loads(raw.decode("utf-8", "replace") or "{}") if raw else {}
                said = re.sub(r"[^\w .,:;'()/@-]", "", str(got.get("error") or got.get("message") or ""))[:160].strip()
            except Exception:  # noqa: BLE001
                said = ""
            try:
                report["send_failed"] = {"code": code, "said": said}
                Path(saved["path"]).write_text(json.dumps(report, indent=1), encoding="utf-8")
            except OSError:
                pass
            return {**saved, "sent": False, "why": why + (f" (it said: {said})" if said else "") + "."}
        try:
            report["sent_ref"] = ref
            Path(saved["path"]).write_text(json.dumps(report, indent=1), encoding="utf-8")
        except OSError:
            pass
        return {**saved, "sent": True, "ref": ref}

    SUGGEST_EVERY = 60.0

    def _suggestions_cached(self) -> list:
        """The allow and promote offers, worked out at most once a minute (the bar is drawn often; the firewall and the
        box are read once), and only while the box plugin is up (it is the one that counts the blocks)."""
        import time as _t
        now = _t.monotonic()
        held = getattr(self, "_suggest_at", None)
        if held is not None and now - held[0] < self.SUGGEST_EVERY:
            return list(held[1])
        got = []
        try:
            if self._acts is not None and self._box_up():
                offers = self.allow_suggestions()
                ports = {str(x["promote"].get("port")) for x in offers if isinstance(x.get("promote"), dict)}
                got = (self.quarantine_suggestions() + offers
                       + [x for x in self.promote_suggestions() if str((x.get("promote") or {}).get("port")) not in ports])
        except Exception:
            got = []
        self._suggest_at = (now, got)
        return list(got)

    # -- BUILD 503 (the maintainer, 11 Nov 2026: "'ive saved this' - where to send them in beta? ... maybe just allow them to
    # unblock with nag bars - show then the steps we will implement in the full version", "screen preview", "build yes"):
    # the page after setup in beta 1, all of it open code. The manager is not in this build, so this page carries what a
    # tester needs most: the offers to let a blocked device through (the same ones the manager shows, with the same
    # passkey and Undo), the firewall's own screen, and what beta 2 adds.
    AFTER_OFFERS = ("allow", "promote")

    def after_state(self) -> dict:
        out = {"box": False, "offers": [], "screen": False, "why": ""}
        if not self._plugin_offered():       # BUILD 513: beta 1 has no plugin: only what the firewall's own API can say
            out["names"] = self.bad_reservation_names()
            out["kea_missing"] = self.kea_missing_ports()
            return out
        if getattr(self, "_acts", None) is None:
            try:
                self.manager_start()                 # beta 1: builds the engine and the box link, opens no window
            except Exception as exc:  # noqa: BLE001 - the page says it plainly
                out["why"] = "Pazuzu could not reach the plugin on the firewall just now (" + _plain(exc) + ")."
                return out
        try:
            up = self._acts is not None and self._box_up()
        except Exception:  # noqa: BLE001
            up = False
        out["box"] = bool(up)
        if not up:
            out["why"] = out["why"] or ("This needs the Pazuzu plugin on the firewall, and this setup carried on without it. "
                                        "Run the setup steps again to add it at the plugin step."
                                        if self._recall("plugin_skipped") and not self._recall("box_link") else
                                        "This needs the Pazuzu plugin on the firewall, and it is not on it yet. "
                                        "Run the setup steps again to add it."
                                        if not self._recall("box_link") else
                                        "The plugin on the firewall is not answering, so blocked devices cannot be read.")
            return out
        out["offers"] = [x for x in self._suggestions_cached() if any(isinstance(x.get(k), dict) for k in self.AFTER_OFFERS)]
        out["names"] = self.bad_reservation_names()
        out["kea_missing"] = self.kea_missing_ports()
        try:
            out["screen"] = bool(self._acts.source.box.screen_link())
        except Exception:  # noqa: BLE001
            out["screen"] = False
        return out

    @staticmethod
    def bad_hostname(name) -> str:
        """Why the firewall's name server would refuse this hostname once the domain is added after it, or ''. Only what
        stops Unbound from starting is flagged: an empty part (a dot at either end, or two dots) or a space."""
        h = str(name or "")
        if not h.strip():
            return ""
        if h.endswith("."):
            return "it ends with a dot"
        if h.startswith("."):
            return "it starts with a dot"
        if ".." in h:
            return "it has two dots in a row"
        if any(c.isspace() for c in h):
            return "it has a space in it"
        return ""

    def bad_reservation_names(self) -> list:
        """BUILD 503 (Unbound would not start, "Bad local-data RR desktop-pc01..example.arpa ...
        Empty label"): "Add reservation" on Kea's leases page copies a Windows PC's name with its trailing dot, the
        firewall adds its domain after it, and Unbound refuses to start over that one name. Reads only."""
        try:
            getter = self._api_getter()
            rows = (getter("/api/kea/dhcpv4/search_reservation?rowCount=-1&searchPhrase=") or {}).get("rows") or [] \
                if getter else []
        except Exception:  # noqa: BLE001 - a firewall without Kea, or no answer: nothing to say
            return []
        out = []
        for r in rows:
            if not isinstance(r, dict):
                continue
            why = self.bad_hostname(r.get("hostname"))
            if why:
                out.append({"ip": str(r.get("ip_address") or ""), "hostname": str(r.get("hostname") or ""), "why": why,
                            "fix": str(r.get("hostname") or "").strip().strip(".").replace("..", ".")})
        return out

    def kea_missing_ports(self) -> list:
        """BUILD 508 (a USB network adapter, ue1 / PZ_Mgmt, was unplugged and nothing on the network got
        an address): Kea will not start while a port it is set to listen on is missing from the system. Which of its
        ports are missing, [{"identifier", "name", "device"}]. Reads only; empty when Kea is off or it cannot be told."""
        try:
            getter = self._api_getter()
            if getter is None:
                return []
            gen = ((getter("/api/kea/dhcpv4/get") or {}).get("dhcpv4") or {}).get("general") or {}
            if str(gen.get("enabled")) not in ("1", "true", "True"):
                return []
            ifs = gen.get("interfaces") or {}
            want = [k for k, v in ifs.items() if isinstance(v, dict) and str(v.get("selected")) in ("1", "true", "True")] \
                if isinstance(ifs, dict) else []
            body = getter("/api/interfaces/overview/interfaces_info/true") or {}
            rows = body.get("rows") if isinstance(body, dict) else body
            rows = [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []
        except Exception:  # noqa: BLE001
            return []
        if not rows:
            return []                                 # the list could not be read: say nothing
        by = {str(r.get("identifier") or ""): r for r in rows}
        out = []
        for ident in want:
            r = by.get(ident)
            there = r is not None and any(r.get(k) for k in ("status", "macaddr", "macaddr_hw", "flags", "link_type"))
            if not there:
                out.append({"identifier": ident, "name": str((r or {}).get("description") or ident.upper()),
                            "device": str((r or {}).get("device") or "")})
        return out

    def screen_link(self) -> str | None:
        """The firewall's own screen page, with the box's code after the # (handed to the browser as a redirect only)."""
        try:
            return self._acts.source.box.screen_link() if getattr(self, "_acts", None) is not None else None
        except Exception:  # noqa: BLE001
            return None

    def pending_nags(self) -> list:
        """Things still to do, for the bar at the top of the manager. Each leaves when it is done."""
        out = []
        if self.keys_state in ("stale", "none") or not self._key_file(en.WRITE).exists():
            return out
        out += self._suggestions_cached()
        self._vpn_already_there()
        if not self._recall("vpn_instance"):
            out.append({"text": "The VPN is not set up yet.", "view": "vpn", "label": "Set it up"})
        root = self._root_factory()
        if root:
            out.insert(0, {"text": "Critical: root still has OPNsense's factory password. Anyone who knows it can take the "
                                   "firewall.", "wizard": "#admin", "label": "Fix it now", "critical": True})
        choice = self._recall("host_choice") or ""
        if self._recall("vpn_instance") and (choice not in ("domain", "ddns", "current")
                                             or (choice == "ddns" and not self._recall("ddns_name"))):
            self._ddns_from_firewall()                  # a name the firewall already keeps up to date counts
            choice = self._recall("host_choice") or ""
        if self._recall("vpn_instance") and choice not in ("domain", "ddns", "current"):
            out.append({"text": "No domain or DynDNS name is set up. A steady VPN needs one: without it your phone loses the "
                                "firewall whenever your internet address changes.", "view": "ddns", "label": "Set it up"})
        elif choice == "ddns" and not self._recall("ddns_name"):
            out.append({"text": "DynDNS is not set up yet, so your home name stops pointing home when your internet address changes.",
                        "view": "ddns", "label": "Set it up"})
        has_wifi = self._wifi_cards_known()
        if has_wifi and not self._recall("wifi_backdoor") and self._wifi_can_host():
            # It is set up from the manager's own Access screen (the plugin comes first, from the Data screen).
            # Only where the plugin has seen a Wi-Fi card: a firewall without one (the production Dell) can never finish it.
            out.append({"text": "The Wi-Fi back door (a way in if the cable fails) is not set up yet.",
                        "view": "access", "label": "Set it up"})
        # 0.6.97: an access point the box keeps in step that is out of step, or no longer answering the box by key
        try:
            st = ((self._acts.source.box.read() or {}).get("status") or {}) if self._box_up() else {}
        except Exception:  # noqa: BLE001 - the bars go on without it
            st = {}
        for a in st.get("aps") or []:
            if a.get("state") in ("off", "silent"):
                first = (a.get("problems") or ["Out of step with the firewall."])[0]
                out.append({"text": f"Access point {a.get('name') or a.get('ip')}: {first}", "view": "wifi", "label": "Look"})
        if has_wifi and not self._recall("wifi_backup"):
            # Offered right after the back door: the same Wi-Fi card can also join a phone's hotspot as a second way to the internet.
            out.append({"text": "The backup internet from your phone's hotspot is not set up yet. If the main internet goes "
                                "down, the firewall would use your phone's data until it comes back.",
                        "view": "access", "label": "Set it up"})
        return out

    def _home_networks(self) -> str:
        """The networks behind the firewall (not the internet side), as the firewall itself lists them."""
        import ipaddress
        getter = self._api_getter()
        if getter is None:
            return ""
        try:
            rows = getter("/api/interfaces/overview/interfaces_info/true").get("rows") or []
        except Exception:
            return ""
        found = []
        for r in rows:
            if not isinstance(r, dict) or str(r.get("identifier")) == "wan" or str(r.get("device", "")).startswith(("lo", "wg", "enc")):
                continue
            cand = r.get("addr4") if isinstance(r.get("addr4"), list) else [r.get("addr4")]
            for c in cand:
                try:
                    net = ipaddress.ip_interface(str(c)).network
                except ValueError:
                    continue
                if net.version == 4 and net.is_private:
                    found.append(str(net))
        return ", ".join(sorted(set(found)))

    def vpn_on(self) -> dict:
        """Switch WireGuard on (its own enable switch), for a VPN that is made but off. Nothing else is changed."""
        return self._write_job("write-vpn", lambda e: [e.build("wg_general", {"enabled": True})])

    def write_vpn_peer(self, d) -> dict:
        d = d if isinstance(d, dict) else {}
        try:
            name = vpn_peer.device_name(d.get("name"))
            address = vpn_peer.tunnel_address(d.get("address"))
        except ValueError as exc:
            raise WizardError(str(exc))
        pub = str(d.get("public") or "").strip()
        values = {"name": name, "pubkey": pub, "tunneladdress": address, "enabled": "1"}

        def plans(e):
            # Tie the device to the VPN instance (the peer's own "Instances" field), as the firewall's page does: a peer
            # on no instance is never used. The instance is the one whose public key the app knows, else the only one.
            vals = dict(values)
            form = e._template(we.CAPS["wg_client"])[1]
            if "servers" in form:
                rows = [r for r in e._rows(we.CAPS["wg_server"]) if str(r.get("enabled", "1")) != "0"]
                key = str((self._recall("vpn_instance") or {}).get("public_key") or "")
                mine = [r for r in rows if key and str(r.get("pubkey")) == key] or (rows if len(rows) == 1 else [])
                if len(mine) == 1 and we._UUID.match(str(mine[0].get("uuid", ""))):
                    vals["servers"] = str(mine[0]["uuid"])
                else:
                    raise we.WriteError("The firewall has more than one VPN instance (or none switched on), so Pazuzu cannot "
                                        "tell which one the device belongs to. Nothing was changed.")
            return [e.build("wg_client", vals)] + self._vpn_access_plans(e)
        return self._write_job("write-peer", plans)

    def _vpn_access_plans(self, e) -> list:
        """What the VPN may reach, made with the first device under the same passkey (the dry run of a fresh Hanbi,
        29 Oct 2026: a phone made on a new box connected and then reached nothing until Finish getting to Happy).
        Anything that cannot be planned here is left to Finish getting to Happy, never in the device's way."""
        from pazuzu_core import vpn_access
        try:
            getter = self._api_getter()
            va = self._vpn_access(getter) if getter is not None else None
        except Exception:
            return []
        if not va:
            return []
        # BUILD 481: five of these rules are written against the list of private addresses (private_networks), which the
        # rules step makes. On a factory box set up from the phone, Reach home comes first, the firewall refused the
        # first of them, and the device was taken out again with it (lab box, 4 Nov 2026). Those wait for Finish
        # getting to Happy, which adds whatever is still missing; the device and the rules to the firewall go in now.
        try:
            names = {str(a.get("name") or "") for a in
                     ((getter("/api/firewall/alias/search_item?rowCount=-1&searchPhrase=") or {}).get("rows") or [])
                     if isinstance(a, dict)}
        except Exception:  # noqa: BLE001
            names = set()
        out = []
        for r in va["missing"]:
            if r.get("destination_net") == "private_networks" and "private_networks" not in names:
                continue
            try:
                out.append(e.build("fw_rule", r))
            except we.WriteError:
                return []                                   # all or none: Finish getting to Happy says why
        if va.get("acl_missing") and we.probe_ready(self._probe, we.CAPS["unbound_acl"])[0]:
            try:
                out.append(e.build("unbound_acl", vpn_access.acl_values(va["net"])))
            except we.WriteError:
                pass
        return out

    def write_gateway(self, d) -> dict:
        d = d if isinstance(d, dict) else {}
        keep = ("name", "interface", "gateway", "priority", "monitor", "ipprotocol", "descr")
        values = {k: str(d[k]).strip() for k in keep if d.get(k) not in (None, "")}
        values.setdefault("ipprotocol", "inet")
        return self._write_job("write-gateway", lambda e: [e.build("gateway", values)])

    def write_country_block(self, d) -> dict:
        d = d if isinstance(d, dict) else {}
        try:
            picked = country_block.save(self.key_dir, d)
        except ValueError as exc:
            raise WizardError(str(exc))
        except OSError:
            raise WizardError("Could not save that choice.")
        zones = (self.status().get("zones") or {}).get("assignments") or {}
        wan = (zones.get("wan") or {}).get("device")
        dmz = (zones.get("dmz") or {}).get("device")
        found: list[str] = []

        def already(engine):
            return ["Country blocking is already on this firewall. Found: " + ", ".join(found) + ".",
                    "Nothing was changed. To change the list, edit " + country_block.ALIAS
                    + " under Firewall, Aliases."]

        def geoip(engine):
            if engine.geoip_source() == "":
                return ["Warning: the firewall has no GeoIP source yet, so no country is being blocked. Add one under "
                        "Firewall, Aliases, GeoIP settings, then check that it shows a number of ranges."]
            return []

        return self._write_job("write-country-block",
                               lambda e: country_block.build_plans(e, picked, wan, dmz, found),
                               {"countries": picked}, notes=geoip, nothing=already)

    def _engine_job(self, kind: str, fn, extra: dict | None = None) -> dict:
        """Like _write_job, for a change to something already there: fn(engine, gate) -> (outcomes, lines)."""
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        if self._probe is None:
            raise WizardError("Check what this firewall supports first. It only reads.")
        session = self._installer_session()
        base = self.base_url.rstrip("/")
        report = self._probe

        def work() -> dict:
            engine = we.Engine(session, base, report)

            def gate(digest, lines):
                return self.window_gate(digest, list(lines) + [self._uses_words()])
            try:
                outs, lines = fn(engine, gate)
            except we.WriteError as exc:
                raise WizardError(str(exc))
            if outs:
                self._last_write = (engine, outs)
            return {"lines": lines, "can_undo": any(o.undo_path for o in outs), "info": not outs, **(extra or {})}

        return self._start(kind, work)

    COUNTRY_READ_EVERY = 60.0

    def _country_on_firewall(self):
        """A country block already on the firewall, read from its aliases: {"alias", "codes", "ours", "enabled"} for
        Pazuzu's own alias when it is there, else for the first other GeoIP alias, else None. This is what the setup
        shows, so it never offers to add a country block the firewall already has (seen on a production firewall set
        up from another device, 28 Oct 2026). Read at most once a minute; None when it cannot be read."""
        import re
        import time as _t
        now = _t.monotonic()
        cached = getattr(self, "_country_fw", None)
        if cached is not None and now - cached[0] < self.COUNTRY_READ_EVERY:
            return cached[1]
        got = None
        getter = self._api_getter() if self.keys_state == "ok" else None     # only once the saved keys were checked
        if getter is not None:
            try:
                rows = (getter("/api/firewall/alias/search_item?rowCount=-1&searchPhrase=") or {}).get("rows") or []
                geo = [r for r in rows if isinstance(r, dict) and "geoip" in str(r.get("type", "")).lower()]
                geo.sort(key=lambda r: str(r.get("name")) != country_block.ALIAS)
                if geo:
                    r = geo[0]
                    codes = sorted({c for c in re.split(r"[\s,;]+", str(r.get("content") or "")) if re.fullmatch(r"[A-Z]{2}", c)})
                    got = {"alias": str(r.get("name")), "codes": codes, "ours": str(r.get("name")) == country_block.ALIAS,
                           "enabled": str(r.get("enabled", "1")) == "1"}
            except Exception:  # noqa: BLE001 - reading only; the card then works from this device's own record
                got = None
        self._country_fw = (now, got)
        return got

    def country_state(self) -> dict:
        """What the manager's country card shows: the saved list, the choices, and whether this firewall can be written to."""
        checking = self.auto_check()
        caps = we.readiness(self._probe)
        need = [caps[c] for c in ("geo_alias", "fw_rule")]
        st = country_block.state(self.key_dir)
        # BUILD 486 (the maintainer, 8 Nov 2026: "incongruent"): the same reading as the setup page (BUILD 28 Oct), so a block put
        # on from another device shows here too, not "No countries are blocked" beside the setup's "248 blocked".
        fw = self._country_on_firewall()
        st["on_firewall"] = fw
        if fw and fw.get("ours") and not st.get("saved"):
            st["saved"] = list(fw.get("codes") or [])
        st["ready"] = all(c["ready"] for c in need)
        st["why"] = "Checking what this firewall supports. This takes a few seconds." if checking else \
            next((c["why"] for c in need if not c["ready"]), "")
        st["checking"] = checking
        st["can_change"] = bool(self._can_change())
        st["broad_dmz"] = self._broad_dmz_rule()
        return st

    def _broad_dmz_rule(self) -> bool:
        """Is the country block's exception for the whole public-servers network on the firewall? Reads only."""
        from urllib.parse import quote
        getter = self._api_getter()
        if getter is None:
            return False
        name = country_block.rule_values("dmz", dmz="0")["description"]
        try:
            rows = getter("/api/firewall/filter/search_rule?rowCount=-1&searchPhrase=" + quote(name, safe="")).get("rows") or []
        except Exception:  # noqa: BLE001
            return False
        return any(isinstance(r, dict) and str(r.get("description")) == name for r in rows)

    def write_country_block_change(self, d) -> dict:
        """Change the list of blocked countries that is already on the firewall (its alias), like any other edit."""
        d = d if isinstance(d, dict) else {}
        try:
            picked = country_block.save(self.key_dir, d)
        except ValueError as exc:
            raise WizardError(str(exc))
        except OSError:
            raise WizardError("Could not save that choice.")

        def run(engine, gate):
            out = engine.change_text("geo_alias", country_block.ALIAS, "content", "\n".join(picked), gate)
            if out is None:                      # nothing there yet (an earlier try failed): add it now
                zones = (self.status().get("zones") or {}).get("assignments") or {}
                plans = country_block.build_plans(engine, picked, (zones.get("wan") or {}).get("device"),
                                                  (zones.get("dmz") or {}).get("device"))
                outs = engine.apply_many(plans, gate) if plans else []
                return outs, [ln for o in outs for ln in o.lines]
            return [out], list(out.lines)

        return self._engine_job("write-country-block", run, {"countries": picked})

    def country_narrow_start(self) -> dict:
        """The country block's exception for the public-servers (DMZ) network, which let the whole network through from
        every country, replaced by one exception per port forward into it (that host, that port, that protocol). The port
        forwards themselves (NAT) are only read, never changed. The narrow ones are added first, then the broad one is
        removed, so nothing that was reachable stops being reachable in between. One passkey."""
        zones = (self.status().get("zones") or {}).get("assignments") or {}
        dmz = (zones.get("dmz") or {}).get("device")
        wan_dev = (zones.get("wan") or {}).get("device")

        def run(engine, gate):
            ok, why = engine.ready("fw_rule")
            if not ok:
                raise we.WriteError(why)
            broad = country_block.rule_values("dmz", dmz="0")["description"]
            if engine._one_row(we.CAPS["fw_rule"], broad) is None:
                return [], ["The country block has no exception for the whole public-servers network, so there is nothing to "
                            "narrow."]
            if not dmz:
                raise we.WriteError("No port is set as the public-servers network, so Pazuzu cannot tell which port forwards "
                                    "go there. Nothing was changed.")
            fwds = country_block.dmz_forwards(engine, dmz)
            if fwds is None:
                raise we.WriteError("The port forwards (Firewall, NAT, Destination NAT) could not be read, so the exception "
                                    "was left as it is. Nothing was changed.")
            wan = engine.interface_id(wan_dev) or "wan"
            plans = []
            for f in fwds:
                vals = country_block.forward_rule(f, wan)
                if not engine.exists("fw_rule", vals["description"]):
                    plans.append(engine.build("fw_rule", vals))
            outs = engine.apply_many(plans, gate) if plans else []
            lines = [ln for o in outs for ln in o.lines]
            lines += [f"Let through from every country: {f['host']} {f['protocol']} {f['port']}"
                      + (f" ({f['name']})" if f["name"] else "") for f in fwds]
            if not fwds:
                lines.append("No port forward goes to the public-servers network, so nothing there is let through from the "
                             "blocked countries any more.")
            gone = engine.remove_named("fw_rule", [broad], gate)
            if gone:
                lines.append("Removed the exception that let the whole public-servers network through. The port forwards "
                             "themselves were not changed.")
                return [], lines                          # the broad rule is gone: an Undo of the new ones alone would close them
            return outs, lines
        return self._engine_job("country-narrow", run)

    def country_ipv4_start(self) -> dict:
        """The country block's two exception rules (the VPN's port, the public servers), made IPv4 only. New ones are
        written that way; this changes the ones an earlier build made as IPv4 and IPv6, which the IPv6 check counts as
        IPv6 being allowed. Only those two rules, only their IP version, one passkey, read back to check."""
        def run(engine, gate):
            ok, why = engine.ready("fw_rule")
            if not ok:
                raise we.WriteError(why)
            cap = we.CAPS["fw_rule"]
            outs, lines = [], []
            for name in country_block.exception_names():
                row = engine._one_row(cap, name)
                if row is None:
                    continue                                 # not on this firewall (no public-servers network, say)
                if str(row.get("ipprotocol")) == "inet":
                    lines.append(f"{name}: already IPv4 only.")
                    continue
                out = engine.change_text("fw_rule", name, "ipprotocol", "inet", gate,
                                         say="Let this rule cover IPv4 only (it now covers IPv4 and IPv6)")
                if out is not None:
                    outs.append(out)
                    lines.append(f"{name}: " + " ".join(out.lines))
            if not lines:
                lines.append("None of the country block's exception rules were found on the firewall.")
            return outs, lines
        return self._engine_job("country-ipv4", run)

    def rule_ipv4_start(self, d) -> dict:
        """One rule that lets IPv4 and IPv6 through (a rule of the person's own, found by its id), made IPv4 only: the IPv6
        check counts it as IPv6 allowed. Only an enabled pass rule set to IPv4 and IPv6; only its IP version changes; one
        passkey; read back; the Undo puts it back. Never an IPv6-only rule (that would start letting IPv4 through) and never
        a block rule (that would stop blocking IPv6)."""
        d = d if isinstance(d, dict) else {}
        uuid = str(d.get("uuid") or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", uuid):
            raise WizardError("That rule could not be found. Nothing was changed.")

        def run(engine, gate):
            ok, why = engine.ready("fw_rule")
            if not ok:
                raise we.WriteError(why)
            cap = we.CAPS["fw_rule"]
            row = next((r for r in engine._rows(cap) if str(r.get("uuid", "")).lower() == uuid), None)
            if row is None:
                raise we.WriteError("That rule is not on the firewall any more. Nothing was changed.")
            if str(row.get("action") or "").strip().lower() != "pass" or str(row.get("enabled", "1")).strip() == "0":
                raise we.WriteError("That rule does not let traffic through, so it is not what the IPv6 check means. "
                                    "Nothing was changed.")
            name = str(row.get("description") or "").strip() or "the rule with no name (id " + uuid[:8] + ")"
            if str(row.get("ipprotocol") or "").strip().lower() == "inet":
                return [], [f"{name}: already IPv4 only."]
            out = engine.change_by_uuid("fw_rule", uuid, "ipprotocol", "inet", gate, label="Change " + name,
                                        say="Let this rule cover IPv4 only (it now covers IPv4 and IPv6)", expect="inet46")
            return [out], [f"{name}: " + " ".join(out.lines)]
        return self._engine_job("rule-ipv4", run)

    def rule_off_start(self, d) -> dict:
        """Switch off one rule of the person's own (found by its id) that a drift card names. Only an enabled pass rule
        that is not Pazuzu's and not a stock allow-all (the plan handles those); only its on/off changes; one passkey;
        read back; Undo switches it on again."""
        d = d if isinstance(d, dict) else {}
        uuid = str(d.get("uuid") or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", uuid):
            raise WizardError("That rule could not be found. Nothing was changed.")

        def run(engine, gate):
            ok, why = engine.ready("fw_rule")
            if not ok:
                raise we.WriteError(why)
            row = next((r for r in engine._rows(we.CAPS["fw_rule"]) if str(r.get("uuid", "")).lower() == uuid), None)
            if row is None:
                raise we.WriteError("That rule is not on the firewall any more. Nothing was changed.")
            desc = str(row.get("description") or "")
            if desc.startswith(("PAZUZU:", "Default allow", "Pazuzu: ")):
                raise we.WriteError("That rule is one the plan looks after, so it is not switched off from here. Nothing was changed.")
            if str(row.get("action") or "").strip().lower() != "pass":
                raise we.WriteError("That rule does not let traffic through. Nothing was changed.")
            name = desc.strip() or "the rule with no name (id " + uuid[:8] + ")"
            if str(row.get("enabled", "1")).strip() == "0":
                return [], [f"{name}: already switched off."]
            out = engine.change_by_uuid("fw_rule", uuid, "enabled", "0", gate, label="Switch off " + name,
                                        say="Switch this rule off (it stays on the firewall; Undo switches it on again)", expect="1")
            return [out], [f"{name}: " + " ".join(out.lines)]
        return self._engine_job("rule-off", run)

    def rules_tidy_start(self, d=None) -> dict:
        """Remove the extra copies of Pazuzu's own rules (same name, matching exactly the same traffic), keeping one of each:
        a switched-on copy if there is one. Read again at the moment of the change, one passkey for the list it shows,
        then read back. Only Pazuzu's rules; one that shares a name but differs is left alone. Pazuzu's record of what it
        added (the receipt) loses the removed ids, so Undo (rollback) still matches the firewall."""
        from pazuzu_core import rule_copies
        from pazuzu_core import firewall_manifest_smoke as smoke

        def recorded() -> list:
            try:
                return list(json.loads(smoke.RECEIPT.read_text(encoding="utf-8")).get("rule_uuids") or [])
            except (OSError, ValueError, AttributeError):
                return []

        def run(engine, gate):
            ok, why = engine.ready("fw_rule")
            if not ok:
                raise we.WriteError(why)
            cap = we.CAPS["fw_rule"]
            found = rule_copies.find(engine._rows(cap), recorded())
            if not found["extra"]:
                return [], ["No rule of Pazuzu's is on the firewall twice. Nothing was changed."]
            items = [(rule_copies.plain_name(g["name"]), u) for g in found["groups"] for u in g["remove"]]
            gone = engine.remove_uuids("fw_rule", items, gate)
            try:
                rec = json.loads(smoke.RECEIPT.read_text(encoding="utf-8"))
                if isinstance(rec, dict) and isinstance(rec.get("rule_uuids"), list):
                    smoke._write_receipt([u for u in rec["rule_uuids"] if u not in set(gone)],
                                         list(rec.get("alias_uuids") or []), str(rec.get("status") or "applied"))
            except (OSError, ValueError):
                pass                                          # no record in this folder: nothing to keep in step
            left = rule_copies.find(engine._rows(cap), recorded())
            lines = [f"Removed {len(gone)} extra cop{'y' if len(gone) == 1 else 'ies'}; one of each rule is kept."]
            lines.append("Read the rules back: no copies left." if not left["extra"] else
                         f"Read the rules back: {left['extra']} cop{'y is' if left['extra'] == 1 else 'ies are'} still there. Look at the firewall's rules page.")
            if found["differ"]:
                lines.append("Left alone, because they share a name but not what they match: "
                             + ", ".join(rule_copies.plain_name(n) for n in found["differ"][:5]) + ".")
            return [], lines
        return self._engine_job("rules-tidy", run)

    def write_country_block_remove(self) -> dict:
        """Take the country block off the firewall: its three rules, then its list. The saved choice is kept off too."""
        names = [country_block.rule_values(k, port="0", dmz="0")["description"] for k in ("block", "vpn", "dmz")]

        def run(engine, gate):
            gone = engine.remove_named("fw_rule", names + getattr(engine, "leftovers", lambda *a: [])("fw_rule", country_block.FWD_PREFIX), gate)
            gone += engine.remove_named("geo_alias", [country_block.ALIAS], lambda d, l: True)
            if not gone:
                return [], ["Nothing of the country block was found on the firewall."]
            country_block.forget(self.key_dir)
            return [], ["Removed from the firewall: " + ", ".join(gone) + "."]

        return self._engine_job("write-country-block", run, {"countries": []})

    def _device_of(self, ip: str) -> tuple[str, str, str]:
        """(mac, name, maker) of the device at this address, from the box's own client list; ("", "", "") when the box
        does not know it."""
        try:
            st = (self._acts.source.box.read() or {}).get("status") if (self._acts is not None and self._box_up()) else {}
        except Exception:
            st = {}
        for c in (st or {}).get("clients") or []:
            if isinstance(c, dict) and str(c.get("ip")) == ip and c.get("mac"):
                return str(c["mac"]).lower(), str(c.get("name") or ((st or {}).get("names") or {}).get(ip) or ""), str(c.get("vendor") or "")
        return "", "", ""

    def block_allow(self, d) -> dict:
        """Allow what one row of the Blocks list shows. For 30 seconds: that address, that port, to anywhere, then taken
        off again whatever happens (a test). Always (BUILD 426): it follows the device's hardware address and never opens
        the home networks: "out" (that port, internet only), "home" (your home network may reach that device on that
        port), "udp" (any UDP to the internet: a doorbell's live video)."""
        from pazuzu_core import block_allow as ba
        d = d if isinstance(d, dict) else {}
        src, proto, dport = str(d.get("src") or ""), str(d.get("proto") or "").lower(), str(d.get("dport") or "")
        device, temp = str(d.get("device") or ""), bool(d.get("temp"))
        kind = str(d.get("kind") or "out")
        problems = ba.check(src, proto, dport, device)
        if problems:
            raise WizardError(" ".join(problems))
        if kind not in ba.KINDS:
            raise WizardError("That kind of allow is not one of out, home or udp.")
        zones = (self.status().get("zones") or {}).get("assignments") or {}
        wan = (zones.get("wan") or {}).get("device")
        if device == wan:
            raise WizardError("That came in from the internet side. Nothing is allowed from there on this list.")
        mac, label = "", ""
        if not temp:
            try:
                mac = ba.clean_mac(d.get("mac") or self._device_of(d.get("target") if kind == "home" else src)[0])
            except ValueError:
                if kind != "out":
                    raise WizardError("Pazuzu does not know that device's hardware address yet (the box plugin lists it "
                                      "once it has seen the device). Use the 30-second allow, or try again in a minute.")
                mac = ""                       # no plugin to name the device: the allow follows the address, internet only
            named = self._device_of(d.get("target") if kind == "home" else src)      # the device the allow is about
            label = re.sub(r"[^\w .:()'-]", "", str(d.get("name") or named[1] or named[2] or ""))[:40].strip()
        target = str(d.get("target") or "")

        def run(engine, gate):
            iface = engine.interface_id(device)
            if not iface or iface == "wan":
                raise we.WriteError("Pazuzu could not find that port on the firewall, so nothing was changed.")
            for stale in engine.leftovers("fw_rule", ba.TEMP):
                engine.remove_named("fw_rule", [stale], lambda dg, ln: True)
            if not temp and not mac:                       # by address (no plugin): the old form, internet only
                vals = ba.rule_values(iface, src, proto, dport, False)
                if engine.exists("fw_rule", vals["description"]):
                    return [], [f"Already allowed: {src} on {proto.upper()} port {dport}."]
                out = engine.apply(engine.build("fw_rule", vals), gate)
                return [out], list(out.lines) + [f"{src} may now use {proto.upper()} port {dport}, to the internet only. Remove it under Firewall, Rules."]
            if not temp:
                who = label or mac
                if kind == "home":
                    home_if, home_net = iface, engine.network_of(src) or ""
                    if not home_net:
                        raise we.WriteError("Pazuzu could not read your home network's range, so nothing was changed.")
                    vals = ba.keep_values("home", home_if, mac, proto, dport, home_net)
                    head = [f"Let your home network reach {who} ({mac}) on {proto.upper()} port {dport}",
                            "Stateful: the device still starts nothing toward your home network"]
                else:
                    vals = ba.keep_values(kind, iface, mac, proto, dport)
                    head = ([f"Let {who} ({mac}) send any UDP to the internet (live video)", "Never to your home networks"]
                            if kind == "udp" else
                            [f"Let {who} ({mac}) use {proto.upper()} port {dport}, to the internet only", "Never to your home networks"])
                if engine.exists("fw_rule", vals["description"]):
                    return [], [f"Already allowed: {who} ({vals['description'][len(ba.KEEP):]})."]
                plans = []
                if not engine.exists("dev_alias", ba.dev_alias(mac)):
                    plans.append(engine.build("dev_alias", ba.dev_alias_values(mac, who)))
                plans.append(engine.build("fw_rule", vals))
                outs = engine.apply_many(plans, lambda dg, ln: gate(dg, head + list(ln)))
                said = {"out": f"{who} may now use {proto.upper()} port {dport}, to the internet only.",
                        "home": f"Your home network may now reach {who} on {proto.upper()} port {dport}.",
                        "udp": f"{who} may now send any UDP to the internet (live video)."}[kind]
                return outs, [said, "Undo takes it back; later, remove the rule called " + vals["description"] + " under Firewall, Rules."]
            vals = ba.rule_values(iface, src, proto, dport, temp)
            if engine.exists("fw_rule", vals["description"]):
                return [], [f"Already allowed: {src} on {proto.upper()} port {dport}."]
            out = engine.apply(engine.build("fw_rule", vals), gate)
            try:
                self._allow_wait(ba.TEMP_SECONDS)
            finally:
                gone = engine.undo(out)
            return [], [f"{src} was allowed on {proto.upper()} port {dport} for {ba.TEMP_SECONDS} seconds."
                        + (" It is closed again." if gone else
                           " Taking it off failed: remove the rule called " + vals["description"] + " under Firewall, Rules.")]

        return self._engine_job("write-block-allow", run, {"src": src, "temp": temp})

    def _allow_wait(self, seconds) -> None:
        time.sleep(seconds)

    def write_undo(self) -> dict:
        held = self._last_write
        if not held:
            raise WizardError("There is nothing of Pazuzu\u2019s to take back.")
        engine, outs = held

        def work() -> dict:
            gone = 0
            try:
                for o in reversed(outs):
                    gone += 1 if engine.undo(o) else 0
            except we.WriteError as exc:
                raise WizardError(str(exc))
            self._last_write = None
            for o in outs:
                if o.cap == "user":
                    self._remember("root_off" if o.undo_body is not None else "admin_user",
                                   False if o.undo_body is not None else None)
            return {"lines": [f"Took back {gone} thing(s) Pazuzu added."]}

        return self._start("write-undo", work)

    # -- interfaces and zones
    def interfaces(self) -> dict:
        scan = self._scan
        if scan is None:
            from pazuzu_core.opnsense_scanner import scan_interfaces as scan
        try:
            with self._env(en.READ):
                report = scan()
        except WizardError:
            raise
        except Exception as exc:
            raise WizardError(f"Could not read the interfaces: {_plain_firewall(exc)}")
        from pazuzu_core.scan_cli import write_report
        write_report(report, self.discovery_path)
        from pazuzu_core.zone_assignment import selectable_interfaces
        found = selectable_interfaces(report)
        try:
            adopted = self._adopt_own_ports(found)
        except Exception:  # noqa: BLE001 - a courtesy; the page still shows the ports
            adopted = []
        out = {"interfaces": found, "suggested_management": suggest_management(found),
               "zones": list(ZONES), "optional": [], "later": self._recall("zones_later") or {},
               "too_small": self._too_small_networks(), "adopted": adopted}
        try:
            out["spare"] = self.spare_ports(found)
        except Exception:  # noqa: BLE001
            out["spare"] = []
        try:                                       # this box's Wi-Fi cards that can host a zone's own network
            out["radios"] = self._radios()
        except Exception:  # noqa: BLE001
            out["radios"] = []
        out["kids"] = kids_present()               # BUILD 539: no KidsNet row in a copy without it
        try:
            from pazuzu_core import zone_vlans as zv
            zones_now = (self.status().get("zones") or {}).get("assignments") or {}
            taken = [z for z, a in zones_now.items() if isinstance(a, dict) and a.get("device") and a.get("state") == "bound"]
            out["suggest"] = zv.suggest([p["device"] for p in out["spare"]],
                                        [r["card"] for r in out["radios"] if r["free"]], taken)
        except Exception:  # noqa: BLE001
            out["suggest"] = {}
        try:                                       # BUILD 499: which DHCP server hands out addresses ("kea", "dnsmasq", "")
            out["dhcp_server"] = self._dhcp_server(self._api_getter())
        except Exception:  # noqa: BLE001
            out["dhcp_server"] = ""
        try:                                       # BUILD 515: can this firewall's own port form set a port up? (None: not read)
            from pazuzu_core import zone_vlans as zv
            got = self._api_getter()("/api/interfaces/assignment/get_item")
            form = next(iter(got.values())) if isinstance(got, dict) and len(got) == 1 else None
            out["port_form"] = all(k in form for k in zv.PORT_FORM_FIELDS) if isinstance(form, dict) else None
        except Exception:  # noqa: BLE001
            out["port_form"] = None
        note = self._drop_stale_zones(report)
        if note:
            out["zones_reset"] = note
            print(note)
        return out

    @staticmethod
    def _dhcp_server(getter) -> str:
        """"kea" when Kea is switched on, else "dnsmasq" when dnsmasq is, else "". Reads only."""
        on = lambda v: str(v if not isinstance(v, dict) else "") in ("1", "true", "True")
        gen = (getter("/api/kea/dhcpv4/get") or {}).get("dhcpv4") or {}
        if isinstance(gen, dict) and on((gen.get("general") or {}).get("enabled")):
            return "kea"
        dm = (getter("/api/dnsmasq/settings/get") or {}).get("dnsmasq") or {}
        return "dnsmasq" if isinstance(dm, dict) and on(dm.get("enable")) else ""

    def _too_small_networks(self) -> dict:
        """{device: "192.168.10.1/32"} for each port whose IPv4 network has no room for a device (a /31 or /32): every rule
        that says "this network" then matches the firewall alone, so the devices on it match no allow. Read with the
        look-only key; {} when it cannot be read."""
        import ipaddress
        getter = self._api_getter()
        if getter is None:
            return {}
        try:
            rows = getter("/api/interfaces/overview/interfaces_info/true").get("rows") or []
        except Exception:
            return {}
        out = {}
        for r in rows:
            if not isinstance(r, dict) or str(r.get("identifier")) == "wan":
                continue
            cand = r.get("addr4") if isinstance(r.get("addr4"), list) else [r.get("addr4")]
            for c in cand:
                try:
                    iface = ipaddress.ip_interface(str(c))
                except ValueError:
                    continue
                if iface.version == 4 and "/" in str(c) and iface.network.prefixlen >= 31:
                    out[str(r.get("device") or "")] = str(c)
        return {k: v for k, v in out.items() if k}

    def _read_op(self, op):
        """One allowlisted read from the firewall, with the look-only key."""

        if self._read_fn is not None:
            return self._read_fn(op)
        from pazuzu_core.opnsense_client import ReadOnlyOPNsenseClient
        with self._env(en.READ):
            client = ReadOnlyOPNsenseClient()
            try:
                return client.execute(op)
            finally:
                client.close()

    def _wan_link_down(self) -> bool:
        """True only when the firewall's WAN port clearly reads "no carrier" right now."""

        if self._read_fn is not None and self._scan is None:
            return False                         # a test double reads the firewall; there is nothing to scan
        try:
            for i in self.interfaces()["interfaces"]:
                if i["identifier"] == "wan":
                    return bool(re.search(r"no carrier|down", str(i.get("status") or "").lower()))
        except Exception:
            pass
        return False

    # -- the internet side, and whether this device's test traffic goes through the firewall
    @staticmethod
    def _local_ip_toward(ip: str) -> str:
        """The address this device would send from to reach `ip`. No packet is sent (a UDP connect only picks a route)."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sk:
            sk.connect((ip, 9))
            return sk.getsockname()[0]

    @staticmethod
    def _resolve_v4(name: str) -> list:
        try:
            return sorted({i[4][0] for i in socket.getaddrinfo(name, 443, socket.AF_INET, socket.SOCK_STREAM)})[:4]
        except OSError:
            return []

    def route_state(self) -> dict:
        """The tests run from this device. The ones aimed at the outside (an outside name server, a web page)
        only mean something if they leave through the firewall. When this device has another way out (Wi-Fi),
        they leave by that instead; say so, and give the short, temporary route that sends them through the firewall."""
        import ipaddress
        if self.phone:
            # BUILD 480: on a Hanbi the tests run on the box itself, so there is no other way out to route around.
            return {"known": False, "via_firewall": None, "detail": ""}
        host, _p = base_host_port(self.base_url)
        try:
            fw = ipaddress.ip_address(host)
            if fw.version != 4:
                raise ValueError
        except ValueError:
            return {"known": False, "via_firewall": None, "detail": "The firewall's address is a name, so the route is not checked."}
        targets = ["8.8.8.8"] + [a for a in self._resolve_v4("example.com") if a != "8.8.8.8"]
        try:
            local = self._local_ip_toward("8.8.8.8")
        except OSError:
            return {"known": False, "via_firewall": None, "detail": "This device has no way out to check."}
        same = ipaddress.ip_address(local) in ipaddress.ip_network(f"{host}/24", strict=False)
        out = {"known": True, "via_firewall": bool(same), "local": local, "firewall": host, "targets": targets}
        if same:
            out["detail"] = "The outside tests leave this device through the firewall, as they should."
        else:
            win = sys.platform.startswith("win")
            out["detail"] = ("The outside tests leave this device another way (from " + local + "), not through the firewall, so "
                             "they cannot show what the firewall does. This temporary route sends them through it.")
            out["commands"] = [(f"route add {t} mask 255.255.255.255 {host}" if win else f"sudo ip route add {t}/32 via {host}")
                               for t in targets]
            out["remove"] = [(f"route delete {t}" if win else f"sudo ip route del {t}/32") for t in targets]
            out["note"] = ("Run them in a terminal opened as administrator. They last until this device restarts, "
                           "or until you run the remove lines.") if win else "Run them with sudo. They last until restart or until you run the remove lines."
        return out

    def internet_state(self) -> dict:
        """Reads only: the firewall's internet-side port and its next router, plus the route check above."""
        out = {"wan": None, "link": "unknown", "gateway": None, "route": self.route_state(),
               "after_rules": getattr(self, "_internet_note", None)}
        getter = self._api_getter()
        if getter is not None:
            try:
                rows = getter("/api/interfaces/overview/interfaces_info/true").get("rows") or []
                for r in rows:
                    if isinstance(r, dict) and str(r.get("identifier")) == "wan":
                        addr = r.get("addr4") if isinstance(r.get("addr4"), list) else [r.get("addr4")]
                        out["wan"] = {"device": str(r.get("device") or ""),
                                      "address": next((str(a) for a in addr if a), ""),
                                      "status": str(r.get("status") or "")}
                        low = out["wan"]["status"].lower()
                        out["link"] = "down" if re.search(r"no carrier|down", low) else ("up" if low else "unknown")
            except Exception:
                pass
            try:
                items = getter("/api/routes/gateway/status").get("items") or []
                first = next((g for g in items if isinstance(g, dict)), None)
                if first:
                    out["gateway"] = {"name": str(first.get("name") or ""), "address": str(first.get("address") or ""),
                                      "status": str(first.get("status_translated") or first.get("status") or ""),
                                      "delay": str(first.get("delay") or "")}
            except Exception:
                pass
        return out

    def _live_box(self):
        """The plugin's link, only when it answers right now."""
        acts = getattr(self, "_acts", None)
        box = getattr(getattr(acts, "source", None), "box", None)
        try:
            return box if box is not None and box.url and box.alive() else None
        except Exception:
            return None

    def _internet_quiet(self):
        """Ask the plugin whether the firewall reaches the internet. True / False, or None when it cannot say."""
        try:
            box = self._live_box()
            got = box.internet() if box is not None else None
        except Exception:
            return None
        if got is None:
            return None
        self._internet_seen = bool(got["reached"])
        return self._internet_seen

    def internet_test(self) -> dict:
        """Can the firewall itself reach the internet? When the plugin is on the firewall, it asks the firewall
        straight away (a few seconds, and it says why not). Without it, the firewall is asked to check its
        package sources, which is slower and fails for other reasons too. Either way a "no" is an answer, not an
        error: nothing about setting up the rules needs the internet."""
        from pazuzu_core import plugin_install as pi
        box = self._live_box()
        if box is not None and box.can("internet_check"):
            def by_plugin() -> dict:
                got = box.internet()
                if got is None:
                    raise WizardError("The plugin did not answer the internet check. Try again in a moment.")
                self._internet_seen = bool(got["reached"])
                return {"lines": [str(x) for x in got["lines"]], "reached": bool(got["reached"]), "by": "plugin"}
            return self._start("internet-test", by_plugin)
        if not self._can_change():
            raise WizardError("Register your passkey first.")
        if self._wan_link_down():
            raise WizardError("The Internet-side port shows no cable. Plug it in first.")
        session = self._installer_session()
        base = self.base_url.rstrip("/")

        def work() -> dict:
            try:
                pi.refresh(session, base, wait=30)
            except pi.PluginError:
                return {"lines": ["The firewall's own update check did not finish. That does not always mean it has no "
                                  "internet. With the Pazuzu plugin on the firewall this test is faster and says why."],
                        "reached": False, "by": "firewall"}
            except Exception as exc:
                raise WizardError(f"The test stopped: {_plain_firewall(exc)}")
            return {"lines": ["The firewall reached the internet (its update check worked)."], "reached": True,
                    "by": "firewall"}

        return self._start("internet-test", work)

    def firmware(self) -> dict:
        """Which version is the firewall on, and is there a newer one, as the firewall last checked. The version it
        is on is known without the internet; only "is there a newer one" needs it."""

        from pazuzu_core.operations import OperationId
        down = self._wan_link_down()
        if not down and getattr(self, "_internet_seen", None) is False:
            try:                                  # an old "no" is asked again, so a fixed cable shows up on Check again
                box = self._live_box()
                got = box.internet() if box is not None else None
                if got is not None:
                    self._internet_seen = bool(got["reached"])
            except Exception:
                pass
        no_net = down or getattr(self, "_internet_seen", None) is False
        why = ("The Internet-side port shows no cable, so the firewall can't check for newer versions. "
               "Plug that port in, then press Check again." if down else
               "The firewall could not reach the internet when it was last tested, so it can't check for newer versions.")
        try:
            data = self._read_op(OperationId.SYSTEM_FIRMWARE)
        except WizardError:
            raise
        except Exception as exc:
            if no_net:
                return {"state": "unknown", "version": None, "needs_reboot": False, "offline": True, "detail": why}
            return {"state": "unknown", "version": None, "needs_reboot": False,
                    "detail": "Could not read the firmware state: " + _plain_firewall(exc)}
        if not isinstance(data, dict):
            return {"state": "unknown", "version": None, "needs_reboot": False,
                    "detail": "The firewall's answer was not understood."}
        product = data.get("product") if isinstance(data.get("product"), dict) else {}
        version = str(data.get("product_version") or product.get("product_version") or "") or None
        self._version_seen = bool(version)
        self._fw_version = version or ""                 # BUILD 497: a feedback report names it
        status = str(data.get("status") or "").lower()
        detail = str(data.get("status_msg") or "")[:300]
        state = ("current" if status in ("none", "ok") else
                 "update" if status in ("update", "upgrade") else "unknown")
        if status == "none" and "check for update first" in detail.lower():
            state = "unchecked"           # a firewall nobody has asked yet answers "none"; that is not "up to date"
        # The firewall's "needs_reboot" belongs to the update it found: "this update will need a restart". It does not mean
        # an update is installed and waiting. So the Restart button is only offered once an update was installed from
        # here (and the firewall still says so); before that the mark only says the update itself restarts.
        reboot = str(data.get("needs_reboot", "0")) in ("1", "true", "True")
        pending = bool(reboot and getattr(self, "_firmware_updated", False))
        if no_net:
            return {"state": "unknown", "version": version, "needs_reboot": pending, "update_restarts": False,
                    "offline": True, "detail": why + (f" It is on version {version}." if version else "")}
        return {"state": state, "version": version, "needs_reboot": pending,
                "update_restarts": bool(reboot and state == "update" and not pending), "detail": detail,
                **_firmware_waiting(data, product)}

    def ids_state(self) -> dict:
        """Packet inspection (IPS). Not readable yet: say so instead of guessing."""

        return {"state": "unknown",
                "detail": "Not checked yet: we can’t read it with the look-only account."}

    def zone_options(self) -> dict:
        """Ports the person can pick for a zone, with the firewall's own names and link."""

        data = self.interfaces()
        zones = (self.status().get("zones") or {}).get("assignments") or {}
        taken = {a.get("device"): z for z, a in zones.items()
                 if (a or {}).get("device") and z != "management"}
        ports = [{"device": i["device"], "label": port_label(i), "assigned": i["assigned"],
                  "link": _link_word(i.get("status"), i["device"], bool(i.get("physical"))),
                  "virtual": is_virtual_device(i["device"]) or not i.get("physical"),
                  "taken_by": taken.get(i["device"])} for i in data["interfaces"]]
        # What can be the way in: a real port that no other zone already uses.
        # (A loopback stays on the list: with no spare port the VPN is the way in, and the page says so.)
        way_in = [p["device"] for p in ports
                  if (not p["virtual"] or p["device"].lower().startswith("lo")) and not p["taken_by"]]
        return {"interfaces": ports, "way_in": way_in,
                "assignments": {z: (a or {}).get("device") for z, a in zones.items()},
                "suggested_management": (data.get("suggested_management") or {}).get("device")}

    def addresses(self, avoid=()) -> dict:
        """A random private network for each mapped zone and for the VPN, with what the person
        does in order. Only a plan: nothing is sent to the firewall and nothing is saved."""

        from pazuzu_core import address_plan as ap
        assigned = (self.status().get("zones") or {}).get("assignments") or {}
        mapped = [z for z in ap.ZONES if z != "wireguard_admin" and (assigned.get(z) or {}).get("device")]
        # Every zone is planned, with or without a port. One with no port sits on a virtual interface for now,
        # so its range, DHCP pool and rules are decided before a port exists. Nothing is created on the firewall.
        virtual = [z for z in ap.ZONES if z not in ("wireguard_admin", *mapped)]
        labels: dict[str, str] = {}
        try:
            from pazuzu_core.zone_assignment import selectable_interfaces
            from pazuzu_core.zone_assignment_cli import load_discovery
            by_dev = {i["device"]: port_label(i)
                      for i in selectable_interfaces(load_discovery(self.discovery_path))}
            labels = {z: by_dev.get(assigned[z]["device"], assigned[z]["device"]) for z in mapped}
        except Exception:
            labels = {z: str(assigned[z]["device"]) for z in mapped}
        try:
            plan = ap.plan_addresses([*mapped, *virtual, "wireguard_admin"], avoid=avoid)
        except ValueError as exc:
            raise WizardError(str(exc))
        return {"can_apply": False,
                "zones": [{"zone": z.zone, "word": ap.zone_word(z.zone), "port": labels.get(z.zone, ""),
                           "network": z.network, "firewall_ip": z.firewall_ip,
                           "virtual": z.zone in virtual,
                           "dhcp_start": z.dhcp_start, "dhcp_end": z.dhcp_end} for z in plan.zones],
                "guidance": ap.guidance_lines(plan, labels, virtual)}

    @staticmethod
    def _own_ports(found) -> dict:
        """{zone: device} for the ports on the firewall that carry Pazuzu's own name for a zone (PZ_Mgmt, PZ_IoT, ...)
        and are switched on: the networks an earlier setup made. A name seen on two ports is left to the person."""
        from pazuzu_core import zone_vlans as zv
        out: dict[str, str] = {}
        for zone, label in zv.LABELS.items():
            mine = [i for i in found if str(i.get("description") or "") == label and i.get("assigned")
                    and i.get("enabled") is not False and i.get("device")]
            if len(mine) == 1:
                out[zone] = str(mine[0]["device"])
        return out

    def _adopt_own_ports(self, found) -> list:
        """BUILD 524 (the maintainer, an installed firewall the wizard had already set up, run again from a new folder, 12 Nov
        2026: "A port called PZ_Mgmt is already on the firewall (opt1) and it is not one Pazuzu made"). Which port is
        which zone is remembered in the folder the wizard runs from, so a new download had forgotten the networks an
        earlier run made: it offered to make them again, and refused its own port as someone else's. The firewall's
        ports that carry Pazuzu's own names are taken as those zones' ports. Only the saved choice on this device
        changes. Once per zone for each run of the wizard, so a zone the person then leaves off stays off."""
        done = getattr(self, "_adopted_zones", None)
        if done is None:
            done = self._adopted_zones = set()
        zones_now = (self.status().get("zones") or {}).get("assignments") or {}
        if not zones_now:
            return []                                   # nothing saved yet: the first save takes them (_port_picks)
        need = {z: d for z, d in self._own_ports(found).items()
                if z not in done and (zones_now.get(z) or {}).get("state") in (None, "unconfigured")}
        if not need:
            return []
        done.update(need)
        try:
            self.save_zones(self._port_picks(found, {z: {"method": "existing", "device": d} for z, d in need.items()}))
        except WizardError:
            return []
        return sorted(need)

    def _port_picks(self, found, change=None):
        """Every zone's port for the saved choice: what the person already chose stays (when the firewall still has
        that port), the internet port and the home port are the ones the firewall already has assigned as WAN and LAN
        when nothing better is saved, and every other zone is left off. `change` is what the person is picking now
        and is never overridden. The ports file needs every zone named, and a WAN, or it is refused."""
        have = {i["device"] for i in found}
        current = (self.status().get("zones") or {}).get("assignments") or {}
        picks: dict[str, dict] = {}
        for z in ALL_ZONES:
            a = current.get(z) or {}
            dev = a.get("device")
            if dev and a.get("state") != "unconfigured" and dev in have:
                picks[z] = {"method": "existing", "device": str(dev)}
            elif z in ZONES:
                picks[z] = {"method": "unconfigured"}
        picks.update(change or {})
        for zone, dev in self._own_ports(found).items():       # BUILD 524: the networks an earlier setup made
            if zone not in (change or {}) and picks.get(zone, {}).get("method") != "existing":
                picks[zone] = {"method": "existing", "device": dev}
        for zone, identifier in (("wan", "wan"), ("trusted", "lan")):
            if zone in (change or {}) or picks[zone]["method"] == "existing":
                continue
            ours = [i for i in found if i.get("identifier") == identifier and i.get("assigned")]
            if len(ours) == 1:
                picks[zone] = {"method": "existing", "device": ours[0]["device"]}
        return picks

    def auto_zones(self) -> dict:
        """The internet port as WAN and the home port as the Trusted network, when the firewall already has both assigned
        Only the saved choice changes, on this device:
        nothing is sent to the firewall. {"done": False} when anything is missing or unclear, and the person picks."""
        try:
            data = self.interfaces()
            found = data["interfaces"]
            wan = [i for i in found if i.get("identifier") == "wan" and i.get("assigned")]
            lan = [i for i in found if i.get("identifier") == "lan" and i.get("assigned")]
            if len(wan) != 1 or len(lan) != 1:
                return {"done": False}
            # BUILD 480: the ports file needs every zone named, so the others are named too (off, or what was saved).
            # With only these two it was refused every time ("Missing zone selections"), and the ports page showed.
            picks = self._port_picks(found, {"wan": {"method": "existing", "device": wan[0]["device"]},
                                             "trusted": {"method": "existing", "device": lan[0]["device"]}})
            return {"done": bool(self.save_zones(picks).get("deployable"))}
        except WizardError:
            return {"done": False}

    def zones_later(self, d) -> dict:
        """Ports picked for a zone before the firewall has set them up. Remembered on this device only, so the pick is
        still there when the page is opened again; the zone itself stays off until the firewall has the port."""
        import re
        d = d if isinstance(d, dict) else {}
        keep: dict[str, str] = {}
        for zone, dev in d.items():
            if zone in ZONES and zone != "wan" and isinstance(dev, str) and re.fullmatch(r"[A-Za-z0-9_.]{1,24}", dev):
                keep[zone] = dev
        self._remember("zones_later", keep)
        return {"later": keep}

    def zone_set(self, zone, device) -> dict:
        """Change one zone's port and keep the others as they are. Only the saved choice
        changes (a file on this device): nothing is sent to the firewall."""

        if zone not in ALL_ZONES:
            raise WizardError("That zone was not understood.")
        if device is not None and not isinstance(device, str):
            raise WizardError("That port was not understood.")
        found = self.interfaces()["interfaces"]        # refresh the list the choice is checked against
        change = ({zone: {"method": "existing", "device": device}} if device
                  else {zone: {"method": "unconfigured"}})
        picks = self._port_picks(found, change)
        if picks["wan"]["method"] != "existing" and "wan" not in change:
            raise WizardError("The firewall has no internet port set up yet, so the ports cannot be saved. "
                              "Set up the internet port on the firewall first, then try again.")
        return self.save_zones(picks)

    def ready(self) -> dict:
        """What is missing before the switch-on: a way in, and the rules themselves.
        Reads only. Each part can fail alone and says why."""

        out: dict = {"zones": None, "zones_error": None, "rules": None, "rules_error": None, "way": {"ok": False, "words": ""}}
        try:
            out["zones"] = self.zone_options()
        except Exception as exc:
            out["zones_error"] = _plain(exc)
        try:                                                 # a way in: the management port once it has a zone, the VPN, Bluetooth
            mgmt = ((out["zones"] or {}).get("assignments") or {}).get("management") if out["zones"] else None
            words = self._way_in_words()
            parts = ([f"the management port ({mgmt})"] if mgmt else []) + ([words] if words else [])
            out["way"] = {"ok": bool(parts), "words": " and ".join(parts)}
        except Exception:  # noqa: BLE001
            pass
        try:
            p = self._preview_filling_in_ports()
            out["rules"] = {"new": p["new_rules"], "there": p["already_there"],
                            "groups": p["groups"],
                            "skipped": [ln for ln in p["lines"] if ln.startswith("skipped ")]}
            if p["new_rules"] is None:
                # The check ran but did not say how many rules are missing. Show its own last words, so the screen
                # says why instead of only that it could not tell.
                out["rules"]["said"] = [str(ln).strip()[:200] for ln in p["lines"][-4:]]
        except Exception as exc:
            out["rules_error"] = _plain(exc)
        return out

    def fill_in_internet_and_home_ports(self) -> bool:
        """Saves the internet and home ports the firewall already has assigned as WAN and LAN, keeping every port the
        person already chose. Only the saved choice changes, on this device. False when anything is missing or unclear.
        (The wizard's own shortcut past the ports page is auto_zones, which is left as it was.)"""
        try:
            found = self.interfaces()["interfaces"]
            picks = self._port_picks(found)
            if picks["wan"]["method"] != "existing" or picks["trusted"]["method"] != "existing":
                return False
            if self.save_zones(picks).get("deployable"):
                return True
            # A port chosen for a zone before the firewall had it set up (no cable, not assigned yet) blocks the whole
            # switch-on. Better no port for that zone than not set up: leave those zones off for now, and keep the
            # choice in "later" so it is still there when the firewall has the port.
            held = self._pending_zones()
            if not held:
                return False
            later = dict(self._recall("zones_later") or {})
            later.update(held)
            self._remember("zones_later", later)
            for zone in held:
                picks[zone] = {"method": "unconfigured"}
            return bool(self.save_zones(picks).get("deployable"))
        except WizardError:
            return False

    def _try_fill_in(self) -> bool:
        """fill_in_internet_and_home_ports, with any failure to read the ports taken as "could not fill in"."""
        try:
            return bool(self.fill_in_internet_and_home_ports())
        except Exception:  # noqa: BLE001 - the caller then says in words what is missing
            return False

    def _pending_zones(self) -> dict:
        """The zones whose saved port the firewall has not set up yet (it is not assigned), by zone name. Reads only."""
        from pazuzu_core.zone_assignment import BLOCKING_STATES
        current = (self.status().get("zones") or {}).get("assignments") or {}
        return {z: str(a.get("device")) for z, a in current.items()
                if z != "wan" and isinstance(a, dict) and a.get("device") and a.get("state") in BLOCKING_STATES}

    def _preview_filling_in_ports(self) -> dict:
        """The rules to add, read-only. When the only thing missing is the saved port choice, the internet and home
        ports the firewall already has are saved (see fill_in_internet_and_home_ports) and the rules are read once more.
        If that cannot settle it, the words stay and the person chooses."""
        try:
            return self.preview_rules()
        except WizardError as exc:
            if str(exc) != PORTS_NOT_SAVED or not self.fill_in_internet_and_home_ports():
                raise
        return self.preview_rules()

    def save_zones(self, selections) -> dict:
        from pazuzu_core.zone_assignment import build_zone_assignment
        from pazuzu_core.zone_assignment_cli import load_discovery, write_assignment
        if not isinstance(selections, dict):
            raise WizardError("Choose an interface for each zone, or leave it off.")
        clean: dict[str, dict] = {}
        for zone, choice in selections.items():
            if zone not in ALL_ZONES or not isinstance(choice, dict):
                raise WizardError("That zone choice was not understood.")
            method = choice.get("method")
            if method == "existing":
                clean[zone] = {"method": "existing", "device": str(choice.get("device") or "")}
            elif method == "unconfigured":
                clean[zone] = {"method": "unconfigured"}
            else:
                raise WizardError("Only an existing interface, or leaving a zone off, "
                                  "is offered here.")
        try:
            discovery = load_discovery(self.discovery_path)
        except (OSError, ValueError):
            raise WizardError("Read the interfaces first.")
        try:
            report = build_zone_assignment(discovery, clean)
        except ValueError as exc:
            raise WizardError(str(exc))
        write_assignment(report, self.zones_path)
        return self.status()["zones"]

    # -- rules
    def preview_rules(self, limit=None) -> dict:
        lines = self._run_apply(approve=False, limit=limit)
        text = "\n".join(lines)
        new = _COUNT_NEW.search(text)
        there = _COUNT_THERE.search(text)
        return {"lines": lines, "groups": _group_explanations(lines),
                "new_rules": int(new.group(1)) if new else (0 if "Nothing to add" in text else None),
                "manifest_rules": int(new.group(2)) if new else None,
                "already_there": int(there.group(1)) if there else 0}

    def _run_apply(self, approve: bool, limit=None) -> list[str]:
        from pazuzu_core import firewall_manifest_smoke as smoke
        if limit is None:
            limit = WHOLE_MANIFEST   # the manager asks with no limit; the smoke tool's own default is 4
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 50:
            raise WizardError("That number of rule groups is not allowed.")
        if not self.zones_path.exists() and not self._try_fill_in():
            # The Ports step was skipped, so no port choice was ever saved. Using the ports the firewall already has as
            # WAN and LAN did not settle it either: say so in words, not as a missing-file error.
            raise WizardError(PORTS_SKIPPED)
        fn = self._apply or smoke.apply
        sink = _Lines()
        role = en.WRITE if approve else en.READ
        try:
            with self._env(role), contextlib.redirect_stdout(sink):
                fn(self.manifest, str(self.zones_path), approve=approve,
                   limit=limit, gate=self.window_gate if approve else None)
        except WizardError:
            raise
        except Exception as exc:
            if "not deployable" in str(exc):
                raise WizardError(PORTS_NOT_SAVED)
            raise WizardError(_plain_firewall(exc))
        return _summary_lines(sink.finish())

    def unguarded(self) -> dict:
        """What is open on the firewall as it is now. Read-only; each read can fail alone."""

        if self._unguarded_fn is not None:
            return self._unguarded_fn()
        items: list[dict] = []
        unreadable: list[str] = []
        with self._env(en.READ):
            try:
                from pazuzu_core.egress_drift import evaluate
                from pazuzu_core.egress_drift_cli import _load_live
                rules, aliases = _load_live()
                report = evaluate(rules, aliases)
                for c in report["controls"]:
                    if c["status"] == "drifted" and c["control"] in _OPEN_WORDS:
                        title, why = _OPEN_WORDS[c["control"]]
                        items.append({"title": title, "why": why, "state": "unsafe"})
            except Exception:
                unreadable.append("which traffic gets around the firewall")
            try:
                from pazuzu_core.stock_rules_cli import run as stock_run
                found = stock_run("scan_results/stock_rules_plan.json")["found"]
                if any(i["role"].startswith("stock_") and i.get("enabled") for i in found):
                    items.append({"title": "The default allow-everything rules are on",
                                  "why": "Your home network can reach anything, in or out.",
                                  "state": "unsafe"})
            except Exception:
                unreadable.append("the default allow-everything rules")
            try:
                from pazuzu_core.firewall_rule_audit_cli import run as audit_run
                sm = audit_run(self.manifest, "scan_results/firewall_rule_audit_v0_4.json")["summary"]
                if sm.get("unsafe", 0):
                    items.append({"title": f"{sm['unsafe']} of your rules look risky",
                                  "why": "They allow more than the baseline would.",
                                  "state": "unsafe"})
            except Exception:
                unreadable.append("your existing rules")
        for what in unreadable:
            items.append({"title": "Could not check " + what, "why": "", "state": "unchecked"})
        items += [
            {"title": "Packet inspection (IPS)", "why": "Not checked yet.", "state": "unchecked"},
            {"title": "Ad lists and block lists", "why": "Not checked yet.", "state": "unchecked"},
            {"title": "The firewall’s admin password",
             "why": "Not checked yet. A new firewall still has the factory password.",
             "state": "unchecked"}]
        return {"items": items}

    def control_state(self) -> dict:
        """Test mode: no rule is added or switched on until the plugin is on the firewall and the version has been
        read, so there is always a way in from the inside first. The careful mode keeps its own checks."""
        if not self.light:
            return {"ok": True, "plugin": True, "version": True, "why": ""}
        if not self._plugin_offered():       # BUILD 513: no plugin in beta 1, so nothing waits for one
            return {"ok": True, "plugin": False, "version": bool(getattr(self, "_version_seen", False)),
                    "why": "", "skipped": True}
        if getattr(self, "_control_skipped", False) or self._recall("plugin_skipped"):
            return {"ok": True, "plugin": self._box_up(), "version": bool(getattr(self, "_version_seen", False)),
                    "why": "", "skipped": True}
        plugin, version = self._box_up(), bool(getattr(self, "_version_seen", False))
        why = ("" if plugin and version else
               "Put the Pazuzu plugin on the firewall first, then read which version it is on. "
               "No rule is added or switched on before that." if not plugin else
               "Read which version the firewall is on first. No rule is added or switched on before that.")
        return {"ok": plugin and version, "plugin": plugin, "version": version, "why": why}

    def control_skip(self) -> dict:
        """BUILD 493 (the maintainer, 10 Nov 2026: "New firewall: add a way to carry on without the plugin"). The person chooses
        to go on without the plugin: the rules still go in and on (the LAN lifeline keeps the way in), and what needs
        the plugin (the Wi-Fi back door, the box's screen, blocks) says so where it is offered."""
        self._control_skipped = True
        self._remember("plugin_skipped", True)
        return self.control_state()

    def _need_control(self) -> None:
        got = self.control_state()
        if not got["ok"]:
            raise WizardError(got["why"])

    def apply_rules(self, limit=None) -> dict:
        if not self.status()["write_user"]:
            raise WizardError("Make the change-making account first.")
        self._need_control()
        if not (self.status()["zones"] or {}).get("deployable") and not self._try_fill_in():
            raise WizardError(PORTS_SKIPPED if not self.zones_path.exists() else
                              "The zone choices are not ready to use yet.")
        return self._start("apply-rules", lambda: {
            "lines": self._run_apply(approve=True, limit=limit)})


    # -- turning rules on, one stage at a time, each under the change guard
    def _inventory(self):
        loader = self._inventory_loader
        if loader is None:
            from pazuzu_core.staged_enabling_cli import _load_live as loader
        return loader()

    def _guard(self) -> dict:
        from pazuzu_core.change_guard import ChangeGuard, GuardError
        try:
            snap = ChangeGuard(None, self.journal).snapshot()
        except (GuardError, OSError, ValueError, KeyError):
            return {"active": False}
        for step in snap.get("steps") or []:
            name = self._names.get(step.get("uuid"))
            if name:
                step["name"] = name
        return snap

    def _management_suggestion(self) -> dict | None:
        """The port the Management network could use, or nothing if it can't be read."""

        try:
            return self.interfaces().get("suggested_management")
        except Exception:
            return None

    def plan(self, lab=None) -> dict:
        from pazuzu_core.staged_enabling import build_plan
        lab = self.lab_lifeline if lab is None else lab
        from pazuzu_core.staged_executor import STAGE_IDS
        try:
            with self._env(en.READ):
                plan = build_plan(self._inventory(), lab_lifeline=lab, way_in=self._way_in_words())
        except WizardError:
            raise
        except Exception as exc:
            raise WizardError(f"Could not read the rules: {_plain_firewall(exc)}")
        stages, checks = [], []
        for stage in plan["stages"]:
            way = None
            if stage.get("kind") == "human_check":
                checks = list(stage["checks"])
                continue
            if stage["id"] not in STAGE_IDS:
                continue
            title, what = _STAGE_WORDS.get(stage["id"], (stage["title"], ""))
            if "lifeline" == stage["id"] and stage["blockers"]:
                way = self._management_suggestion()
            stages.append({"id": stage["id"], "title": title, "what": what,
                           "status": stage["status"], "steps": len(stage["steps"]),
                           "blockers": [_name_the_port(_plain_blocker(b), way)
                                        for b in stage["blockers"]],
                           "window": stage["timeout_seconds"],
                           "checks_before": checks,
                           "window_checks": list(stage.get("window_checks", []))})
            checks = []
        return {"stages": stages}

    def stage_preview(self, stage_id, services_checked=False, lab=None) -> dict:
        from pazuzu_core import staged_executor as sx
        try:
            with self._env(en.READ):
                prepared = sx.prepare_stage(
                    self._inventory(), stage_id,
                    services_checked=services_checked is True or self.light or self.services_state()["ok"],   # test mode: no internet checks are needed
                    lab_lifeline=self.lab_lifeline if lab is None else lab)
        except WizardError:
            raise
        except (sx.ExecutorError, ValueError) as exc:
            text = _plain(exc)
            if "is already done" in text:
                raise WizardError("Handled. Nothing is left to change here.")
            raise WizardError(text.replace("needs --services-checked:",
                                           "needs the box ticked:"))
        except Exception as exc:
            raise WizardError(f"Could not read the rules: {_plain_firewall(exc)}")
        for step in prepared.steps:
            self._names[step["uuid"]] = sx._rule_name(prepared, step["uuid"])
        return {"stage": stage_id, "digest": prepared.digest,
                "window": prepared.timeout_seconds, "steps": len(prepared.steps),
                "lines": list(sx.describe(prepared))}

    def stage_run(self, stage_id, digest, services_checked=False, lab=None) -> dict:
        from pazuzu_core.staged_executor import STAGE_IDS
        if stage_id not in STAGE_IDS or not isinstance(digest, str) or not digest:
            raise WizardError("That stage was not understood.")
        status = self.status()
        if not status["write_user"]:
            raise WizardError("Make the change-making account first.")
        if status["guard"].get("active"):
            raise WizardError("A change is already waiting for you to keep or undo it.")
        argv = ["stage", stage_id, "--approve-digest", digest, "--journal", self.journal]
        if services_checked is True or self.services_state()["ok"]:
            argv.append("--services-checked")
        if self.lab_lifeline if lab is None else lab:
            argv.append("--lab-lifeline")

        def work() -> dict:
            main = self._stage_main
            if main is None:
                from pazuzu_core.staged_executor_cli import main
            problems = io.StringIO()
            with self._env(en.WRITE), contextlib.redirect_stderr(problems):
                code = main(argv, gate=self.change_gate(stage_id))
            if code == 2:
                text = problems.getvalue().strip().splitlines()
                raise WizardError(_plain(Exception(
                    text[-1].removeprefix("error: ") if text else "refused")))
            return {"exit": code,
                    "outcome": {0: "kept", 1: "undone"}.get(code, "needs_a_person")}

        return self._start("stage-" + stage_id, work)

    def decide(self, decision) -> dict:
        from pazuzu_core.change_guard import CONFIRM, REVERT, ChangeGuard, GuardError
        if decision not in ("keep", "undo"):
            raise WizardError("Choose keep or undo.")
        try:
            ChangeGuard(None, self.journal).decide(CONFIRM if decision == "keep" else REVERT)
        except (GuardError, OSError, ValueError) as exc:
            raise WizardError(_plain(exc))
        return {"recorded": decision}

    # -- the whole plan on one passkey, each stage kept only if the app's tests pass
    def preflight(self) -> list:
        """What the firewall's ports look like now against what was chosen earlier (read only). A list of findings,
        {"id", "level": "stop" | "warn", "text"}; empty when all is as it was or when there is nothing to compare."""
        from pazuzu_core import preflight as pf
        scan = self._scan
        if scan is None:
            if self._inventory_loader is not None or self._read_fn is not None:
                return []                                  # a test double reads the firewall: nothing real to scan
            from pazuzu_core.opnsense_scanner import scan_interfaces as scan
        try:
            with self._env(en.READ):
                report = scan()
        except Exception as exc:
            return [{"id": "unread", "level": "warn",
                     "text": "The firewall's ports could not be read to check them (" + _plain_firewall(exc) + ")."}]
        saved = None
        try:
            saved = json.loads(self.zones_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            saved = None
        return pf.check(report, saved)

    def plan_preview(self, lab=None, group=None) -> dict:
        # BUILD 437: the preview takes the keys several times over (the rules, the port scan, the VPN look) and the
        # manager's board refresh took them in between each one, so every wait stacked up and the button sat on
        # "Reading..." for minutes. The refreshes queue behind the whole preview instead; the board shows
        # its last reading meanwhile.
        with self._bg_lock:
            return self._plan_preview(lab, group)

    def _plan_preview(self, lab=None, group=None) -> dict:
        from pazuzu_core.passkey_gate import plan_digest
        from pazuzu_core.staged_enabling import build_plan
        from pazuzu_core import staged_executor as sx
        lab = self.lab_lifeline if lab is None else lab
        try:
            with self._env(en.READ):
                inventory = self._inventory()
            plan = build_plan(inventory, lab_lifeline=lab, way_in=self._way_in_words())
        except WizardError:
            raise
        except Exception as exc:
            raise WizardError(f"Could not read the rules: {_plain_firewall(exc)}")
        rows = {str(r.get("uuid")): r for r in inventory.get("rows", []) if isinstance(r, dict)}
        if group is not None and group not in STAGE_GROUPS:
            raise WizardError("That part of the setup was not understood.")
        todo = [st for st in plan["stages"]
                if st["id"] in sx.STAGE_IDS and st["status"] != "done" and st["steps"]
                and (group is None or st["id"] in STAGE_GROUPS[group])]
        ipv6_global = self._ipv6_state() == "on"
        ipv6_ifaces = self._ipv6_iface_todo()
        ipv6_on = ipv6_global or ipv6_ifaces           # IPv6 goes off first, whichever part of the setup runs first
        if not todo and not ipv6_on:
            raise WizardError("Handled. Nothing is left to switch on.")
        if todo and todo[0]["blockers"]:
            way = self._management_suggestion() if todo[0]["id"] == "lifeline" else None
            raise WizardError(" ".join(_name_the_port(_plain_blocker(b), way)
                                       for b in todo[0]["blockers"]))
        findings = self.preflight()
        stops = [f["text"] for f in findings if f["level"] == "stop"]
        if stops:
            raise WizardError(" ".join(stops))
        base = baseline_lines(inventory.get("rows", []))
        lines = (["The whole baseline on this firewall, as it stands:"] + base + [""]) if base else []
        lines += ["Switch on everything that is left, one stage after another, on this one passkey.",
                 "After each stage the app tests it from this device. If every test passes the "
                 "stage is kept; if one fails that stage is undone and the run stops."]
        stages, payload = [], []
        first = 1
        if ipv6_on:
            from pazuzu_core import ipv6_off
            if ipv6_global:
                lines.append(f"1. {ipv6_off.LINE}")
            else:
                lines.append("1. Turn IPv6 off.")
            if ipv6_ifaces:
                lines.append(f"   {ipv6_off.IFACES_LINE}")
            stages.append({"id": "ipv6", "title": "Turn IPv6 off", "steps": 1, "window": 0})
            step = {"kind": "ipv6_off"}
            if ipv6_ifaces:
                step["interfaces"] = "none"
            payload.append({"id": "ipv6", "steps": [step]})
            first = 2
        for n, st in enumerate(todo, first):
            title, _what = _STAGE_WORDS.get(st["id"], (st["title"], ""))
            lines.append(f"{n}. {title}")
            for step in st["steps"]:
                name = sx.name_of(rows.get(step["uuid"], {}).get("description"), step["uuid"])
                if step["kind"] == "toggle_rule":
                    lines.append(("   Turn on: " if step["after"] else "   Turn off: ") + name)
                else:
                    lines.append(f"   Add a note to: {name}")
            stages.append({"id": st["id"], "title": title, "steps": len(st["steps"]),
                           "window": st["timeout_seconds"]})
            payload.append({"id": st["id"], "steps": [dict(x) for x in st["steps"]]})
        return {"digest": plan_digest("run-plan", {"stages": payload, "lab": bool(lab)}),
                "stages": stages, "lines": lines, "lab": bool(lab),
                "notes": [f["text"] for f in findings if f["level"] == "warn"]}

    def _ipv6_state(self):
        """"on", "off", or None (not read): is IPv6 allowed for the whole firewall? Read with the read account."""
        from pazuzu_core import ipv6_off
        try:
            engine = we.Engine(self._role_session(en.READ, "Make the read account first."),
                               self.base_url.rstrip("/"), self._probe)
            return ipv6_off.state(engine)
        except Exception:
            return None

    def _ipv6_types(self):
        """What the plugin reads for the IPv6 type of the WAN and the LAN, or None when it cannot say."""
        try:
            if not self._box_up():
                return None
            return self._acts.source.box.ipv6_none_status()
        except Exception:
            return None

    def _ipv6_iface_todo(self) -> bool:
        """Is there a WAN or LAN IPv6 type to set to None, or a change saved as None but never applied, and a plugin that
        can do it?"""
        got = self._ipv6_types()
        return got is not None and (not got.get("all_none") or bool(got.get("pending")))

    def _ipv6_none_apply(self) -> dict:
        """Ask the plugin to set the WAN and LAN IPv6 type to None. If the answer is lost (the interfaces are
        reconfigured while it is given), read the types back for a little while before calling it a failure."""
        box = self._acts.source.box
        try:
            got = box.ipv6_none()
        except Exception:
            got = None
        if isinstance(got, dict) and got.get("ok") is not None:
            return got
        for _ in range(IPV6_NONE_POLLS):
            time.sleep(IPV6_NONE_WAIT)
            seen = self._ipv6_types()
            if seen is not None and seen.get("all_none") and not seen.get("pending"):
                return {"ok": True, "changed": True}
        return {"ok": False, "error": "The plugin did not answer, and the types were not None when read back."}

    @staticmethod
    def _ipv6_types_by_form(engine) -> str:
        """BUILD 518 (the maintainer, 12 Nov 2026: "have that step set the WAN to None too"): with no plugin, set IPv6
        Configuration Type to None on the WAN and the LAN through the firewall's own port form. Returns what to say.
        A port it could not set never stops the rules: it is named, with the by-hand way."""
        from pazuzu_core import zone_vlans as zv
        try:
            got = zv.ZoneVlans(engine).ipv6_types_none()
        except Exception:  # noqa: BLE001 - this part is a courtesy; the rules go on either way
            return ""
        names = lambda xs: " and ".join("the " + x.upper() for x in xs)
        said = ""
        if got["changed"]:
            said += "The IPv6 type is now None on " + names(got["changed"]) + " (read back to check). "
        if got["cannot"]:
            said += ("The IPv6 type on " + names(got["cannot"]) + " could not be set from here: on the firewall, "
                     "Interfaces, that port, IPv6 Configuration Type: None, then Save and Apply. ")
        return said

    def _ipv6_by_form_after_plugin(self) -> str:
        """BUILD 535: the plugin could not apply the None it saved. Set it (or, if already saved, apply it) through the
        firewall's own port form. Returns what to say, or "" if that did not work either."""
        from pazuzu_core import zone_vlans as zv
        try:
            engine = we.Engine(self._installer_session(), self.base_url.rstrip("/"), self._probe)
            got = zv.ZoneVlans(engine).ipv6_types_none(apply_anyway=True)
        except Exception:  # noqa: BLE001 - the plugin's own error is the one shown
            return ""
        if got.get("cannot") or not (got.get("changed") or got.get("applied")):
            return ""
        return "The IPv6 type is None on the WAN and the LAN, applied through the firewall's own Interfaces form (read back to check). "

    def _ipv6_stage(self, entry: dict) -> bool:
        """The first thing the finish page does: the IPv6 type None on the WAN and the LAN, then IPv6 off for the
        whole firewall, each read back to check."""
        from pazuzu_core import ipv6_off
        from pazuzu_core import ipv6_execution as ix
        did = ""
        if self._ipv6_iface_todo():
            got = self._ipv6_none_apply()
            if not got.get("ok"):
                # BUILD 535 (the maintainer, 13 Nov 2026, 26.7.9: the plugin's apply failed in interface_reset after saving None):
                # the firewall's own port form and its Apply, the way proven on 26.7.9, before giving up.
                did = self._ipv6_by_form_after_plugin()
                if not did:
                    entry.update(state="stopped", detail=(
                        "The IPv6 type could not be set to None on the WAN and the LAN ("
                        + str(got.get("error") or "no reason given").rstrip(".")
                        + "). Nothing else was changed. " + ipv6_off.BY_HAND))
                    return False
            else:
                did = "The IPv6 type is None on the WAN and the LAN (read back to check). "
                if got.get("restart"):
                    did += "A restart of the firewall clears any old IPv6 address left on the ports. "
        try:
            engine = we.Engine(self._installer_session(), self.base_url.rstrip("/"), self._probe)
            if not did and not self._box_up():
                did = self._ipv6_types_by_form(engine)      # BUILD 518: no plugin: the firewall's own port form
            if ipv6_off.state(engine) == "off":
                entry.update(state="kept" if did else "handled", detail=did + "IPv6 was already off for the whole firewall.")
                return True
            ipv6_off.turn_off(engine)
        except (WizardError, ix.ExecutionFailed, we.WriteError) as exc:
            entry.update(state="stopped", detail=(
                did + "IPv6 could not be switched off for the whole firewall (" + _plain_firewall(exc).rstrip(".")
                + "). " + ("Nothing else was changed. " if not did else "") + ipv6_off.BY_HAND))
            return False
        entry.update(state="kept", detail=did + "IPv6 is off for the whole firewall (read back to check).")
        return True

    def _stage_entry(self, sid: str, lab: bool) -> dict | None:
        from pazuzu_core.staged_enabling import build_plan
        with self._env(en.READ):
            inventory = self._inventory()
        return next((st for st in build_plan(inventory, lab_lifeline=lab, way_in=self._way_in_words())["stages"]
                     if st["id"] == sid), None)

    def _window_tests(self, sid: str) -> list:
        from pazuzu_core import lan_tests as lt
        host, _p = base_host_port(self.base_url)
        only = None if sid in ("stock_disable", "blocking") else ("dns_firewall", "time_firewall", "web")
        if only is None and self.phone:
            # BUILD 480: on a Hanbi the tests run on the box itself, and the box's own lookups are let out by the firewall's
            # own rule, so an outside name server always answers there: that test cannot judge the LAN's rule from here.
            only = ("dns_firewall", "time_firewall", "web", "no_ipv6")
        if self._lan_fn:
            rows = self._lan_fn(host, only=only)
        else:
            # Test mode needs no internet: a firewall that answers is enough. Careful mode stays strict.
            rows = lt.run(host, only=only, lenient=bool(self.light))
        for r in rows:
            self._lan_seen[r["id"]] = r["status"]
        return rows

    def plan_run(self, digest, lab=None, group=None) -> dict:
        from pazuzu_core.passkey_gate import plan_digest
        lab = self.lab_lifeline if lab is None else lab
        if not isinstance(digest, str) or not digest:
            raise WizardError("That plan was not understood.")
        status = self.status()
        if not status["write_user"]:
            raise WizardError("Make the change-making account first.")
        if status["guard"].get("active"):
            raise WizardError("A change is already waiting for you to keep or undo it.")
        self._need_control()
        preview = self.plan_preview(lab, group)
        if preview["digest"] != digest:
            raise WizardError("The plan changed since the preview. Look at it again.")
        ids = [st["id"] for st in preview["stages"]]
        titles = {st["id"]: st["title"] for st in preview["stages"]}
        window = sum(st["window"] for st in preview["stages"]) + 120 * len(ids)

        def work() -> dict:
            if self._now() >= self._grace_until:          # a touch in the last two minutes covers this too
                if not self.gate(plan_digest("run-plan-approval", {"digest": digest}),
                                 preview["lines"]):
                    raise WizardError("Not approved with a passkey. Nothing was changed.")
                self._grace_until = self._now() + GRACE_SECONDS
            self._plan_grant = {"ids": set(ids), "until": self._now() + window}
            before = self._internet_quiet()               # the firewall's own way out, before and after the rules
            progress = [{"id": i, "title": titles[i], "state": "waiting", "detail": ""} for i in ids]
            self._job["progress"] = progress
            stopped = None
            try:
                for entry in progress:
                    entry["state"] = "running"
                    ok = self._run_one_stage(entry, lab)
                    print(f"{entry['title']}: {entry['state']}. {entry['detail']}")
                    if not ok:
                        stopped = entry
                        break
            finally:
                self._plan_grant = None
            after = self._internet_quiet()
            note = None
            if before is True and after is False:
                note = ("The firewall could reach the internet before the rules went on and cannot now. "
                        "The rules are cutting its own traffic: that needs fixing before block lists or updates can work.")
            elif after is False:
                note = "The firewall cannot reach the internet (it could not before the rules either)."
            elif after is True:
                note = "The firewall still reaches the internet with the rules on."
            self._internet_note = {"before": before, "after": after, "line": note}
            return {"outcome": "stopped" if stopped else "done", "stages": progress, "internet": note,
                    "internet_ok": after}

        return self._start("plan", work)

    def _plugin_link_rule(self, entry: dict) -> bool:
        """Add the one rule that keeps the plugin reachable once the stock allow-all rules are off.

        Returns True when the old rules may go off: the rule is in place, or there is no plugin to keep reachable.
        Returns False, with the stage marked stopped and the reason, when the plugin is on the firewall (or was) and
        the rule could not be added. The old rules then stay on: once they are off with no rule for the plugin, the
        firewall's default deny cuts the plugin off, and it cannot be reached again to put the rule right."""
        from urllib.parse import urlparse
        from pazuzu_core import plugin_link
        box = self._live_box()
        if box is None:
            if not plugin_present():
                # BUILD 517 (the maintainer, live disc, the 516 zip, 12 Nov 2026: "The plugin is not answering ... Open the plugin
                # step"): beta 1 has no plugin, so there is none to keep reachable. This PC still remembered a plugin's
                # link from an older install at the same address, and part 2 of the rules stopped on it for good.
                return True
            if isinstance(self._recall("box_link"), dict):
                entry.update(state="stopped", detail=(
                    "The plugin is not answering. The old allow-all rules were left on, because turning them off "
                    "now would cut the plugin off for good. Open the plugin step, reconnect it, and run this again."))
                return False
            if self.light and not self.control_state().get("skipped"):
                entry.update(state="stopped", detail=(
                    "The plugin is not answering. The old allow-all rules were left on, because turning them off "
                    "now would cut the plugin off for good. Open the plugin step, reconnect it, and run this again."))
                return False
            return True        # no plugin ever put on (careful mode, or Carry on without the plugin): nothing to keep reachable
        if self._probe is None:
            entry.update(state="stopped", detail=(
                "The rule that keeps the plugin reachable was not added: check what this firewall supports first. "
                "The old allow-all rules were left on."))
            return False
        try:
            url = urlparse(box.url)
            engine = we.Engine(self._installer_session(), self.base_url.rstrip("/"), self._probe)
            plans = plugin_link.build_plans(engine, url.hostname or "", url.port or 8787)
            if plans:
                engine.apply_many(plans, self.change_gate("stock_disable"))
        except Exception as exc:
            entry.update(state="stopped", detail=(
                "The rule that keeps the plugin reachable could not be added (" + _plain_firewall(exc) + "). "
                "The old allow-all rules were left on."))
            return False
        return True

    def _outside_dns_help(self, bad: list) -> str:
        """What to do when the outside name server test fails. It runs from this device, so a second way out (Wi-Fi) is the
        usual cause: say so, and say what to do, in plain words. Empty when that test was not the one that failed."""
        if not any(r.get("id") == "dns_outside" and r["id"] not in self._lan_skip for r in bad):
            return ""
        try:
            route = self.route_state()
        except Exception:
            route = {}
        if route.get("via_firewall") is False:
            return (" This device has another way out (" + str(route.get("local") or "another network") + "), so that answer did not "
                    "come through the firewall, and the rules may be fine. Turn off this device's other network (for example its "
                    "Wi-Fi), then press Try again.")
        return (" That means a device can still reach an outside name server through the firewall. Check that the rule "
                "\"Stop devices using outside name servers\" is on (Firewall, Rules), then press Try again.")

    def _stage_ended_early(self) -> str:
        """Why a change was no longer waiting for a decision when the tests finished, from what the guard and the
        run itself recorded, not a guess. The window is minutes long, so a tests-took-too-long reading is the last resort."""
        snap = self._guard()
        sink = (self._job or {}).get("sink")
        log = [ln.strip() for ln in (getattr(sink, "lines", None) or [])]
        mismatch = [ln for ln in log if ln.startswith(("The firewall does not match the plan", "Could not read the firewall back"))]
        state = str(snap.get("state") or "")
        errors = [str(x) for x in (snap.get("errors") or [])]
        if mismatch:
            more = [ln for ln in log[log.index(mismatch[0]) + 1:log.index(mismatch[0]) + 5] if ln and not ln.startswith("Undoing")]
            return ("Right after the change went in, the firewall did not match the plan, so it was undone before the tests "
                    "finished. " + " ".join([mismatch[0]] + more) + " Nothing is left half done.")
        if errors:
            return ("The change was undone before the tests finished (" + _plain_firewall(Exception(errors[-1])) + "). "
                    "Its state is now: " + (state or "unknown") + ".")
        if state in ("reverted", "revert_failed"):
            return ("The change was undone before the tests finished, and the firewall recorded no reason. "
                    "The window is " + str(DEFAULT_WINDOW_NOTE) + " minutes, so it was not the timer unless the tests ran longer than that.")
        return ("The change was no longer waiting for a decision when the tests finished (its state: " + (state or "none")
                + "). Nothing is left half done.")

    def _run_one_stage(self, entry: dict, lab: bool) -> bool:
        """Run one stage, test it, keep it if every test passes, undo it if not.
        Returns False when the run must stop here."""
        sid = entry["id"]
        if sid == "ipv6":
            return self._ipv6_stage(entry)
        stage = self._stage_entry(sid, lab)
        if stage is None or stage["status"] == "done":
            entry.update(state="handled", detail="Already in place.")
            return True
        if stage["blockers"]:
            entry.update(state="stopped",
                         detail=" ".join(_plain_blocker(b) for b in stage["blockers"]))
            return False
        if sid == "stock_disable":
            if not self._plugin_link_rule(entry):      # before the stock allows go, so the plugin link survives them
                return False
        if sid == "stock_disable" and not self.light:      # test mode needs no time-sync or other outside checks
            svc = self.services_test()
            if not svc["ok"]:
                left = [r["title"] for r in (svc["rows"] or []) if r["status"] != "good"
                        and r["id"] not in svc["acked"] and r["id"] not in svc["skipped"]]
                entry.update(state="stopped",
                             detail="The last stage waits for these checks: " + "; ".join(left) + ".")
                return False
        try:
            preview = self.stage_preview(sid, lab=lab)
        except WizardError as exc:
            entry.update(state="stopped", detail=str(exc))
            return False
        argv = ["stage", sid, "--approve-digest", preview["digest"], "--journal", self.journal]
        if self.light or self.services_state()["ok"]:
            argv.append("--services-checked")
        if lab:
            argv.append("--lab-lifeline")
        result: dict = {}

        def go() -> None:
            _who.job = True
            main = self._stage_main
            if main is None:
                from pazuzu_core.staged_executor_cli import main
            problems = io.StringIO()
            try:
                with self._env(en.WRITE), contextlib.redirect_stderr(problems):
                    result["code"] = main(argv, gate=self.change_gate(sid))
                if result["code"] == 2:
                    text = problems.getvalue().strip().splitlines()
                    result["error"] = _plain(Exception(
                        text[-1].removeprefix("error: ") if text else "refused"))
            except Exception as exc:
                result["error"] = _plain(exc)

        worker = threading.Thread(target=go, daemon=True)
        worker.start()
        waited = 0.0
        armed = False
        while worker.is_alive() and waited < self._plan_wait:
            guard = self._guard()
            if guard.get("active") and guard.get("state") == "armed":
                armed = True
                break
            self._sleep(0.3)
            waited += 0.3
        if not armed:
            worker.join(timeout=5)
            entry.update(state="stopped", detail=result.get("error") or "The change did not start.")
            return False
        rows = self._window_tests(sid)
        bad = [r for r in rows if r["status"] != "good"]
        if bad:
            # The firewall reloads its rules when a change is applied, and a slow box can miss a test for a few
            # seconds. A test must fail twice, a moment apart, before the change is undone for it.
            self._sleep(3.0)
            rows = self._window_tests(sid)
            bad = [r for r in rows if r["status"] != "good"]
        real_bad = [r for r in bad if r["id"] not in self._lan_skip]
        held = [r["title"] for r in bad if r["id"] in self._lan_skip]
        # A dual-homed setup PC cannot judge the "no outside name servers" test: that query leaves by this
        # device's other network (its Wi-Fi), not through the firewall, so a fail there proves nothing and the
        # rule is most likely fine. Don't undo good rules over a test this device can't run — keep them and flag
        # it, so the install is never stonewalled here. Any OTHER failing test still undoes the stage as before.
        route = {}
        inconclusive = []
        if any(r["id"] == "dns_outside" for r in real_bad):
            try:
                route = self.route_state()
            except Exception:
                route = {}
            if route.get("via_firewall") is False:
                inconclusive = [r for r in real_bad if r["id"] == "dns_outside"]
                real_bad = [r for r in real_bad if r["id"] != "dns_outside"]
        failed = [r["title"] + (" (" + r["detail"] + ")" if r.get("detail") else "")
                  for r in real_bad]
        inconclusive_note = ""
        if inconclusive:
            inconclusive_note = (" Could not confirm “no outside name servers” from this device: it has another way "
                                 "out (" + str(route.get("local") or "another network") + "), so that query did not go through "
                                 "the firewall. The rule is on; confirm it from a device that uses only the firewall. The "
                                 "manager flags this until it is confirmed.")
        if held and not failed:
            # The person skipped a test that did not pass. A skipped test never keeps a change by
            # itself: the change stays open for Keep or Undo, and the timer still undoes it.
            entry.update(state="stopped",
                         detail="Waiting for you to keep or undo it. You skipped: " + "; ".join(held) + ".")
            return False
        try:
            self.decide("undo" if failed else "keep")
        except WizardError as exc:
            if not failed and self._guard().get("state") == "confirmed":
                pass    # already kept (the Keep button, or the stage's own wait, got there first): carry on
            else:
                said = str(exc)
                if "no armed change" in said:
                    worker.join(timeout=30)
                    snap = self._guard()
                    from pazuzu_core import activity
                    activity.note("Stage %s: the decision (%s) found no armed change; the change is now %s; the run's exit code %s; "
                                  "tests that did not pass: %d" % (sid, "undo" if failed else "keep", snap.get("state") or "unreadable",
                                                                   result.get("code"), len(failed)))
                    if not failed and snap.get("state") == "confirmed" and result.get("code") in (0, None):
                        # the Keep button got there a moment before this check could see it: it was kept
                        entry.update(state="kept", detail=f"Kept. {len(rows)} of {len(rows)} tests passed."
                                     + self._clear_old_states())
                        return True
                    if failed and snap.get("state") == "confirmed":
                        entry.update(state="stopped", detail=(
                            "The change was kept (by a Keep press) before the tests finished, and these did not pass: "
                            + "; ".join(failed) + ". The rules are on as they are now."))
                        return False
                    said = self._stage_ended_early()
                entry.update(state="stopped", detail=said)
                worker.join(timeout=30)
                return False
        worker.join(timeout=60)
        code = result.get("code")
        if failed:
            entry.update(state="undone",
                         detail="Undone, because this did not pass: " + "; ".join(failed) + "." + self._outside_dns_help(real_bad) + inconclusive_note)
            return False
        if code == 0:
            if inconclusive:
                entry.update(state="kept", detail="Kept. " + str(len(rows) - len(bad)) + " of " + str(len(rows))
                             + " tests passed; " + str(len(inconclusive)) + " could not be checked from this device."
                             + inconclusive_note + self._clear_old_states())
            else:
                entry.update(state="kept", detail=f"Kept. {len(rows)} of {len(rows)} tests passed." + self._clear_old_states())
            return True
        entry.update(state="stopped", detail=result.get("error") or "The change ended before it was kept.")
        return False

    def _clear_old_states(self) -> str:
        """After a stage is kept: drop the connections the firewall was already passing that a block now on should
        stop (state_clear). Returns a sentence to add (with a leading space), or ""."""
        from pazuzu_core import state_clear
        try:
            session = self._installer_session()
            eng = we.Engine(session, self.base_url.rstrip("/"), self._probe)
            getter = self._api_getter()
            own = []
            for r in ((getter("/api/interfaces/overview/interfaces_info/true") or {}).get("rows") or []) if getter else []:
                for c in (r.get("addr4") if isinstance(r.get("addr4"), list) else [r.get("addr4")]):
                    if c:
                        own.append(str(c).split("/")[0])
            said = state_clear.words(state_clear.clear(eng._req, own))
        except Exception:
            return ""
        return (" " + said) if said else ""

    # -- the shields: lower them for a while, or pause for 15 seconds
    def _pause_log(self, event: str, who: str, digest: str) -> None:
        try:
            path = Path(self.journal).with_name("pause_log.jsonl")
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({"at": time.strftime("%Y-%m-%dT%H:%M:%S"), "event": event,
                                     "who": who, "plan": digest}) + "\n")
        except OSError:
            pass

    def _shield_prepared(self, seconds, pause: bool):
        from pazuzu_core import staged_executor as sx
        try:
            with self._env(en.READ):
                return sx.prepare_shield(self._inventory(), seconds, pause=pause)
        except WizardError:
            raise
        except sx.ExecutorError as exc:
            raise WizardError(_plain(exc))
        except Exception as exc:
            raise WizardError(f"Could not read the rules: {_plain_firewall(exc)}")

    def _guard_busy(self) -> None:
        status = self.status()
        if not status["write_user"]:
            raise WizardError("Make the change-making account first.")
        if status["guard"].get("active"):
            raise WizardError("A change is already open. Finish it first.")

    def shield_set(self, level, seconds=None) -> dict:
        if level == "on":
            guard = self._guard()
            label = str(guard.get("label") or "")
            if guard.get("active") and label.startswith(("shields:", "pause:")):
                self.decide("undo")
            return {"level": "on"}
        if level != "off":
            raise WizardError("That shield setting was not understood.")
        self._guard_busy()
        secs = SHIELD_SECONDS if seconds is None else seconds
        prepared = self._shield_prepared(secs, pause=False)
        argv = ["shield", "off", "--timeout", str(prepared.timeout_seconds),
                "--approve-digest", prepared.digest, "--journal", self.journal]

        def work() -> dict:
            main = self._stage_main
            if main is None:
                from pazuzu_core.staged_executor_cli import main
            problems = io.StringIO()
            with self._env(en.WRITE), contextlib.redirect_stderr(problems):
                code = main(argv, gate=self.change_gate())
            if code == 2:
                text = problems.getvalue().strip().splitlines()
                raise WizardError(_plain(Exception(
                    text[-1].removeprefix("error: ") if text else "refused")))
            return {"exit": code, "outcome": "back_up" if code == 1 else "kept"}

        return self._start("shield", work)

    def pause_now(self, who: str = "the manager") -> dict:
        """Fifteen seconds with the old allow-all rules back on, to find out whether the
        firewall is what is blocking something. No passkey: it is short, it undoes itself,
        it can only touch the rules Pazuzu switched off, and it is logged."""

        self._guard_busy()
        now = self._now()
        if self._last_pause is not None and now - self._last_pause < PAUSE_COOLDOWN:
            wait = int(PAUSE_COOLDOWN - (now - self._last_pause)) + 1
            raise WizardError(f"Wait {wait} more seconds before pausing again.")
        prepared = self._shield_prepared(None, pause=True)
        argv = ["pause", "--approve-digest", prepared.digest, "--journal", self.journal]

        def gate(digest, lines) -> bool:
            self._pause_log("started", who, digest)
            return True

        def work() -> dict:
            main = self._stage_main
            if main is None:
                from pazuzu_core.staged_executor_cli import main
            problems = io.StringIO()
            try:
                with self._env(en.WRITE), contextlib.redirect_stderr(problems):
                    code = main(argv, gate=gate)
            finally:
                self._last_pause = self._now()
                self._pause_log("ended", who, prepared.digest)
            if code == 2:
                text = problems.getvalue().strip().splitlines()
                raise WizardError(_plain(Exception(
                    text[-1].removeprefix("error: ") if text else "refused")))
            return {"exit": code, "outcome": "back_up" if code == 1 else "kept"}

        return self._start("pause", work)

    # -- checks that only read
    def run_checks(self) -> dict:
        checks = self._checks if self._checks is not None else _default_checks(self)
        rows = []
        with self._env(en.READ):
            for check_id, title, fn in checks:
                try:
                    rows.append(dict(fn(), id=check_id))
                except Exception as exc:
                    rows.append({"id": check_id, "title": title, "status": "unknown",
                                 "detail": "Could not check: " + _plain(exc)})
        counts = {k: sum(r["status"] == k for r in rows)
                  for k in ("good", "attention", "not_yet", "unknown")}
        return {"rows": rows, "counts": counts}


class ManagerActions:
    """What the manager may ask the wizard to do. Every change still goes
    through the wizard's passkey gate and the change guard's timer; this only
    carries the request across and turns refusals into plain sentences."""

    def __init__(self, wizard: "Wizard"):
        self.w = wizard

    def _call(self, fn, *args):
        from pazuzu_core.console import ActionError
        was = getattr(_who, "origin", None)
        _who.origin = "manager"                     # what the manager starts asks the manager's way (see Wizard.gate)
        try:
            return fn(*args)
        except WizardError as exc:
            raise ActionError(str(exc))
        finally:
            _who.origin = was

    def manager_unlock(self, d=None):
        return self._call(self.w.manager_unlock_start)

    def manager_lock_state(self):
        return self.w.manager_unlocked()

    def manager_alive(self, d=None):
        return self.w.manager_alive()

    def manager_closing(self, d=None):
        return self.w.manager_closing()

    def manager_lock_now(self, d=None):
        return self.w.manager_lock_now()

    def preview(self, stage, services, lab):
        return self._call(self.w.stage_preview, stage, services, lab)

    def run(self, stage, digest, services, lab):
        return self._call(self.w.stage_run, stage, digest, services, lab)

    def decide(self, decision):
        return self._call(self.w.decide, decision)

    def plan_preview(self, lab):
        return self._call(self.w.plan_preview, lab)

    def plan_run(self, digest, lab):
        return self._call(self.w.plan_run, digest, lab)

    def window_end(self):
        return self.w.window_end()

    def shield(self, level, seconds):
        return self._call(self.w.shield_set, level, seconds)

    def pause(self):
        return self._call(self.w.pause_now)

    def ready(self):
        return self._call(self.w.ready)

    def zone_set(self, zone, device):
        return self._call(self.w.zone_set, zone, device)

    def rules_apply(self):
        return self._call(self.w.apply_rules)

    def addresses(self):
        """A plan for new private networks. The networks already in use (as the box reports them)
        are kept clear; the plan itself never leaves this device."""
        avoid = []
        try:
            status = (self.source.box.read() or {}).get("status") or {}
            for i in status.get("ifaces", []):
                for a in (i.get("addrs") or [])[:2]:
                    avoid.append(str(a) + "/24")
        except Exception:
            avoid = []
        clean = []
        for a in avoid:
            try:
                import ipaddress
                if ipaddress.ip_network(a, strict=False).version == 4:
                    clean.append(a)
            except ValueError:
                continue
        return self._call(self.w.addresses, clean)

    def services(self):
        busy = self.w.auto_checks_start()             # the check steps test themselves; this only starts that
        return dict(self.w.services_state(), auto=bool(busy))

    # -- the VPN tab
    def vpn_state(self):
        return self._call(self.w.vpn_state)

    def nags(self):
        try:
            return self.w.pending_nags()
        except Exception:
            return []

    def vpn_on(self):
        return self._call(self.w.vpn_on)

    def vpn_make(self, d):
        return self._call(self.w.write_vpn_instance, d)

    def vpn_device(self, d):
        return self._call(self.w.vpn_device, d)

    def vpn_check(self):
        return self._call(self.w.probe_run)

    def ddns_state(self):
        return self._call(self.w.ddns_state)

    def ddns_suggest(self):
        return self._call(self.w.ddns_suggest)

    def ddns_manual(self, d):
        return self._call(self.w.ddns_manual, d)

    def ddns_choose(self, d):
        return self._call(self.w.ddns_choose, d)

    def ddns_change(self):
        return self._call(self.w.ddns_change)

    def ddns_install(self):
        return self._call(self.w.ddns_install)

    def ddns_write(self, d):
        return self._call(self.w.write_ddns, d)

    def ddns_fix(self, d):
        return self._call(self.w.ddns_fix_address, d)

    def ddns_force(self, d):
        return self._call(self.w.ddns_force, d)

    def box_known(self) -> str:
        """BUILD 468: the box the setup already knows (its address), reconnected to quietly; "" when none."""
        saved = self.w._recall("box_link")
        if not isinstance(saved, dict) or not saved.get("url"):
            return ""
        try:
            self.w._reconnect_box()
        except Exception:  # noqa: BLE001
            pass
        return str(saved.get("url"))

    def wifi_state(self):
        return self._call(self.w.wifi_state)

    def ap_passphrase(self, d):
        return self._call(self.w.ap_passphrase, d)

    def ap_revert(self, d):
        return self._call(self.w.ap_revert, d)

    def ap_wifi_state(self, ip):
        return self._call(self.w.ap_wifi_state, ip)

    def ap_vlan_options(self):
        return self._call(self.w.ap_vlan_options)

    def iot_suggestions(self):
        return self._call(self.w.iot_suggestions)

    def cert_state(self):
        return self._call(self.w.cert_state)

    def advanced_state(self):
        return self.w.advanced_state()

    def advanced_set(self, d):
        return self.w.advanced_set(d)

    def resolver_state(self):
        return self.w.resolver_state()

    def resolver_set(self, d):
        return self._call(self.w.resolver_set, (d or {}).get("choice") if isinstance(d, dict) else None)

    def cert_install(self):
        return self._call(self.w.cert_install)

    def cert_setup(self, d):
        return self._call(self.w.cert_start, d)

    def ap_fix(self, d):
        return self._call(self.w.ap_fix_start, d)

    def plugin_state(self):
        return self._call(self.w.plugin_state)

    def plugin_update(self):
        return self._call(self.w.plugin_update)

    def time_start(self):
        return self._call(self.w.time_service_start)

    def zenarmor_start(self):
        return self._call(self.w.zenarmor_start)

    def zenarmor_install(self):
        return self._call(self.w.plugin_install, "zenarmor")

    def firewall_url(self):
        return str(self.w.base_url).rstrip("/")

    def geoip_set(self, d):
        return self._call(self.w.geoip_set_start, d)

    def ipv6_off(self):
        return self._call(self.w.ipv6_off_start)

    def country_ipv4(self):
        return self._call(self.w.country_ipv4_start)

    def country_narrow(self):
        return self._call(self.w.country_narrow_start)

    def rule_ipv4(self, d):
        return self._call(self.w.rule_ipv4_start, d)

    def happy_finish(self, d=None):
        return self._call(self.w.happy_finish_start)

    def rule_off(self, d):
        return self._call(self.w.rule_off_start, d)

    def rules_tidy(self, d=None):
        return self._call(self.w.rules_tidy_start, d)

    def firewall_services(self):
        return self._call(self.w.firewall_services)

    def service_start(self, d):
        return self._call(self.w.service_start, d)

    def quarantine_state(self):
        return self._call(self.w.quarantine_state)

    def box_ask(self):
        try:
            return self.w.box_ask()
        except Exception:
            return None

    def box_ask_answer(self, d):
        return self._call(self.w.box_ask_answer, d)

    def quarantine_add(self, d):
        return self._call(self.w.quarantine_add, d)

    def ignore_offer(self, d):
        return self._call(self.w.ignore_offer, d)

    def ignored_offers(self):
        return self._call(self.w.ignored_offers)

    def devices_state(self):
        return self._call(self.w.devices_state)

    def device_kind_set(self, d):
        return self._call(self.w.device_kind_set, d)

    def quarantine_release(self, d):
        return self._call(self.w.quarantine_release, d)

    def levels_state(self):
        return self._call(self.w.levels_state)

    def report_state(self):
        return self._call(self.w.report_state)

    def report_change(self, d):
        return self._call(self.w.report_change, d)

    def country_state(self):
        return self._call(self.w.country_state)

    def country_set(self, d):
        return self._call(self.w.write_country_block_change, d)

    def block_allow(self, d):
        return self._call(self.w.block_allow, d)

    def promote_port(self, d):
        return self._call(self.w.promote_port, d)

    def telemetry_view(self):
        return self._call(self.w.telemetry_view)

    def forwards_state(self):
        return self._call(self.w.forwards_state)

    def kids_state(self):                       # BUILD 537: KidsNet, for the manager
        return self._call(self.w.kids_state)

    def kids_apply(self, d):
        return self._call(self.w.kids_apply, d)

    def forwards_name(self, d):
        return self._call(self.w.forwards_name, d)

    def telemetry_change(self, d):
        return self._call(self.w.telemetry_change, d)

    def control_confirm(self, d):
        return self._call(self.w.control_confirm, d)

    def recheck(self):
        return {"started": self.w.auto_check(force=True)}

    def country_remove(self):
        return self._call(self.w.write_country_block_remove)

    def levels_set(self, d):
        return self._call(self.w.levels_set, (d or {}).get("level"))

    def levels_undo(self):
        return self._call(self.w.write_undo)

    def wifi_prepare(self):
        return self._call(self.w.wifi_prepare)

    def hotspot_state(self):
        return self._call(self.w.hotspot_state)

    def hotspot_set(self, d):
        return self._call(self.w.hotspot_set, d)

    def hotspot_finish(self):
        return self._call(self.w.hotspot_finish)

    def hotspot_undo(self):
        return self._call(self.w.write_undo)

    def usb_backup_set(self, d):
        return self._call(self.w.usb_backup_set, d)

    def zones_setup(self, d):
        return self._call(self.w.zone_vlans_start, d)

    def dhcp_zones(self):
        return self._call(self.w.dhcp_zones_start)

    def dns_trace(self, name):
        return self._call(self.w.dns_trace, name)

    def dns_allow(self, d):
        return self._call(self.w.dns_allow_start, d)

    def console_shell(self):
        return self._call(self.w.console_shell_start)

    def console_sudo(self, d=None):
        return self._call(self.w.console_sudo_start, d)

    def cert_page_use(self, d=None):
        return self._call(self.w.gui_cert_use, d)

    def cert_page_undo(self, d=None):
        return self._call(self.w.gui_cert_undo_start, d)

    def ssh_fix(self, d):
        return self._call(self.w.ssh_fix_start, d)

    def ap_vlans(self, d):
        return self._call(self.w.ap_vlans_start, d)

    def usb_backup_finish(self, d):
        return self._call(self.w.usb_backup_set, d, True)

    # -- the box plugin, put on the firewall from here
    def box_offer(self):
        from pazuzu_core import box_install as bi
        host, _p = base_host_port(self.w.base_url)
        old = getattr(self, "_offer", None)
        if old is not None:
            old.close()
        try:
            def started(url, tok):
                # "Started" is only the firewall saying it ran the line. The link counts as made when the plugin
                # answers; until then it is kept, and the watcher below keeps knocking, so a slow start is not lost.
                self.w._save_box_link(url, tok, fresh=True)       # BUILD 565: just put on from here: its key now
                threading.Thread(target=self.source.box.try_connect, args=(url, tok), daemon=True).start()
            self._offer = bi.Offer(host, on_started=started, update_pub=self.w._update_pub())
        except (ValueError, OSError) as exc:
            from pazuzu_core.console import ActionError
            raise ActionError("Could not offer the plugin: " + str(exc))
        # The firewall's "started" message back to this device can fail on some networks, so also
        # knock on the plugin ourselves, with the token only this offer knows, until it answers.
        threading.Thread(target=self.watch_offer, args=(self._offer,), daemon=True).start()
        return self.box_state()

    def watch_offer(self, offer, step: float = 3.0, sleep=time.sleep, grace: float = 300.0) -> bool:
        """Connect to the plugin as soon as it answers. Stops when connected, replaced, or too late."""
        from pazuzu_core import box_install as bi
        url = f"http://{offer.firewall_ip}:{bi.FEED_PORT}"
        end = offer.expires + grace
        while offer.clock() < end and getattr(self, "_offer", None) is offer:
            if self.source.box.url:
                return True
            if offer.state() != "waiting" and self.source.box.try_connect(url, offer.feed_token):
                self.w._save_box_link(url, offer.feed_token)
                return True
            sleep(step)
        return False

    def box_state(self):
        offer = getattr(self, "_offer", None)
        root = self.w._root_install_ready()      # BUILD 553: the manager offers the root-password way first, too
        if offer is None:
            return {"state": "none", "root_install": root}
        return {"state": offer.state(), "command": offer.command() if offer.state() in ("waiting", "fetched") else None,
                "seconds_left": max(0, int(offer.expires - offer.clock())), "root_install": root}

    def box_root_install(self, d):
        return self._call(self.w.box_root_install, d)

    def services_test(self):
        return self._call(self.w.services_test)

    def services_ack(self, ids):
        return self._call(self.w.services_ack, ids)

    def lan_test(self, only):
        return self._call(self.w.lan_test, only)

    def services_skip(self, ids):
        return self._call(self.w.services_skip, ids)

    def lan_skip(self, ids):
        return self._call(self.w.lan_skip, ids)

    def job(self):
        pending = self.w.passkeys.state().get("pending")
        return {"job": self.w._job_view(), "guard": self.w._guard(),
                "window": self.w.window_state(),
                "approval": ({"first": (pending["lines"] or [""])[0], "lines": list(pending["lines"] or []),
                              "digest": pending["digest"]} if pending else None),
                "page_url": str(self.w.passkeys.origin).rstrip("/") + "/"}

    # -- the passkey approval, done in the manager's own page
    def approve_begin(self):
        from pazuzu_core.console import ActionError
        from pazuzu_core.passkey import PasskeyError
        try:
            return self.w.passkeys.approve_begin("plan")
        except PasskeyError as exc:
            raise ActionError(str(exc))

    def approve_cancel(self):
        return self.w.approval_cancel()

    def approve_finish(self, data):
        from pazuzu_core.console import ActionError
        from pazuzu_core.passkey import PasskeyError
        parts = [data.get(k) for k in ("id", "client", "auth", "sig")]
        if not all(isinstance(p, str) and 0 < len(p) <= 2048 for p in parts):
            raise ActionError("the passkey answer was not understood")
        try:
            return self.w.passkeys.approve_finish("plan", *parts)
        except PasskeyError as exc:
            raise ActionError(str(exc))


def _plain(exc: Exception) -> str:
    text = str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__
    return text[:300]


def _plain_enroll(lines: list[str]) -> str:
    """Say why a sign-in made no user, in words, instead of silently starting over."""

    text = " ".join(lines)
    if "web sign-in did not work" in text:
        return ("The firewall did not accept that user name and password. Check both. "
                "If it asks for a one-time code, type the password and the code together. "
                "Nothing was changed.")
    if "not on a private network" in text:
        return "That address is not on a private network, so nothing was sent."
    if "no change token" in text:
        return "Signed in, but the firewall page was not what we expected. Nothing was changed."
    if "stopped while" in text:
        return ("Could not finish talking to the firewall (" +
                next((l for l in lines if "stopped while" in l), text) +
                "). Nothing was changed.")
    if "not approved" in text:
        return "Not approved with a passkey. Nothing was changed."
    if "user was not found" in text or "not understood" in text:
        said = next((l for l in lines if l.startswith("the firewall refused the user: ")), "")
        return ("The firewall did not make the user as expected. Check its Users page."
                + (" " + said[0].upper() + said[1:] + "." if said else ""))
    return (lines[0].capitalize() if lines else "That did not work; nothing was changed.")


def _cannot_host(report) -> list:
    """The cards the plugin's failure report says cannot host a network at all: the system refused to make an access point
    on them ("SIOCIFCREATE2 ... Operation not supported", as Intel iwn cards answer). They can still join a hotspot."""
    out = []
    for line in str(report or "").splitlines():
        m = re.search(r"\b([a-z]+\d{1,3}) refused:.*(SIOCIFCREATE2|operation not supported)", line, re.I)
        if m and m.group(1) not in out:
            out.append(m.group(1))
    return out


def _no_beacon(report) -> list:
    """BUILD 504: cards that made the network but could not broadcast it. The kernel notes say
    "rtwn0: rtwn_tx_beacon_check: cannot push beacon into chip, error 60!" and "could not move to RUN state": a known
    weakness of some Realtek USB adapters in hosting mode. Not remembered as unable to host: a replug can bring it back."""
    out = []
    for line in str(report or "").splitlines():
        m = re.search(r"\b([a-z]+\d{1,3}): .*(cannot push beacon|unable to push beacon|could not move to RUN state)", line, re.I)
        if m and m.group(1) not in out:
            out.append(m.group(1))
    return out


def _no_wifi_card(report) -> bool:
    """The plugin's failure report says the firewall has no Wi-Fi card the system can use. Trying again cannot help."""
    low = str(report or "").lower()
    return "no wi-fi card is attached" in low or "wi-fi cards (nothing)" in low


def _firmware_waiting(data: dict, product: dict) -> dict:
    """What is waiting, from the firewall's own status: the new version of the firewall itself when that is what
    waits, how many packages, and the download size. Empty keys left out; never guessed (BUILD 440)."""
    out: dict = {}
    pkgs = [p for p in (data.get("upgrade_packages") or []) if isinstance(p, dict)]
    pkgs += [p for p in (data.get("new_packages") or []) if isinstance(p, dict)]
    name = str(product.get("product_name") or data.get("product_name") or "opnsense").lower()
    for p in pkgs:
        if str(p.get("name") or "").lower() in (name, "opnsense", "opnsense-devel") and p.get("new_version"):
            out["new_version"] = str(p["new_version"])[:40]
            break
    if pkgs:
        out["waiting"] = len(pkgs)
    size = str(data.get("download_size") or "").strip()
    if size and size.lower() not in ("none", "0", "0b"):
        out["size"] = size[:20]
    return out


def _plain_firewall(exc: Exception) -> str:
    """Like _plain, but says what a rejected key usually means."""

    text = _plain(exc)
    low = (str(exc) + " " + type(exc).__name__).lower()
    chain = " ".join((str(e) + " " + type(e).__name__).lower() for e in (exc, exc.__cause__, exc.__context__) if e)
    if "ssl" in chain or "certificate" in chain:      # checked first: a retry error often wraps it
        return ("The firewall answered, but with a different security certificate than the one Pazuzu saved. "
                "That usually means it was reset. Press the button to set the old keys aside, then sign in again.")
    if any(w in low for w in ("timed out", "timeout", "max retries", "connection refused", "connectionerror",
                              "no route", "unreachable", "name or service")):
        return ("The firewall did not answer in time. Check that its cable is plugged in and its web page "
                "opens, then press Check again.")
    if "401" in text and "Unauthorized" in text:
        return ("The firewall no longer recognises Pazuzu’s saved keys. This usually means the "
                "firewall was reset. Press the button to set the old keys aside, then sign in again.")
    return text


_FRIENDLY = {"ipv6": "IPv6", "client_ntp": "devices using their own time servers",
             "dns_bypass": "devices using their own DNS", "quic": "QUIC"}


def _default_checks(wizard: "Wizard"):
    """Each check reads from the firewall and returns plain words. Nothing here writes."""

    def interrogation():
        from pazuzu_core.interrogation_cli import run
        summary = run("scan_results/interrogation.json").get("summary", {})
        seen, total = summary.get("observed", 0), summary.get("total", 0)
        ok = total and seen == total
        return {"title": "Pazuzu can read your firewall",
                "detail": ("Every check could read it." if ok
                           else f"{seen} of {total} checks could read it."),
                "status": "good" if ok else "attention"}

    def drift():
        from pazuzu_core.firewall_drift_cli import run
        report = run(wizard.manifest, str(wizard.zones_path), None, 50,
                     "scan_results/firewall_drift_report.json")
        # A rule Pazuzu made but has not switched on yet differs from the plan only in "enabled". That is waiting,
        # not changed: the last step (Blocking rules) turns those on.
        off = [m for m in report.modified if all(d[0] == "enabled" and str(d[2]) in ("0", "") for d in m.diffs)]
        edited = [m for m in report.modified if m not in off]

        def names(items, n=3):
            out = [str(getattr(i, "description", i)).split(":", 2)[-1].strip()[:60] for i in items[:n]]
            return "; ".join(out) + (f" and {len(items) - n} more" if len(items) > n else "")

        parts = [f"{report.in_sync} of Pazuzu's rules are in place and match the plan"]
        status = "good"
        if off:
            parts.append(f"{len(off)} more are in place but still switched off. They come on at the last step, Blocking rules")
            status = "not_yet"
        if report.missing:
            parts.append(f"{len(report.missing)} are not on the firewall yet. Go back to the Rules step to add them")
            status = "attention"
        if edited:
            parts.append(f"{len(edited)} were edited on the firewall after Pazuzu made them ({names(edited)}). "
                         "Change them back, or add the rules again at the Rules step")
            status = "attention"
        if report.orphans:
            parts.append(f"{len(report.orphans)} start with Pazuzu's name but are not in the plan ({names(list(report.orphans))}). "
                         "They may be yours from testing. Pazuzu leaves them alone; delete them under Firewall, Rules if you do not want them")
            status = "attention" if status == "good" else status
        if report.duplicates:
            parts.append(f"{len(report.duplicates)} rules appear twice. Delete the extra copy under Firewall, Rules")
            status = "attention"
        return {"title": "Pazuzu's rules match the plan" if status == "good" else "Pazuzu's rules and the plan",
                "detail": ". ".join(parts) + ".", "status": status}

    def audit():
        from pazuzu_core.firewall_rule_audit_cli import run
        report = run(wizard.manifest, "scan_results/firewall_rule_audit_v0_4.json")
        sm = report["summary"]
        unsafe = sm.get("unsafe", 0)
        seen = sm.get("observed_rules", 0)
        return {"title": "Nothing risky in your rules" if not unsafe
                else "Some of your rules look risky",
                "detail": (f"None of the {seen} rules we looked at is risky." if not unsafe
                           else f"{unsafe} of the {seen} rules we looked at look risky."),
                "status": "good" if not unsafe else "attention"}

    def egress():
        from pazuzu_core.egress_drift import evaluate
        from pazuzu_core.egress_drift_cli import _load_live
        rules, aliases = _load_live()
        report = evaluate(rules, aliases)
        drifted = [c["control"] for c in report["controls"] if c["status"] == "drifted"]
        if not drifted:
            return {"title": "Nothing slips past the firewall's DNS, time and IPv6 rules",
                    "detail": "No rule allows what the baseline blocks.", "status": "good"}
        names = ", ".join(_FRIENDLY.get(d, d) for d in drifted)
        return {"title": "Some traffic still gets around the firewall",
                "detail": "Not blocked yet: " + names + ".", "status": "attention"}

    def stock():
        from pazuzu_core.stock_rules_cli import run
        from pazuzu_core.staged_enabling import blocker_kind
        report = run("scan_results/stock_rules_plan.json")
        if report["ready"]:
            return {"title": "Ready to switch the old allow-all rules off",
                    "detail": "Pazuzu's own allow rules are in place first.",
                    "status": "good"}
        blockers = report.get("blockers")
        if not blockers:
            # Nothing is blocking and nothing is left to switch off: the old allow-all rules are already off.
            return {"title": "The old allow-all rules are already off",
                    "detail": "There is nothing left to switch off.", "status": "good"}
        if all(blocker_kind(b) == "wait" for b in blockers):
            return {"title": "Waiting for the earlier stages before the old allow-all rules go",
                    "detail": _plain_blocker(_plain(Exception(blockers[0]))),
                    "status": "not_yet", "waiting": True}
        return {"title": "Not ready to switch the old allow-all rules off",
                "detail": _plain_blocker(_plain(Exception(blockers[0]))), "status": "not_yet"}

    def nat():
        """Port forwards and redirects, read only (see nat_audit)."""
        from pazuzu_core import nat_audit
        getter = wizard._api_getter()
        if getter is None:
            return {"title": "Port forwards and redirects", "status": "unknown", "detail": "Not signed in to the firewall yet."}
        zones = (wizard.status().get("zones") or {}).get("assignments") or {}
        got = nat_audit.read(getter, zones)
        title = {"good": "Port forwards and redirects look right", "not_yet": "Port forwards and redirects: one thing to add",
                 "attention": "Port forwards and redirects need a look"}.get(got["status"], "Port forwards and redirects")
        return {"title": title, "detail": " ".join(got["lines"]), "status": got["status"]}

    return (("interrogation", "The firewall answered every question", interrogation),
            ("drift", "Pazuzu's rules match the plan", drift),
            ("audit", "Nothing unsafe found in your rules", audit),
            ("egress", "The old allow-all rules", egress),
            ("stock", "Switching the old rules off", stock),
            ("nat", "Port forwards and redirects", nat))


# --- the page --------------------------------------------------------------------

# BUILD 493: beta 1 is the setup alone; the manager (beta 2, the paid part) opens only in test mode. False opens it for all.
BETA_MANAGER_TEST_ONLY = True
BETA_PLUGIN_HIDDEN = True       # BUILD 513: beta 1 shows no plugin steps (see Wizard._plugin_offered)


def kids_present() -> bool:
    """BUILD 539: is KidsNet in this build? A public copy leaves kids_net.py out (the maintainer, 14 Nov 2026: "For now"), and
    then the wizard offers no KidsNet: no row for it, no card."""
    import importlib.util
    try:
        return importlib.util.find_spec("pazuzu_core.kids_net") is not None
    except (ImportError, ValueError):
        return False


def plugin_present() -> bool:
    """Is the plugin in this build? The public beta 1 zip leaves it out, as it leaves the manager out."""
    import importlib.util
    try:
        return importlib.util.find_spec("hanbi_box") is not None
    except (ImportError, ValueError):
        return False
BUILD = 566
PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pazuzu setup</title>
<style nonce="NONCE">
/* BUILD 509: one meaning per colour on every screen. Teal: on, done, OK. Amber: in
   progress, or needs you. Coral: a problem, or off. Dark: ground #0E131B, card #161D28, line #232C3A, text #E8EDF3,
   muted #8B98AA, teal #4FE0B0, amber #F5B942, coral #F4877A. */
:root{color-scheme:light dark;--bg:#F3F5F7;--card:#fff;--fg:#121821;--mut:#5B6672;--line:#DDE2E8;--acc:#0F6E5C;--accbg:#E3F2EE;--accfg:#0B5A4B;--warn:#7A4800;--warnbg:#FFF1D6;--bad:#A12D2D}
@media (prefers-color-scheme:dark){:root{--bg:#0E131B;--card:#161D28;--fg:#E8EDF3;--mut:#8B98AA;--line:#232C3A;--acc:#4FE0B0;--accbg:#12332B;--accfg:#8FEBD0;--warn:#F5B942;--warnbg:#3A2C10;--bad:#F4877A}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 "Work Sans",system-ui,sans-serif}
.app{display:flex;min-height:100vh}
.lvcard{border-left:6px solid var(--lvc,var(--acc));background:linear-gradient(rgba(var(--lvr,15,110,92),.16),rgba(var(--lvr,15,110,92),.16)),var(--card)}
.unsafe{border-left:6px solid var(--bad);background:linear-gradient(rgba(161,45,45,.12),rgba(161,45,45,.12)),var(--card)}
.lvname{font-size:20px;font-weight:700;margin:2px 0 4px}
.lvsay{margin:0 0 10px}
body[data-level]{background-image:linear-gradient(rgba(var(--lvr),.10),rgba(var(--lvr),.10))}
body[data-level=critical]{--lvr:161,45,45;--lvc:#A12D2D}body[data-level=warning]{--lvr:232,137,12;--lvc:#E8890C}body[data-level=caution]{--lvr:224,180,0;--lvc:#E0B400}body[data-level=secure]{--lvr:59,125,216;--lvc:#3B7DD8}body[data-level=normal]{--lvr:15,160,120;--lvc:#0FA078}
.rail{width:248px;flex-shrink:0;background:var(--card);border-right:1px solid var(--line);padding:28px 20px;display:flex;flex-direction:column;gap:6px}
.logo{font-size:22px;font-weight:700;letter-spacing:.5px;padding:0 12px 20px}
.rs{display:flex;align-items:center;gap:12px;padding:10px 12px;border-radius:10px;color:var(--mut)}
.rs .n{width:24px;height:24px;border-radius:50%;border:1.5px solid var(--line);display:flex;align-items:center;justify-content:center;font-size:13px}
.rs.on{background:var(--warnbg);color:var(--warn);font-weight:600}.rs.on .n{background:var(--warn);border-color:var(--warn);color:var(--card)}
.rs.done{color:var(--acc);font-weight:500}.rs.done .n{background:var(--acc);border-color:var(--acc);color:var(--card)}
.note{margin-top:auto;padding:12px;border-radius:10px;background:var(--bg);font-size:13px;color:var(--mut)}
.main{flex:1;padding:40px 48px;max-width:960px}
.eye{font-size:12px;font-weight:600;letter-spacing:1.2px;color:var(--mut)}
h1{margin:6px 0 8px;font-size:30px;line-height:1.15}
.sub{margin:0 0 22px;max-width:620px;color:var(--mut)}
.row{display:flex;gap:20px;flex-wrap:wrap}
.card{flex:1 1 300px;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:22px;margin-bottom:20px}
.card h2{margin:0 0 12px;font-size:17px}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace}
.fp{font-size:16px;font-weight:600;padding:14px;border-radius:10px;background:var(--bg);border:1px solid var(--line);word-break:break-all}
.mut{color:var(--mut);font-size:14px}
button{font:600 15px "Work Sans",system-ui,sans-serif;min-height:44px;padding:0 22px;border-radius:10px;border:0;background:var(--acc);color:var(--card);cursor:pointer}
button.quiet{background:var(--card);color:var(--fg);border:1px solid var(--line)}button.back{background:var(--card);border:1px solid var(--line);color:var(--fg);padding:7px 14px;margin-bottom:14px;font-size:14px;border-radius:8px;cursor:pointer;display:inline-flex;align-items:center;gap:4px}button.back:hover{border-color:var(--acc);color:var(--acc)}button:disabled{opacity:.5;cursor:default}
.opt{display:flex;gap:12px;padding:14px;border-radius:10px;border:1px solid var(--line);margin-bottom:10px;cursor:pointer}
.opt.sel{background:var(--accbg);border:1.5px solid var(--acc)}
.opt input[type=radio]{margin-top:4px}
input[type=password],input[type=text]{width:100%;min-height:40px;border-radius:8px;border:1px solid var(--line);background:var(--bg);color:var(--fg);padding:0 12px;font:inherit}
select{min-width:150px;min-height:36px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--fg);font:inherit;padding:0 8px}
table{width:100%;border-collapse:collapse}th{text-align:left;font-size:12px;letter-spacing:1px;color:var(--mut);padding:8px 12px;background:var(--bg)}
td{padding:8px 12px;border-top:1px solid var(--line)}
.pbar.busy>i{width:35%;animation:pz-slide 1.4s ease-in-out infinite alternate}@keyframes pz-slide{from{margin-left:0}to{margin-left:65%}}
.pbar{height:8px;background:var(--line);border-radius:6px;overflow:hidden;margin:10px 0}.pbar>i{display:block;height:100%;background:var(--accfg);transition:width .4s}
ul.plain{list-style:none;padding-left:0;margin:6px 0}
.offer{border-top:1px solid var(--line);padding:12px 0 4px}.offer:first-of-type{border-top:0}.offer button{margin:0 8px 8px 0}
.btnrow{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:12px}
.qrbox{display:inline-block;background:#fff;padding:8px;border-radius:10px;max-width:100%}
.qrbox svg{display:block;max-width:100%;height:auto}
a.btn{display:inline-flex;align-items:center;min-height:44px;padding:0 22px;border-radius:10px;border:1px solid var(--line);color:var(--fg);text-decoration:none;font:600 15px "Work Sans",system-ui,sans-serif;background:var(--card)}
.card ol{margin:6px 0;padding-left:22px}.card li{margin:6px 0}
.chip{padding:3px 10px;border-radius:999px;font-size:13px;font-weight:600;background:var(--accbg);color:var(--accfg)}
.chip.warn{background:var(--warnbg);color:var(--warn)}
.tiles{display:flex;gap:16px;margin-bottom:20px}.tiles.wrap{flex-wrap:wrap}.tiles.wrap .tile{flex:1 1 180px}.tile.done{border-color:var(--accfg)}.tile{flex:1;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px 20px}
.big{font-size:38px;font-weight:700;line-height:1}
.bar{display:flex;align-items:center;gap:16px;padding:16px 20px;border-radius:14px;background:var(--card);border:1px solid var(--line)}
.bar .grow{flex-grow:1;color:var(--mut);font-size:14px}
pre{margin:0;white-space:pre-wrap;font:13px/1.5 ui-monospace,Menlo,Consolas,monospace;color:var(--mut)}
#err{color:var(--bad);min-height:1.5rem;margin:10px 0}
.livebox{margin-top:28px;border:1px solid var(--line,#d8dee4);border-radius:12px;padding:10px 14px}
.livebox summary{cursor:pointer;font-weight:600}
.livebox pre{max-height:260px;overflow:auto;margin-top:8px}
.big.warn{color:var(--warn)}
.chip.mute{background:var(--bg);color:var(--mut)}
.card.soon{opacity:.6}
label.tick{display:block;margin:10px 0}
img.preview{display:block;max-width:100%;height:auto;border-radius:10px;border:1px solid rgba(255,255,255,.12);margin:12px 0 6px}.card.soon h2 .chip{margin-left:6px;vertical-align:middle}
.vrow{display:flex;align-items:center;gap:16px;padding:14px 0;border-top:1px solid var(--line)}.vrow:first-child{border-top:0}
.vrow .grow{flex-grow:1}.vt{font-weight:600}
.stage{display:flex;gap:14px;padding:14px 0;border-top:1px solid var(--line)}.stage:first-child{border-top:0}
.stage .n{width:24px;height:24px;border-radius:50%;border:1.5px solid var(--line);display:flex;align-items:center;justify-content:center;font-size:13px;flex-shrink:0}
.stage.go .n{background:var(--acc);border-color:var(--acc);color:var(--card)}
.scroll{max-height:150px;overflow-y:auto;margin:8px 0;padding:8px 12px;border:1px solid var(--line);border-radius:10px}.scroll ul{margin:4px 0}.scroll p{margin:6px 0}
.stage .grow{flex-grow:1}.stage ul{margin:8px 0;padding-left:1.2rem}
.veil[hidden]{display:none}
.veil{position:fixed;inset:0;background:rgba(18,24,33,.6);display:flex;align-items:center;justify-content:center}
.dlg{width:520px;max-width:92vw;background:var(--card);border-radius:18px;padding:30px;box-shadow:0 24px 60px rgba(0,0,0,.4)}
.dlg h2{margin:0 0 4px;font-size:22px}.dlg ul{padding-left:1.2rem;margin:12px 0}
@media (max-width:800px){.app{flex-direction:column}.rail{width:auto;border-right:0;border-bottom:1px solid var(--line);padding:14px 16px}.main{padding:20px 16px;max-width:none}
.rail .rs:not(.on){display:none}
table,tbody,tr,td{display:block;width:auto}th{display:none}tr{border-top:1px solid var(--line);padding:10px 0}td{border-top:0;padding:4px 0}
select,input[type=text],input[type=password],input:not([type]){width:100%;box-sizing:border-box}
.bar{flex-wrap:wrap}.bar>button{flex:1 1 auto}.tiles{flex-direction:column}.card{padding:16px}}
@media print{ .rail,.bar,button,.back,#err,#live,#winnote,.eye{display:none!important} body,.main,.card{background:#fff!important;color:#000!important;box-shadow:none!important} .card:not(.accesscard){display:none!important} .accesscard{border:1px solid #888!important} .app{display:block!important} }
</style></head><body>
<div class="app"><nav class="rail" id="rail"></nav><main class="main"><p id="winnote" class="mut" hidden></p><div id="body" class="mut">Loading…</div><p id="err" role="alert"></p><details id="live" class="livebox"><summary>What Pazuzu is doing, live</summary><p class="mut">Each request to the firewall, one line each. It never shows passwords, keys or what was sent.</p><pre id="livelog">Nothing yet.</pre></details></main></div>
<div class="veil" id="veil" hidden><div class="dlg" id="dlg"></div></div>
<script nonce="NONCE">
const $ = (id) => document.getElementById(id);
const dec = (s) => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0));
const enc = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
// Test mode has no passkey, so its words never mention one: "…, with passkey" and "Your passkey approves it" are dropped.
var pzLight=false;
function nopk(t){
  if(!pzLight || typeof t!=='string' || t.indexOf('asskey')<0) return t;
  return t.replace(/,? with passkey/g,'')
    .replace(/[Yy]our passkey approves it\. ?/g,'')
    .replace(/([Yy])our passkey approves it,? (?:and )?(\w)/g,(m,y,c)=>y==='Y'?c.toUpperCase():c)
    .replace(/\s+$/,'');
}
// Outside links are opened by a click, never loaded by this page. They are put together here so the page holds no literal web address.
const web=(rest)=>'https:'+'//'+rest;
// BUILD 511 (the maintainer, 11 Nov 2026: "make sure all the pieces of the wizard are in and i can publish this today"). Beta 1
// has no manager, but many lines written before it still sent the person there ("switch them on in the manager", "set
// zones up any time in the manager"). In beta 1 each of those says what is true instead. One table, so every page that
// uses a line gets it; with the manager open (the maintainer's --manager, a Hanbi's phone setup) the lines stay as they were.
const BETA1_WORDS=[
  ['or skip and set zones up any time in the manager','or skip and set zones up later by running this setup again'],
  ['you can set zones up any time in the manager','you can set zones up later by running this setup again'],
  ['on an OpenWrt access point, the manager’s Wi-Fi section tags it for you after setup','on an OpenWrt access point, read it in the card above and this setup tags it for you'],
  ['and the manager flags the network as not-done until you scramble','and the network counts as not done until you scramble'],
  ['so it’s done from the manager with a reconnect, never silently here','so that waits for the manager in beta 2, and is never done silently here'],
  ['You will be reminded at the top of the manager until it is set up.','You can set it up later by running this setup again.'],
  ['the manager switches it on once it can read the setting back','the Switch protection on step switches it on'],
  ['the manager switches them on once it can read the setting back','the Switch protection on step switches them on'],
  ['The manager has a VPN tab for it.','On a new firewall the Reach home step sets it up; on a running one it comes with the manager, in beta 2.'],
  ['The manager flags this until it is confirmed.','Run this setup again from such a device to confirm it.'],
  ['The manager flags this until you scramble.','It counts as not done until you scramble.'],
  ['Still to do, in the manager','Still to do'],
  ['the manager checks it step by step','this setup checks it step by step'],
  ['the manager checks that one step by step','this setup checks that one step by step'],
  ['what is left for the manager','what is left'],
  ['The manager\u2019s slider does it.','Run this setup again to try once more.'],
  ['Leave it for the manager','Leave it for later'],
  [': left for the manager',': left for later'],
  ['can be finished later from the manager','can be finished later by running this setup again'],
  ['You can do this later in the manager.','You can do this later by running this setup again.'],
  ['They are switched on in the manager.','The next step switches them on.'],
  ['Switch them on in the manager.','The next step switches them on.'],
  ['Continue. The manager switches these on, one guarded step at a time, and tests each one for you.','Continue. The next step switches these on, one part at a time, and tests each one for you.'],
  ['In the manager','Next step']
];
// BUILD 513: the same for the plugin, which beta 1 does not have either.
const NOPLUGIN_WORDS=[
  ['so it comes after the plugin, Wi-Fi, the name and the VPN','so it comes after the ports, the name and the VPN'],
  [' It first adds one rule that keeps the plugin reachable.','']
];
function beta1(t){
  let open=true; try{ open=ui.managerOpen!==false; }catch(e){ open=true; }
  if(typeof t==='string' && t.indexOf('lugin')>=0){ let np=false; try{ np=ui.pluginOffered===false; }catch(e){ np=false; }
    if(np) for(const [a,b] of NOPLUGIN_WORDS){ if(t.indexOf(a)>=0) t=t.split(a).join(b); } }
  if(typeof t!=='string' || open || t.indexOf('anager')<0) return t;
  for(const [a,b] of BETA1_WORDS){ if(t.indexOf(a)>=0) t=t.split(a).join(b); }
  return t;
}
function el(tag, text, cls){const e=document.createElement(tag); if(text!==undefined&&text!==null)e.textContent=beta1(nopk(text)); if(cls)e.className=cls;
  // BUILD 481: every field here is a name, an address, a key or a code, never a sentence: no capital first letter, no
  // autocorrect (the lab run, 4 Nov 2026: iOS made the admin's user name "the maintainer", which the firewall's names refuse)
  if(tag==='input'){ e.setAttribute('autocapitalize','none'); e.setAttribute('autocorrect','off'); e.spellcheck=false; }
  return e;}
async function get(path){ const r=await fetch(path); const j=await r.json().catch(()=>({})); if(!r.ok) throw new Error(j.error||'That did not work.'); return j; }
// BUILD 531 (the maintainer, dev, 12 Nov 2026: pressed "Switch the old rules off…" and got "Something is already running. Wait
// for it to finish."; a second press ran): one job runs at a time, and a press that lands while a short one is ending
// was refused. The page now waits for it itself, a few seconds, and asks again; nothing was started by the refusal.
const BUSY_WORDS=/^Something is already running/;
async function post(path, body){
  for(let tries=0;;tries++){
    const r = await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body||{})});
    const j = await r.json().catch(()=>({}));
    if(r.ok) return j;
    if(tries<4 && BUSY_WORDS.test(j.error||'')){ await new Promise(done=>setTimeout(done,1500)); continue; }
    throw new Error(j.error || 'That did not work.');
  }
}
// BUILD 493 (the maintainer: the feedback button "has to be very easy and offered right after anything fails"). Next to any
// failure: one press saves a report on this PC (versions, the step, the error, your words; no screenshot is taken) and
// offers a mail draft. Nothing is sent unless you send it.
function feedbackOffer(where, error){
  if(where.querySelector('[data-fb]')) return;
  const b=el('button','Send report','quiet'); b.dataset.fb='1';
  b.onclick=()=>feedbackSheet(error);
  where.append(' ', b);
}
// BUILD 497: the privacy notice, word for word, and consent at each send (apart from the Welcome switches).
function feedbackSheet(error){
  const old=document.getElementById('fbsheet'); if(old) old.remove();
  const c=el('div',undefined,'card'); c.id='fbsheet';
  c.append(el('h2','Send a report'));
  c.append(el('p','This report goes to hanbi.net and is read only by Zach Bovard (Hanbi). It contains the Pazuzu and firewall versions, the step you were on, the error, and what you write below.','mut'));
  c.append(el('p','A screenshot is sent only if you attach one. Check it first: it can show device names, addresses and how your network is laid out.','mut'));
  // the notice's own words; the page keeps its rule of no web addresses (it loads and links nothing outside)
  c.append(el('p','Reports are stored in the United States, kept for 90 days and then deleted. After sending you get a ref code; email it to privacy@hanbi.net to have your report deleted sooner. More: hanbi.net/privacy','mut'));
  const note=document.createElement('textarea'); note.rows=3; note.style.width='100%'; note.placeholder='What happened, in your own words (optional)'; c.append(note);
  const fl=el('label'); fl.style.display='block'; fl.style.margin='8px 0'; const file=document.createElement('input'); file.type='file'; file.accept='image/png,image/jpeg';
  fl.append(document.createTextNode('Attach a screenshot (optional, PNG or JPEG, up to 5 MB): '), file); c.append(fl);
  const cl=el('label'); cl.style.display='block'; cl.style.margin='8px 0'; const ok=el('input'); ok.type='checkbox';
  cl.append(ok, document.createTextNode(' Send this report to Hanbi. I agree to it being stored and read as described above.')); c.append(cl);
  const send=el('button','Send report'); send.disabled=true; ok.onchange=()=>{ send.disabled=!ok.checked; };
  const close=el('button','Close','quiet'); close.onclick=()=>c.remove();
  const said=el('p','','vt');
  send.onclick=async()=>{ send.disabled=true; said.textContent='Sending…';
    try{
      let shot='';
      const f=file.files&&file.files[0];
      if(f){ if(f.size>5*1024*1024) throw new Error('The screenshot is over 5 MB. Attach a smaller one.');
        shot=await new Promise((res,rej)=>{ const r=new FileReader(); r.onload=()=>res(String(r.result).split(',')[1]||''); r.onerror=()=>rej(new Error('The screenshot could not be read.')); r.readAsDataURL(f); }); }
      const title=document.querySelector('h1');
      const r=await post('/api/feedback/send',{step:title?title.textContent.trim():'', error:error||'', note:note.value, consent:ok.checked, screenshot:shot});
      if(r.sent){
        c.replaceChildren(el('h2','Report sent'), el('p','Report sent. Your ref code is '+r.ref+'. Keep it if you may want the report deleted before its 90 days are up.','mut'));
      } else {
        c.replaceChildren(el('h2','Saved on '+(ui.phone?'your firewall':'this device')+', not sent.'), el('p',(r.why||'')+' The report is saved on '+(ui.phone?'your firewall':'this device')+' at '+r.path+'. You can mail it to feedback@hanbi.net, with a screenshot if one helps; check the screenshot first.','mut'));
        const mail=el('button','Open a mail draft'); mail.onclick=()=>{ try{ location.href=r.mailto; }catch(e){} };
        const row0=el('div',undefined,'btnrow'); row0.append(mail); c.append(row0);
      }
      const done=el('button','Close','quiet'); done.onclick=()=>c.remove();
      const row=el('div',undefined,'btnrow'); row.append(done); c.append(row);
    }catch(e){ send.disabled=!ok.checked; said.textContent=e.message||String(e); }
  };
  const row=el('div',undefined,'btnrow'); row.append(send, close); c.append(row, said);
  $('err').after(c);
  try{ c.scrollIntoView({behavior:'smooth', block:'center'}); }catch(e){}
}
function fail(e){
  const msg=(e && e.name==='NotAllowedError') ? 'The passkey was cancelled or timed out. Try again.' : (e.message || String(e));
  $('err').textContent = msg;
  feedbackOffer($('err'), msg);
  // BUILD 520 (the maintainer, 12 Nov 2026: "hitting read it it did nothing i could notice"): the red line sits under the page, and
  // on a long page the button that caused it is screens above. It is brought into view when it is said.
  try{ if(msg) $('err').scrollIntoView({behavior:'smooth', block:'center'}); }catch(x){}
  if(/no longer recognises|different security certificate/.test(msg)){
    const b=el('button','Set the old keys aside','quiet');
    b.onclick=async()=>{ b.disabled=true; try{ const r=await post('/api/keys/aside',{}); $('err').textContent='The old keys were moved to a folder called '+(r.folder||'(none)')+' beside them. Sign in again.'; ui.force=null; ui.autoFound={}; await refresh(); }catch(x){ $('err').textContent=x.message||String(x); } };
    $('err').append(' ', b);
  }
}
async function act(button, work){ $('err').textContent=''; if(button) button.disabled=true; try{ await work(); ui.force=null; }catch(e){ fail(e); } if(button) button.disabled=false; await refresh(); }
async function registerPasskey(label){
  const b = await post('/api/register/begin',{label});
  const cred = await navigator.credentials.create({publicKey:{
    challenge: dec(b.challenge), rp:{id:b.rp_id,name:b.rp_name},
    user:{id:new TextEncoder().encode('pazuzu-'+(label||'passkey')),name:label||'passkey',displayName:label||'passkey'},
    pubKeyCredParams:[{type:'public-key',alg:-7}], attestation:'none', timeout:120000,
    excludeCredentials:b.exclude.map(id=>({type:'public-key',id:dec(id)})),
    authenticatorSelection:{residentKey:'preferred',userVerification:'required'}}});
  await post('/api/register/finish',{label,attestation:enc(cred.response.attestationObject),client:enc(cred.response.clientDataJSON)});
}
async function cancelApproval(){ try{ await post('/api/approve/cancel',{}); }catch(e){} }
async function approvePlan(){
  const b = await post('/api/approve/begin',{purpose:'plan'});
  let cred;
  try{ cred = await navigator.credentials.get({publicKey:{
    challenge: dec(b.challenge), rpId:b.rp_id, timeout:120000, userVerification:'required',
    allowCredentials:b.allow.map(id=>({type:'public-key',id:dec(id)}))}}); }catch(e){ if(e && (e.name==='NotAllowedError'||e.name==='AbortError')){ await cancelApproval(); throw new Error('The passkey prompt was cancelled, so nothing was changed.'); } throw e; }
  await post('/api/approve/finish',{purpose:'plan',id:enc(cred.rawId),client:enc(cred.response.clientDataJSON),
    auth:enc(cred.response.authenticatorData),sig:enc(cred.response.signature)});
}
const STEPS=['Sign in','Ports','Safety settings','Finish'];
// Test mode shows the whole order. The older four-step calls map onto it: sign in, ports, the allow rules, finish.
const LIGHT_STEPS=['Sign in','Plugin','Version','Ports','Wi-Fi','Reach home','Rules','Admin','Finish'];
const LIGHT_AT={0:0,1:3,2:7,3:8};
// The box tells the wizard which platform it is (Hanbi or Pazuzu); the name shows in the rail logo and the tab title.
function applyBrand(){ try{ document.title=(ui.platform==='hanbi'?'Hanbi':'Pazuzu')+' setup'; }catch(e){} }
function rail(at, direct){
  let list = ui.light ? LIGHT_STEPS : STEPS;
  if(ui.light && !direct && LIGHT_AT[at]!==undefined) at=LIGHT_AT[at];
  if(ui.lastRail!==at){ if($('err').textContent!==ui.jobErr || ui.jobErrGen!==ui.gen) $('err').textContent=''; ui.lastRail=at; }   // a failed run's words last only until the page moves on
  // BUILD 513: beta 1 has no plugin, so the rail has no Plugin step. The Wi-Fi step stays, greyed, to show what is coming.
  // BUILD 514: done after the step is remembered (ui.lastRail keeps the full order's number). Done before it, a job's
  // Working page counted the step down twice ("Version" while the ports were being set up) and wiped the job's error.
  if(ui.light && ui.pluginOffered===false){ list=list.filter(t=>t!=='Plugin'); at = at>=2 ? at-1 : at; }
  const r=$('rail'); r.replaceChildren(el('div', (ui.platform==='hanbi'?'Hanbi':'Pazuzu'),'logo'));
  // BUILD 509: done is teal with a tick, the step you are on is amber with a dot, the rest are plain numbers (never colour alone)
  list.forEach((t,i)=>{ const d=el('div',undefined,'rs '+(i<at?'done':i===at?'on':'')); if(i===at) d.setAttribute('aria-current','step'); d.title=i<at?'Done':i===at?'You are here':''; d.append(el('span',i<at?'✓':i===at?'●':String(i+1),'n'), document.createTextNode(t)); r.append(d); });
  const mg=el('button','Open the manager','quiet'); mg.id='rail-manager'; mg.title='Opens the manager in its own tab. This page keeps running.';
  if(!ui.managerReady){ mg.disabled=true; mg.title='Sign in to the firewall and put the plugin on first; the manager needs both.'; }   // BUILD 468
  if(!ui.managerOpen){ mg.disabled=true; mg.textContent='The manager: beta 2'; mg.title='The manager comes in beta 2. Beta 1 is this setup: run it again any time.'; }   // BUILD 493
  if(ui.phone) mg.hidden=true;      // BUILD 477: the manager window is the PC's; on the phone it opened localhost
  mg.onclick=()=>{ const w=openBlank(); openManagerNow(w).catch(e=>{ if(w) try{ w.close(); }catch(x){} fail(e); }); };
  r.append(mg);
  r.append(el('div', ui.phone ? 'Data sharing is opt-in only. You signed in with your phone\u2019s passkey; that is your approval while you set up. Every change is tested and undone by itself if it fails.' : ui.light ? 'Data sharing is opt-in only. Test mode: no passkey. Every change is tested and undone by itself if it fails.' : (ui.managerOpen===false ? 'Data sharing is opt-in only. Reading your firewall asks nothing; each change asks for your passkey.' : 'Data sharing is opt-in only. Setting up asks no passkey; the manager asks once when it opens, and the shield slider each time.'),'note'));
}
// BUILD 546 (an iPhone run: "the words were clear, the bar sat still"): the page is drawn again at
// every look at the job, and each new bar started its slide from the left again, so it never got anywhere. The slide now
// takes its place from the clock, so a bar drawn again carries on where the last one was.
function slideOn(i){ i.style.animationDelay='-'+((Date.now()%2800)/1000).toFixed(2)+'s'; return i; }
function busyCard(text){ const c=el('div',undefined,'card'); c.append(el('div',text,'vt')); const b=el('div',undefined,'pbar busy'); b.append(slideOn(document.createElement('i'))); c.append(b);
  // BUILD 468: a job that starts brings its status into view (it sat below the screen on a phone, steps 5 and 6)
  if(ui.busyShown!==text){ ui.busyShown=text; setTimeout(()=>{ try{ c.scrollIntoView({behavior:'smooth', block:'center'}); }catch(e){} },0); }
  return c; }
function bar(text, ...buttons){ const b=el('div',undefined,'bar'); b.append(el('div',text,'grow'), ...buttons.filter(Boolean)); return b; }
const BACK={admin:'firmware',zones:'admin',rules:'zones'}; BACK.access='allset'; BACK.happy='allset';   // the access card goes back to the page before it
// In the light (New/Testing) flow the order is Plugin -> Ports(zones) -> Wi-Fi(wayback) -> Reach(reach) -> Rules -> Admin -> Finish(allset).
// Each key is the screen you are on; its value is the screen Back returns to.
const LIGHT_BACK={zones:'plugin',wayback:'zones',reach:'wayback',rules:'reach',admin:'rules',allset:'admin'}; LIGHT_BACK.access='allset';
function goBack(to){ const er=$('err'); if(er) er.textContent=''; ui.fwAuto=true;   // a Back never re-runs the firmware update check
  if(to==='plugin'){ delete ui.done.plugin; delete ui.skipped.plugin; ui.force=null; }
  else if(to==='reach'){ delete ui.done.reach; delete ui.skipped.reach; ui.force=null; }
  else if(to==='wayback'){ delete ui.done.wayback; delete ui.skipped.wayback; ui.force='wayback'; }
  else if(to==='rules' && ui.light){ delete ui.done.rules; delete ui.skipped.rules; ui.at='rules'; ui.force=null; }
  else if(to==='admin' && ui.light){ delete ui.done.admin; delete ui.skipped.admin; ui.force=null; }
  else if(to==='allset'){ ui.at='allset'; ui.force=null; }
  else { ui.force=to; }            // careful-mode targets (firmware/admin/zones) and any direct force
  saveUi(); refresh().catch(fail);
}
function backLink(from){ const map=ui.light?LIGHT_BACK:BACK; const to=map[from]; const f=document.createDocumentFragment(); if(!to) return f; const b=el('button','\u2039 Back','back'); b.onclick=()=>goBack(to); f.append(b); return f; }
function head(step, title, sub, direct){ const f=document.createDocumentFragment(); let n = ui.light && !direct ? ({1:1,2:4,3:8,4:9}[step]||step) : step; let of=ui.light?LIGHT_STEPS.length:4;
  if(ui.light && ui.pluginOffered===false){ n = n>=3 ? n-1 : n; of-=1; }   // BUILD 513: no Plugin step
  f.append(el('div','STEP '+n+' OF '+of,'eye'), el('h1',title)); if(sub) f.append(el('p',sub,'sub'));
  // BUILD 480: each step the box hears replaces the last, so while the one-time code is up the admin page's own heading
  // carries it too (the heading and the code went out together and the heading, arriving second, wiped the code)
  const tb={step:n, of:of, title:title, do:sub||''}; if(ui.boxQr && title===ui.boxQr.title) Object.assign(tb, {qr:ui.boxQr.qr, qr_words:ui.boxQr.qr_words});
  if(ui.boxQr && title===ui.boxQr.title && ui.boxQr.steps) tb.steps=ui.boxQr.steps;
  ui.lastTb=tb; tellBox(tb); return f; }
// BUILD 438: the box's own screen (and a phone on its feed) follows this page: the step it is on and what to do. Best effort;
// the wizard never waits on it, and a firewall without the plugin yet simply does not hear it.
// BUILD 450: a busy heading ("Working…") is not a step: the box keeps showing the step it is on.
// BUILD 480: one after the other, so the box hears them in the order the page said them (each replaces the last; sent
// together, a page's heading could arrive after the one-time code drawn under it and wipe it off the box's screen)
let boxSaid=Promise.resolve();
function tellBox(body){ if(body && /^Working/.test(body.title||'')) return; boxSaid=boxSaid.then(()=>post('/api/box/setup_step', body)).catch(()=>{}); }
// Plugin 0.6.83 (the maintainer's newcomer run, 5 Nov): the page's own steps go on the box's screen as a numbered list, the way the
// app shows them. Each is words, or [words, state] with state todo, now, done or failed. The box keeps the last six.
function stepList(steps){ return (steps||[]).slice(0,6).map(x=>Array.isArray(x)?{text:String(x[0]), state:x[1]||'todo'}:{text:String(x), state:'todo'}); }
function boxSteps(steps){ if(!ui.lastTb) return; tellBox(Object.assign({}, ui.lastTb, {steps:stepList(steps)})); }
let ui={gen:0, useDefault:true, fp:null, pw:'', at:'rules', limit:50, level:null, prev:null, checked:false, mode:null, done:{}, skipped:{}, base:'', terms:false, consent:{versions:false,checks:false,problems:false}};
try{ const sv=JSON.parse(sessionStorage.getItem('pz_ui')||'null'); if(sv){ ui.mode=sv.mode||null; ui.done=sv.done||{}; ui.skipped=sv.skipped||{}; ui.sid=sv.sid; } }catch(e){}
try{ void 0; }catch(e){}
function saveConsent(){}
function saveUi(){ try{ sessionStorage.setItem('pz_ui', JSON.stringify({mode:ui.mode, done:ui.done, skipped:ui.skipped, sid:ui.sid})); }catch(e){} }
// BUILD 510: the steps kept in this tab belong to one setup of one firewall. A firewall installed again is a new setup:
// what was done on the old one (the plugin, the version, the ports) is forgotten, so no step is skipped on the new one.
function sameSetup(sid){
  const kept=Object.keys(ui.done).length+Object.keys(ui.skipped).length;
  const other = ui.sid ? ui.sid!==sid : (ui.sid===undefined && !sid && kept>0);
  if(other){ ui.done={}; ui.skipped={}; ui.mode=null; ui.at='rules'; ui.force=null; ui.fwAuto=false; ui.fwBehind=false; }
  if(ui.sid!==sid){ ui.sid=sid; saveUi(); }
  return !other;
}
const handled=(k)=>!!(ui.done[k]||ui.skipped[k]);
function mark(k, how){ ui.force=null; if(how==='done'){ ui.done[k]=true; delete ui.skipped[k]; } else { ui.skipped[k]=true; delete ui.done[k]; } saveUi(); refresh().catch(fail); }
// Things the person has nothing to decide about: kept, and one tap away, but not in the way. Decisions stay on the screen.
// BUILD 555 (the maintainer's run, 17 Nov 2026: "Details: came back collapsed (had to expand) to see the found AP"): the page is
// drawn again after every action, and each new fold started closed, so pressing a button inside one hid its own answer.
// A fold now stays as the person left it (by its title, for this visit). The click is noted at once: the page may be
// drawn again before the browser says 'toggle'.
function fold(title, ...nodes){
  const d=el('details',undefined,'card fold'); d.dataset.fold='1';
  ui.folds=ui.folds||{};
  d.open=!!ui.folds[title];
  const sm=el('summary','Details: '+title); sm.addEventListener('click',()=>{ ui.folds[title]=!d.open; });
  d.addEventListener('toggle',()=>{ ui.folds[title]=d.open; });
  d.append(sm);
  nodes.filter(Boolean).forEach(n=>d.append(n));
  return d;
}
// One plain line under a decision: what the choice means in everyday words, so nobody is left guessing.
function means(text){ const p=el('p',undefined,'mut means'); p.append(el('strong','What this means: '), document.createTextNode(nopk(text))); return p; }
// A step Pazuzu cannot do for the person yet: plain steps, a link to the firewall's own page, a way to say it is done.
function handoff(key, cfg){
  const c=el('div',undefined,'card'); c.append(el('h2',cfg.title)); if(cfg.intro) c.append(el('p',cfg.intro,'mut'));
  const sc=el('div',undefined,'scroll'); const ol=el('ol'); cfg.steps.forEach(t=>ol.append(el('li',t))); sc.append(ol); if(cfg.note) sc.append(el('p',cfg.note,'mut')); c.append(sc);
  const row=el('div',undefined,'btnrow');
  if(cfg.link){ row.append(fwLink(cfg.linkLabel||'Open on the firewall', cfg.link)); }
  if(cfg.link2){ const a2=el('a',cfg.link2Label||'Open','btn'); a2.href=cfg.link2; a2.target='_blank'; a2.rel='noopener noreferrer'; row.append(a2); }
  if(cfg.toggle){
    const st=ui.done[key]?'Done':ui.skipped[key]?'Not now':'';
    if(st) row.append(el('span',st,'chip'+(ui.done[key]?'':' warn')));
    const d=el('button',cfg.doneLabel||'Done'); d.onclick=()=>mark(key,'done'); const n=el('button','Not now','quiet'); n.onclick=()=>mark(key,'skip'); row.append(d,n);
  }
  c.append(row); return c;
}
let polling=null;
// Guarded additions: what this firewall has been seen to support, and what the last one did.
function writeGate(st, cap){
  const w=st.writes||{};
  if(!w.checked) return {ok:false, why:'Check what this firewall supports first. It only reads.'};
  const c=(w.caps||{})[cap]; if(!c) return {ok:false, why:'Not known.'};
  return {ok:!!c.ready, why:c.why||''};
}
function checkCard(st){
  const w=st.writes||{}; const c=el('div',undefined,'card'); c.append(el('h2','What this firewall supports'));
  const caps=Object.values(w.caps||{});
  c.append(el('p', w.checked ? 'Checked'+(w.version?' (version '+w.version+')':'')+'. '+caps.filter(x=>x.ready).length+' of '+caps.length+' things Pazuzu can add for you are available here.'
    : 'Not checked yet. The check only reads: it asks the firewall which settings pages it has and changes nothing. Pazuzu adds nothing until it has seen the matching page.','mut'));
  if(w.checked){ const ul=el('ul'); caps.forEach(x=>ul.append(el('li',(x.ready?'\u2713 ':'\u2717 ')+x.title+(x.ready?'':' \u2014 '+x.why)))); c.append(ul); }
  const go=el('button', w.checked?'Check again':'Check this firewall', w.checked?'quiet':''); go.onclick=()=>act(go, async()=>{ await post('/api/probe',{}); }); c.append(go);
  return c;
}
// BUILD 537 (the maintainer, 14 Nov 2026: "big idea -> KidsNet as part of setup"; "default to OpenDNS FamilyShield"): once KidsNet
// has a network, the family DNS service that filters it is picked here. Optional: nothing is built unless it is picked.
async function kidsCard(body, st){
  let k; try{ k=await get('/api/kids'); }catch(e){ return; }
  if(!k || k.offered===false) return;          // BUILD 539: a copy without KidsNet offers none
  const c=el('div',undefined,'card'); c.dataset.kids='1'; c.append(el('h2','KidsNet'));
  const s=k.state||{};
  if(!s.built){
    c.append(el('p','Optional. A network for the kids\u2019 devices: a family DNS service filters what they can look up, and they reach the web and nothing in your home. To build one, pick a home for KidsNet in the list above and press Set these up; its filter is then chosen here.','mut'));
    if(k.why) c.append(el('p',k.why,'mut'));
    body.append(c); return; }
  const cur=(k.choices||[]).find(x=>x.id===s.provider);
  c.append(el('p', s.done ? 'KidsNet is filtered by '+(cur?cur.name:'its family DNS service')+'. Every lookup a device there makes goes to it, whatever DNS server the device is set to.'
    : 'KidsNet has its network. Pick the family DNS service that filters it. Every lookup a device there makes is sent to it, whatever DNS server the device is set to; your home and guest networks keep the firewall\u2019s own DNS.'));
  if(ui.kidsPick===undefined || !(k.choices||[]).some(x=>x.id===ui.kidsPick)) ui.kidsPick=s.provider||s.want;
  const box=el('div'); box.dataset.kidsChoices='1';
  (k.choices||[]).forEach(x=>{ const l=el('label',undefined,'opt '+(ui.kidsPick===x.id?'sel':'')); const r=el('input'); r.type='radio'; r.name='kidsPick'; r.value=x.id; r.checked=ui.kidsPick===x.id;
    const t=el('div'); t.append(el('div',x.name+(x.default?' (recommended)':'')), el('div',x.what,'mut')); l.append(r,t);
    r.onchange=()=>{ ui.kidsPick=x.id; box.querySelectorAll('label.opt').forEach(o=>o.className='opt'); l.className='opt sel'; go.textContent=label(); }; box.append(l); });
  c.append(box);
  const label=()=> !s.done ? 'Set up KidsNet\u2019s filter' : (ui.kidsPick===s.provider ? 'Check KidsNet again' : 'Change KidsNet\u2019s filter');
  const go=el('button',label(), s.done?'quiet':''); go.dataset.kidsGo='1';
  go.onclick=()=>act(go, async()=>{ await post('/api/kids/apply',{provider:ui.kidsPick}); });
  // BUILD 558 (KidsNet always carries the DNS-provider line, "No filter catches everything" and "Free
  // during the beta; a paid feature later"; never "safe for kids" or "private"; no provider logos)
  c.append(el('p','No filter catches everything. This is one layer, on this network only; a device that leaves the house, or joins another Wi-Fi, is not covered.','mut'));
  c.append(el('p','Free during the beta; a paid feature later.','mut'));
  c.append(el('p', k.plugin ? 'Bedtime and Pause KidsNet are set from the Pazuzu app.' : 'Bedtime and Pause KidsNet come with the plugin; without it KidsNet is filtered all day.','mut'));
  c.append(bar('',go));
  body.append(c);
  const wr=writeResult(st,['write-kids-net']); if(wr) body.append(wr);
}
function writeResult(st, kinds){
  const j=st.job; if(!j || !j.kind || !j.kind.startsWith('write-') || j.state!=='done') return null;
  if(kinds && kinds.indexOf(j.kind)<0) return null;
  const c=el('div',undefined,'card'); c.append(el('h2', j.kind==='write-undo'?'Taken back':(j.result&&j.result.info?'Already on the firewall':'Done on the firewall')));
  // BUILD 525: a job that saves several settings said "Saved / Read it back / Applied" once for each; each is said once, with how many
  const seen=new Map(); (j.lines||[]).forEach(t=>seen.set(t,(seen.get(t)||0)+1));
  const ul=el('ul'); seen.forEach((n,t)=>ul.append(el('li', n>1 ? String(t).replace(/\.\s*$/,'')+', '+n+' times.' : t))); c.append(ul);
  if(j.kind!=='write-undo' && j.result && j.result.can_undo){
    const u=el('button','Undo this','quiet'); u.onclick=()=>act(u, async()=>{ await post('/api/write/undo',{}); });
    c.append(el('p','Undo removes only what Pazuzu just added, and needs no passkey.','mut'), u); }
  return c;
}

async function refresh(){
  const my = ++ui.gen;
  const s = await get('/api/state');
  if(my!==ui.gen) return;                  // a newer draw has started; this one is out of date
  const st = s.wizard, pk = s.passkey;
  { const er=$('err'); if(er && /Failed to fetch|NetworkError|Load failed/.test(er.textContent)) er.textContent=''; }   // a dropped request is old news once this one answered
  sameSetup(st.setup_id||'');
  ui.base = st.firewall_url || '';
  /* BUILD 476: on the phone, the firewall's own pages are reached by the address this page came in on (the box's LAN
     address, or 192.168.77.1 on Hanbi_Setup), not the address the wizard was started with */
  if(st.phone && ui.base){ try{ const u=new URL(ui.base); u.hostname=location.hostname; ui.base=u.origin; }catch(e){} }
  ui.phoneApp = st.phone_app_url || ''; ui.managerUrl = st.manager_url || ''; ui.legal = st.legal || {terms:false, consent_answered:false, consent:{}};
  showApproval(pk, st);
  const wn=document.getElementById('winnote'); if(wn){ const w=(st.light?{}:st.window)||{}; wn.textContent = w.active ? 'Your passkey is open for '+Math.floor(w.seconds_left/60)+':'+String(w.seconds_left%60).padStart(2,'0')+'. Changes in that time need no new touch (switching root off always asks).' : ''; wn.hidden=!w.active; }
  const host=$('body'); host.className=''; const body=document.createElement('div'); host.replaceChildren(body); document.body.removeAttribute('data-level');
  ui.light=!!st.light; pzLight=ui.light; ui.phone=!!st.phone; ui.managerReady=!!st.manager_ready; ui.managerOpen=st.manager_open!==false; ui.pluginOffered=st.plugin_offered!==false;
  { const lv=document.getElementById('live'); if(lv) lv.hidden=!!ui.phone; }   // BUILD 477: the request log is for the PC
  earlyPlugin(body);                         // BUILD 485: the box's software, brought up to date before anything else
  if(st.platform && st.platform!==ui.platform){ ui.platform=st.platform; applyBrand(); }   // BUILD 480: it had been swallowed by the comment above
  { const want=ui.mode; const ok = !want || (want==='audit' ? (!st.light&&!st.trial) : want==='trial' ? (st.light&&st.trial) : (st.light&&!st.trial));
    if(!ok && (ui.modeTry||0)<3){ ui.modeTry=(ui.modeTry||0)+1; try{ await post('/api/mode',{mode:want}); }catch(e){} return refresh(); }
    if(ok) ui.modeTry=0; }
  if(!(ui.legal && ui.legal.terms && ui.legal.consent_answered)){ rail(0); if(ui.legal&&ui.legal.terms) ui.terms=true; return legalStep(body, st); }   // terms + the call-home choice come first, before anything on the firewall; a switch added later is asked too
  if(ui.mode==='trial'){
    const tn=el('div',undefined,'card'); tn.append(el('h2','Test flight'), el('p','This firewall is running from the live CD. Nothing here is saved: when it restarts, every change is gone, including Pazuzu\u2019s accounts and rules. Install it to disk to keep them.','mut')); body.append(tn);
  }
  const job=st.job;
  ui.installer=!!st.installer_user; ui.installerStale=!!st.installer_stale;     // BUILD 528: the update buttons need it
  // BUILD 480: while a run is testing a stage, the run keeps or undoes it by itself: Keep and Undo are not for the person
  // then (the phone showed them in the middle of the rules). A change still waiting after the run stops is theirs.
  if(st.guard && st.guard.active && st.guard.state==='armed' && !(job && job.state==='running' && job.kind==='plan')){ return armedStep(body, st.guard); }
  // BUILD 481: the last step keeps its own page while a part runs (which parts are done, which is on now), with what it
  // is doing and how long it has been at it. A bare "Working…" for three minutes looked stuck (lab run, 4 Nov 2026).
  if(job && job.state==='running' && ui.at==='happy' && ui.happy && ui.happy.started && HAPPY_PARTS.some(p=>p[2]===job.kind)){
    rail(3); await happyStep(body, st, job); body.append(busyLines(job)); schedule(); return; }   // BUILD 490: 3 is Finish on both paths
  if(job && job.state==='running' && job.kind==='write-zone-vlans' && ui.hw && ui.hw.started){     // BUILD 482: its own page
    rail(4,true); await homeWifiStep(body, st, job); body.append(busyLines(job)); schedule(); return; }
  if(job && job.state==='running'){
    if(job.kind==='plan') ui.sawPlan=false;      // a new run: its stop, if it stops, is shown
    const at = job.kind.startsWith('stage-') || job.kind.startsWith('apply') || job.kind==='plan' ? 2 : (job.kind==='plugin-install'||job.kind==='enroll-installer') ? 3 : 0;
    const stay = ui.light && at===0 && typeof ui.lastRail==='number' && ui.lastRail>0;     // a job with no step of its own: the rail stays where it was
    const adding = ui.light && job.kind.startsWith('apply');     // BUILD 525: adding the rules is the Rules step (it said Admin, "Step 7 of 8")
    if(ui.light && job.kind==='plan' && ui.runAt){ rail(ui.runAt,true); } else if(adding){ rail(6,true); } else if(stay){ rail(ui.lastRail,true); } else rail(at);
    const real=job.kind.startsWith('stage-')||job.kind.startsWith('apply')||job.kind==='plan'||job.kind==='plugin-install'||job.kind==='box-root-install'||job.kind==='ddns-install'||job.kind==='firmware-check'||job.kind==='firmware-update'||job.kind==='firmware-reboot'; body.append(ui.light && job.kind==='plan' && ui.runAt ? head(ui.runAt+1,'Working\u2026',undefined,true) : adding ? head(7,'Working\u2026',undefined,true) : stay ? head(ui.lastRail+1,'Working\u2026',undefined,true) : head(at+1,'Working\u2026')); if(real) body.append(progressCard(job, st)); else body.append(busyLines(job)); schedule(); return; }
  if(job && job.state==='failed' && ui.jobSeen!==(job.id||job.kind+'|'+job.error)){ ui.jobSeen=job.id||job.kind+'|'+job.error; ui.jobErr=job.error||'That did not work.'; ui.jobErrGen=my; fail(new Error(ui.jobErr));
    // The firewall refused the saved keys (it was reset or reinstalled): ask the server to check them now, so the page
    // moves to the step that sets them aside instead of reading the firewall again and again with keys it refuses.
    if(/no longer recognises|different security certificate/.test(ui.jobErr)){ post('/api/keys/check',{}).then(()=>refresh()).catch(()=>{}); } }   // said once, not on every page after
  if(st.keys_stale){ rail(0); return staleKeysStep(body, st); }
  if(st.keys_silent){ rail(0); return silentFirewallStep(body, st); }
  if(st.keys_checking && (ui.keyWait||0)<40){
    ui.keyWait=(ui.keyWait||0)+1; rail(0); body.append(head(1,'Checking Pazuzu\u2019s saved keys\u2026'), busyCard('Asking the firewall if it still knows them.')); setTimeout(refresh,600); return;
  }
  if(st.installer_user && st.passkeys!==undefined && st.writes && (!st.writes.checked || st.writes.role!=='installer') && (ui.autoProbed||0)<3 && !(job&&job.state==='running')){
    ui.autoProbed=(ui.autoProbed||0)+1; try{ await post('/api/probe',{}); }catch(e){} return refresh();
  }
  if(!st.read_user){ rail(0); return signIn(body, st, 'read'); }
  if(pk.passkeys.length===0 && !st.light){ rail(0); return passkeyStep(body); }
  if(!st.write_user){ rail(0); return signIn(body, st, 'write'); }
  if(st.installer_stale && !ui.installerLater){            // it closed itself overnight: offer to make it again, once, here
    rail(0); const c=el('div',undefined,'card');
    c.append(el('h2','The installer account has closed itself'),
      el('p','The firewall closes it after a day. Making it again also gives Pazuzu’s own two accounts the pages they need, so the board stays whole after it closes next time.','mut'));
    installerForm(c, 'Your firewall password is used once, here, and not saved. Your passkey approves it.',
      async()=>{ for(let i=0;i<60;i++){ const s=await get('/api/state'); if(!(s.wizard.job&&s.wizard.job.state==='running')) break; await new Promise(r=>setTimeout(r,500)); }
        const s2=await get('/api/state'); if(s2.wizard.installer_user) await post('/api/probe',{}); });
    const later=el('button','Not now','quiet'); later.onclick=()=>{ ui.installerLater=true; refresh().catch(fail); }; c.append(later);
    body.append(c); return;
  }
  if(st.light && !handled('plugin') && ui.force!=='zones'){ return pluginStep(body, st, job); }   // test mode: the plugin and the version come before anything else
  if(ui.force==='firmware'){ rail(0); return firmwareStep(body, st, job); }
  if(ui.force==='admin'){ rail(0); return adminStep(body, st); }
  if(ui.force==='zones'){ rail(1); return zonesStep(body, st, job); }
  if(st.light){
    // Test mode, in this order: Ports, Wi-Fi, Reach home (the name, the certificate, then the VPN),
    // the rules in three runs (allow, old allow-everything off, blocking), and your own admin sign-in
    // LAST — on the way out, right before Finish, once the lifeline and allow rules already protect the way in.
    if(!handled('zones')){ if((!st.zones || !st.zones.deployable) && await autoZones(st)) return refresh();
      if(st.phone && st.zones && st.zones.deployable){ ui.skipped.zones=true; saveUi(); return refresh(); }   // BUILD 477: the ports are bound; the rest is the manager's
      rail(1); return zonesStep(body, st, job); }
    if(st.phone && !handled('homewifi')){ rail(4,true); return homeWifiStep(body, st, job); }   // BUILD 482: Hanbi's own Wi-Fi
    if(st.phone && !handled('wayback') && ui.force!=='wayback'){ ui.skipped.wayback=true; saveUi(); return refresh(); }   // BUILD 477: the phone over Bluetooth is the way back
    if(ui.force==='wayback' || !handled('wayback')){ rail(4,true); return wayStep(body, st, 5); }
    if(!handled('reach')){ rail(5,true); return reachStep(body, st, job); }
    if(ui.at==='access'){ rail(8); return accessStep(body, st); }
    if(ui.at==='after'){ rail(8); return afterStep(body, st, job); }   // BUILD 503
    if(ui.at==='happy'){ rail(8); return happyStep(body, st, job); }
    if(ui.at==='extras'||ui.at==='allset'){ rail(8); return allsetStep(body, st, job); }
    if(!handled('rules')){ return lightRules(body, st, job); }
    if(!handled('admin')){ rail(7,true); return adminStep(body, st, 8); }      // your own sign-in + one-time code, LAST, right before the hand-off
    rail(8); return allsetStep(body, st, job);
  }
  if(!st.light && !handled('firmware')){ rail(0); return firmwareStep(body, st, job); }
  if(ui.force==='wayback'){ rail(2); return wayStep(body, st); }      // sent from the manager's reminder
  if(!st.light && !handled('admin')){ rail(0); return adminStep(body, st); }
  if((!st.zones || !st.zones.deployable) && !handled('zones')){ if(await autoZones(st)) return refresh(); rail(1); return zonesStep(body, st, job); }   // honor Skip/Done in the full flow too, not just light
  if(ui.at==='access'){ rail(3); return accessStep(body, st); }
  if(ui.at==='after'){ rail(3); return afterStep(body, st, job); }   // BUILD 503: beta 1's page after setup
  if(ui.at==='rules-on'){ rail(3); return lightRules(body, st, job); }   // BUILD 493: the careful way switches the rules on here
  if(ui.at==='happy'){ rail(3); return happyStep(body, st, job); }
  if(ui.at==='extras'||ui.at==='allset'){ rail(3); return allsetStep(body, st, job); }
  if(!st.light && !handled('wayback')){ rail(2); return wayStep(body, st); }       // a safety setting: it comes with them, after sign-in, admin and ports
  if(!st.light && !handled('wayin')){ rail(2); return wayInStep(body, st, job); }   // BUILD 493: a way in before the rules go on
  rail(2); return rulesStep(body, st, job);
}
function schedule(){ if(polling) return; polling=setTimeout(async()=>{ polling=null; try{ await refresh(); }catch(e){ fail(e); } }, 1000); }
const STEP_WORDS={toggle_rule:'Switch a rule on or off', set_description:'Write the note on a rule'};
const STEP_STATE={pending:'waiting',attempted:'working',applied:'done',undone:'undone',undo_failed:'could not undo'};
const STEP_MARK={pending:'○', attempted:'…', applied:'✓', undone:'↩', undo_failed:'✗'};
// BUILD 481: under "Working…", for a job with no progress bar of its own: what it is doing in plain words, and how long
// it has been at it, counted from when this page first saw it.
const JOB_WORDS={
  'write-zone-vlans':'Making the Smart devices and Guest networks on your Hanbi, then the Wi-Fi on your access point. Its Wi-Fi restarts: about a minute.',
  'write-zone-vlans:pc':'Setting up the networks on the firewall: each port or VLAN, its addresses, and who hands them out. About a minute.',
  'ap-join':'Joining the access point\u2019s Wi-Fi with a spare radio on the firewall, then waiting for it to hand the firewall an address. Up to two minutes.',
  'shield-levels':'Switching on the block lists, the ad lists and packet inspection. The lists download now, which can take a few minutes.',
  'happy-finish':'Encrypted lookups, each network\u2019s DNS and time sent to the firewall, the lists refreshed nightly.',
  'ipv6-off':'Switching IPv6 off everywhere.',
  'ssh-fix':'Switching Secure Shell off.',
  'write-admin-finish':'Making your admin and checking each part: the code, the web page, sudo, then root off.',
  'enroll-read':'Pazuzu is making its own accounts on the firewall.',
  'write-time-zone':'Setting the firewall\u2019s time zone.',
  'write-peer':'Adding your phone to the VPN.',
  'write-vpn':'Making the VPN.'};
function busyLines(job){
  const c=el('div',undefined,'card'); c.dataset.busy='1';
  if(!ui.jobT || ui.jobT.id!==job.id) ui.jobT={id:job.id, at:Date.now()};
  const s=Math.max(0, Math.floor((Date.now()-ui.jobT.at)/1000));
  { const w=(!ui.phone && JOB_WORDS[job.kind+':pc']) || JOB_WORDS[job.kind]; if(w) c.append(el('p',w)); }   // BUILD 514: a PC's setup has no Hanbi and may have no access point
  // the lines themselves only where they are written for a person (your admin's steps); the others are for the log
  const last=job.kind==='write-admin-finish' ? (job.lines||[]).filter(t=>t && String(t).trim()).slice(-3) : [];
  if(last.length){ const ul=el('ul'); last.forEach(t=>ul.append(el('li',String(t)))); c.append(ul); }
  c.append(el('p','Still working, '+Math.floor(s/60)+':'+String(s%60).padStart(2,'0')+'. This page carries on by itself.','mut'));
  return c;
}
function progressCard(job, st){
  const c=el('div',undefined,'card'); let items=[], done=0, total=0;
  const steps=(st.guard&&st.guard.steps)||[];
  if(job.kind.startsWith('stage-') && steps.length){
    steps.forEach(x=>{ items.push([STEP_MARK[x.status]||'○', (x.name||STEP_WORDS[x.kind]||x.kind.replace(/_/g,' '))+(x.status==='attempted'?' — working':'')]); if(x.status==='applied') done++; });
    total=steps.length;
  } else {
    (job.lines||[]).filter(l=>/^Added/.test(l)).forEach(l=>{ items.push(['✓',l.replace(/^Added[^:]*:\s*/,'')||l]); done++; });
    total=ui.total||0;
    if(!items.length) items.push(['…','Waiting for the firewall']);
  }
  const lineJob=job.kind==='plugin-install'||job.kind==='box-root-install'||job.kind==='ddns-install'||job.kind==='firmware-check'||job.kind==='firmware-update'||job.kind==='firmware-reboot';
  if(lineJob){ items=(job.lines||[]).map(l=>['…',l]); total=0; if(job.kind==='firmware-reboot') items=[['…','Asking the firewall to restart']]; }
  if(job.kind==='plan' && job.progress){ items=job.progress.map(x=>[x.state==='kept'||x.state==='handled'?'✓':x.state==='running'?'…':x.state==='stopped'||x.state==='undone'?'✗':'○', x.title+(x.detail?' — '+x.detail:'')]); total=job.progress.length; done=job.progress.filter(x=>x.state==='kept'||x.state==='handled').length; }
  const bar=el('div',undefined,'pbar'+(lineJob?' busy':'')); const fill=document.createElement('i'); if(lineJob) slideOn(fill); else fill.style.width=(total?Math.min(100,Math.round(100*done/total)):5)+'%'; bar.append(fill);
  c.append(el('div',job.kind==='plugin-install'?'Installing':job.kind==='box-root-install'?'Putting the plugin on the firewall':job.kind==='ddns-install'?'Installing the name plugin':job.kind==='firmware-check'?'Asking the firewall to look for updates':job.kind==='firmware-update'?'Updating the firewall':job.kind==='firmware-reboot'?'Restarting the firewall':(total?done+' of '+total:'Starting'),'vt'), bar);
  const ul=el('ul',undefined,'plain'); items.slice(-12).forEach(([m,t])=>ul.append(el('li',m+' '+t))); const sc=el('div',undefined,'scroll'); sc.append(ul); c.append(sc);
  if(lineJob){   // BUILD 546: how long it has been at it, as the other waits say (a firewall's own update check can take ten minutes)
    if(!ui.jobT || ui.jobT.id!==job.id) ui.jobT={id:job.id, at:Date.now()};
    const s=Math.max(0, Math.floor((Date.now()-ui.jobT.at)/1000));
    c.append(el('p','Still working, '+Math.floor(s/60)+':'+String(s%60).padStart(2,'0')+'. This page carries on by itself.','mut')); }
  return c;
}
function jobCard(job){ const c=el('div',undefined,'card'); const p=el('pre'); p.textContent=(job.lines||[]).join('\n')||'Starting…'; c.append(p); return c; }

function showApproval(pk, st){
  const veil=$('veil'), dlg=$('dlg');
  if(!pk.pending){ veil.hidden=true; return; }
  veil.hidden=false; dlg.replaceChildren();
  dlg.append(el('h2','Approve with your passkey'), el('p', pk.pending.lines[0]||'', 'mut'));
  if(pk.pending.lines.length>1){ const dt=el('details'); dt.append(el('summary','Details')); const ul=el('ul'); pk.pending.lines.slice(1).forEach(t=>ul.append(el('li',t))); dt.append(ul, el('p','Plan ID '+pk.pending.digest,'mut mono')); dlg.append(dt); }
  const btn=el('button','Approve with passkey'); btn.onclick=()=>act(btn, approvePlan);
  const no=el('button','Cancel','quiet'); no.onclick=()=>act(no, cancelApproval); dlg.append(btn, no);
  schedule();
}

async function signIn(body, st, role){
  const write = role==='write';
  if(!write && ui.mode===null && st.phone){ ui.mode='new'; ui.done.intro=true; saveUi(); }   // BUILD 477: a Hanbi from the app is always new; no "Hang in with us"
  if(!write && ui.mode===null){ return forkStep(body); }
  // BUILD 480: a Hanbi from the app comes from the factory with the factory password, so the box signs itself in and
  // makes Pazuzu's accounts without a page. Only when that is refused (the password was changed) is the page shown.
  if(!write && st.phone && !ui.autoSignIn){
    ui.autoSignIn=true; body.append(head(1,'Getting your Hanbi ready'), busyCard('Pazuzu is making its own accounts on the firewall\u2026'));
    try{ await post('/api/mode',{mode:'new'}); }catch(e){}       // first: which accounts the sign-in makes depends on it
    try{ await post('/api/enroll',{role:'read',use_default:true,password:null,fingerprint:null,username:null,also_installer:false}); }catch(e){ fail(e); }
    return refresh(); }
  if(!write && ui.mode==='audit') ui.useDefault=false;
  if(!write && ui.mode==='trial') ui.useDefault=true;
  body.append(head(1, write ? 'Make a passkey for changes' : 'Sign in to your firewall once',
    write ? 'Pazuzu keeps one account that only looks and one that can change things. This makes the second one, and your passkey approves it. It also makes the installer account in the same go (it can open every page, is used only when your passkey approves, and the firewall closes it after a day), so later steps never ask for this password again.'
          : (ui.mode==='audit'
              ? 'This firewall is already running, so we look first and change nothing without your approval. Use the sign-in you already have. It is used one time and never saved.'
              : 'Pazuzu makes its own limited users so it never needs your main password again. This password is used one time and never saved.'+(st.phone?' This one sign-in makes everything it needs; your phone\u2019s passkey already approves the rest.':st.light?' This one sign-in makes everything it needs. There is no passkey in this mode.':''))));
  if(st.light && !write && !ui.done.intro){
    const ic=el('div',undefined,'card'); ic.append(el('h2','Hang in with us'),
      el('p','To have proper security, this firewall has to be made your own: set up for your network, your devices and your passwords, not left the way it came. We will walk you through every step.','mut'),
      el('p','This takes about 30 minutes, a little longer if the firewall needs an update. Most of that is waiting while the firewall downloads or restarts. There are nine steps, listed down the left, and every one is needed for a correct setup. When you reach Finish, you are all set.','mut'));
    const gi=el('button','Got it','quiet'); gi.onclick=()=>{ ui.done.intro=true; saveUi(); refresh().catch(fail); }; ic.append(gi); body.append(ic);
  }
  const row=el('div',undefined,'row');
  let fpInfo=null, confirmed=false, fpFailed=false;
  const left=el('div',undefined,'card');
  if(!write){
    left.append(el('h2','Is this your firewall?'));
    if(st.startup){
      const sx=st.startup;
      if(sx.why) left.append(el('p', sx.why + (sx.fresh ? ' ' + sx.fresh : ''), 'mut'));
      if(sx.others && sx.others.length) left.append(el('p','Also answering on your network, and not used: ' + sx.others.join(', ') + '.','mut'));
    }
    try{ fpInfo=await get('/api/fingerprint'); }catch(e){ fpFailed=true; }
    if(fpInfo && fpInfo.needed){
      left.append(el('p','Firewall: '+fpInfo.host+(fpInfo.cert_name?' · certificate name: '+fpInfo.cert_name:''),'mut'));
      left.append(el('p','Its certificate fingerprint is:','mut'), el(fpInfo.changed?'div':'div',fpInfo.fingerprint,'fp mono'));
      if(fpInfo.changed) left.append(el('p','This is DIFFERENT from the one you trusted before.','mut'));
      left.append(el('p','On the firewall’s own screen, find the line that starts HTTPS: SHA256 and compare it.','mut'));
      const yes=el('button','They match'); const no=el('button','They don’t match','quiet');
      const note=el('p','','mut');
      yes.onclick=()=>{ confirmed=true; ui.fp=fpInfo.raw; note.textContent='Confirmed. Now the password.'; lock(false); waiting(); };
      no.onclick=()=>{ confirmed=false; ui.fp=null; note.textContent='Stop here. Check you are on the right network and try again.'; lock(true); waiting(); };
      const br=el('div'); br.append(yes,document.createTextNode(' '),no); left.append(br,note);
    } else if(fpFailed) left.append(finderPanel(st.firewall_url||''));
    else left.append(el('p','This connection does not need a fingerprint check.','mut'));
  } else left.append(el('h2','Your firewall'), el('p',st.firewall,'mut mono'));
  const right=el('div',undefined,'card'); right.append(el('h2','Password for this one sign-in'));
  const a=el('label',undefined,'opt '+(ui.useDefault?'sel':'')); const ra=el('input'); ra.type='radio'; ra.name='pw'; ra.checked=ui.useDefault;
  const at=el('div'); at.append(el('div','Brand-new firewall'), el('div','We’ll try the factory password for you: opnsense','mut'));
  if(!st.phone) at.append(el('div','Running the live image without installing? Then root and installer both use opnsense, and everything is lost at the next reboot.','mut'));
  a.append(ra,at);
  const b2=el('label',undefined,'opt '+(!ui.useDefault?'sel':'')); const rb=el('input'); rb.type='radio'; rb.name='pw'; rb.checked=!ui.useDefault;
  const bt=el('div'); bt.append(el('div','I’ve changed it')); const un=el('input'); un.type='text'; un.autocomplete='off'; un.value='root'; un.placeholder='User name (usually root)'; bt.append(un); const pw=el('input'); pw.type='password'; pw.autocomplete='off'; pw.placeholder='Type your password'; bt.append(pw); b2.append(rb,bt);
  ra.onchange=()=>{ ui.useDefault=true; a.className='opt sel'; b2.className='opt'; };
  rb.onchange=()=>{ ui.useDefault=false; b2.className='opt sel'; a.className='opt'; pw.focus(); };
  right.append(...(ui.mode==='audit'?[b2]:[a,b2]),el('p','Not saved, not shown again, and sent only to your firewall. If it asks for a one-time code, type your password and the code together, in the order the firewall expects. Each sign-in needs a fresh code, so wait for the next one before the second sign-in.','mut'));
  const go=el('button', write ? 'Create the account for changes' : 'Create Pazuzu’s user');
  const lock=(on)=>{ [ra,rb,un,pw,go].forEach(x=>{ x.disabled=on; }); right.style.opacity=on?'0.5':''; };
  const why=el('p','','mut');
  const waiting=()=>{ why.textContent = fpFailed ? 'Not yet. This device cannot reach the firewall, so pick your firewall on the left first.'
      : (fpInfo && fpInfo.needed && !confirmed) ? 'Not yet. Check the fingerprint on the left first.' : ''; };
  const lockOrNot=!write && ((fpInfo && fpInfo.needed) || fpFailed);
  lock(!!lockOrNot); waiting();
  go.onclick=()=>act(go, async()=>{ const pass=ui.useDefault?null:pw.value; pw.value=''; await post('/api/enroll',{role,use_default:ui.useDefault,password:pass,fingerprint:ui.fp,username:ui.useDefault?null:un.value.trim(),also_installer:write}); });
  right.append(why, el('p',write?(st.light?'No passkey is asked for in this mode.':'Your passkey will be asked to approve this.'):(st.light?'Next: which port is which.':'Next: register your passkey with Windows Hello. One touch, once.'),'mut'), go);
  row.append(left,right); body.append(row);
  body.append(cablingHelp());
  body.append(ispHelp());
  if(fpFailed) body.append(consoleHelp());
}

function cablingHelp(){
  const d=el('details',undefined,'card'); d.append(el('summary','Which cable goes where'));
  const ol=el('ul'); [
    'WAN (the Internet side) goes to your modem or your internet provider\u2019s box.',
    'LAN (your side) goes to this device, or to a switch this device is on. On many boxes LAN is the port marked 1.',
    'Using a Wi-Fi router for the rest of the house? Plug it into the LAN side, with its own DHCP switched off.',
    'Look at the lights on both ports. No light means no link: try another cable or port.',
    'A virtual machine needs its two network adapters set to different networks, one for each side.'].forEach(t=>ol.append(el('li',t)));
  d.append(ol); return d;
}

// Where to look when the internet provider's own box needs something special. Real places only; the search opens in a new
// tab and sends only what was typed, only when the button is pressed.
function ispHelp(){
  const d=el('details',undefined,'card'); d.dataset.ispHelp='1'; d.append(el('summary','Help for your internet provider'));
  d.append(el('p','Some providers need a setting on their own box (often called bridge mode or IP passthrough), a login, or a VLAN number before a firewall works behind them. Places to look:','mut'));
  const ul=el('ul');
  [['The OPNsense forum: search it, or ask, with your provider\u2019s name',web('forum.opnsense.org/')],['The OPNsense documentation',web('docs.opnsense.org/')]].forEach(([t,u])=>{ const li=el('li'); const a=el('a',t); a.href=u; a.target='_blank'; a.rel='noopener noreferrer'; li.append(a); ul.append(li); });
  ul.append(el('li','Your provider\u2019s own support pages for their box: look for \u201cbridge mode\u201d or \u201cpassthrough\u201d.'));
  d.append(ul);
  const nm=el('input'); nm.type='text'; nm.autocomplete='off'; nm.placeholder='Your internet provider\u2019s name';
  const go=el('button','Search the web for it','quiet');
  go.onclick=()=>{ const q=nm.value.trim(); if(!q){ nm.focus(); return; } window.open(web('duckduckgo.com/?q=')+encodeURIComponent(q+' bridge mode OPNsense'),'_blank','noopener'); };
  const row=el('div',undefined,'btnrow'); row.append(nm,go); d.append(row);
  d.append(el('p','Only what you type is sent to the search, and only when you press the button.','mut'));
  return d;
}

function rootCard(body){
  const c=el('div',undefined,'card'); c.append(el('h2','Shut the factory root account'));
  c.append(el('p','The factory account is the first thing anyone tries. Shut it for the web page and SSH once you have another way in. Pazuzu never does this for you, and its own accounts are not affected.','mut'));
  const need=[]; if(!ui.done.admin) need.push('Make your own admin sign-in and sign in with it from a second window.');
  const pwd=el('input'); pwd.type='checkbox'; const pl=el('label'); pl.append(pwd, document.createTextNode(' root has a strong password that I have written down. The firewall\u2019s own screen still accepts it.'));
  const steps=el('div');
  const draw=()=>{ steps.replaceChildren();
    if(need.length){ steps.append(el('p','Not yet. First:','vt')); const ul=el('ul'); need.forEach(t=>ul.append(el('li',t))); steps.append(ul); return; }
    if(!pwd.checked){ steps.append(el('p','Tick the box above first.','mut')); return; }
    const ol=el('ol'); ['Keep the window where you are signed in as your own admin open the whole time.','Open the Users page (the button), edit root, and tick Disabled (or the option that stops it signing in to the web page). Save.','In a second window, sign in as your own admin to prove it still works. Then try root: it should be refused.','Locked out anyway? On the firewall\u2019s own screen choose 3 (Reset the root password), or use the console\u2019s own root.'].forEach(t=>ol.append(el('li',t))); steps.append(ol);
    steps.append(fwLink('Open Users','/ui/auth/user')); };
  pwd.onchange=draw; const did=el('button','Already done','quiet'); did.onclick=()=>{ ui.done.rootoff=true; saveUi(); refresh().catch(fail); };
  c.append(pl, steps, did); draw(); body.append(c);
}

// Where to get an authenticator app. Plain links to each store; nothing is sent from here.
function authApps(){
  const d=el('div',undefined,'tips'); d.dataset.authApps='1';
  d.append(el('p','No authenticator app yet? Get one on your phone:','vt'));
  const row=(name, links)=>{ const r=el('div',undefined,'btnrow'); r.append(el('span',name+': ')); links.forEach(([t,u])=>{ const a=el('a',t,'btn'); a.href=u; a.target='_blank'; a.rel='noopener'; r.append(a); }); return r; };
  d.append(row('Google Authenticator',[['iPhone',web('apps.apple.com/app/google-authenticator/id388497605')],['Android',web('play.google.com/store/apps/details?id=com.google.android.apps.authenticator2')]]));
  d.append(row('Microsoft Authenticator',[['iPhone',web('apps.apple.com/app/microsoft-authenticator/id983156458')],['Android',web('play.google.com/store/apps/details?id=com.azure.authenticator')]]));
  d.append(el('p','Any app that makes 6-digit codes works. Newer iPhones can also keep them in the built-in Passwords app.','mut'));
  return d;
}
function renderOtp(out, r, opts){
  opts=opts||{};
  out.replaceChildren();
  if(opts.onScreen){ ui.otpShown=false; out.append(el('p','The code is on your Hanbi\u2019s screen.','vt')); }
  else { const pic=el('div',undefined,'qrbox'); pic.append(document.importNode(new DOMParser().parseFromString(r.svg,'image/svg+xml').documentElement,true)); out.append(pic); }
  const seedP=el('p',opts.compact?'Cannot scan? Type this seed into the app:':'Seed (paste it into the OTP seed field):','vt'), seedV=el('div',r.seed,'fp mono'), apps=authApps();
  if(!opts.onScreen) out.append(seedP, seedV, apps);   // 0.6.83: on the phone they go under the field (Check sat below a scroll)
  const ol=el('ol'); (opts.onScreen?['Open an authenticator app on this phone and scan the code on your Hanbi\u2019s screen.','Type the 6-digit code it shows now and press Check.']:opts.compact?['Scan the picture with an authenticator app on your phone.','Type the 6-digit code it shows now and press Check.']:['Scan the picture with an authenticator app on your phone.','Paste the seed into the OTP seed field of the new user on the firewall and save. Or use the card below and Pazuzu adds it.','Type the 6-digit code your phone shows now, and press Check, to prove the scan worked.']).forEach(t=>ol.append(el('li',t))); out.append(ol);
  const code=el('input'); code.type='text'; code.autocomplete='off'; code.inputMode='numeric'; code.placeholder='6-digit code';
  const chk=el('button','Check'); const res=el('p','','mut');
  chk.onclick=async()=>{ res.textContent=''; chk.disabled=true; try{ const v=await post('/api/otp/check',{seed:r.seed, code:code.value}); ui.otpOk=!!v.match; if(v.match) ui.otpCode=code.value.trim(); if(v.match && opts.onMatch){ res.textContent='It matches. Next…'; setTimeout(opts.onMatch,500); chk.disabled=false; return; } res.textContent=v.match?'It matches. Your phone and this seed agree.':'It does not match. Wait for the next code and try again, and check your phone\u2019s clock is on automatic.'; }catch(e){ fail(e); } chk.disabled=false; };
  const hide=el('button','Hide it now','quiet'); hide.onclick=()=>{ ui.otp=null; ui.otpOk=false; if(ui.otpUpd) ui.otpUpd(); out.replaceChildren(el('p','Gone. Nothing was saved. Make another if you need to.','mut')); };
  const cr=el('div',undefined,'btnrow'); cr.append(code,chk); if(!opts.compact) cr.append(hide); out.append(cr,res);
  if(opts.onScreen) out.append(seedP, seedV, apps);
}

function otpCard(){
  const c=el('div',undefined,'card'); c.append(el('h2','One-time code (recommended)'));
  c.append(el('p','Pazuzu can make the secret here, on this device. It is shown here only, is never saved, and is lost when you close or reload this page. Paste it into the firewall\u2019s form, or let Pazuzu add the user for you (the card below).','mut'));
  const name=el('input'); name.type='text'; name.autocomplete='off'; name.placeholder='The new username, for the label'; name.value=ui.otpName||''; name.oninput=()=>{ ui.otpName=name.value; };
  const make=el('button','Make a one-time code'); const out=el('div'); const row=el('div',undefined,'btnrow'); row.append(name, make);
  make.onclick=async()=>{
    $('err').textContent=''; make.disabled=true;
    let r; try{ r=await post('/api/otp/new',{account:name.value.trim()}); }catch(e){ make.disabled=false; fail(e); return; }
    make.disabled=false; ui.otp=r; renderOtp(out, r); if(ui.otpUpd) ui.otpUpd();
  };
  if(ui.otp) renderOtp(out, ui.otp);
  c.append(row,out); return c;
}

// Where you are in making your own sign-in: eight short steps with ticks, so it is never unclear what is next.
// One card at a time: what Pazuzu is doing now, and the one field or button for it. A card leaves when it is done.
function adminFlow(st){
  const j=st.job||{};
  if(j.kind==='write-undo' && j.state==='done'){ ui.credsOk=false; ui.otpOk=false; ui.otp=null; ui.proved=false; }
  if(st.root_secured) ui.adminPw='';          // let go only when root is secured: until then a retry, the test and the sign-in check can use it (memory only)
  const c=el('div',undefined,'card');
  const title=(n,t)=>{ c.append(el('div','Step '+n+(ui.phone?' of 2':' of 8'),'eye'), el('h2',t)); };   // BUILD 480: the phone asks two things
  const g=writeGate(st,'user');
  // The password just made, for the steps that sign in with it. It lives only in this page's memory; after a reload it is gone.
  const passwordRow=()=>{
    const row=el('div',undefined,'btnrow');
    if(ui.adminPw){
      const shown=el('code','\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022'); let open=false;
      const eye=el('button','Show','quiet'); eye.onclick=()=>{ open=!open; shown.textContent=open?ui.adminPw:'\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022'; eye.textContent=open?'Hide':'Show'; };
      row.append(el('span','Your password: '), shown, eye, copyButton(ui.adminPw,'Copy password'));
    } else row.append(el('p','The password is not kept after this page is reloaded. Use the one you chose, or the one your browser or password app saved on the firewall\u2019s own address.','mut'));
    return row;
  };
  const recheck=()=>{ if(!g.ok){ c.append(el('p',g.why,'mut')); const re=el('button','Check this firewall again','quiet'); re.onclick=()=>act(re, async()=>{ await post('/api/probe',{}); }); c.append(re); } };
  if(!st.installer_user){
    title(1,'Pazuzu needs its installer account');
    if(st.installer_stale) c.append(el('p','The firewall no longer accepts the installer account. It closes itself after a day, so it has to be made again. Your old key is kept aside on this device.','mut'));
    installerForm(c, 'Only the installer account may open the Users page. Your passkey approves it, and the check runs again by itself.',
      async()=>{ for(let i=0;i<60;i++){ const s=await get('/api/state'); if(!(s.wizard.job&&s.wizard.job.state==='running')) break; await new Promise(r=>setTimeout(r,500)); }
        const s2=await get('/api/state'); if(s2.wizard.installer_user) await post('/api/probe',{}); });
    return c;
  }
  if(ui.phone && !st.root_secured){ const pa=phoneAdmin(st, c, title); if(pa) return pa; }
  if(!st.admin_user && !ui.credsOk){
    title(ui.phone?1:2,'Choose your own sign-in');
    const un=el('input'); un.type='text'; un.autocomplete='off'; un.placeholder='A user name (not root)'; un.value=ui.otpName||st.admin_user||''; 
    const pw=el('input'); pw.type='password'; pw.autocomplete='new-password'; pw.placeholder='A long password, at least 12 characters'; pw.value=ui.adminPw||'';
    const next=el('button','Next'); const need=el('p','','mut');
    const upd=()=>{ if(un.value!==un.value.toLowerCase()) un.value=un.value.toLowerCase();      // user names are lower-case
      ui.otpName=un.value; ui.adminPw=pw.value; const miss=[]; const nm=un.value.trim();
      if(!/^[a-z][a-z0-9_.-]{0,31}$/.test(nm)||nm==='root'||nm.startsWith('pazuzu-')) miss.push('a user name (lower-case letters and digits, not root)');
      if(pw.value.length<12) miss.push('a password of at least 12 characters');
      need.textContent=miss.length?'Still needed: '+miss.join('; ')+'.':''; next.disabled=miss.length>0; };
    un.oninput=upd; pw.oninput=upd; upd();
    next.onclick=()=>{ ui.credsOk=true; refresh().catch(fail); };
    // See it, and copy it, before it is used (a device-made password is long and easy to mistype).
    const eye=el('button','Show','quiet'); eye.type='button'; eye.setAttribute('aria-label','Show the password'); eye.dataset.pwEye='1';
    eye.onclick=()=>{ const show=pw.type==='password'; pw.type=show?'text':'password'; eye.textContent=show?'Hide':'Show'; eye.setAttribute('aria-label',show?'Hide the password':'Show the password'); };
    const cp=el('button','Copy','quiet'); cp.type='button'; cp.dataset.pwCopy='1';
    cp.onclick=async()=>{ try{ await navigator.clipboard.writeText(pw.value); cp.textContent='Copied'; setTimeout(()=>{ cp.textContent='Copy'; },1500); }catch(e){ cp.textContent='Copy it by hand'; } };
    const pwRow=el('div',undefined,'btnrow'); pwRow.append(pw, eye, cp);
    c.append(un, pwRow, need, next); return c;
  }
  if(!st.admin_user && !ui.otpOk){
    title(3,'Add a one-time code');
    const out=el('div'); const make=el('button', ui.phone ? 'Show the code on my Hanbi\u2019s screen' : 'Show my one-time code');
    make.onclick=async()=>{ $('err').textContent=''; make.disabled=true; let r; try{ r=await post('/api/otp/new',{account:(ui.otpName||'').trim()}); }catch(e){ make.disabled=false; fail(e); return; }
      ui.otp=r; make.remove(); renderOtp(out, r, otpOpts); };
    // BUILD 477: on the phone the code goes to the box's own screen (a phone cannot scan itself); the seed stays here
    // as the fallback. The screen drops it with the next step.
    const otpOpts={compact:true, onScreen: ui.phone, onMatch:()=>{ if(ui.phone) tellBox({step:8, of:ui.light?LIGHT_STEPS.length:4, title:'Your own admin sign-in', do:'Code checked. Carry on in the app.'}); refresh().catch(fail); }};
    if(ui.phone && ui.otp && !ui.otpShown){ ui.otpShown=true; tellBox({step:8, of:ui.light?LIGHT_STEPS.length:4, title:'Add a one-time code', do:'Scan this with your authenticator app, then type the 6-digit code it shows into the Pazuzu app.', qr: ui.otp.uri, qr_words:'Scan with your authenticator app'}); }
    if(ui.otp){ renderOtp(out, ui.otp, otpOpts); } else { c.append(make); }
    c.append(out); return c;
  }
  if(!st.admin_user){
    title(4,'Add '+(ui.otpName||'your user'));
    const gone=(j.kind==='write-user' && j.state==='failed' && /already one called/.test(j.error||''));
    if(gone){
      c.append(el('p',(ui.otpName||'That user')+' is already on the firewall (it was made on an earlier try). If it is the one you just made, use it: nothing is changed on the firewall.','mut'));
      const use=el('button','It is already there: use it');
      use.onclick=()=>act(use, async()=>{ await post('/api/admin/adopt',{name:(ui.otpName||'').trim()}); });
      c.append(use); return c;
    }
    c.append(el('p','Password set, one-time code checked. Your passkey approves it.','mut'));
    // The password is kept here until the user is made. If it is missing (the page was reloaded, or a try failed
    // on it), it is asked for right here, never left as a dead end.
    const pw=el('input'); pw.type='password'; pw.autocomplete='new-password'; pw.placeholder='Type the password again (at least 12 characters)'; pw.value=ui.adminPw||'';
    const go=el('button','Add this user, with passkey');
    const upd=()=>{ ui.adminPw=pw.value; go.disabled=!(g.ok && pw.value.length>=12); };
    pw.oninput=upd;
    if((ui.adminPw||'').length<12) c.append(el('p','The password is needed again.','mut'), pw);
    recheck(); upd();
    go.onclick=()=>act(go, async()=>{ await post('/api/write/admin',{name:(ui.otpName||'').trim(), password:ui.adminPw||'', otp_seed:(ui.otp&&ui.otp.seed)||''}); });
    c.append(go); return c;
  }
  if(!st.root_secured){
    // The one-time code only counts when the firewall has a login server for it AND the web page signs in with it.
    if((j.kind==='write-otp-server'||j.kind==='write-otp-switch') && j.state==='done' && !ui.otpSeen){ ui.otpSeen=true; ui.otpSrv=undefined; }
    if(ui.otpSrv===undefined){ ui.otpSrv=null;
      get('/api/otp-server').then(r=>{ ui.otpSrv=r; ui.otpAt=Date.now(); }).catch(()=>{ ui.otpSrv={can:false, why:'Could not ask the plugin just now.'}; ui.otpAt=Date.now(); }).then(()=>refresh().catch(fail)); }
    const os=ui.otpSrv;
    const nm=st.admin_user;
    const recheckSrv=(label)=>{ const b=el('button',label||'Check again','quiet'); b.onclick=()=>{ ui.otpSrv=undefined; refresh().catch(fail); }; return b; };
    const link=fwLink;
    if(os===null){
      title(5,'Looking at the firewall’s login servers'); c.append(el('p','One moment…','mut')); return c;
    }
    const there=!!(os.can && os.present) || !!ui.done.otphand;
    if(!there){
      title(5,'Add the sign-in server for codes');
      c.append(el('p','The user and the code seed are not enough on their own. The firewall also needs a login server of the type Local + Timebased One Time Password, and the web page has to sign in with it.','mut'));
      if(os.can){
        c.append(el('p','Your passkey approves it. The plugin adds one server called Pazuzu OTP, keeps a backup of the old settings, and Pazuzu reads it back. It does not change how the web page signs in.','mut'));
        const go=el('button','Add it, with passkey'); go.disabled=!g.ok;
        go.onclick=()=>act(go, async()=>{ ui.otpSeen=false; await post('/api/otp-server/change',{action:'add'}); });
        recheck(); c.append(go);
      } else {
        c.append(el('p',os.why||'','mut'));
        // "Look again" must visibly do something: say when the plugin was last asked, and what to do instead.
        if(os.beta2) c.append(el('p','When it is saved, press I added it by hand and carry on.','mut'));
        else c.append(el('p','Last looked at '+(ui.otpAt?new Date(ui.otpAt).toLocaleTimeString():'just now')+'. The app cannot see the server until the plugin answers. If you added it by hand, press I added it by hand and carry on.','mut'));
      }
      c.append(el('p', os.beta2 ? 'Add it by hand:' : 'Or add it by hand:','vt'));
      const ol=el('ol'); ['Open Servers and press the + button.','Descriptive name: Pazuzu OTP.','Type: Local + Timebased One Time Password.','Token length: 6. Leave Time window and Grace period empty.','Tick Reverse token order, so the password goes first and the code after it.','Save.'].forEach(t=>ol.append(el('li',t))); c.append(ol, link('Open Servers','/system_authservers.php'));
      const did=el('button','I added it by hand','quiet'); did.onclick=()=>{ ui.done.otphand=true; saveUi(); refresh().catch(fail); };
      if(os.beta2){ did.className=''; c.append(did); } else c.append(did, recheckSrv('Look again'));   // BUILD 519: nothing to look for again without a plugin
      return c;
    }
    const sw=(os.can && os.switch) ? os.switch : null;       // a plugin that switches the page itself, with its own timer
    if(sw && sw.state==='waiting'){
      title(7,'Sign in from a second window, then keep it');
      const left0=Math.max(0, (sw.seconds_left||0) - Math.floor((Date.now()-(ui.otpAt||Date.now()))/1000));
      const clock=(n)=>Math.floor(n/60)+':'+String(n%60).padStart(2,'0');
      const tl=el('p','The web page now asks for your password followed by the code. Time left: '+clock(left0)+'. If you do nothing, the firewall puts the old sign-in back by itself.','mut'); c.append(tl);
      const t0=Date.now(); const tick=setInterval(()=>{ if(!document.body.contains(tl)){ clearInterval(tick); return; } const n=Math.max(0,left0-Math.floor((Date.now()-t0)/1000)); tl.textContent='The web page now asks for your password followed by the code. Time left: '+clock(n)+'. If you do nothing, the firewall puts the old sign-in back by itself.'; },1000);
      const ol=el('ol'); ['Open a second window (a private window is fine) on the firewall\u2019s page.','Sign in as '+nm+'. In the Password field type your password first and then the 6-digit code from your phone, with nothing between (for example yourpassword123456).','Once you are in, come back here and press the button below. Keep this window open.'].forEach(t=>ol.append(el('li',t)));
      c.append(ol, link('Open the firewall page','/'), passwordRow());
      const keepB=el('button','It worked, keep it'); keepB.onclick=()=>act(keepB, async()=>{ ui.otpSeen=false; await post('/api/otp-switch/change',{action:'keep'}); });
      const backB=el('button','Put it back now','quiet'); backB.onclick=()=>act(backB, async()=>{ ui.otpSeen=false; await post('/api/otp-switch/change',{action:'undo'}); });
      c.append(keepB, backB);
      if(!ui.otpPoll){ ui.otpPoll=setTimeout(()=>{ ui.otpPoll=null; ui.otpSrv=undefined; refresh().catch(fail); }, 5000); }
      return c;
    }
    if(!ui.done.otptested && !sw){
      title(6,'Test the server before you use it');
      const ol=el('ol'); ['Open System, Access, Tester on the firewall.','Server: Pazuzu OTP. User name: '+nm+'.','In the Password field type your password first and then the 6-digit code from your phone, with nothing between (for example yourpassword123456).','Press Test. It should say it authenticated successfully.'].forEach(t=>ol.append(el('li',t)));
      c.append(ol);
      { const row=el('div',undefined,'btnrow'); row.append(link('Open the Tester','/diag_authentication.php')); c.append(row); }
      c.append(passwordRow());
      c.append(el('p','If it fails, wait for the next code and try once more. Do not go on until it passes.','mut'));
      const lab=el('label'); const cb=el('input'); cb.type='checkbox'; lab.append(cb, document.createTextNode(' The Tester said it authenticated.')); lab.className='tick';
      const go=el('button','Next'); go.disabled=true; cb.onchange=()=>{ go.disabled=!cb.checked; };
      go.onclick=()=>{ ui.done.otptested=true; saveUi(); refresh().catch(fail); };
      c.append(lab, go);
      if(os.can && os.present && !os.in_use){ const rm=el('button','Undo: remove the server I just added','quiet'); rm.disabled=!g.ok; rm.onclick=()=>act(rm, async()=>{ ui.otpSeen=false; ui.done.otphand=false; await post('/api/otp-server/change',{action:'remove'}); }); c.append(rm); }
      return c;
    }
    if(!(os.can && os.in_use) && !ui.done.otpswitched){
      if(sw){
        title(6,'Switch the web page to the code');
        c.append(el('p','Until you do this the firewall does not ask for the code at all. The plugin makes the switch, and the firewall puts the old sign-in back by itself after 5 minutes unless you keep it, so waiting cannot lock you out.','mut'));
        if(sw.state==='reverted') c.append(el('p','It was put back (you undid it, or the time ran out). Nothing is locked. Try again when you are ready.','mut'));
        const goB=el('button','Switch it, with passkey'); goB.disabled=!g.ok;
        goB.onclick=()=>act(goB, async()=>{ ui.otpSeen=false; await post('/api/otp-switch/change',{action:'on'}); });
        recheck(); c.append(goB, recheckSrv('Check again'));
        return c;
      }
      title(7,'Point the web page at it');
      c.append(el('p','Until you do this the firewall does not ask for the code at all.','mut'));
      const ol=el('ol'); ['Keep the window where you are signed in open the whole time.','Open System, Settings, Administration (the button), find Authentication, Server.','Choose Pazuzu OTP and save. Choose only that one: with Local Database ticked as well, a password alone may still get in.','In a second window sign in as '+nm+' with your password followed by the code. Root has no code, so expect the web page to refuse it.','Locked out anyway? The firewall’s own console menu has Restore a backup (option 13 on most versions, pick the copy from before) and Reset the root password (3).'].forEach(t=>ol.append(el('li',t)));
      c.append(ol, link('Open Administration','/system_advanced_admin.php'));
      if(os.can){
        c.append(el('p','Pazuzu reads the setting back, so this turns done by itself once the page uses Pazuzu OTP.','mut'), recheckSrv('Check again'));
      } else {
        const lab=el('label'); const cb=el('input'); cb.type='checkbox'; lab.append(cb, document.createTextNode(' I switched it and signed in from a second window with the code.'));
        const go=el('button','Next'); go.disabled=true; cb.onchange=()=>{ go.disabled=!cb.checked; };
        go.onclick=()=>{ ui.done.otpswitched=true; saveUi(); refresh().catch(fail); };
        c.append(lab, go);
      }
      return c;
    }
  }
  if(!st.root_secured && ui.phone){
    // BUILD 477: a Hanbi set up from the app has no second window and no keyboard console. The box vouches: your admin
    // has a login shell and admins may use sudo (both read, with a button for each when not), then root goes off.
    title(8,'Switch root off');
    c.append(el('p','Root is the factory account everyone knows. Once your own admin can do everything root could at the box, root goes off for the web page and SSH.','mut'));
    const facts=el('div'); c.append(facts);
    const go=el('button','Switch root off'); go.disabled=true;
    const draw=async()=>{ let f; try{ f=await get('/api/console/state'); }catch(e){ f={known:false}; }
      facts.replaceChildren();
      const row=(ok,text,btn)=>{ const r=el('div',undefined,'btnrow'); r.append(el('span',(ok?'\u2713 ':'\u2022 ')+text)); if(!ok && btn) r.append(btn); facts.append(r); };
      if(!f.known){ row(false,'Your admin could not be read from the firewall yet.'); }
      else {
        const sh=el('button','Give it a login shell','quiet'); sh.onclick=()=>act(sh, async()=>{ await post('/api/console/shell',{}); });
        row(!!f.real, f.real ? f.user+' can sign in at the box\u2019s console' : f.user+' cannot sign in at the box\u2019s console yet', sh);
        const su=el('button','Let admins use sudo','quiet'); su.onclick=()=>act(su, async()=>{ await post('/api/console/sudo',{action:'allow'}); });
        row(f.sudo===true, f.sudo===true ? 'admins may open the menu there (sudo)' : f.sudo===false ? 'admins may not open the menu there yet' : 'whether admins may use sudo could not be read', f.sudo===false && f.can_sudo_set ? su : null);
      }
      go.disabled=!(f.ok && g.ok); };
    go.onclick=()=>act(go, async()=>{ await post('/api/write/root-off',{keep:st.admin_user, proved:true, console:true}); });
    const again=el('button','Check again','quiet'); again.onclick=()=>draw().catch(fail);
    draw().catch(()=>{}); recheck(); c.append(bar('', again, go));
    const alt=el('details'); alt.dataset.rootPw='1'; alt.append(el('summary','Rather keep root, with a new password?'));
    alt.append(el('p','Root keeps working, but the factory password stops. Choose a long one and write it down: this app cannot read it back.','mut'));
    const p1=el('input'); p1.type='password'; p1.autocomplete='new-password'; p1.placeholder='A new root password, at least 12 characters';
    const p2=el('input'); p2.type='password'; p2.autocomplete='new-password'; p2.placeholder='Type it again';
    const rg=el('button','Change root\u2019s password'); rg.disabled=true;
    const upd=()=>{ rg.disabled=!(p1.value.length>=12 && p1.value===p2.value); }; p1.oninput=upd; p2.oninput=upd;
    rg.onclick=()=>act(rg, async()=>{ const a=p1.value, b=p2.value; p1.value=''; p2.value=''; await post('/api/write/root-password',{password:a, again:b}); });
    alt.append(p1, p2, rg); c.append(alt);
    return c;
  }
  if(!st.root_secured){
    title(8,'Switch root off');
    c.append(el('p','Open a second window and sign in as '+st.admin_user+' with its password followed by its code. Root then stops working on the web page and SSH, so keep the password and code safe.','mut'));
    c.append(passwordRow());
    const lab=el('label'); const cb=el('input'); cb.type='checkbox'; cb.checked=!!ui.proved; lab.append(cb, document.createTextNode(' I signed in from a second window, and it worked.')); lab.className='tick';
    // Root is the only one that can sign in at the console until this is proved: switching root off before it would lock the console.
    c.append(el('p','Then at the firewall\u2019s own screen and keyboard: sign in as '+st.admin_user+' and type  sudo opnsense-shell  for the menu. (Sudo has to be allowed: System, Settings, Administration, at the very bottom, sudo for admins asks for a password.)','mut'));
    const labC=el('label'); const cbC=el('input'); cbC.type='checkbox'; cbC.dataset.consoleProved='1'; cbC.checked=!!ui.consoleProved; labC.append(cbC, document.createTextNode(' I signed in at the console as '+st.admin_user+', and the menu opened.')); labC.className='tick';
    const go=el('button','Switch root off, with passkey'); const draw=()=>{ ui.proved=cb.checked; ui.consoleProved=cbC.checked; go.disabled=!(cb.checked && cbC.checked && g.ok); }; cb.onchange=draw; cbC.onchange=draw; draw();
    go.onclick=()=>act(go, async()=>{ await post('/api/write/root-off',{keep:st.admin_user, proved:cb.checked, console:cbC.checked}); });
    c.append(lab, labC); recheck(); c.append(go);
    // The other way to stop the factory password working: keep root, with a password of your own.
    const alt=el('details'); alt.dataset.rootPw='1'; alt.append(el('summary','Rather keep root, with a new password?'));
    alt.append(el('p','Root keeps working, but the factory password stops. Choose a long one and write it down: this app cannot read it back. Root with a new password is better than the factory one, but switching root off is safer.','mut'));
    const p1=el('input'); p1.type='password'; p1.autocomplete='new-password'; p1.placeholder='A new root password, at least 12 characters';
    const p2=el('input'); p2.type='password'; p2.autocomplete='new-password'; p2.placeholder='Type it again';
    const need=el('p','','mut'); const rg=el('button','Change root\u2019s password, with passkey');
    const upd=()=>{ const miss=[]; if(p1.value.length<12) miss.push('at least 12 characters'); else if(p1.value!==p2.value) miss.push('the same password twice'); need.textContent=miss.length?'Still needed: '+miss.join('; ')+'.':''; rg.disabled=!(miss.length===0 && g.ok); };
    p1.oninput=upd; p2.oninput=upd; upd();
    rg.onclick=()=>act(rg, async()=>{ const a=p1.value, b=p2.value; p1.value=''; p2.value=''; await post('/api/write/root-password',{password:a, again:b}); });
    alt.append(p1, p2, need, rg); c.append(alt);
    return c;
  }
  return null;
}

function countryCard(body, st){
  const cb=st.country_block; if(!cb) return;
  const fw=cb.on_firewall;
  // A country block made outside Pazuzu (its own GeoIP alias): shown as it is, never offered again or changed here.
  if(fw && !fw.ours && !(cb.saved && cb.saved.length)){
    const s=el('div',undefined,'card'); s.append(el('h2','Block countries'));
    s.append(el('p','✓ Your firewall already has a country list: '+fw.alias+(fw.codes.length?' ('+fw.codes.length+' countries)':'')+(fw.enabled?'':', switched off')+'. Pazuzu leaves it as it is.','mut'));
    body.append(s); return;
  }
  // Pazuzu's own list already on the firewall (set up from another device): show it, with change and remove.
  if(fw && fw.ours && !(cb.saved && cb.saved.length)) cb.saved=fw.codes;
  if(!ui.cc) ui.cc={sel:new Set(cb.saved||[]), q:''};
  const editing=!!(cb.saved && cb.saved.length) || !!(fw && fw.ours);
  if(editing && !ui.ccOpen){
    const s=el('div',undefined,'card'); s.append(el('h2','Block countries'));
    const names=new Map(cb.countries.map(x=>[x.code,x.name]));
    s.append(el('p',(cb.saved.length?cb.saved.length+' blocked: '+cb.saved.map(c=>names.get(c)||c).join(', ')+'.':'On your firewall ('+(fw?fw.alias:'')+'), list not read.'),'mut'));
    const gg=writeGate(st,'geo_alias'), gg2=writeGate(st,'fw_rule');
    const ch=el('button','Change the list','quiet'); ch.onclick=()=>{ ui.ccOpen=true; ui.cc={sel:new Set(cb.saved), q:''}; refresh(); };
    const rm=el('button','Remove the country block','quiet'); rm.disabled=!(gg.ok&&gg2.ok);
    rm.onclick=()=>act(rm, async()=>{ await post('/api/write/country-block/remove',{}); ui.ccOpen=false; ui.cc=null; });
    s.append(ch, rm); if(!(gg.ok&&gg2.ok)) s.append(el('p',gg.ok?gg2.why:gg.why,'mut'));
    body.append(s); return;
  }
  const g=writeGate(st,'geo_alias'), g2=writeGate(st,'fw_rule');
  const c=el('div',undefined,'card'); const list=el('div',undefined,'scroll'); const note=el('p',undefined,'mut');
  c.append(el('h2','Block countries'));
  cb.says.forEach(t=>c.append(el('p',t,'mut')));
  c.append(means('visitors from the countries you tick cannot start a connection to your home. Things you start yourself, like browsing, still work.'));
  const q=el('input'); q.type='text'; q.autocomplete='off'; q.placeholder='Find a country'; q.value=ui.cc.q;
  const go=el('button',editing?'Save the change':'Add the country block to the firewall');
  const paintList=()=>{ list.replaceChildren(); const w=ui.cc.q.trim().toLowerCase();
    cb.countries.filter(x=>!w||x.name.toLowerCase().includes(w)||x.code.toLowerCase()===w).forEach(x=>{
      const l=el('label',undefined,'opt '+(ui.cc.sel.has(x.code)?'sel':'')); const k=el('input'); k.type='checkbox'; k.checked=ui.cc.sel.has(x.code);
      k.onchange=()=>{ if(k.checked) ui.cc.sel.add(x.code); else ui.cc.sel.delete(x.code); l.className='opt '+(k.checked?'sel':''); count(); };
      l.append(k, el('div',x.name+' ('+x.code+')','vt')); list.append(l); }); };
  const count=()=>{ const n=ui.cc.sel.size; note.textContent=(n?n+' picked: '+Array.from(ui.cc.sel).sort().join(', '):'None picked yet.')+(cb.home&&ui.cc.sel.has(cb.home.code)?' Your own country ('+cb.home.code+') is ticked, so visitors from it will be blocked too.':''); go.disabled=!(n&&g.ok&&g2.ok); };
  q.oninput=()=>{ ui.cc.q=q.value; paintList(); };
  go.onclick=()=>act(go, async()=>{ await post(editing?'/api/write/country-block/change':'/api/write/country-block',{countries:Array.from(ui.cc.sel)}); ui.ccOpen=false; ui.cc=null; });
  if(cb.home){
    const only=el('button','Block everyone except '+cb.home.name+' ('+cb.home.code+')','quiet');
    only.onclick=()=>{ ui.cc.sel=new Set(cb.countries.map(x=>x.code).filter(x=>x!==cb.home.code)); paintList(); count(); };
    c.append(el('p','This device says you are in '+cb.home.name+'. If that is wrong, pick the countries by hand below. Replies to things you start yourself still come back in. Only unasked visitors from other countries are stopped.','mut'), only);
  }
  c.append(q, list, note);
  if(!(g.ok&&g2.ok)) c.append(el('p',g.ok?g2.why:g.why,'mut'));
  c.append(go); paintList(); count(); body.append(c);
}

function gatewayCard(st){
  const c=el('div',undefined,'card'); c.append(el('h2','Backup internet: add a gateway by hand'));
  c.append(el('p','For a second connection that is a router with a fixed address on its own port (a 4G router, say). A phone by USB or a router that hands out its address by DHCP makes its own gateway, so you do not need this: the manager checks that one step by step. Your passkey approves it, Pazuzu reads it back, and you can undo it right after.','mut'));
  const g=writeGate(st,'gateway');
  const f=ui.gw=ui.gw||{name:'BACKUP_GW',interface:'',gateway:'',priority:'255',monitor:''};
  const inp=(label,key,ph)=>{ const w=el('div'); w.append(el('div',label,'vt')); const i=el('input'); i.type='text'; i.autocomplete='off'; i.placeholder=ph; i.value=f[key]; i.oninput=()=>{ f[key]=i.value; }; w.append(i); return w; };
  c.append(inp('Name','name','BACKUP_GW'), inp('Its port on the firewall (its short name, like opt1)','interface','opt1'), inp('The second router\u2019s address','gateway','192.168.8.1'),
    inp('Priority (the lower number is used first; the main internet is usually 255 or less, so give the backup a higher one)','priority','255'), inp('An address to ping to see if it works (optional)','monitor','9.9.9.9'));
  if(!g.ok) c.append(el('p',g.why,'mut'));
  const go=el('button','Add the gateway'); go.disabled=!g.ok;
  go.onclick=()=>act(go, async()=>{ await post('/api/write/gateway',{name:f.name, interface:f.interface, gateway:f.gateway, priority:f.priority, monitor:f.monitor}); });
  c.append(go); return c;
}

function finderPanel(tried, opts){
  opts=opts||{};
  const c=el('div');
  c.append(el('p','Not the right firewall? Pazuzu can look for it on the network this device is on. It only looks; it sends no password.','mut'));
  const out=el('div'); const go=el('button','Find my firewall','quiet');
  const addr=el('input'); addr.type='text'; addr.autocomplete='off'; addr.placeholder='Or type its address, like 192.168.1.1';
  const run=async(auto)=>{
    if(auto!==true) $('err').textContent=''; go.disabled=true; out.replaceChildren(busyCard('Looking on this network…'));
    let r; try{ r=await post('/api/find',{address:addr.value.trim()||null}); }catch(e){ out.replaceChildren(); go.disabled=false; fail(e); return; }
    go.disabled=false; out.replaceChildren(); showFound(r);
  };
  const showFound=(r)=>{
    if(r.found.length>1) out.append(el('p', r.found.length+' firewalls answered. Pick the one you want to set up. The certificate name and the start of its fingerprint tell them apart; the keys in this folder belong to one of them at most.','mut'));
    r.found.forEach(f=>{ const row=el('div',undefined,'card'); row.append(el('div',f.url,'vt mono'), el('p','Looks like OPNsense · found via '+f.via,'mut'));
      const who=[]; if(f.cert_name) who.push('certificate name '+f.cert_name); if(f.fingerprint_start) who.push('certificate starts '+f.fingerprint_start);
      if(who.length) row.append(el('p',who.join(' · '),'mut'));
      if(f.keys_here) row.append(el('p','The keys in this key folder were made on this firewall.','mut'));
      if(opts.keysAt && f.host!==opts.keysAt){
        row.append(el('p','The keys in this key folder belong to the firewall at '+opts.keysAt+', and keys only work on the firewall that made them. To use this one, set the old keys aside with the button below, then press Find my firewall again.','mut'));
      } else if(opts.keysAt){
        const again=el('button','It answers now, look again'); again.onclick=()=>act(again, async()=>{ await post('/api/keys/check',{}); }); row.append(again);
      } else {
        const use=el('button','Use this one'); use.onclick=()=>act(use, async()=>{ await post('/api/find/use',{url:f.url}); }); row.append(use);
      }
      out.append(row); });
    if(!r.found.length) out.append(el('p', r.note || 'Nothing answered.', 'mut'));
    if(r.wifi && r.wifi.length){ const w=el('div',undefined,'card'); w.append(el('div','Hanbi signal nearby','vt'));
      r.wifi.forEach(x=>w.append(el('p', x.name+(x.signal?' · '+x.signal+'%':''),'mut')));
      w.append(el('p','Join it in your Wi-Fi settings, then press Find my firewall again.','mut')); out.append(w); }
  };
  const hard=el('button','Search harder','quiet');
  hard.onclick=async()=>{
    $('err').textContent=''; const a=addr.value.trim()||tried; if(!a){ fail(new Error('Type the firewall\u2019s address first.')); return; }
    hard.disabled=true; go.disabled=true; out.replaceChildren(busyCard('Looking at every port on '+a+'. This takes a minute or two…'));
    let r; try{ r=await post('/api/find/harder',{address:a}); }catch(e){ out.replaceChildren(); hard.disabled=false; go.disabled=false; fail(e); return; }
    hard.disabled=false; go.disabled=false; out.replaceChildren(); showFound(r);
  };
  go.onclick=run; c.append(addr, el('div',' '), go, ' ', hard, el('p','Search harder looks at every port on that one address, for a firewall whose page was moved somewhere unusual. It only reads, and takes a minute or two.','mut'), out);
  ui.autoFound=ui.autoFound||{};
  if(!ui.autoFound[tried]){ ui.autoFound[tried]=true; setTimeout(()=>run(true),0); }
  return c;
}

function silentFirewallStep(body, st){
  const where = (st.firewall||'the firewall');
  body.append(head(1,'Nothing answered at '+where,'Pazuzu has saved keys for that firewall, so it stopped here instead of waiting on a firewall that is not there.'));
  const c=el('div',undefined,'card');
  c.append(el('p','The keys in this key folder were made on the firewall at '+where+'. It did not answer just now. It may be off, still starting, on another cable, or this device may be on a different network than it. Nothing was changed.','mut'));
  if(st.keys_note) c.append(el('p',st.keys_note,'mut'));
  const again=el('button','Look again'); again.onclick=()=>act(again, async()=>{ await post('/api/keys/check',{}); });
  c.append(again); body.append(c);
  const f=el('div',undefined,'card'); f.append(el('h2','Or pick a different firewall'), finderPanel('silent:'+where, {keysAt: where})); body.append(f);
  const k=el('div',undefined,'card'); k.append(el('h2','Starting over with another firewall'),
    el('p','Keys only work on the firewall that made them. To set up a different one here, the old keys are moved into a dated folder beside them (nothing is deleted), and you sign in to the other firewall from the start.','mut'));
  const b=el('button','Set the old keys aside and start again','quiet');
  b.onclick=()=>act(b, async()=>{ await post('/api/keys/aside',{}); ui.mode=null; ui.force=null; ui.autoFound={}; saveUi(); });
  k.append(b); body.append(k);
}

function staleKeysStep(body, st){
  body.append(head(1,'This firewall does not know your saved keys','The keys on this device were made for a firewall that has since been reset or replaced.'));
  const c=el('div',undefined,'card');
  c.append(el('p','Pazuzu made these keys the last time. The firewall you are connected to now refused them, which usually means it was reset (a live CD, a re-install) or it is a different firewall. Nothing is deleted: the old keys are moved into a dated folder beside them, then you find and sign in to your firewall again. Your passkey stays.','mut'));
  if(st && st.keys_note) c.append(el('p','What answered: '+st.keys_note,'mut'));
  const again=el('button','Look again','quiet'); again.onclick=()=>act(again, async()=>{ await post('/api/keys/check',{}); });
  c.append(again);
  const b=el('button','Set the old keys aside and start again');
  b.onclick=()=>act(b, async()=>{ await post('/api/keys/aside',{}); ui.mode=null; ui.force=null; ui.autoFound={}; saveUi(); });
  c.append(b); body.append(c);
}

function forkStep(body){
  body.append(head(1,'Is this firewall new, or already running?','This decides how careful we are.'));
  const row=el('div',undefined,'row');
  const mk=(title,txt,mode)=>{ const c=el('div',undefined,'card'); c.append(el('h2',title), el('p',txt,'mut')); const b=el('button','This one'); b.onclick=async()=>{ ui.mode=mode; ui.useDefault=(mode!=='audit'); saveUi(); try{ await post('/api/mode',{mode:mode}); }catch(e){ fail(e); return; } refresh().catch(fail); }; c.append(b); return c; };
  row.append(mk('New / Testing','Fresh from the box or just installed. We set it up from the start, the quick way: one sign-in, no passkey, and each change tests itself and undoes itself if it fails.','new'),
             mk('Running','You use it today. We look first, and never change a rule of yours without your approval.','audit'),
             mk('Just trying it','Running from the live CD. Nothing is saved when it restarts, so this is a test flight. Same quick way, no passkey.','trial'));
  body.append(row);
}

// BUILD 497: the beta 1 terms, word for word. The tick is stored with TERMS_VERSION.
const BETA_TERMS_TITLE='PAZUZU BETA TERMS \u2014 version 2026-11-18';
const BETA_TERMS_LEAD='By ticking "I accept these terms" you agree to the following with Hanbi LLC, a Kansas limited liability company ("we").';
const BETA_TERMS=[
  ['1. This is a beta.','Pazuzu is free, unfinished test software that changes your firewall. It can lock you out of the firewall, cut your internet, stop devices working, or show protection as on when it is not. Use it only if you can recover from that.'],
  ['2. No warranty.','To the fullest extent the law allows, Pazuzu is provided as is, with no promise of any kind, including that it is secure, fits your purpose or is free of errors.'],
  ['3. You stay in charge.','You are responsible for your firewall, your network and every change made on it. Before you start, back up your firewall\u2019s configuration and keep a way back in.'],
  ['4. Who may use it.','You must be 18 or older, and you may use Pazuzu only on firewalls you own or are authorised to run.'],
  ['5. Limit of liability.','To the fullest extent the law allows, we are not liable for indirect or consequential loss, such as downtime, lost data or lost profits, and our total liability for anything to do with Pazuzu is limited to US$50.'],
  ['6. Passwords and keys.','Pazuzu asks for your firewall\u2019s admin password once, to create its own accounts on the firewall, and does not save it. The keys for those accounts stay on your firewall, or with the Windows wizard on your PC in storage protected from other users; the phone apps keep none. Your passkey is your device\u2019s own: its system keeps it and may sync it to your other devices, and the firewall keeps only the public half. Keys you enter for your own services, such as a dynamic DNS provider, are stored on your firewall.'],
  ['7. Your data.','Nothing leaves this device unless you switch a sharing option on above or press Send report. If you installed a test build through TestFlight or Google Play, Apple or Google also collect crash and usage data under their own terms. The privacy notice at hanbi.net/privacy explains both, how long reports are kept and how to have them deleted.'],
  ['8. Other people\u2019s products.','OPNsense (Deciso B.V.), Zenarmor (Sunny Valley Networks), block lists and open-source parts belong to their owners and come under their own licences and terms. Pazuzu is made for OPNsense but is not part of it, and is not endorsed by Deciso or Sunny Valley Networks.'],
  ['9. Licences.','The wizard is open source under the Apache License 2.0, included with it; that licence governs copying and sharing its code. The Pazuzu apps, the plugin and the manager are not open source. They remain ours, and you may not copy, resell, redistribute or reverse-engineer them.'],
  ['10. Changes and paid features.','We may update these terms. You will be asked to accept the new version before continuing. Some features, including the plugin and KidsNet, are free during the beta and will become paid. We will tell you before that happens, paid features will come with their own terms, and nothing will be charged without your agreement.'],
  ['11. Ending.','You may stop using Pazuzu at any time, and we may end the beta at any time.'],
  ['12. Law.','Kansas law governs these terms. Disputes go to the state courts in Johnson County, Kansas, or the federal court for the District of Kansas.']];
function termsInto(tsc){ tsc.append(el('p',BETA_TERMS_TITLE,'vt'), el('p',BETA_TERMS_LEAD,'mut'));
  BETA_TERMS.forEach(([t,b])=>{ const p=el('p',undefined,'mut'); p.append(el('strong',t), document.createTextNode(' '+b)); tsc.append(p); }); }
function legalStep(body, st){
  // Shown before anything on the firewall: accept the terms, and choose what (if anything) may be sent later.
  const brand = ui.platform==='hanbi' ? 'Hanbi' : 'Pazuzu';
  if(ui.legal&&ui.legal.consent) for(const k in ui.legal.consent) if(ui.legal.consent[k]) ui.consent[k]=true;   // switches answered before stay as answered
  body.append(el('h1','Welcome to '+brand), el('p',ui.legal&&ui.legal.terms ? 'A new switch to answer before we go on.' : 'Two quick things before we set up your firewall.','sub'));
  // BUILD 484 (the maintainer, 5 Nov 2026: "step 1 screen mirror selections"): the box's screen shows this page too, each switch
  // on or off and the terms, and follows every tap.
  const WELCOME_SHORT={versions:'Versions you run', checks:'How the checks come out', problems:'Reports when something breaks', devices:'What smart devices needed'};
  const tellWelcome=()=>{ const steps=Object.keys(WELCOME_SHORT).map(k=>[WELCOME_SHORT[k]+': '+(ui.consent[k]?'on':'off'), ui.consent[k]?'done':'todo']);
    steps.push(['Accept the terms', ui.terms?'done':'now']);
    tellBox({step:1, of:ui.light?LIGHT_STEPS.length:4, title:'Welcome to '+brand, do:'On your phone: choose what may be sent, then accept the terms.', steps:stepList(steps)}); };
  const ch=el('div',undefined,'card'); ch.append(el('h2','Help us make this better'));
  ch.append(el('p','Each switch below is yours to turn on, and each is off until you do. Nothing leaves this device unless you press Send. A switch that is on only lets Pazuzu write that kind of report here, for you to look at and send from the manager\u2019s Reports page. Your choice is kept here and nothing else.','mut'));
  [['versions','Tell us which versions you run','Your Pazuzu, plugin and firewall versions, whether it is a Hanbi box, and the class of hardware (cores, memory, ports, Wi-Fi, Bluetooth, virtual). No addresses, names or settings.'],
   ['checks','Tell us how the checks come out','Only pass or fail for each check, with no details.'],
   ['problems','Send a report when something breaks','An error code and the step it happened on. Never passwords, keys or rules.'],
   ['devices','Tell us what your smart devices needed','The maker and the port, so the next person\u2019s lights work on day one. Never which devices you have or their addresses.']].forEach(([k,t,d])=>{
    const l=el('label'); l.style.display='block'; l.style.margin='10px 0'; const cb=el('input'); cb.type='checkbox'; cb.checked=!!ui.consent[k];
    cb.onchange=()=>{ ui.consent[k]=cb.checked; tellWelcome(); };
    l.append(cb, document.createTextNode(' '+t)); const dd=el('div',d,'mut'); dd.style.marginLeft='24px'; ch.append(l,dd);
  });
  ch.append(el('p','You are only asked this once.','mut'));
  body.append(ch);
  const by=el('div',undefined,'card'); by.append(el('h2','Before you start'));                 // BUILD 494
  by.append(el('p','Pazuzu will change your firewall. First:','mut'));        // BUILD 530: the final wording
  const bu=el('ul');
  ['Save a backup of its configuration somewhere other than the firewall (OPNsense: System \u203a Configuration \u203a Backups).',
   'Make sure you can get back in without Pazuzu: know the admin password, and have a computer and cable you could plug into the firewall.',
   'Pick a time when losing internet for a while won\u2019t hurt.'].forEach(t=>bu.append(el('li',t)));
  by.append(bu); body.append(by);
  const tm=el('div',undefined,'card'); tm.append(el('h2','Terms'));
  const tsc=el('div',undefined,'scroll'); termsInto(tsc);

  tm.append(tsc);
  const tl=el('label'); const tcb=el('input'); tcb.type='checkbox'; tcb.checked=!!ui.terms; tl.append(tcb, document.createTextNode(' I accept these terms')); tm.append(tl);
  body.append(tm);
  const go=el('button','Agree and start'); go.disabled=!ui.terms;
  tcb.onchange=()=>{ ui.terms=tcb.checked; go.disabled=!ui.terms; tellWelcome(); };
  tellWelcome();
  go.onclick=()=>act(go, async()=>{ await post('/api/legal',{terms:true, consent: ui.consent}); });
  body.append(bar(ui.terms?'':'Accept the terms to start.', go));
  body.append(creditsCard());
}
// BUILD 532: the credit wording, on the Welcome page and the last page. The block list and
// rule lines are what this wizard offers or switches on (blocklist_choices, shield_levels, ids_rulesets).
const CREDIT_LISTS=[['HaGeZi','github.com/hagezi/dns-blocklists'],['Steven Black','github.com/StevenBlack/hosts'],['OISD','oisd.nl'],
  ['r0xd4n3t (Pi-hole lists, a list of lists)','github.com/r0xd4n3t/pihole-adlists'],
  ['The ad lists your firewall offers itself, which Pazuzu switches on by name: AdAway, AdGuard, EasyList and Peter Lowe\u2019s list','']];
function creditsCard(){
  const d=el('details',undefined,'card'); d.dataset.credits='1'; d.append(el('summary','Credits and licences'));
  d.append(el('p','Pazuzu stands on other people\u2019s work. Thank you to:','mut'));
  const a=el('ul'); ['Python, by the Python Software Foundation (PSF License)','requests, and the libraries it uses (urllib3, idna, charset-normalizer, certifi)',
    'cryptography, by the Python Cryptographic Authority','the block list authors, credited below'].forEach(t=>a.append(el('li',t))); d.append(a);
  d.append(el('p','Each part keeps its own licence; the full texts ship with Pazuzu in THIRD-PARTY-LICENSES.','mut'));
  d.append(el('h2','Block lists'), el('p','Pazuzu does not copy or change any block list. It tells your firewall where each list lives, and your firewall downloads it directly from its author. The lists are the work of:','mut'));
  const b=el('ul'); CREDIT_LISTS.forEach(([who,where])=>b.append(el('li', who+(where?' \u2014 '+where:'')))); d.append(b);
  d.append(el('p','If a list blocks something it shouldn\u2019t, please tell its author.','mut'));
  d.append(el('h2','Packet inspection rules'), el('p','When packet inspection is switched on, your firewall downloads its rules from their authors through its own Intrusion Detection pages: the abuse.ch lists, and the Emerging Threats Open rules. Pazuzu copies none of them.','mut'));
  d.append(el('h2','OPNsense and Zenarmor'), el('p','Pazuzu is an independent tool for OPNsense. OPNsense is a trademark of Deciso B.V.; Pazuzu is not part of the OPNsense project and is not endorsed by Deciso. Zenarmor is a product of Sunny Valley Networks, under its own terms; Pazuzu is not affiliated with or endorsed by Sunny Valley Networks.','mut'));
  return d;
}

function consoleHelp(){
  const d=el('details',undefined,'card'); d.append(el('summary','Check it from the firewall\u2019s own screen'));
  const ol=el('ol'); [
    'Look under the logo on the firewall\u2019s screen. The WAN line should show an address (v4/DHCP4). If it shows none, the cable, the modem or the port is the problem.',
    'Ports mixed up? Press 1 (Assign interfaces). Unplug one cable to see which port it is, then give LAN and WAN the right ports.',
    'WAN has no address? Press 2 (Set interface IP address), choose WAN, answer yes to DHCP for IPv4 and no for IPv6.',
    'LAN has no address? Press 2 again, choose LAN and give it one, for example 192.168.1.1 with 24. Say yes to the DHCP server for it.',
    'Press 7 (Ping host) and try 9.9.9.9. When replies come back, press Check again here.',
    'To run a command on the firewall: press 8 (Shell), then type sh, then type or paste the command.'].forEach(t=>ol.append(el('li',t)));
  d.append(ol); return d;
}
async function firmwareStep(body, st, job){
  body.append(head(1,'Is your firewall up to date?','A new firewall is often a version behind, so it is best updated now.'));   // BUILD 483 (the maintainer, 5 Nov): the card says whether this update restarts it
  const busy=busyCard('Asking the firewall…'); body.append(busy);
  let f; try{ f=await get('/api/firmware'); }catch(e){ fail(e); f={state:'unknown',detail:'Could not read it.'}; }
  busy.remove();
  // What the firewall "last found" may be nothing at all (a new one has never looked) or old. Ask it once to look now.
  fwRecheckAfter(job);
  if(f && (f.state==='current'||f.state==='unchecked') && !f.offline && f.version && !ui.fwAuto){ ui.fwAuto=true; try{ await post('/api/firmware/check',{}); }catch(e){} return refresh(); }
  const c=el('div',undefined,'card');
  // BUILD 440: the version in brackets was the one it is ON, which read as the one waiting ("An update is available
  // (version 26.7.8_1)" while 26.7.8_2 waited). Say both.
  const ver=f.version?' (version '+f.version+')':'';
  const waitWords=f.new_version ? f.new_version+' waiting' : (f.waiting ? f.waiting+' update'+(f.waiting>1?'s':'')+' waiting' : 'an update waiting');
  const justChecked=!!(job && job.kind==='firmware-check' && job.state==='done' && job.result && job.result.checked);
  c.append(el('h2', f.offline ? (f.version ? 'Version '+f.version+' (can\u2019t check for newer: no internet)' : 'No internet link right now') : f.state==='current' ? 'Up to date'+ver : f.state==='update' ? (f.version ? 'You\u2019re on '+f.version+' \u00b7 ' : '')+waitWords+(f.size ? ' ('+f.size+')' : '') : f.state==='unchecked' ? 'Not checked yet'+ver : 'We couldn’t tell'));
  if(f.detail && f.state!=='unchecked'){ const sc=el('div',undefined,'scroll'); sc.append(el('p',f.detail,'mut')); c.append(sc); }
  c.append(el('p', justChecked ? 'The firewall has just looked for updates.' : f.state==='unchecked' ? 'The firewall has not looked for updates yet. Press Look for updates.' : 'This is what the firewall last found. Press Look for updates to make it look again.','mut'));
  firmwareActions(c, f, job);
  body.append(c);
  body.append(clockCard());
  if(f.offline||f.state==='unknown') body.append(consoleHelp());
  if(f.state!=='current' && f.state!=='unchecked' && !f.offline){
    body.append(handoff('firmware',{title:'Update it first', steps:[
      'Open the firewall’s Firmware page (the button).',
      'Press Check for updates, then Update. It may restart once. Wait for it to come back.',
      'Come back here and press Check again.'], link:'/ui/core/firmware', linkLabel:'Open Firmware'}));
  }
  const again=el('button','Check again','quiet'); again.onclick=()=>refresh().catch(fail);
  if(mustUpdate(f, st)){ body.append(updateGate()); body.append(bar('The firewall has an update waiting. Update it first: the steps after this stay locked until it is done.', again)); return; }
  const next=el('button', f.state==='current' ? 'Continue' : 'Continue anyway', f.state==='current'?'':'quiet');
  next.onclick=()=>mark('firmware', f.state==='current'?'done':'skip');
  body.append(bar(f.state==='current' ? 'Nothing to update.' : 'You can update later, but a new firewall is best updated first.', again, next));
}

// A Copy button for a line the person has to paste somewhere else. It says "Copied" so they know it worked.
// A button that opens a page on the firewall itself in a new tab (the firewall's own address, never typed by hand).
/* BUILD 476: a button to one of the firewall's own pages. On the phone (a Hanbi set up from the app) these are not shown:
   each is a by-hand fallback for something the wizard does itself there, and a stranger should never land on OPNsense's
   page mid-setup (its self-signed warning, its root sign-in). The hidden span keeps the callers' append() happy. */
function fwLink(text, path){ if(ui.phone){ const s=el('span'); s.hidden=true; return s; }
  const a=el('a',text,'btn'); a.href=(ui.base||'')+path; a.target='_blank'; a.rel='noopener'; return a; }
function copyButton(text, label){
  const b=el('button',label||'Copy','quiet'); b.dataset.copy='1';
  b.onclick=async()=>{
    let ok=false;
    try{ await navigator.clipboard.writeText(text); ok=true; }catch(e){
      try{ const t=document.createElement('textarea'); t.value=text; t.style.position='fixed'; t.style.opacity='0'; document.body.append(t); t.select(); ok=document.execCommand('copy'); t.remove(); }catch(e2){ ok=false; }
    }
    b.textContent=ok?'Copied':'Select it and copy it'; setTimeout(()=>{ b.textContent=label||'Copy'; },2500);
  };
  return b;
}
function pluginCard(bs, title){
  // BUILD 552 (the maintainer, 17 Nov 2026: "correct"): the same words as the app for the same step, "Put Pazuzu on this firewall";
  // once it is on, the heading says that instead. "Hanbi" only on a Hanbi box.
  const pc=el('div',undefined,'card'); pc.dataset.way='1'; pc.append(el('h2', bs.connected ? title.replace('Put Pazuzu on this firewall', ui.platform==='hanbi' ? 'Hanbi\u2019s software' : 'Pazuzu is on this firewall') : title));
  if(bs.connected){
    pc.append(el('p', (ui.platform==='hanbi' ? 'Hanbi’s software is already aboard' : 'Connected. The plugin is on the firewall')
      + (bs.version ? ': version '+bs.version+'.' : '.'),'mut'));   // BUILD 483: which version, said
    if(bs.ssh_seen && !ui.phone){   // BUILD 557 (the maintainer, 17 Nov 2026: "show the cert more plainly?")
      const k=bs.ssh_seen, kc=el('div',undefined,'card'); kc.dataset.sshSeen='1';
      kc.append(el('h3','Who answered Secure Shell'),
        el('p',(k.name?k.name+' · ':'')+(k.state==='same'?'the same key as last time':'the first time this device has seen its key')+'.'),
        el('div',k.key,'fp mono'),
        el('p',(k.state==='same'?'It matches what this device kept from the last install. ':'There was nothing to check a first key against, so it was trusted and is kept for next time. ')+'To check it yourself: the firewall\u2019s own console shows its Secure Shell fingerprints (the lines that start \u201cSSH:\u201d). Secure Shell is off again.','mut'));
      pc.append(kc); }
    if(bs.page && !ui.phone){
      const pa=el('a','Open the plugin’s own page','btn'); pa.href=bs.page; pa.target='_blank'; pa.rel='noopener'; pa.dataset.pluginPage='1';
      pc.append(fold('the plugin’s own page', pa,
        el('p','Its live numbers, laid out for a touch screen. Open it, press F11 for full screen, and bookmark it. The address carries the code after the # sign, which the browser keeps to itself; anyone who can read your bookmarks can read it.','mut')));
    }
  }
  else if(ui.phone){
    // BUILD 480: on a Hanbi the plugin is the box itself; a moment without the link is the link starting, never a line
    // to paste (the sim saw "Show me the line" flash for 3 s on the phone)
    pc.append(el('p','Connecting to your Hanbi\u2026 this page updates by itself.','mut'));
  }
  else{
    // BUILD 550 (the maintainer, 17 Nov 2026: "in that order all three"): 1. a plugin already on the firewall is said, and the line
    // goes under a fold; 2. the line comes first and the help for a line that ran and never connected comes after it;
    // 3. the buttons and the fold each get their own row.
    let into=pc;
    if(bs.aboard){
      const ab=bs.aboard;
      pc.dataset.aboard='1';
      pc.append(el('p','A plugin is already on this firewall: version '+ab.version+'.'+(ab.enrolled ? ' It was set up from the Pazuzu app, and a phone holds its key.' : '')));
      pc.append(el('p','This device is not linked to it, and does not need to be. Carry on without the plugin below: the setup works over the firewall\u2019s own API, and the plugin stays as it is for the app.','mut'));
      const dt=document.createElement('details'); dt.dataset.linkToo='1'; dt.open=!!bs.command||!!ui.linkToo; dt.addEventListener('toggle',()=>{ ui.linkToo=dt.open; }); { const sm=el('summary','Link this device to it as well'); sm.addEventListener('click',()=>{ ui.linkToo=!dt.open; }); dt.append(sm); }   // the click is noted at once: the page may be drawn again before 'toggle' comes
      dt.append(el('p','The line below puts this device\u2019s copy of the plugin'+(ab.ours ? ' (version '+ab.ours+')' : '')+' in place of the one aboard'+((ab.ours && ab.ours!==ab.version) ? ', which is version '+ab.version : '')+', and gives this device its own link. The phone\u2019s sign-in stays. From then on the firewall also takes plugin updates from this device.','mut'));
      pc.append(dt); into=dt;
    }
    pluginLine(into, bs);
  }
  return pc;
}
// BUILD 551: the firewall's root password puts the plugin on, as the Pazuzu app does it. The line is the other way.
function pluginRoot(pc, bs){
  const d=el('div'); d.dataset.rootInstall='1';
  d.append(el('p','Type the firewall\u2019s root password, the one set when OPNsense was installed, and Pazuzu is put on for you. Nothing to type at the firewall.'));
  const ol=el('ol'); ['Signs in to the firewall as root.','Switches Secure Shell on for a moment, on your home network only.','Sends the plugin from this device, installs it and starts it.','Puts Secure Shell back as it was, and reads the setting back to make sure.'].forEach(t=>ol.append(el('li',t,'mut'))); d.append(ol);
  const pw=el('input'); pw.type='password'; pw.autocomplete='off'; pw.maxLength=256; pw.placeholder='The firewall\u2019s root password'; pw.dataset.rootPw='1';
  const go=el('button','Put Pazuzu on this firewall'); go.dataset.rootGo='1';
  // BUILD 557: after "this is not the Secure Shell key ... last time", the person can say the firewall was reinstalled
  let again=null;
  if(/not the Secure Shell key/.test(ui.jobErr||'')){ const lb=el('label'); lb.style.display='block'; lb.style.margin='8px 0'; again=el('input'); again.type='checkbox'; again.dataset.rootReinstalled='1';
    lb.append(again, document.createTextNode(' It was reinstalled or reset: take its new Secure Shell key')); d.append(lb); }
  go.onclick=async()=>{ const p=pw.value; if(!p){ pw.focus(); return; } pw.value=''; go.disabled=true; try{ await post('/api/box/root-install',{password:p, reinstalled:!!(again&&again.checked)}); }catch(e){ fail(e); } await refresh(); };
  pw.addEventListener('keydown',e=>{ if(e.key==='Enter') go.click(); });
  const row=el('div',undefined,'btnrow'); row.append(pw, go); d.append(row);
  d.append(el('p','The password is used for this once and is never kept. The plugin is checked against its fingerprint before it runs; this first install trusts this device, and later updates are only taken if they are signed.','mut'));
  pc.append(d);
  const dt=document.createElement('details'); dt.dataset.lineToo='1'; dt.style.marginTop='12px'; dt.open=!!bs.command||!!ui.lineToo; dt.addEventListener('toggle',()=>{ ui.lineToo=dt.open; });
  { const sm=el('summary','Rather paste one line at the firewall\u2019s console?'); sm.addEventListener('click',()=>{ ui.lineToo=!dt.open; }); dt.append(sm); }
  pc.append(dt);
  return dt;
}
function pluginLine(pc, bs){
  if(bs.root_install) pc=pluginRoot(pc, bs);
  {
    pc.append(el('p','One line, pasted at the firewall\u2019s own console (log in as root, choose 8 for the shell, then type sh). It fetches the plugin from this device, so it needs no internet.','mut'));
    pc.append(el('p','The firewall checks the download against the fingerprint in that line\u2019s script, so a broken download stops. This first install trusts this device; later updates are only taken if they are signed with the release key.','mut'));   // BUILD 533 ("checked by its SHA-256 and trusted on first use, not signed and checked")
    if(bs.command){ const box=el('div',undefined,'scroll'); box.append(el('code',bs.command)); pc.append(box); pc.append(copyButton(bs.command)); pc.append(el('p','Waiting for the firewall\u2026 this page updates by itself.','mut')); }
    if(bs.command){
      // No keyboard on the firewall? Secure Shell, switched on from the firewall's own Administration page, reaches the same shell.
      // There is no way to switch it on from outside, so the page says where, and notices by itself when it answers.
      const sh=el('div',undefined,'card'); sh.dataset.ssh='1'; sh.append(el('h3','No keyboard on the firewall? Use this device instead'));
      const ssh=bs.ssh||null, host=(ssh&&ssh.host)||'';
      sh.append(el('p','1. Open the firewall’s Administration page and sign in if it asks.','mut'));
      sh.append(fwLink('Open the Administration page','/system_advanced_admin.php'));
      sh.append(el('p','2. Under Secure Shell tick all three: Enable Secure Shell, Permit root user login, Permit password login. Then press Save at the bottom of that page.','mut'));
      if(ssh && ssh.on){
        sh.append(el('p','3. Secure Shell is answering. In PowerShell (Windows) or Terminal (Mac, Linux) on this device, type the line below and press Enter. Sign in as root with the firewall’s password, choose 8, type sh, then paste the plugin line above.','mut'));
        const cmd='ssh root@'+host; const cb=el('div',undefined,'scroll'); cb.append(el('code',cmd)); sh.append(cb); sh.append(copyButton(cmd));
      } else {
        sh.append(el('p','3. This page checks by itself and says here when Secure Shell answers.','mut'));
      }
      sh.append(el('p','4. When the plugin is on, turn Secure Shell off again on the same page and Save. It is only needed for this one step.','mut'));
      pc.append(sh);
    }
    if(bs.note) pc.append(el('p',bs.note,'mut'));
    const b=el('button',bs.command?'Make a new line':'Show me the line'); b.onclick=async()=>{ b.disabled=true; try{ await post('/api/box/offer',{}); }catch(e){ fail(e); } await refresh(); };
    const lineRow=el('div',undefined,'btnrow'); lineRow.append(b); pc.append(lineRow);
    if(bs.can_open_port){
      pc.append(el('h3','Ran the line and still waiting?'));
      const po=bs.port||null, working=!!(po && po.state==='working');
      pc.append(el('p','If the line ran but this page never connects, the firewall\u2019s own rules may be stopping this device from reaching the plugin. This adds one rule: pass, from the plugin\u2019s network to the firewall itself, TCP port 8787 only. Your passkey approves it, it is checked straight away, and it is taken out again if it did not help.','mut'));
      if(po && po.message) pc.append(el('p',po.message, po.state==='failed'||po.state==='rule_present'?'':'mut'));
      const ob=el('button',working?'Working\u2026':'Open the plugin\u2019s port','quiet'); ob.disabled=working;
      ob.onclick=async()=>{ ob.disabled=true; try{ await post('/api/box/open-port',{}); }catch(e){ fail(e); } await refresh(); };
      const portRow=el('div',undefined,'btnrow'); portRow.append(ob); pc.append(portRow);
      const dt=document.createElement('details'); dt.style.marginTop='12px'; dt.append(el('summary','Rather add the rule yourself?'));
      const tb=el('table'); ((po&&po.manual&&po.manual.length)?po.manual:[['Action','Pass'],['Interface','the network the plugin\u2019s address is on'],['Direction','in'],['TCP/IP version','IPv4'],['Protocol','TCP'],['Source','that network\u2019s net'],['Destination','This Firewall'],['Destination port range','8787 to 8787'],['Description','Pazuzu: let this network reach the Pazuzu plugin']]).forEach(r=>{ const tr=document.createElement('tr'); tr.append(el('td',r[0]),el('td',r[1])); tb.append(tr); });
      dt.append(tb); dt.append(el('p','On the firewall: Firewall \u203a Rules, the plugin\u2019s network tab, Add. The plugin still needs its code to answer.','mut')); pc.append(dt);
    }
  }
}
// Test mode: the plugin, then which version, come before anything else. No rule is added or switched on without both.
// The plugin keeps itself current: a newer one is sent as soon as the plugin answers (once per visit), and the card
// says so. If it did not take, the button stays. Returns a card, or null when there is nothing to say.
// BUILD 485 (the maintainer, 5 Nov 2026: "wizard didnt update lab plugin"): on the PC, the box's software is brought up to date first,
// before sign-in. A reset to factory clears the plugin's link code, so the box is asked by its own address, and a newer
// plugin signed with this PC's key goes on with no code (the box keeps the key through a reset). Once per page load.
function earlyPlugin(body){
  if(ui.phone) return;
  if(!ui.early){ ui.early={state:'asking'};
    get('/api/plugin/state').then(ps=>{
      if(ps && ps.open && ps.state==='behind'){
        ui.early={state:'sending', to:ps.mine, from:ps.theirs}; refresh().catch(()=>{});
        return post('/api/plugin/update',{}).then(()=>{ ui.early={state:'done', to:ps.mine}; })
          .catch(e=>{ ui.early={state:'failed', why:String((e&&e.message)||e)}; }); }
      ui.early={state:'quiet'};
    }).catch(()=>{ ui.early={state:'quiet'}; }).finally(()=>{ if(ui.early.state!=='quiet') refresh().catch(()=>{}); });
  }
  const e=ui.early; if(!e || e.state==='asking' || e.state==='quiet') return;
  const c=el('div',undefined,'card'); c.dataset.earlyPlugin=e.state;
  if(e.state==='sending') c.append(el('h2','Updating your box\u2019s software'), el('p','From '+e.from+' to '+e.to+'. About a minute: the box restarts its plugin by itself.','mut'));
  else if(e.state==='done') c.append(el('h2','Your box\u2019s software is up to date'), el('p','It is on '+e.to+' now.','mut'));
  else if(/only takes updates signed by where it was set up/.test(e.why)){ c.dataset.earlyPlugin='other-key';   // BUILD 538: not a failure
    c.append(el('h2','This firewall\u2019s plugin is updated from the Pazuzu app'), el('p',e.why,'mut')); }
  else c.append(el('h2','The box\u2019s software was not updated'), el('p',e.why,'mut'), el('p','The plugin line still works: it is on the plugin step.','mut'));
  body.append(c);
}
async function pluginUpdateCard(){
  let ps=null; try{ ps=await get('/api/plugin/state'); }catch(e){ ps=null; }
  // A newer plugin is sent as soon as the plugin answers, once per visit; the button stays if that did not work.
  if(ps && ps.state==='behind' && !ui.pluginAuto){
    ui.pluginAuto=true; ui.pluginUpdating=true; ui.pluginAutoErr='';
    post('/api/plugin/update',{}).then(()=>{ ui.pluginUpdated=true; }).catch(e=>{ ui.pluginAutoErr=(e&&e.message)||String(e); })
      .finally(()=>{ ui.pluginUpdating=false; refresh().catch(()=>{}); });
  }
  if(ps && (ps.state==='behind' || ps.state==='old' || ui.pluginUpdated || ui.pluginUpdating)){
    const uc=el('div',undefined,'card'); uc.append(el('h2','Plugin update'));
    if(ui.pluginUpdating) uc.append(el('p','Updating the plugin. It restarts itself and comes back in a few seconds.','mut'));
    else if(ui.pluginUpdated && ps.state==='current') uc.append(el('p','Updated. The plugin is now '+(ps.theirs||ps.mine)+'.','mut'));
    else if(ps.state==='behind'){
      uc.append(el('p','A newer plugin is ready here ('+ps.mine+'; the firewall has '+(ps.theirs||'an older one')+'). The plugin only accepts it if it is signed by the key kept on this device.','mut'));
      const ub=el('button','Update the plugin'); ub.onclick=()=>act(ub, async()=>{ await post('/api/plugin/update',{}); ui.pluginUpdated=true; });
      uc.append(ub);
      if(ui.pluginAutoErr) uc.append(el('p','It did not update by itself: '+ui.pluginAutoErr,'mut'));
    } else if(ps.state==='old') uc.append(el('p','This plugin is an older one'+(ps.theirs?' ('+ps.theirs+')':'')+', which cannot take updates. Put it on once more with the line below; after that it updates from here with no line.','mut'));
    return uc;
  }
  return null;
}
// A new firewall does not know where it is: its clock, logs and screen can be hours off. The plugin sets the zone the way the
// General settings page's Save does; this device's own zone is offered first. A plugin that cannot do it leaves the old way.
function clockCard(){
  const c=el('div',undefined,'card'); c.dataset.clock='1';
  let zone=''; try{ zone=Intl.DateTimeFormat().resolvedOptions().timeZone||''; }catch(e){ zone=''; }
  if(zone==='UTC'||zone==='GMT') zone='Etc/UTC';
  // BUILD 521 (the maintainer, the careful way, 12 Nov 2026: "The plugin did not answer, so the time zone could not be read here"
  // with a "Go to the plugin" button, in a build with no plugin): the by-hand card, on both ways.
  if(ui.pluginOffered===false){
    c.append(el('h2','Check the firewall\u2019s time zone'), el('p','A new firewall is set to UTC. Logs and the nightly jobs read better in your own zone'+(zone?' ('+zone+', this device\u2019s)':'')+'. On the firewall: System, Settings, General, pick the Time zone and press Save. Setting it for you comes in beta 2.','mut'), fwLink('Open General settings','/system_general.php'));
    { const h=c.querySelector('h2'); if(h){ h.append(' '); const t=el('span','Set for you in beta 2','chip mute'); t.style.marginLeft='6px'; h.append(t); } }   // BUILD 523 (the maintainer: "in beta 2")
    return c; }
  c.append(el('h2','Set the firewall’s time zone'));
  const holder=el('div'); holder.append(el('p','Reading the firewall’s time zone…','mut')); c.append(holder);
  // The plugin may still be coming up: ask again a few times before falling back to the by-hand way.
  let tries=0; const ask=()=>get('/api/time-zone').then(tz=>{ if(tz.retry && tries++<5 && holder.isConnected){ clockFill(holder, {can:false, why:tz.why, waiting:true}, zone); setTimeout(ask, 4000); } else clockFill(holder, tz.retry?{can:false, why:'The plugin did not answer, so the time zone could not be read here.'}:tz, zone); }).catch(()=>clockFill(holder, {can:false}, zone));
  ask();
  return c;
}
function clockFill(holder, tz, zone){
  holder.replaceChildren();
  const lead='A new firewall does not know where you are, so its clock, its logs and the times on its screen can be hours off. ';
  if(!tz.can){
    // Say why the plugin cannot do it (not answering, or too old), so the old way does not look like the only way.
    if(tz.why){ const w=el('p',tz.why); w.dataset.clockWhy='1'; holder.append(w); }
    if(tz.waiting) return;
    // Nothing was read, so nothing is claimed about the firewall's clock: only what to check, and where.
    holder.append(el('p', 'To check it yourself, open the General settings'+(zone?': the time zone should be '+zone+' (this device’s)':'')+'. If it is not, pick it and press Save.','mut'));
    const row=el('div',undefined,'btnrow');
    if(tz.why && /plugin/i.test(tz.why) && typeof ui!=='undefined' && ui.skipped){
      const toPlugin=el('button','Go to the plugin'); toPlugin.dataset.clockPlugin='1';
      toPlugin.onclick=()=>{ delete ui.skipped.plugin; delete ui.done.plugin; saveUi(); ui.force=null; refresh().catch(fail); };
      row.append(toPlugin);
    }
    row.append(fwLink('Open General settings','/system_general.php')); holder.append(row);
    return;
  }
  const same = !!zone && tz.zone===zone;
  if(same || tz.ours){                      // handled: its control leaves the screen (only the way back stays, while it is Pazuzu's)
    holder.append(el('p', 'The firewall is on '+tz.zone+(same?', the same as this device.':'.'),'mut'));
  } else {
    holder.append(el('p', lead+'Its time zone is '+tz.zone+(tz.saved?'':' (the setting it came with)')+'. '+(zone ? (tz.zones.indexOf(zone)>=0 ? 'This device is on '+zone+'.' : 'This device says '+zone+', which the firewall does not list: pick the nearest one.') : 'Pick yours.'),'mut'));
    const sel=el('select'); sel.dataset.clockZone='1'; sel.setAttribute('aria-label','Time zone');
    tz.zones.forEach(z=>{ const o=el('option',z); o.value=z; sel.append(o); });
    sel.value = tz.zones.indexOf(zone)>=0 ? zone : tz.zone;
    const go=el('button','Set the time zone'); go.dataset.clockSet='1'; go.disabled=!sel.value; sel.onchange=()=>{ go.disabled=!sel.value; };      // nothing picked, nothing to send
    go.onclick=()=>act(go, async()=>{ await post('/api/time-zone/change',{action:'set', zone:sel.value}); });
    const row=el('div',undefined,'btnrow'); row.append(sel, go); holder.append(row,
      el('p','This changes only the time zone, the way the General settings page does. Your passkey approves it.','mut'));
  }
  if(tz.ours && tz.was){
    const back=el('button','Put it back to '+tz.was,'quiet'); back.dataset.clockBack='1';
    back.onclick=()=>act(back, async()=>{ await post('/api/time-zone/change',{action:'undo'}); });
    holder.append(back);
  }
}
// Zenarmor checks the hardware itself when it is set up. This check comes earlier, so a person learns now, and not after
// installing it, whether the firewall will be happy. It never blocks anything: Zenarmor has the last word.
function hardwareCard(){
  const c=el('div',undefined,'card'); c.dataset.hardware='1';
  c.append(el('h2','Will this firewall be happy with Zenarmor?'));
  const holder=el('div'); holder.append(el('p','Reading the firewall’s hardware…','mut')); c.append(holder);
  get('/api/hardware').then(h=>hardwareFill(holder, h)).catch(()=>hardwareFill(holder, {can:false, why:'Could not ask the plugin just now.'}));
  return c;
}
function hardwareFill(holder, h){
  holder.replaceChildren();
  if(!h.can){ holder.append(el('p',h.why||'The hardware could not be read.','mut')); return; }
  const line=(r)=>{ const d=el('div',undefined,'vrow'); const m=el('div',undefined,'grow'); m.append(el('div',r.what+': '+r.says,'vt'), el('div',r.help,'mut'));
    d.append(m, el('span', r.level==='ok'?'Good':r.level==='note'?'Worth knowing':'Stops it','chip'+(r.level==='ok'?'':' warn'))); return d; };
  holder.append(el('p', h.headline, h.level==='ok'?'mut':undefined));
  h.rows.filter(r=>r.level!=='ok').forEach(r=>holder.append(line(r)));      // what is worth knowing stays on the screen
  const fine=h.rows.filter(r=>r.level==='ok');
  if(fine.length){ const f=el('details'); f.append(el('summary','Details: what was read, and what Zenarmor says about it')); fine.forEach(r=>f.append(line(r))); holder.append(f); }
  holder.append(el('p','Zenarmor checks the hardware again when you set it up, and it has the last word.','mut'));
}
// Update the firewall from here, with its own updater. A restart is its own button, pressed on purpose.
// An update waiting stops the wizard: the firewall refuses to install plugins until it is current, and almost every step
// after this one needs a plugin. A test flight from the live CD cannot update, and a firewall with no internet cannot
// either: those only warn. (A restart the update asked for counts as still waiting.)
// BUILD 483: after an update the firewall forgets its last check, so the step read "Not checked
// yet" right above "The update finished.", with "Continue anyway". When an update, or the restart it asked for, has just
// finished, the step looks again by itself, once, and lands on "Up to date" with Continue.
function fwRecheckAfter(job){
  if(job && (job.kind==='firmware-update' || job.kind==='firmware-reboot') && job.state==='done' && ui.fwAfter!==job.id){
    ui.fwAfter=job.id; ui.fwAuto=false; }
}
function mustUpdate(f, st){
  if(!f || f.offline || (st && st.trial)) return false;
  return f.state==='update' || !!f.needs_reboot;
}
function updateGate(){
  const c=el('div',undefined,'card'); c.dataset.updateGate='1';
  c.append(el('h2','Update the firewall first'));
  c.append(el('p','The firewall has a newer version waiting. Until it is installed, the firewall will not add the plugins the next steps need, and updates often carry security fixes. Press Update it now above: it can take a few minutes and may restart the firewall once. This page carries on by itself when it is back.','mut'));
  return c;
}
function firmwareActions(card, f, job){
  // BUILD 528 (Look for updates answered "Make the installer account first." and nothing on
  // the page made one): a firewall Pazuzu set up more than a day ago has closed its installer account. The form is here.
  if(ui.installer===false && !ui.phone && f && !f.offline){
    const box=el('div'); box.dataset.fwInstaller='1';
    installerForm(box, (ui.installerStale ? 'The firewall closed Pazuzu\u2019s installer account, as it does after a day. ' : '')+'Looking for updates and installing them needs Pazuzu\u2019s installer account, which can open every page. It is made with your firewall password, used once and not saved, and the firewall closes it after a day.');
    card.append(box); return; }
  if(job && job.kind==='firmware-update' && job.state==='done') card.append(el('p','The update finished.','mut'));
  if(job && job.kind==='firmware-reboot' && job.state==='done') card.append(el('p','The firewall was asked to restart. It is off for a minute or two; this page reconnects by itself. Press Check again when it is back.','mut'));
  if(ui.phone && f && (f.state==='update' || f.needs_reboot)) card.append(el('p','Your phone may lose the box for a few minutes while the firewall updates or restarts. Stay close by: the app finds it again, and you carry on from this step.','mut'));   // BUILD 450 (N5)
  // BUILD 517 (the maintainer, live disc, 12 Nov 2026: "toe catcher (update it now)"): with the update installed and a restart
  // waiting, the firewall still says "update", and the page offered Update it now a second time.
  if(f && f.state==='update' && !f.offline && !f.needs_reboot){
    const ub=el('button','Update it now'); ub.dataset.fwUpdate='1'; ub.onclick=()=>act(ub,()=>post('/api/firmware/update',{}));
    card.append(ub, el('p','This runs the firewall\u2019s own updater and takes a few minutes. '+(f.update_restarts?(ui.trialNow?'The firewall says this update needs a restart to finish. On a live disc you leave that out: nothing is kept through a restart, and what the setup needs is in without it.':'The firewall says this update needs a restart to finish: once it is installed, a Restart button appears here, and you press it when it suits you.'):'It does not restart the firewall.')+' A new major version is not run from here: that is done on the firewall\u2019s own Firmware page.','mut'));
  }
  if(f && f.state!=='update' && !f.offline && f.version){
    const cb=el('button','Look for updates','quiet'); cb.dataset.fwCheck='1'; cb.onclick=()=>act(cb,()=>post('/api/firmware/check',{}));
    card.append(cb);
  }
  if(job && job.kind==='firmware-check' && job.state==='done' && job.result && job.result.checked===false) card.append(el('p',(job.result.lines||[])[0]||'','mut'));
  if(f && f.needs_reboot && ui.trialNow){
    // a live disc: a restart would lose the update and everything else, so none is offered
    card.append(el('p','The update is installed. It would take a restart to finish it, and a live disc keeps nothing through a restart, so leave it running: what the ports step needs is in. Press Continue.','mut'));
  } else if(f && f.needs_reboot){
    card.append(el('p','The update is installed. The firewall needs a restart to finish it.','mut'));
    const rb=el('button','Restart the firewall now'); rb.dataset.fwReboot='1'; rb.onclick=()=>act(rb,()=>post('/api/firmware/reboot',{})); card.append(rb);
  }
}
// An install the firewall refused because it is behind: the update is offered right there, not left for the person to find.
// BUILD 484: `where` is the step showing it, so that step alone shows the update's result after (the lab run, 5 Nov:
// Reach home showed "Updating the firewall" for the software step's own check).
function installRefused(job){ return !!(job && job.state==='failed' && /until it is updated|did not update it for you/.test(job.error||'')); }
function staleInstall(job, where, waiting){
  if(!installRefused(job) && !waiting) return null;
  const c=el('div',undefined,'card unsafe'); c.dataset.staleInstall='1';
  if(ui.fwInstalled){          // BUILD 517: the update is in and a restart is waiting; "Update it now" again was a toe catcher
    c.append(el('h2','The firewall has to restart first'), el('p', ui.trialNow
      ? 'It will not install anything until it has restarted after its update, and a live disc keeps nothing through a restart. The name plugin can be tried once the firewall is installed to disk. Press Not now below.'
      : 'It will not install anything until it has restarted after its update. Go back to the version step and press Restart the firewall now, then press the install button again.','mut'));
    return c; }
  c.append(el('h2','The firewall has to be updated first'), el('p','It will not install anything until it is on its newest version. Pazuzu can run that update for you. It takes a few minutes and does not restart the firewall by itself. Then press the install button again.','mut'));
  const b=el('button','Update it now'); b.dataset.fwUpdate='1'; b.onclick=()=>{ ui.fwFrom=where||''; return act(b,()=>post('/api/firmware/update',{})); }; c.append(b);
  return c;
}
// BUILD 502 (the maintainer, 11 Nov 2026: "put instructions in access card/and other types of hotspots too"): what to do on the
// phone, for each kind of hotspot. The firewall joins only while the main internet is down, so this is what a person does
// then; the same words are on the access card. A hotspot on 2.4 GHz with WPA2 is the one every firewall card can join.
const HOTSPOT_HOWTO=[
  ['iPhone','Settings, Personal Hotspot: switch on Allow Others to Join and Maximize Compatibility, and keep that screen open until the firewall has joined (an iPhone hides its hotspot otherwise). The hotspot’s name is the phone’s name (Settings, General, About).'],
  ['Android','Settings, Network (or Connections), Hotspot and tethering, Wi-Fi hotspot: switch it on, set the band to 2.4 GHz and the security to WPA2, and switch off “turn off when no devices are connected” if it has one.'],
  ['A stand-alone hotspot (a mobile Wi-Fi box, a travel router, a car’s Wi-Fi)','switch it on near the firewall; set it to 2.4 GHz (or both bands) with WPA2. It can stay on all the time: the firewall only joins it while the main internet is down.']
];
function hotspotHowTo(title){
  const d=el('div'); d.dataset.hotspotHowto='1'; d.append(el('h3',title));
  const ul=el('ul',undefined,'plain');
  HOTSPOT_HOWTO.forEach(([who,what])=>{ const li=el('li'); li.append(el('strong',who+': '), document.createTextNode(what)); ul.append(li); });
  d.append(ul);
  d.append(el('p','The firewall joins within about half a minute of the main internet stopping, and lets the phone go a few minutes after it is back.','mut'));
  return d;
}
// The phone's hotspot as the backup way to the internet: its name and password, one passkey touch. Offered right under the back door.
async function hotspotCard(body, bs){
  const c=el('div',undefined,'card'); c.dataset.hotspot='1'; c.append(el('h2','Backup internet from your phone'));
  c.append(el('p','If the main internet goes down, the firewall joins your phone’s hotspot and uses its data until the main internet is back. The rest of the time it leaves the phone alone: it joins only while the main internet is down, and switches back by itself.','mut'));
  if(!bs.connected){ c.append(el('p','Needs the plugin first.','mut')); body.append(c); return; }
  let hs=null; try{ hs=await get('/api/hotspot'); }catch(e){ hs=null; }
  if(!hs){ c.append(el('p','Could not read this just now.','mut')); body.append(c); return; }
  if(!hs.can){ c.append(el('p',hs.why||'This is not available on the firewall right now.','mut')); body.append(c); return; }
  if(hs.stage==='done'){ ui.done.hotspot=true; saveUi(); }
  const gw=(g,who,into)=>{ if(g) (into||c).append(el('p',who+': '+g.name+', number '+g.priority+' (the lower number is used first)'+(g.monitor_disable==='1'?', not checked':g.monitor?', checked against '+g.monitor:', checked')+(g.status?', '+g.status:'')+'.','mut')); };
  if(hs.stage==='done' && !ui.hsChange){
    const sb=hs.standby||null, reserve=!!(sb && sb.on);
    c.append(el('p','Set up. The main internet is used first. '+(reserve
      ? (sb.joined_for_outage ? 'The main internet is down, so the firewall is on the hotspot'+(hs.ssid?' “'+hs.ssid+'”':'')+' now.' : 'If it goes down for about half a minute, the firewall joins the hotspot'+(hs.ssid?' “'+hs.ssid+'”':'')+' and uses it until the main internet is back.')
      : 'The firewall stays joined to the hotspot'+(hs.ssid?' “'+hs.ssid+'”':'')+' and uses it if the main internet goes down. (Press Finish once the plugin is 0.7.1 or newer, so it joins only while the main internet is down.)')));
    // BUILD 504 (the maintainer: "they can collapse as configured"): the details fold away once it is set up
    const more=el('details'); more.append(el('summary','What to do when the internet goes down, and the two connections'));
    more.append(hotspotHowTo('When the internet goes down'));
    gw(hs.main,'Main',more);
    if(reserve && !sb.joined_for_outage && hs.gateway) more.append(el('p','Backup: '+hs.gateway.name+', number '+hs.gateway.priority+', in reserve: off until the main internet stops answering.','mut'));
    else gw(hs.gateway,'Backup',more);
    c.append(more);
    const ch=el('button','Use a different phone','quiet'); ch.onclick=()=>{ ui.hsChange=true; refresh().catch(fail); }; c.append(ch);
    body.append(c); return;
  }
  if(hs.stage==='set' || hs.stage==='joined'){
    c.append(el('p', hs.stage==='set' ? 'The port is switched on, but the phone has not let the firewall join yet.' : 'The firewall has joined the phone. The order of the two connections is not set yet.'));
    c.append(el('p','On the phone, switch the hotspot on and keep its screen open (an iPhone stops the hotspot a minute after the last visitor leaves). Then press Finish.','mut'));
    const fin=el('button','Finish, with passkey'); fin.onclick=()=>act(fin, async()=>{ await post('/api/hotspot/finish',{}); }); c.append(fin);
  }
  c.append(el('p', hs.reuse ? 'The firewall already has a Wi-Fi device from an earlier try. It will be pointed at this hotspot.' : 'The firewall’s Wi-Fi card will join this hotspot.'));
  c.append(means('the firewall joins your phone’s hotspot the way any device joins Wi-Fi, so type the name and password exactly as the phone shows them.'));
  const ssid=el('input'); ssid.type='text'; ssid.autocomplete='off'; ssid.maxLength=32; ssid.placeholder='The hotspot’s name, as the phone shows it'; ssid.value=ui.hsSsid||hs.ssid||''; ssid.oninput=()=>{ ui.hsSsid=ssid.value; };
  const pw=el('input'); pw.type='password'; pw.autocomplete='off'; pw.maxLength=63; pw.placeholder='The hotspot’s password';
  c.append(ssid, pw);
  c.append(hotspotHowTo('Before you press Set it up'));
  c.append(el('p','The passkey shows every change before it is made: a Wi-Fi device, a port, a check of the main internet gateway, default gateway switching, and the order of the two connections. The password is used once and is not kept.','mut'));
  const go=el('button','Set it up, with passkey'); go.onclick=()=>act(go, async()=>{ const p=pw.value; pw.value=''; ui.hsChange=false; await post('/api/hotspot/set',{ssid:ssid.value, passphrase:p}); }); c.append(go);
  body.append(c);
}
async function pluginStep(body, st, job){
  let bs={state:'none',connected:false}; try{ bs=await get('/api/box/state'); }catch(e){ fail(e); }
  if(bs && bs.platform){ ui.platform=bs.platform; applyBrand(); }
  const hanbi = ui.platform==='hanbi';
  // BUILD 513 (the maintainer, 12 Nov 2026): beta 1 has no plugin. This step is then the version alone, read over the firewall's own API.
  const np = ui.pluginOffered===false;
  if(np) body.append(head(2,'Which version is your firewall on','Read from the firewall itself. A waiting update is best installed before the rules. Nothing is added or switched on here.',true));
  else body.append(head(2, hanbi?'Your firewall’s software':'The plugin, then the version',
    hanbi?'Hanbi’s software is already aboard, so there is nothing to install. Next: make sure it is up to date. Nothing is added or switched on until you say so.'
         :'The plugin goes on the firewall first, so this app can see it from the inside. It needs no internet. Then: which version is the firewall on. The plugin is optional: without it the setup still works, and the bar at the bottom carries on without it.',true));
  if(!np && !bs.connected && bs.command){ try{ bs.ssh=await get('/api/ssh/state'); }catch(e){} }
  if(!np) body.append(pluginCard(bs, 'Put Pazuzu on this firewall'));
  if(hanbi && !ui.phone && !np){ const bt=el('div',undefined,'card'); bt.append(el('h2','Setup channel: Bluetooth'),
    el('p','On a Hanbi the plugin is already aboard, and a phone pairs to the box over certified Bluetooth to set it up — the plugin and the Bluetooth pairing are the one setup channel. (This device reaches the box over the network; the Bluetooth path is for a phone.)','mut')); body.append(bt); }
  { const sc=staleInstall(job); if(sc) body.append(sc); }
  let seen=false;
  // BUILD 512 (the maintainer, dev, 12 Nov 2026: "didnt see version page?"): the version is read from the firewall itself, so it
  // is shown with or without the plugin. Before, going on without the plugin meant never seeing it.
  if(bs.connected || !ui.phone){
    // The plugin keeps itself current: when this app carries a newer one, offer it here, before anything depends on it.
    if(bs.connected){ const uc=await pluginUpdateCard(); if(uc) body.append(uc); }
    let f=null; try{ f=await get('/api/firmware'); }catch(e){ f=null; }
    seen=!!(f && f.version);
    ui.fwWaiting = !!(f && f.state==='update' && !f.needs_reboot);      // BUILD 514: the firewall installs no plugin of its own while an update waits
    ui.fwInstalled = !!(f && f.needs_reboot);                           // BUILD 517: installed, a restart waiting
    ui.fwBehind = mustUpdate(f, st);
    if(job && job.kind==='firmware-check' && job.state==='done' && job.result) ui.fwCheckFailed = job.result.checked===false;   // kept past later jobs
    ui.fwOffline = !!(f && f.offline) || !!ui.fwCheckFailed;
    // A fresh firewall has not looked for updates, so "current" may only mean "not asked". Ask once.
    fwRecheckAfter(job);
    if(f && (f.state==='current'||f.state==='unchecked') && !f.offline && !ui.fwAuto){ ui.fwAuto=true; try{ await post('/api/firmware/check',{}); }catch(e){} return refresh(); }
    const vc=el('div',undefined,'card'); vc.append(el('h2','Which version'));
    vc.append(el('p', seen ? 'The firewall is on version '+f.version+'.' : 'Could not read which version the firewall is on.', 'mut'));
    ui.trialNow=!!(st && st.trial);
    if(f && f.offline && f.detail) vc.append(el('p',f.detail,'mut'));
    else if(f && f.state==='update' && !f.needs_reboot) vc.append(el('p','A newer version is available. It is best installed before the rules.','mut'));   // BUILD 484: the card under the button says whether it restarts
    else if(f && f.state==='unchecked') vc.append(el('p','It has not looked for updates yet. Press Look for updates.','mut'));
    else if(f && f.state==='current') vc.append(el('p', (job && job.kind==='firmware-check' && job.state==='done' && job.result && job.result.checked) ? 'Up to date. The firewall has just looked and found nothing newer.' : 'That is the newest it found when it last looked.','mut'));
    firmwareActions(vc, f, job);
    if(!seen){ const again=el('button','Read it again','quiet'); again.onclick=()=>refresh().catch(fail); vc.append(again); }
    // BUILD 449: the words say "press Check again" when the outside port has no cable, so there is a button for it
    // (the lab box, 2 Nov 2026: the cable went in and there was nothing to press).
    else if(f && f.offline){ const again=el('button','Check again','quiet'); again.dataset.fwAgain='1'; again.onclick=()=>act(again, async()=>{ ui.fwAuto=false; }); vc.append(again); }
    body.append(vc);
    if(bs.connected && !ui.phone) body.append(clockCard());           // BUILD 480: the phone sets it from its own zone, below
    else if(np && !ui.phone) body.append(clockCard());      // BUILD 517 (the maintainer: "didn't notice time zone"): no plugin to set it, so the by-hand way
    if(bs.connected && !ui.phone) body.append(hardwareCard());
  }
  rail(bs.connected ? 2 : 1, true);
  clearTimeout(ui.wayT);
  const watch=()=>{ ui.wayT=setTimeout(async()=>{
    if(!document.querySelector('[data-way]')) return;
    try{ const b2=await get('/api/box/state'); if(b2.connected!==bs.connected||b2.state!==bs.state||b2.note!==bs.note||JSON.stringify(b2.port||null)!==JSON.stringify(bs.port||null)||!!b2.can_open_port!==!!bs.can_open_port){ await refresh(); return; }
      if(!bs.connected && bs.command){ const s2=await get('/api/ssh/state'); if(!!s2.on!==!!(bs.ssh&&bs.ssh.on)){ await refresh(); return; } } }catch(e){}
    watch(); },3000); };
  if(!bs.connected && !np) watch();
  if(np){
    const late=seen && ui.fwBehind;
    // BUILD 515 (the maintainer, live disc on plain 26.7, 12 Nov 2026): a waiting update is needed again on an installed firewall.
    // Plain 26.7 cannot set a zone's port up or install the name plugin until it is updated, and "Carry on without
    // updating" (BUILD 513) walked people into that. A live disc does not keep an update, so there it is left alone.
    const live=!!(st && st.trial) && !!ui.fwWaiting;
    const on=late ? null : el('button', seen ? 'Continue' : 'Carry on', seen ? undefined : 'quiet'); if(on){ on.dataset.versionOn='1'; on.onclick=()=>mark('plugin','done'); }
    body.append(bar(late ? 'A newer version is waiting. Update it first: press Update it now above. It takes a few minutes and may restart the firewall once, and this page carries on by itself when it is back. The steps after this need it: plain 26.7 cannot set up a zone\u2019s port or install the name plugin.'
      : (st && st.trial && ui.fwInstalled) ? 'The update is in. Do not restart the firewall: a live disc keeps nothing through a restart. Next: the ports.'
      : live ? 'A newer version is waiting. On a live disc an update lasts only until the firewall restarts. Update it now to try everything, and do not restart it afterwards; or press Continue to try without it. Two things need the update: giving zones their own port or VLAN, and the name plugin.'
      : seen ? 'The version is read. Next: the ports, a name and the VPN to reach home, then the rules.'
      : 'The version could not be read. Press Read it again, or carry on: the setup checks each change as it makes it.', on));
    return;
  }
  const behind=bs.connected && seen && ui.fwBehind;
  const ready=bs.connected && seen && !behind;
  if(behind && !ui.phone) body.append(updateGate());
  // No skip here: everything after this step needs the plugin, and a skip only sent the person round in a circle.
  // BUILD 480: on the phone there is nothing to decide here when it is ready: the time zone is set from the phone's own
  // and the step goes on by itself. An update waiting is offered, with Later (nothing in the setup needs it).
  if(ui.phone && (ready || behind) && !ui.tzAuto){
    let tz=null; try{ tz=await get('/api/time-zone'); }catch(e){ tz=null; }
    let zone=''; try{ zone=Intl.DateTimeFormat().resolvedOptions().timeZone||''; }catch(e){ zone=''; }
    ui.tzAuto=true;
    if(tz && tz.can && zone && tz.zone!==zone && !tz.ours && (tz.zones||[]).indexOf(zone)>=0){
      try{ await post('/api/time-zone/change',{action:'set', zone:zone}); }catch(e){} return refresh(); }
  }
  // BUILD 481: a box with no way out is said here, on the phone too: the block lists and encrypted DNS at the end need
  // it, and the lab run (4 Nov 2026) went on to Reach home with none and found out there. Carry on stays possible.
  if(ui.phone && ready && ui.fwOffline){
    const anyway=el('button','Carry on anyway','quiet'); anyway.onclick=()=>mark('plugin','done');
    const again=el('button','Check again'); again.onclick=()=>act(again, async()=>{ ui.fwAuto=false; });
    body.append(bar('Your Hanbi cannot reach the internet yet. Check the cable from its internet port to your router, then press Check again. The protection at the end needs it.', anyway, again)); return;
  }
  if(ui.phone && ready) return mark('plugin','done');
  if(ui.phone && behind){
    const later=el('button','Later','quiet'); later.onclick=()=>mark('plugin','done');
    body.append(bar('An update is waiting: update it now, or later from the app.', later)); return;
  }
  const go=ready ? el('button','Continue') : null; if(go) go.onclick=()=>mark('plugin','done');
  // BUILD 493 (the maintainer: "add a way to carry on without the plugin"): the wizard alone still sets everything up; what needs
  // the plugin says so where it is offered. The LAN lifeline keeps the way in.
  const noPlug=(!bs.connected && !ui.phone) ? el('button','Carry on without the plugin', bs.aboard?undefined:'quiet') : null;   // BUILD 550: the main button when the plugin aboard is the app's
  if(noPlug) noPlug.onclick=()=>act(noPlug, async()=>{ await post('/api/control/skip',{}); ui.skipped.plugin=true; saveUi(); });
  body.append(bar(ready?'The plugin is on and the version is read. Next: the ports, Wi-Fi, a name and the VPN to reach home, then the rules.':
    behind?'The firewall has an update waiting. Update it first: the steps after this stay locked until it is done.':
    (bs.aboard && seen)?'The version is read. The plugin on this firewall belongs to the app, so carry on without it here: the setup works over the firewall\u2019s own API.':
    (seen?'The version is read. Waiting for the plugin: this':'Waiting for the plugin and the version. This')+' page updates by itself. The plugin adds the box’s screen, the blocks list, the Wi-Fi back door and the phone hotspot backup; without it the setup still works.', ...(noPlug?[noPlug]:[]), go));
}
// Two things that cost a test flight: a Wi-Fi card with its antennas off is too weak for a phone to hear, and the
// firewall's own certificate makes every phone warn. Said before and after the network is made.
function wifiTips(done){
  const d=el('div',undefined,'tips'); d.dataset.wifiTips='1';
  d.append(el('p','Attach the Wi-Fi antennas to the firewall\u2019s Wi-Fi card, and hold the phone close to the firewall when you join. Without antennas the signal is too weak for most phones to find.','mut'));
  if(done) d.append(el('p','When the phone opens the firewall\u2019s page it will warn that the connection is not private. That is the firewall\u2019s own certificate, which no phone knows, and here the page is reached by number. It is safe to accept on this Wi-Fi: choose Visit Website. To stop seeing the warning in everyday use, give the firewall a name (the Reach home from outside step) and a certificate made for that name.','mut'));
  return d;
}
// BUILD 513 (the maintainer, 12 Nov 2026: "keep these greyed to show off future features"): beta 1 has no plugin, so the Wi-Fi
// back door and the phone hotspot backup cannot be set up. They are shown, greyed, with what each will do.
function waySoon(body, lstep){
  body.append(backLink('wayback'));
  body.append(head(lstep||3,'A safe way back in','Two ways to stay connected when a cable or your internet fails. Both come in beta 2.', !!lstep));
  [['The Wi-Fi back door','A hidden Wi-Fi network from the firewall\u2019s own Wi-Fi card, with a long password. It reaches the firewall\u2019s page and nothing else, and closes itself after use. If a cable or a setting ever locks you out, it is the way back in.'],
   ['Backup internet from your phone','If the main internet goes down, the firewall joins your phone\u2019s hotspot and uses its data until the main internet is back. The rest of the time it leaves the phone alone.']
  ].forEach(([t,w])=>{ const c=el('div',undefined,'card soon'); c.dataset.soon='1'; c.setAttribute('aria-disabled','true');
    const h=el('h2',t+' '); h.append(el('span','Beta 2','chip mute')); c.append(h, el('p',w,'mut'));
    const b=el('button','Set it up','quiet'); b.disabled=true; b.title='Comes in beta 2.'; c.append(b); body.append(c); });
  const go=el('button','Continue'); go.onclick=()=>mark('wayback','done');
  body.append(bar('Nothing to do here in beta 1. Until beta 2, a cable from your own network is the way in to the firewall, and the setup keeps that way open.', go));
}
async function wayStep(body, st, lstep){
  if(ui.pluginOffered===false) return waySoon(body, lstep);
  body.append(backLink('wayback'));
  body.append(head(lstep||3,'A safe way back in','If the cable ever fails, a Wi-Fi way in to the firewall\u2019s page keeps you from being locked out.'+(lstep?'':' First the Pazuzu plugin goes on the firewall, then the Wi-Fi.'), !!lstep));
  let bs={state:'none',connected:false}, ws={state:'none',done:false};
  try{ bs=await get('/api/box/state'); ws=await get('/api/wifi/state'); }catch(e){ fail(e); }
  { const hanbi=(bs&&bs.platform==='hanbi')||ui.platform==='hanbi';
    const sc=el('div',undefined,'card'); sc.append(el('h2', hanbi?'A way back in':'Setup channel: Wi-Fi'));
    sc.append(el('p', hanbi
      ? 'Your phone paired over Bluetooth back at the plugin step. This Wi-Fi back door is a separate way in if a cable ever fails.'
      : 'No certified Bluetooth here, so this isn’t a Hanbi — setup uses the Wi-Fi back door below. (On a Hanbi, your phone pairs over Bluetooth at the plugin step instead.)','mut'));
    body.append(sc); }
  if(!bs.connected && bs.command){ try{ bs.ssh=await get('/api/ssh/state'); }catch(e){} }
  // In the wizard-only order the plugin was done two steps ago: its card is not shown again once it is connected.
  if(!(lstep && bs.connected)){ body.append(pluginCard(bs, '1. Put Pazuzu on this firewall')); }
  if(bs.connected && !lstep){ const uc=await pluginUpdateCard(); if(uc) body.append(uc); }
  { const hr=writeResult(st,['write-hotspot']); if(hr) body.append(hr); }
  const wc=el('div',undefined,'card'); wc.dataset.way='1'; wc.append(el('h2', lstep ? 'The Wi-Fi back door' : '2. The Wi-Fi back door'));   // the watcher below looks for this
  if(ws.done){
    wc.append(el('p','Set up. The network is hidden and reaches only the firewall\u2019s page.','mut'));
    if(ws.ssid && ws.passphrase){
      wc.append(el('p','Name: '+ws.ssid+'    Password: '+ws.passphrase));
      if(ws.qr){ const pic=el('div',undefined,'qrbox'); pic.append(document.importNode(new DOMParser().parseFromString(ws.qr,'image/svg+xml').documentElement,true)); wc.append(pic); wc.append(el('p','A phone can scan this to join. The network is hidden, so the name is entered for you.','mut')); }
    }
    wc.append(wifiTips(true));
  }
  else if(!bs.connected){ wc.append(el('p','Needs the plugin first.','mut')); }
  else{
    if(ws.closed_after_use) wc.append(el('p','The Wi-Fi back door was used and then closed itself, as it was set up to. Make a new one whenever you want one.','mut'));
    wc.append(el('p','A hidden Wi-Fi network from the firewall\u2019s own Wi-Fi card, with a long password. It reaches the firewall\u2019s web page and nothing else, and it closes itself once a device has used it and left. '+(ws.direct?'Your passkey approves it and the plugin on the firewall sets it up: no line to paste.':'Your passkey approves it. The plugin on this firewall is an older one, so one last pasted line sets it up and updates the plugin; after that no lines are needed.'),'mut'));
    if(ws.state!=='running') wc.append(wifiTips(false));
    if(ws.state==='running'){
      wc.append(el('p','Setting it up on the firewall now. This takes about half a minute and this page updates by itself.','mut'));
    }
    else if(ws.state==='failed' && ws.no_card){
      wc.append(el('p','The firewall\u2019s system does not see a Wi-Fi card it can use right now. A card can be fitted and still not show up: it may need a driver or firmware the system does not have (some cards fetch their firmware from the internet; many USB adapters have no driver at all). Nothing was changed on the firewall.','mut'));
      const rep=el('div',undefined,'scroll'); String(ws.report||'').split('\n').forEach(l=>rep.append(el('div',l||'\u00a0','mut'))); wc.append(rep);
      wc.append(el('p','Trying again only helps once the system lists the card. Nothing else in the setup depends on the Wi-Fi.','mut'));
    }
    else if(ws.state==='failed' && ((ws.cannot_host && ws.cannot_host.length) || (ws.no_beacon && ws.no_beacon.length))){
      // BUILD 504: say what each card did. iwn0 refused outright; rtwn0 made the network and could not broadcast it.
      if(ws.no_beacon && ws.no_beacon.length) wc.append(el('p','The Wi-Fi card '+ws.no_beacon.join(', ')+' made the network but could not broadcast it: its driver timed out sending the network\u2019s beacon, a known weakness of some Realtek USB adapters when they host a network. So it was removed again, and nothing else changed. Unplug the adapter, plug it back in and press Check again; if it fails the same way, this adapter cannot host the back door on this firewall.','mut'));
      if(ws.cannot_host && ws.cannot_host.length) wc.append(el('p','The Wi-Fi card '+ws.cannot_host.join(', ')+' cannot host a network: the firewall\u2019s system refused to make one on it (some cards, Intel\u2019s among them, can only join a network, not offer one). Nothing was changed, and trying again will not help with this card. It can still join your phone\u2019s hotspot as backup internet.','mut'));
      wc.append(el('p','To have a back door, plug in a USB Wi-Fi adapter that the system supports for hosting. The reminder for the back door stops for this card and comes back by itself when a new card shows up.','mut'));
      const rep=el('details'); rep.append(el('summary','What the firewall said')); String(ws.report||'').split('\n').forEach(l=>rep.append(el('div',l||'\u00a0','mut'))); wc.append(rep);
    }
    else if(ws.state==='failed'){
      wc.append(el('p','The firewall tried and could not bring the Wi-Fi up, so it removed it again and changed nothing else. What it found:','mut'));
      const rep=el('div',undefined,'scroll'); String(ws.report||'').split('\n').forEach(l=>rep.append(el('div',l||'\u00a0','mut'))); wc.append(rep);
      wc.append(el('p','You can try again, or press Do this later: nothing else in the setup depends on it.','mut'));
    }
    else if(ws.command){
      if(ws.earlier_report){
        wc.append(el('p','Last time the firewall said:','mut'));
        const prev=el('div',undefined,'scroll'); String(ws.earlier_report).split('\n').forEach(l=>prev.append(el('div',l||'\u00a0','mut'))); wc.append(prev);
      }
      const box=el('div',undefined,'scroll'); box.append(el('code',ws.command)); wc.append(box);
      wc.append(el('p',ws.state==='closed'?'That line has expired. Make a new one.':'Paste it at the firewall\u2019s shell (choose 8, then type sh). The Wi-Fi name and password show here once the firewall says it worked.','mut'));
    }
    if(ws.state!=='running'){ const nohost=ws.state==='failed'&&((ws.cannot_host&&ws.cannot_host.length)||(ws.no_beacon&&ws.no_beacon.length)); const b=el('button',(ws.no_card||nohost)?'Check again':(ws.command||ws.state==='failed')?'Start over, with a new password':'Set it up, with passkey'); if(ws.no_card||nohost) b.className='quiet'; b.onclick=async()=>{ b.disabled=true; try{ await post('/api/wifi/prepare',{}); }catch(e){ fail(e); } await refresh(); }; wc.append(b); }
  }
  body.append(wc);
  await hotspotCard(body, bs);                                  // the phone's hotspot, offered right under the back door
  // Watch quietly: the page is redrawn only when something changed, so the line can be read and copied.
  clearTimeout(ui.wayT);
  const watch=()=>{ ui.wayT=setTimeout(async()=>{
    if(!document.querySelector('[data-way]')) return;
    try{ const b2=await get('/api/box/state'), w2=await get('/api/wifi/state');
      if(b2.connected!==bs.connected||w2.done!==ws.done||w2.state!==ws.state||b2.state!==bs.state||b2.note!==bs.note||JSON.stringify(b2.port||null)!==JSON.stringify(bs.port||null)||!!b2.can_open_port!==!!bs.can_open_port){ await refresh(); return; }
      if(!bs.connected && bs.command){ const s2=await get('/api/ssh/state'); if(!!s2.on!==!!(bs.ssh&&bs.ssh.on)){ await refresh(); return; } } }catch(e){}
    watch(); },3000); };
  if(!(bs.connected && ws.done)) watch();
  // BUILD 504 (the maintainer: "everything completed - user gets a do this later button (confusing)"): when no card here can host
  // the back door, there is nothing to do later; the bar says so and carries on.
  const cannot=!ws.done && ws.state==='failed' && (ws.no_card || (ws.cannot_host&&ws.cannot_host.length) || (ws.no_beacon&&ws.no_beacon.length));
  const skip=el('button',ws.done?'Continue':cannot?'Continue without it':'Do this later', (ws.done||cannot)?'':'quiet'); skip.onclick=()=>mark('wayback', ws.done?'done':'skip');
  body.append(bar(ws.done?'You have a way back in.':cannot?'No Wi-Fi card on this firewall can host the back door right now. Nothing else depends on it; the cable and your access card are the way in.':'You will be reminded at the top of the manager until it is set up.', skip));
}

// When the firewall already has its internet port and its home port assigned, Pazuzu saves that mapping itself (see
// auto_zones) and skips the ports page. The page still shows when something is missing or unclear.
async function autoZones(st){
  if(ui.autoZoned) return false; ui.autoZoned=true;
  try{ const z=await post('/api/zones/auto',{}); return !!z.done; }catch(e){ return false; }
}
function adminStep(body, st, at){
  body.append(backLink('admin'));
  body.append(head(at||1,'Your own admin sign-in','Pazuzu has its own limited users. You also need a sign-in of your own, so the factory root account can be shut.', !!at));
  body.append(means('every firewall ships with the same well-known account, root. Your own sign-in, plus a one-time code from an authenticator app, means only you can change it, and the factory account can be shut.'));

  const wr=writeResult(st,['write-user','write-root-off','write-root-password','write-undo','write-otp-server','write-otp-switch','write-admin-finish']); if(wr) body.append(wr);
  { const f=adminFlow(st); if(f) body.append(f); else body.append(el('p', st.root_off ? 'Your admin sign-in is set and root is off.' : 'Your admin sign-in is set and root has its own new password.','mut')); }
  if(st.admin_user && !st.root_off){
    // To test with a fresh user: Pazuzu forgets the one it remembers (nothing on the firewall changes) and the steps start again.
    const again=el('button','Make a different user','quiet'); again.dataset.adminAgain='1';
    again.onclick=()=>act(again, async()=>{ await post('/api/admin/forget',{}); ui.credsOk=false; ui.otpOk=false; ui.otp=null; ui.proved=false; ui.consoleProved=false; ui.otpName=''; ui.adminPw=''; });
    body.append(bar('Pazuzu remembers '+st.admin_user+' as your sign-in. To try a new one, it forgets that (the user stays on the firewall) and the steps start again.', again));
  }
  const hd=handoff('admin',{title:'Make it, then prove it', steps:[
    'Open the firewall’s Users page (the button) and add a user in the admin group, with a new name and a strong password you choose.',
    'Recommended: add a one-time code. That needs a login server of type Local + Timebased One Time Password (name Pazuzu OTP, token length 6, time window and grace period empty, reverse token order ticked), the code tested in System, Access, Tester, and then System, Settings, Administration, Authentication set to it. The cards above walk through each of these.',
    'Open a second window and sign in with the new user. If a code is needed, type your password followed by the code, with nothing between.',
    'Only when that works, press the button below.',
    'Then switch root off: the card above does it for you, with your passkey. Or do it by hand on the Users page (edit root, tick Disabled).'],
    link:'/ui/auth/user', linkLabel:'Open Users',
    note:'The Pazuzu users use keys, not passwords, so they are not affected by the code.'});
  const fc=el('div',undefined,'card'); fc.append(el('h2','Fill in the form like this'));
  const ft=el('table'); [
    ['Username','A new name you choose. Not root, not admin.'],
    ['Password','A long one that only you know.'],
    ['Group membership','admins. That gives every web page; nothing more is needed.'],
    ['Effective privileges','Leave them as they are. The admins group already gives them. Extra ones only widen what this user can do.'],
    ['Login shell','/bin/sh. Without a shell this user cannot sign in at the firewall\u2019s own screen and keyboard, and root goes off later.'],
    ['OTP seed','Paste the seed from the one-time code card above. If the field will not take it, tick Generate new secret instead, save, open the user again and scan the firewall\u2019s own QR code.'],
    ['Everything else','Leave it alone.']].forEach(r=>{ const tr=el('tr'); tr.append(el('th',r[0]), el('td',r[1])); ft.append(tr); });
  fc.append(ft, el('p','Names on the firewall\u2019s page can differ a little between versions.','mut'));
  if(!ui.phone){ const fold=el('details',undefined,'card'); fold.append(el('summary','Prefer the firewall\u2019s own form? Open the steps and the form table')); fold.append(hd, fc); body.append(fold); }   // BUILD 480: a phone has no second window for it
  const ok=el('button','Continue'); ok.onclick=()=>mark('admin','done');
  const no=el('button','Not now','quiet'); no.onclick=()=>mark('admin','skip');
  body.append(st.root_secured ? bar('', ok) : bar('Skipping leaves the factory account as your only sign-in.', no));
}

// BUILD 480: your own admin from the app on a Hanbi. Two things are asked: a name and a password, then the 6 digits from
// the authenticator app once it has scanned the code on the box's screen. The box does the rest in one job and checks
// each part (/api/admin/finish): the user with its code, the login server, the proof that the firewall lets you in with
// the password and the code, the web page asking for the code, sudo for the console menu, then root off.
// Returns null for the name-and-password card (the ordinary one, below in adminFlow).
function phoneAdmin(st, c, title){
  const j=st.job||{};
  if(j.kind==='write-admin-finish' && j.state==='failed' && ui.afSeen!==j.id){ ui.afSeen=j.id; ui.otpOk=false; }   // type a fresh code to try again
  const have=!!(ui.otp && (ui.adminPw||'').length>=12 && (ui.otpName||'').trim());
  if(st.admin_user && !have){
    title(1,'Start your sign-in again');
    c.append(el('p','Setting up '+st.admin_user+' stopped before it finished, and this app no longer holds its password and code (they are never kept). Choose a new user name and password. '+st.admin_user+' stays on the firewall unused; you can remove it later.','mut'));
    const again=el('button','Start again'); again.onclick=()=>act(again, async()=>{ await post('/api/admin/forget',{}); ui.credsOk=false; ui.otpOk=false; ui.otp=null; ui.otpName=''; ui.adminPw=''; });
    c.append(again); return c;
  }
  if(!ui.credsOk) return null;
  if(!ui.otpOk){
    title(2,'Add a one-time code');
    if(!ui.otp){
      if(ui.otpMakeErr){ const again=el('button','Try again'); again.onclick=()=>{ ui.otpMakeErr=false; refresh().catch(fail); };
        c.append(el('p','The code could not be made just now.','mut'), again); return c; }
      if(!ui.otpMaking){ ui.otpMaking=true;
        post('/api/otp/new',{account:(ui.otpName||'').trim()}).then(r=>{ ui.otp=r; ui.otpShown=false; }).catch(e=>{ ui.otpMakeErr=true; fail(e); }).then(()=>{ ui.otpMaking=false; refresh().catch(fail); }); }
      c.append(el('p','Putting the code on your Hanbi\u2019s screen\u2026','mut')); return c;
    }
    ui.boxQr={qr: ui.otp.uri, qr_words:'Scan with your authenticator app', title:'Your own admin sign-in',
      steps:stepList([['Choose a user name and password','done'],['Scan this code with your authenticator app','now'],['Type the 6 digits in the app and press Check','todo']])};
    if(!ui.otpShown){ ui.otpShown=true; tellBox({step:8, of:LIGHT_STEPS.length, title:'Add a one-time code', do:'Scan this with your authenticator app, then type the 6-digit code it shows into the app.', qr:ui.boxQr.qr, qr_words:ui.boxQr.qr_words, steps:ui.boxQr.steps}); }
    const out=el('div');
    renderOtp(out, ui.otp, {compact:true, onScreen:true, onMatch:()=>{
      ui.boxQr=null; tellBox({step:8, of:LIGHT_STEPS.length, title:'Your own admin sign-in', do:'Code checked. Finishing your sign-in.'});
      act(null, async()=>{ try{ await post('/api/admin/finish',{name:(ui.otpName||'').trim(), password:ui.adminPw||'', seed:ui.otp.seed, code:ui.otpCode||''}); }
        catch(e){ ui.otpOk=false; throw e; } }); }});      // refused before it started (a code that just ran out, say): type the next one
    c.append(out);
    const back=el('button','Change the name or password','quiet'); back.onclick=()=>{ ui.credsOk=false; ui.otp=null; ui.otpOk=false; ui.boxQr=null; refresh().catch(fail); };
    c.append(back); return c;
  }
  title(2,'Finishing your sign-in'); c.append(el('p','The box is making your admin and checking each part\u2026','mut')); return c;
}

// The installer account form. Used on the plugins page and on the admin page, so every account is made in one place.
function installerForm(c, why, after){
  c.append(el('p',why,'mut'));
  const un=el('input'); un.type='text'; un.autocomplete='off'; un.value='root'; un.placeholder='User name (usually root)';
  const pw=el('input'); pw.type='password'; pw.autocomplete='off'; pw.placeholder='Your firewall password (used once, not saved)';
  const lab=el('label'); const cb=el('input'); cb.type='checkbox'; cb.checked=false; lab.append(cb, document.createTextNode(' Brand-new firewall: use the factory password'));   // BUILD 498: starts unticked; by the installer step the password is usually yours, not the factory one
  const go=el('button','Create the installer account');
  go.onclick=()=>act(go, async()=>{ const pass=cb.checked?null:pw.value; pw.value=''; await post('/api/enroll',{role:'installer',use_default:cb.checked,password:pass,fingerprint:null,username:cb.checked?null:un.value.trim()}); if(after) await after(); });
  c.append(lab, un, pw, go);
}

// Zenarmor's own setup is five screens on the firewall. This says what each one asks and what to pick, taken from Zenarmor's
// and OPNsense's documentation. Zenarmor does its own hardware check on screen 2 and has the last word.
function zenarmorWalk(hw){
  const c=el('div',undefined,'card'); c.dataset.zenWalk='1';
  c.append(el('h2','Setting up Zenarmor: what to pick on each screen'),
    el('p','Zenarmor does not run until you finish its own setup on the firewall. It has five screens. This is what each one asks. The words in quotes are the buttons and options as Zenarmor shows them.','mut'));
  // The setup page itself, right under the heading: it opens in a new tab so these notes stay here beside it.
  const top=el('div',undefined,'btnrow'); const open=fwLink('Open Zenarmor setup','/ui/zenarmor/app/wizard'); open.dataset.zenOpen='1'; top.append(open); c.append(top);
  const ol=el('ol');
  const item=(title, what, ...notes)=>{ const li=el('li'); li.append(el('strong',title+'. '), document.createTextNode(nopk(what))); notes.forEach(n=>li.append(means(n))); ol.append(li); };
  const pick = hw && hw.can && hw.database==='elasticsearch'
    ? 'This firewall has the memory and processor Zenarmor names for the fuller one, so “Local ElasticSearch DB” is a good pick. “SQLite Database” is fine if you would rather keep it light.'
    : hw && hw.can && hw.database==='sqlite'
      ? 'This firewall is on the small side for the fuller one, so “SQLite Database” is the pick.'
      : '“SQLite Database” is the light pick. “Local ElasticSearch DB” wants about 8 GB of memory.';
  item('Before you open it','On the firewall, open Interfaces, Settings. Hardware CRC, Hardware TSO and Hardware LRO should be ticked (here, ticked means switched off), and VLAN Hardware Filtering should be on Disable. A new firewall already has them this way, so most people change nothing. If you do change one, it takes effect after a restart.',
    'Zenarmor reads the traffic straight off the network card. The card’s own shortcuts (doing checksums and joining packets itself) get in the way of that, so Zenarmor needs them off.');
  item('Screen 1, Welcome','Tick the box for the terms of service and privacy policy, then press “I Agree”.',
    'These are Zenarmor’s own terms, between you and Zenarmor.');
  item('Screen 2, Hardware check and reporting database','Zenarmor checks this machine and says compatible, low-end or incompatible. It does not go on if it is incompatible. Then pick where it keeps its reports. '+pick+' You cannot change this after you finish. If you pick a local one, press “Install Database”, wait for it to finish, then press “Next”.',
    'Reports are the lists and charts of which apps and sites your devices use. “Local ElasticSearch DB” keeps them on this firewall with richer search and charts; it wants more memory and is not offered to low-end machines. “SQLite Database” is the light one, also on this firewall, for up to about 100 devices. “Remote ElasticSearch DB” keeps them on another server you run, which most homes do not have.');
  item('Screen 3, Deployment mode and ports','Keep the mode Zenarmor picked (“Routed mode”) and leave CPU pinning alone. Move the port your own devices plug into (your Trusted Network port, the physical port and not a VLAN on it) over to the protected side, and leave the internet side alone. Then open “Set Security Zone” and tag the protected port “lan”. Press “Next”.',
    'Routed mode puts Zenarmor on the firewall itself, so it can block as well as report. The other modes are for special set-ups. CPU pinning gives Zenarmor’s packet work a processor core of its own so it runs smoother.',
    'Zenarmor’s own advice is to protect the inside (LAN) side. The tag tells it which side is yours. A wrong tag, such as the internet port tagged “lan”, makes outside addresses look like your own devices in its reports.');
  item('Screen 4, Subscription','Pick one: the free edition (“Get Me the Free Edition”; an email is optional), the 15-day free trial of the Business subscription (it asks for an email and no card), or “I already have my subscription key”. Press “Next”.',
    'The free edition is free for good. The trial gives you the Business edition for 15 days. A key is for people who already bought a subscription.');
  item('Screen 5, Finish','Press “Complete”.',
    'Zenarmor saves these choices and starts. Then come back here and press the button below.');
  c.append(ol);
  const done=el('button','I finished Zenarmor’s setup','quiet'); done.dataset.zenDone='1'; done.onclick=()=>mark('zenarmor','done');
  const row=el('div',undefined,'btnrow'); row.append(done); c.append(row);
  return c;
}
async function pluginsCard(body, st, job){
  const c=el('div',undefined,'card'); c.append(el('h2', ui.pluginOffered===false ? 'Plugins: Zenarmor' : 'Plugins: Zenarmor and the Pazuzu plugin'));
  if(!st.installer_user){
    installerForm(c, 'Installing a plugin needs an account that can open every page. It is for testing: your passkey approves it, the firewall closes it after a day, and you should delete it on the firewall’s Users page when you are done. Its key stays on this device.');
    body.append(c); return;
  }
  if(job && job.kind==='plugin-install' && job.state==='done'){ c.append(el('h2','Installed'), jobCard(job)); }
  let list=null, why='';
  const busyP=busyCard('Reading the plugin list…'); c.append(busyP);
  let unread='', usb=[]; try{ const pr=await get('/api/plugins'); list=pr.plugins; unread=pr.unread||''; usb=pr.usb_ports||[]; }catch(e){ why=(e&&e.message)||'Could not read the plugin list.'; }
  busyP.remove();
  if(list===null){ c.append(el('p',why,'mut')); }
  else {
    let bx={connected:false}; try{ bx=await get('/api/box/state'); }catch(e){}
    const has=(n)=>list.find(p=>p.name===n);
    const zen=has('os-sensei'), repo=has('os-sunnyvalley');
    if(unread && zen && zen.installed) c.append(el('p','The firewall is still busy after the install, so its package list could not be read just now. Zenarmor went on; its own lines above say so.','mut'));   // BUILD 527
    else if(unread) c.append(el('p','Could not read the firewall\u2019s package list ('+unread+') but you can still press Install: the firewall will say if it does not have the package.','mut'));
    if(zen&&zen.installed){
      if(!ui.done.zenarmor){                // handled: the walkthrough and its link leave the screen
        let hw=null; try{ hw=await get('/api/hardware'); }catch(e){ hw=null; }
        c.append(zenarmorWalk(hw));        // its setup button sits in the walkthrough, under the heading
      }
    }
    if(usb.length) c.append(el('p','Heads-up: this firewall\u2019s ports include USB network adapters ('+usb.join(', ')+'). Zenarmor takes over the ports it protects, and on one firewall like this it left the network unreachable. Think twice before installing it here.','mut'));
    const rows=[
      ['Zenarmor','Sees which apps and sites devices use, with reports. Check its hardware needs first, and make sure hardware offloading is off under Interfaces, Settings.',
        zen&&zen.installed ? 'installed' : (zen||repo||unread) ? 'zenarmor' : null],
      ['Pazuzu plugin','The guard and live data screen that run on the firewall itself. It goes on with one pasted line, in the step called A safe way back in.', bx.connected ? 'installed' : 'box']];
    if(ui.pluginOffered===false) rows.pop();      // BUILD 513: no plugin in beta 1
    c.append(el('p','Zenarmor is a separate product from Sunny Valley Networks, with its own terms, which you accept when you set it up. Pazuzu only starts the install through your firewall\u2019s own package system.','mut'));   // BUILD 532
    rows.forEach(([title,what,act2])=>{
      const row=el('div',undefined,'vrow'); const m=el('div',undefined,'grow'); m.append(el('div',title,'vt'), el('div',what,'mut')); row.append(m);
      if(act2==='installed') row.append(el('span','Installed','chip'));
      else if(act2==='box'){ const b=el('button','Put it on the firewall'); b.onclick=()=>{ ui.force='wayback'; refresh().catch(fail); }; row.append(b); }
      else if(act2){ const b=el('button','Install, with passkey'); b.onclick=()=>act(b, async()=>{ await post('/api/plugin/install',{name:act2}); }); row.append(b); }
      else row.append(el('span','Not installable here yet','chip mute'));
      c.append(row);
    });
  }
  const again=el('button','Check again','quiet'); again.onclick=()=>refresh().catch(fail);
  const r=el('div',undefined,'btnrow'); r.append(fwLink('Open Firmware','/ui/core/firmware'), again);
  c.append(r);
  body.append(c);
}

function resolverCard(body, st){
  const r=st.resolver; if(!r) return;
  if(!ui.resolverOpen){                          // Quad9 unless changed (decided 29 Oct 2026): one line, with Change
    const o=r.options.find(x=>x.id===(r.choice||'quad9'))||{name:r.choice};
    const c=el('div',undefined,'card'); c.append(el('h2','Where your firewall asks for names'));
    c.append(el('p',(r.choice?'Chosen: ':'')+o.name+(r.choice?'':' (the default)')+', asked over DNS over TLS (encrypted).','mut'));
    const ch=el('button','Change','quiet'); ch.onclick=()=>{ ui.resolverOpen=true; refresh(); };
    c.append(ch); body.append(c); return;
  }
  const c=el('div',undefined,'card'); c.append(el('h2','Where your firewall asks for names'));
  c.append(el('p','Your devices ask the firewall. The firewall asks one outside service for the answer. Pick one. This is only saved now; the manager switches it on once it can read the setting back.','mut'));
  c.append(means('every time a device opens a website, the firewall asks the service you pick to turn the name into an address. That service sees which names your home looks up, so pick the one you trust.'));
  const note=el('p', r.choice ? 'Chosen: '+(r.options.find(o=>o.id===r.choice)||{}).name : 'Not chosen yet.', 'mut');
  r.options.forEach(o=>{
    const l=el('label',undefined,'opt '+(r.choice===o.id?'sel':'')); const rb=el('input'); rb.type='radio'; rb.name='resolver'; rb.checked=r.choice===o.id;
    const t=el('div'); t.append(el('div',o.name,'vt'), el('div',o.says,'mut'));
    rb.onchange=()=>act(null, async()=>{ await post('/api/resolver',{choice:o.id}); ui.resolverOpen=false; });
    l.append(rb,t); c.append(l);
  });
  c.append(note);
  if(r.choice){ const sc=el('div',undefined,'scroll'); sc.append(el('p','How to check it later','vt')); const ul=el('ul'); r.checks.forEach(x=>ul.append(el('li',x))); sc.append(ul); c.append(sc); }
  body.append(c);
}

function blocklistCard(body, st){
  const b=st.blocklists; if(!b) return;
  const saved=b.choice;
  if(saved && !ui.bl && !ui.blOpen){  // chosen and saved: one line says what, with a way to change it
    const c=el('div',undefined,'card'); c.append(el('h2','Block lists'));
    c.append(el('p','Chosen: '+((b.levels.find(o=>o.id===saved.main)||{}).name||saved.main)+(saved.extras.length?' and '+saved.extras.length+' add-on'+(saved.extras.length>1?'s':''):'')+'.','mut'));
    const ch=el('button','Change','quiet'); ch.onclick=()=>{ ui.blOpen=true; refresh(); };
    c.append(ch); body.append(c); return;
  }
  if(!ui.bl) ui.bl={main:saved?saved.main:null, extras:new Set(saved?saved.extras:[]), tif:saved&&saved.tif_size?saved.tif_size:'full'};
  const c=el('div',undefined,'card');
  const paint=()=>{ c.replaceChildren(); c.append(el('h2','Block lists'));
  c.append(el('p','Block lists stop your devices reaching known ad, tracker and scam sites. Pick one main list. It is required. Other lists are optional. This is only saved now; the manager switches them on once it can read the setting back.','mut'));
  c.append(means('the firewall will not answer when a device asks for a name on these lists, so those ads, trackers and scam sites do not load on any of your devices. A stricter level catches more, and is more likely to block something you wanted.'));
  c.append(el('p','Main list (pick one level, '+b.author+')','vt'));
  b.levels.forEach(o=>{
    const l=el('label',undefined,'opt '+(ui.bl.main===o.id?'sel':'')); const rb=el('input'); rb.type='radio'; rb.name='bl-main'; rb.checked=ui.bl.main===o.id;
    const t=el('div'); t.append(el('div',o.name+(o.id===b.recommended?' (the author\u2019s pick for most people)':'')+' - '+o.size,'vt'), el('div',o.says,'mut'));
    rb.onchange=()=>{ ui.bl.main=o.id; paint(); };
    l.append(rb,t); c.append(l);
  });
  c.append(el('p','Add-ons (optional)','vt'));
  b.extras.forEach(o=>{
    const l=el('label',undefined,'opt '+(ui.bl.extras.has(o.id)?'sel':'')); const cb=el('input'); cb.type='checkbox'; cb.checked=ui.bl.extras.has(o.id);
    const t=el('div'); t.append(el('div',o.name,'vt'), el('div',o.says,'mut'));
    if(o.overlaps) t.append(el('div',o.overlaps,'mut'));
    cb.onchange=()=>{ if(cb.checked) ui.bl.extras.add(o.id); else ui.bl.extras.delete(o.id); paint(); };
    l.append(cb,t); c.append(l);
    if(o.kind==='sizes' && ui.bl.extras.has(o.id)){
      const sel=el('select'); b.tif_sizes.forEach(z=>{ const op=el('option',z.name+' - '+z.size); op.value=z.id; if(z.id===ui.bl.tif) op.selected=true; sel.append(op); });
      sel.onchange=()=>{ ui.bl.tif=sel.value; };
      c.append(sel);
    }
  });
  const ul=el('ul'); b.warnings.forEach(w=>ul.append(el('li',w))); c.append(ul);
  const note=el('p', saved ? 'Saved: '+((b.levels.find(o=>o.id===saved.main)||{}).name||'')+(saved.extras.length?' and '+saved.extras.length+' add-on'+(saved.extras.length>1?'s':''):'') : 'Not chosen yet.', 'mut');
  const go=el('button','Save my choice'); go.disabled=!ui.bl.main;
  go.onclick=()=>act(go, async()=>{ await post('/api/blocklists',{main:ui.bl.main, extras:Array.from(ui.bl.extras), tif_size:ui.bl.tif}); ui.bl=null; ui.blOpen=false; });
  c.append(note, go); };
  paint(); body.append(c);
}

function tipsCard(body, st){
  if(!st.tips || !st.tips.length) return;
  const c=el('div',undefined,'card'); c.append(el('h2','Good to know'));
  const sc=el('div',undefined,'scroll'); const ul=el('ul'); st.tips.forEach(t=>ul.append(el('li',t.text))); sc.append(ul); c.append(sc);
  body.append(c);
}

async function allsetStep(body, st, job){
  body.append(backLink('allset'));
  body.append(head(4,'How your firewall looks right now'));
  const busy=busyCard('Reading your firewall…'); body.append(busy);
  const [plR, idsR, fwR, vR, inR, shR] = await Promise.allSettled([get('/api/plan'), get('/api/ids'), get('/api/firmware'), get('/api/verify'), get('/api/internet'), get('/api/shields')]);
  busy.remove();
  const shv = shR.status==='fulfilled' ? shR.value : null;
  const sf = (shv && shv.ready && shv.flags) ? shv.flags : null;     // the three shields read from the firewall itself; null when they could not be
  const allOn = plR.status==='fulfilled' && plR.value.stages.length>0 && plR.value.stages.every(x=>x.status==='done');
  const ids = idsR.status==='fulfilled' ? idsR.value : {state:'unknown',detail:'Not checked yet.'};
  const fw = fwR.status==='fulfilled' ? fwR.value : null;
  const open=[];
  if(!allOn) open.push('The safety rules are not switched on.');
  if(fw && fw.state==='update') open.push('A firmware update is waiting.');
  const ar = inR.status==='fulfilled' && inR.value.after_rules; if(ar && ar.after===false && ar.line) open.unshift(ar.line);
  // BUILD 549 (the maintainer's run, 16 Nov 2026; 17 Nov: soften it): a skipped Admin step is the person's own choice, not a fault, so
  // this is a reminder of what is still to do, not "Error:" in the colour of something broken.
  if(!ui.done.admin) body.append(el('div','Still to do: an admin sign-in of your own. The factory account is still the only way in.'+(ui.managerOpen ? ' The management app will flag this until it is fixed.' : ' Run the setup steps again to make one: the Admin step.'),'card'));
  if(!ui.done.admin) open.push('Your own admin sign-in isn’t confirmed, so the factory account is still your way in.');
  if(ui.skipped.reach==='waiting') open.push('Reach home from outside is waiting for the internet: the home name and the VPN are not set up yet.');
  else if(!st.vpn_instance) open.push('The VPN is not set up yet. The manager has a VPN tab for it.');
  if(sf){ if(!sf.ips) open.push('Packet inspection (IPS) is off.'); }
  else if(ids.state!=='on') open.push(ids.state==='unknown' ? 'Packet inspection (IPS) isn’t checked.' : 'Packet inspection is '+(ids.state==='watching'?'only watching':'off')+'.');
  if(sf){ if(!sf.block) open.push('Block lists are off.'); if(!sf.ads) open.push('Ad lists are off.'); }
  else open.push('Block lists and ad lists aren’t checked yet'+(shv&&shv.why?' ('+shv.why+')':'')+'.');
  // The level counts only what was really read: a shield that could not be checked is never counted as down.
  const shState=[allOn?1:0, sf?(sf.ips?1:0):(ids.state==='on'?1:ids.state==='unknown'?null:0), sf?(sf.block?1:0):null, sf?(sf.ads?1:0):null];
  let lvl=0; while(lvl<SHIELDS.length && shState[lvl]===1) lvl++;
  const lvKnown = lvl===SHIELDS.length || shState[lvl]!==null;
  const lv=LEVELS[lvl];   // the happiness colour/tint lives in the manager (the happiness index), not in the wizard
  const top=el('div',undefined,'card lvcard');
  top.append(el('div', (lvl===4 && !open.length) ? 'All set' : 'Set up, with '+open.length+' thing'+(open.length===1?'':'s')+' still open','lvname'), el('p', lvKnown ? lv.name+' · '+lv.mood : 'Protection level: not all of it could be read yet','mut'));
  if(lvl===0 && lvKnown) top.append(el('p',lv.says,'lvsay'));
  const sc=el('div',undefined,'scroll'); const ul=el('ul'); open.forEach(t=>ul.append(el('li',t))); sc.append(ul); top.append(sc);
  // BUILD 480: on the phone the next press switches these on, so a list of what is still off is only noise here
  if(!ui.phone) body.append(top);
  else body.append(el('p','One press: block lists, ad lists and packet inspection on, encrypted name lookups, IPv6 and Secure Shell off. Each part is tested. Then your access card.','mut'));
  const info=el('div',undefined,'card'); info.append(el('h2','Your firewall'));
  const il=el('ul');
  const ac=st.access||{};
  (ui.phone ? [] : [['The address Pazuzu uses', ui.base||'its address'],
   ['Its page right now', ac.host ? ac.host+', port '+ac.web_port_now : 'its address'],
   ['A new port for its page', ac.web_port ? ac.web_port+' (planned: not switched yet)' : 'not planned yet'],
   ['Secure shell', 'on your access card, next']]).concat([
   ['Your admin sign-in', ui.done.admin?'the one you made':'not set up'],
   ['Packet inspection', ids.detail],
   ['Lists', sf ? ('block lists '+(sf.block?'on':'off')+', ad lists '+(sf.ads?'on':'off')) : 'not read yet'],
   ['Wi-Fi backup', ui.done.hotspot?'set up':'not set up']]).filter(([a])=>!(a==='Wi-Fi backup' && ui.pluginOffered===false)).forEach(([a,b])=>il.append(el('li',a+': '+b)));   // BUILD 513: the backup is the plugin's
  const isc=el('div',undefined,'scroll'); isc.append(il); info.append(isc); if(!ui.phone) body.append(info);
  // What the person has nothing to decide about goes into one fold, right under the list of where everything is.
  const details=[];
  if(ids.state!=='on') details.push(el('p','Up your security: coming in the management app. It will turn on packet inspection and the lists for you.','mut'));
  const v = vR.status==='fulfilled' ? vR.value : null;
  if(v){
    const card=el('div',undefined,'card'); card.append(el('h2','What we checked'));
    const names={good:'Good',attention:'Needs a look',not_yet:'Not yet',unknown:'Unknown'};
    const scr=el('div',undefined,'scroll');
    v.rows.forEach(r=>{ const row=el('div',undefined,'vrow'); const m=el('div',undefined,'grow'); m.append(el('div',r.title,'vt'), el('div',r.detail,'mut')); row.append(m, el('span',r.waiting?'Waiting':(names[r.status]||r.status),'chip '+(r.status==='good'?'':(r.status==='unknown'||r.waiting)?'mute':'warn'))); scr.append(row); });
    card.append(scr); details.push(card);
  }
  { const tt=el('div'); tipsCard(tt, st); details.push(...tt.children); }
  details.push(checkCard(st));
  { const left=el('div',undefined,'card'); left.append(el('h2','Still to do, in the manager'));
    const lul=el('ul'); [['Switch the rules on','one guarded step at a time, with a countdown to keep or undo'],['Backup internet','a phone by USB, or a Wi-Fi card; the manager checks it step by step'],['Packet inspection and block lists','turned on for you once the app can read them'],['Alerts','who gets told when something is blocked']].forEach(([t,w])=>lul.append(el('li',t+': '+w))); left.append(lul); details.push(left); }
  if(!ui.phone) body.append(fold('what was checked, what this firewall supports, good to know and what is left for the manager', ...details));
  if(ui.phone){ const hold=el('div'); resolverCard(hold, st); blocklistCard(hold, st);       // BUILD 480: the recommended ones unless changed
    if(hold.children.length){ const f=fold('the name server and the block lists (the recommended ones unless you change them)', ...Array.from(hold.children));
      if(ui.resolverOpen || ui.blOpen || ui.bl) f.open=true; body.append(f); } }
  else { resolverCard(body, st); blocklistCard(body, st); }
  // BUILD 477: on the phone the extras (countries, a backup gateway, Zenarmor, root by hand) are the manager's, later
  if(!ui.phone){
  body.append(el('h2','Extras (optional)'));
  const wr=writeResult(st,['write-gateway','write-country-block','write-undo']); if(wr) body.append(wr);
  countryCard(body, st);
  { const adv=el('details',undefined,'card'); adv.append(el('summary','Advanced: add a backup gateway by hand (most people do not need this)')); adv.append(gatewayCard(st)); body.append(adv); }
  await pluginsCard(body, st, job);
  if(!st.root_secured && !ui.done.rootoff) rootCard(body);
  }
  const needConsent=!(ui.legal&&ui.legal.consent_answered), needTerms=!(ui.legal&&ui.legal.terms);
  const ch=el('div',undefined,'card'); ch.append(el('h2','Help us make this better'));
  ch.append(el('p','Come on, help us make this better. Each switch below is yours to turn on, and each is off until you do. Nothing leaves this box unless you press Send. A switch that is on only lets Pazuzu write that kind of report here, for you to look at and send from the manager\u2019s Reports page. Your choice is kept here and nothing else.','mut'));
  [['versions','Tell us which versions you run','Your Pazuzu, plugin and firewall versions, whether it is a Hanbi box, and the class of hardware (cores, memory, ports, Wi-Fi, Bluetooth, virtual). No addresses, names or settings.'],
   ['checks','Tell us how the checks come out','Only pass or fail for each check above, with no details.'],
   ['problems','Send a report when something breaks','An error code and the step it happened on. Never passwords, keys or rules.'],
   ['devices','Tell us what your smart devices needed','The maker and the port, so the next person\u2019s lights work on day one. Never which devices you have or their addresses.']].forEach(([k,t,d])=>{
    const l=el('label'); l.style.display='block'; l.style.margin='10px 0'; const cb=el('input'); cb.type='checkbox'; cb.checked=ui.consent[k];
    cb.onchange=()=>{ ui.consent[k]=cb.checked; };
    l.append(cb, document.createTextNode(' '+t)); const dd=el('div',d,'mut'); dd.style.marginLeft='24px'; ch.append(l,dd);
  });
  ch.append(el('p','You are only asked this once.','mut'));
  if(needConsent) body.append(ch);
  const tm=el('div',undefined,'card'); tm.append(el('h2','Terms'));
  const tsc=el('div',undefined,'scroll'); termsInto(tsc);

  tm.append(tsc);
  if(!needTerms) ui.terms=true;
  const tl=el('label'); const tcb=el('input'); tcb.type='checkbox'; tcb.checked=ui.terms; tl.append(tcb, document.createTextNode(' I accept these terms')); tm.append(tl);
  if(needTerms) body.append(tm);
  const bk=el('button','Back to safety settings','quiet'); bk.onclick=()=>{ ui.at='rules'; refresh().catch(fail); };
  // The last page is the access card on its own: where everything is, to print or save before going to the manager.
  // BUILD 477: Happy is the setup's last step: protection goes on here, then the access card. Leaving it is a choice
  // made afterwards, in the manager, not a default.
  const fin=el('button','Switch protection on and finish'); fin.disabled=!ui.terms;
  tcb.onchange=()=>{ ui.terms=tcb.checked; fin.disabled=!ui.terms; };
  fin.onclick=()=>act(fin, async()=>{ if(needTerms||needConsent) await post('/api/legal',{terms:ui.terms, consent: needConsent?ui.consent:null}); ui.happy=null; ui.at='happy'; });
  body.append(bar(ui.terms?'':'Accept the terms to finish.', ...[bk, fin].filter(Boolean)));
}

// BUILD 477: the setup's last step. Everything the manager's "Finish getting to Happy" and the shield slider's Normal
// would do, run here one after the other, each its own guarded job (tested, undone by itself if it fails). A part
// that has nothing to do is skipped; a part that stops can be tried again or left for the manager.
const HAPPY_PARTS=[
  ['shields','/api/happy/shields','shield-levels','Block lists, ad lists and packet inspection on'],
  ['finish','/api/happy/finish','happy-finish','Encrypted lookups, every network\u2019s DNS and time sent to the firewall, the lists refreshed nightly'],
  ['ipv6','/api/happy/ipv6','ipv6-off','IPv6 off everywhere'],
  ['ssh','/api/happy/ssh','ssh-fix','Secure Shell (SSH) off: the app and the box\u2019s screen are the way in']];
const HAPPY_SKIP=/already at that level|nothing (left|to do|more)|Nothing (left|to do|more)|all done|every.*already/i;
const HAPPY_SHORT={shields:'Block lists and inspection', finish:'Encrypted lookups and time', ipv6:'IPv6 off', ssh:'Secure Shell off'};
async function happyStep(body, st, job){
  body.append(head(4,'Switch protection on','The last step. Each part is switched on and tested; the access card comes after.'));   // BUILD 490: step 4 is 9 of 9 on the light path; the careful path said "9 of 4"
  if(!ui.happy){ ui.happy={left:null, i:0, lines:[], err:null, started:null}; }
  const h=ui.happy;
  if(h.left===null){
    body.append(busyCard('Reading what is still off\u2026'));
    const L=await get('/api/happy/left');
    h.left=HAPPY_PARTS.filter(p=>L[p[0]]);
    if(L.shields && !L.shields_ready) h.lines.push('The shields could not be set from here: '+(L.shields_why||'not ready')+'. The manager\u2019s slider does it.');
    return refresh();
  }
  const part=h.left[h.i];
  if(part && job && job.kind===part[2] && h.started===part[0] && job.state!=='running'){
    if(job.state==='failed' && !HAPPY_SKIP.test(job.error||'')){ h.err=job.error||'That did not work.'; }
    else { if(job.state==='done') h.lines.push(part[3]+': done'); h.i++; h.started=null; h.err=null; return refresh(); }
  }
  boxSteps(h.left.map((p,k)=>[HAPPY_SHORT[p[0]]||p[3], k<h.i?'done':k>h.i?'todo':h.err?'failed':'now']));   // 0.6.83
  const c=el('div',undefined,'card'+(h.err?' unsafe':''));
  c.append(el('h2', h.err ? 'One part stopped' : part ? 'Switching on\u2026' : 'Protection is on'));
  const ul=el('ul'); h.lines.forEach(t=>ul.append(el('li',t))); h.left.slice(h.i).forEach((p,k)=>ul.append(el('li',p[3]+(k===0 && !h.err ? ' (now)' : ''),'mut'))); c.append(ul);
  if(h.err){ c.append(el('p',h.err,'vt'));
    const again=el('button','Try again'); again.onclick=()=>act(again, async()=>{ h.err=null; });
    const skip=el('button','Leave it for the manager','quiet'); skip.onclick=()=>act(skip, async()=>{ h.lines.push(part[3]+': left for the manager'); h.i++; h.started=null; h.err=null; });
    c.append(bar('', again, skip)); body.append(c); return; }
  body.append(c);
  if(!part){
    let allOn=true;
    if(!ui.light){ try{ const pl=await get('/api/plan'); allOn=pl.stages.length>0 && pl.stages.every(x=>x.status==='done'); }catch(e){ allOn=true; } }
    const go=el('button', allOn ? 'Next: your access card' : 'Next: switch the rules on');   // BUILD 493: part 2's checks needed these parts first
    go.onclick=()=>act(go, async()=>{ ui.at = allOn ? 'access' : 'rules-on'; });
    body.append(bar(allOn ? '' : 'The rules are on your firewall, still switched off. Next they go on, one part at a time, each under your passkey.', go)); return; }
  if(h.started===part[0]) return;                 // its job is running: the page shows it
  h.started=part[0];
  try{ await post(part[1],{}); }catch(e){ if(HAPPY_SKIP.test(String(e.message||e))){ h.lines.push(part[3]+': already on'); h.i++; h.started=null; return refresh(); } h.err=String(e.message||e); return refresh(); }
  return refresh();
}

// BUILD 482 (the maintainer, 5 Nov 2026): Hanbi's own Wi-Fi. With an OpenWrt access point on the Home port, three networks are made
// on it (Home, Smart devices, Guest) with names and passwords the box makes, and its security done for the person: WPS
// off, WPA3 where it can, its IPv6 and its own address handing off, isolation on Smart devices and Guest. At most the
// access point's own password is asked, once. No access point: the person keeps their own Wi-Fi.
const HW_WORDS={trusted:['Home','Your phones, computers and tablets'], iot:['Smart devices','Lights, plugs, TVs, cameras'], guest:['Guest','Visitors: online only']};
async function homeWifiStep(body, st, job){
  body.append(head(5,'Your Wi-Fi','Hanbi can set up your Wi-Fi on an OpenWrt access point plugged into its Home port: three networks, with the access point\u2019s security done for you.',true));
  const hw=ui.hw||(ui.hw={found:null, plan:null, pw:'', pwGiven:false, err:'', looking:false, planning:false, started:false, done:null});
  const skipBtn=()=>{ const b=el('button','Skip: keep my own Wi-Fi','quiet'); b.onclick=()=>{ ui.hw=null; ui.boxQr=null; mark('homewifi','skipped'); }; return b; };
  if(hw.started && job && job.kind==='write-zone-vlans' && job.state==='running'){
    boxSteps([['Plug your access point into the Home port','done'],['Hanbi finds it','done'],['Three networks, set up for you','now']]); return; }
  if(hw.started && job && job.kind==='write-zone-vlans' && job.state==='failed'){
    hw.started=false; hw.err=job.error||'That did not work.'; }
  if(hw.started && job && job.kind==='write-zone-vlans' && job.state==='done'){ hw.started=false; hw.done=(job.result&&job.result.lines)||[]; }
  if(hw.done){
    let got=null; try{ got=await post('/api/homewifi/state',{}); }catch(e){ got=null; }
    const nets=(got&&got.networks)||[]; const home=nets.find(n=>n.zone==='trusted');
    const c=el('div',undefined,'card'); c.append(el('h2', got&&got.made ? 'Your Wi-Fi is on' : 'It stopped part way'));
    const ul=el('ul'); nets.forEach(n=>{ const w=HW_WORDS[n.zone]||[n.zone,'']; ul.append(el('li', w[0]+': '+n.ssid+' \u2014 '+w[1])); }); c.append(ul);
    const fold1=fold('what was done', (()=>{ const u=el('ul'); hw.done.forEach(t=>u.append(el('li',t))); return u; })());
    if(home && got.made){
      ui.boxQr={qr:home.join, qr_words:'Join '+home.ssid+' with your phone\u2019s camera', title:'Your Wi-Fi',
        steps:stepList([['Three networks, set up for you','done'],['Point your phone\u2019s camera at this code','now'],['Tap Join','todo']])};
      tellBox({step:5, of:LIGHT_STEPS.length, title:'Your Wi-Fi', do:'Join '+home.ssid+': scan this with your phone\u2019s camera.', qr:ui.boxQr.qr, qr_words:ui.boxQr.qr_words, steps:ui.boxQr.steps});
      c.append(el('p','To join '+home.ssid+', scan the code on your Hanbi\u2019s screen with this phone\u2019s camera. Your Hanbi keeps the passwords; its screen shows the code again later.','mut'));
    }
    c.append(el('p','To take the access point back: hold its reset button. It goes back to factory, with the password it came with.','mut'));   // BUILD 483
    body.append(c, fold1);
    const go=el('button','Continue'); go.onclick=()=>{ ui.boxQr=null; ui.hw=null; mark('homewifi','done'); };
    body.append(bar(got&&got.made ? 'Next: reach home from outside.' : 'Your zones are made; the access point can be finished later from the manager.', go)); return;
  }
  if(hw.found===null){
    if(!hw.looking){ hw.looking=true;
      post('/api/ap/find',{}).then(r=>{ hw.found=(r&&r.found)||[]; hw.why=(r&&r.why)||''; }).catch(e=>{ hw.found=[]; hw.why=String(e.message||e); })
        .then(()=>{ hw.looking=false; refresh().catch(fail); }); }
    boxSteps([['Plug your access point into the Home port','now'],['Hanbi finds it','todo'],['Three networks, set up for you','todo']]);
    body.append(busyCard('Looking for your access point\u2026')); return;
  }
  if(!hw.found.length){
    boxSteps([['Plug your access point into the Home port','now'],['Hanbi finds it','failed'],['Three networks, set up for you','todo']]);
    const c=el('div',undefined,'card'); c.append(el('h2','No OpenWrt access point found'));
    c.append(el('p','Plug your access point into the Home port of your Hanbi and give it a minute to start. It needs to run OpenWrt.','mut'));
    if(hw.why) c.append(el('p',hw.why,'mut'));
    const again=el('button','Look again'); again.onclick=()=>{ hw.found=null; refresh().catch(fail); };
    body.append(c, bar('Or keep your own Wi-Fi: it stays on your home network.', again, skipBtn())); return;
  }
  const apx=hw.found[0];
  if(!hw.plan){
    if(!apx.no_password && !hw.pwGiven){
      const c=el('div',undefined,'card'); c.append(el('h2','Your access point asks for its password'));
      c.append(el('p','Type the password for its own web page once. It\u2019s often on a sticker on the bottom. Your Hanbi uses it to set the access point up, then gives it a new one of its own that you never need to type.','mut'));
      if(ui.lastTb) tellBox(Object.assign({}, ui.lastTb, {do:'Type your access point\u2019s password on your phone. It\u2019s often on a sticker on the bottom.',
        steps:stepList([['Plug your access point into the Home port','done'],['Hanbi found it','done'],['Type its password on your phone','now'],['Three networks, set up for you','todo']])}));   // BUILD 483: the help on the box's screen too
      const pw=el('input'); pw.type='password'; pw.autocomplete='off'; pw.placeholder='Its password';
      const use=el('button','Use this password'); use.onclick=()=>{ hw.pw=pw.value; pw.value=''; hw.pwGiven=true; hw.err=''; refresh().catch(fail); };
      c.append(pw, use); body.append(c, bar('', skipBtn())); return;
    }
    if(!hw.planning && !hw.err){ hw.planning=true;
      post('/api/homewifi/plan',{ip:apx.ip, password:hw.pw}).then(r=>{ if(r && r.ok){ hw.plan=r; } else { hw.err=(r&&r.why)||'It could not be read.'; if(r && r.needs_password){ hw.pwGiven=false; apx.no_password=false; } } })
        .catch(e=>{ hw.err=String(e.message||e); }).then(()=>{ hw.planning=false; refresh().catch(fail); }); }
    if(hw.err){
      const c=el('div',undefined,'card unsafe'); c.append(el('h2','Your access point could not be set up from here'), el('p',hw.err,'mut'));
      const again=el('button','Try again'); again.onclick=()=>{ hw.err=''; refresh().catch(fail); };
      body.append(c, bar('', again, skipBtn())); return;
    }
    body.append(busyCard('Reading your access point\u2026')); return;
  }
  boxSteps([['Plug your access point into the Home port','done'],['Hanbi found it: '+(hw.plan.model||apx.ip),'done'],['Three networks, set up for you','now']]);
  const c=el('div',undefined,'card'); c.append(el('h2','Found: '+(hw.plan.model||'your access point')));
  const ul=el('ul'); (hw.plan.networks||[]).forEach(n=>{ const w=HW_WORDS[n.zone]||[n.zone,'']; ul.append(el('li', w[0]+': '+n.ssid+' \u2014 '+w[1])); }); c.append(ul);
  c.append(el('p','Your Hanbi makes the names and passwords. It also turns off what people never get to: WPS, the access point\u2019s own address handing and IPv6, and devices on Smart devices and Guest seeing each other.','mut'));
  body.append(c);
  const go=el('button','Set up my Wi-Fi'); go.onclick=()=>act(go, async()=>{ hw.started=true; await post('/api/homewifi/start',{ip:apx.ip, password:hw.pw}); });
  body.append(bar('Its Wi-Fi restarts: about a minute.', go, skipBtn()));
}

// The way out: one card with everything needed to reach the firewall again, and one button. Print it, save it as a
// PDF, or take a screenshot; then close this and open the manager.
// BUILD 525: the Wi-Fi names this setup made, by zone and where each lives. Names only; no password is kept or shown.
function zoneWifiLine(st){ const zw=st&&st.zone_wifi; if(!zw||typeof zw!=='object') return [];
  const order=['trusted','iot','guest','kids','dmz','quarantine','management'];
  const got=Object.keys(zw).filter(z=>zw[z]&&zw[z].ssid).sort((a,b)=>order.indexOf(a)-order.indexOf(b))
    .map(z=>(z==='trusted'?'Home':(ZONE_NAMES[z]||z))+': \u201c'+zw[z].ssid+'\u201d ('+(zw[z].where==='ap'?'on the access point':'on the firewall\u2019s own Wi-Fi card')+')');
  return got.length ? [['Wi-Fi', got.join('; ')+'. The passwords are the ones you noted when you made them.']] : []; }
async function accessStep(body, st){
  body.append(backLink('access'));
  body.append(head(4,'Your access card','Keep this. It is how you get back into your firewall. Print it, save it as a PDF, or take a screenshot.'));
  const busy=busyCard('Reading your firewall…'); body.append(busy);
  const [sshR, idsR] = await Promise.allSettled([get('/api/ssh/state'), get('/api/ids')]);
  busy.remove();
  const ac=st.access||{}; const ssh=sshR.status==='fulfilled'?sshR.value:null;
  const sshLine = !ssh ? 'could not be read' : ssh.on ? ('on, port '+(ssh.port||22)+(ssh.root_login?' · root may sign in':'')+(ssh.password_login?' · passwords allowed':'')+'. Switch it off when you are done.')
    : (ssh.sure===false && ssh.how==='port check' ? 'no answer on port 22'+(ac.ssh_port?' or '+ac.ssh_port:'')+' (it may be off). When you turn it on it uses port '+(ac.ssh_port||22) : 'off'+(ac.ssh_port?'. When you turn it on it uses port '+ac.ssh_port:''));
  const card=el('div',undefined,'card accesscard'); card.dataset.access='1';
  card.append(el('h2',(ui.platform==='hanbi'?'Hanbi':'Pazuzu')+' · access card'));
  const ul=el('ul',undefined,'plain');
  // BUILD 477: on the phone the card says where things are for a person with the app, not the PC's lines
  // BUILD 480: the card is kept, so on the phone it gives the box's LAN address (the one the wizard was started with), not
  // the address this page came in on (192.168.77.1 on Hanbi_Setup is gone after setup)
  const lanPage=(()=>{ try{ return st.firewall_url ? new URL(st.firewall_url).origin : ''; }catch(e){ return ''; } })();
  const usbMgmt=(()=>{ const m=st.zones&&st.zones.assignments&&st.zones.assignments.management; return m&&/^ue\d+$/.test(m.device||'') ? m.device : ''; })();   // BUILD 508
  (ui.phone ? [['Firewall page', lanPage || ui.base || (ac.host ? ac.host+', port '+ac.web_port_now : 'its address')],
   ['Secure Shell (SSH)', sshLine],
   ['Your admin sign-in', st.admin_user ? st.admin_user+', with its one-time code: type the password, then the 6 digits, with nothing between' : (ui.done.admin ? 'the one you made, with its one-time code' : 'not set up: the factory account is still the way in')],
   ['VPN', st.vpn_instance ? 'set up'+(st.vpn_instance.port?', port '+st.vpn_instance.port:'') : 'not set up yet (Reach home, in the app)'],
   ...(ui.done.hotspot ? [['If the internet goes down', 'switch your phone’s hotspot on; the firewall joins it within about half a minute and lets it go once the internet is back. '+HOTSPOT_HOWTO.map(([who,what])=>who+': '+what).join(' ')]] : []),
   ['Your Hanbi', 'the Pazuzu app on this phone, signed in with its passkey']]
  : [['Firewall page', ui.base || (ac.host ? ac.host+', port '+ac.web_port_now : 'its address')],
   ['Planned new page port', ac.web_port ? ac.web_port+' (not switched yet)' : 'not planned yet'],
   ...(usbMgmt ? [['Management port', usbMgmt+' is a USB adapter. Keep it plugged in: if it is unplugged, the firewall stops handing out addresses on every network until it is back.']] : []),
   ['Secure Shell (SSH)', sshLine],
   ['Your admin sign-in', st.admin_user ? st.admin_user+', with its one-time code' : (ui.done.admin ? 'the one you made, with its one-time code' : 'not set up: the factory account is still the way in')],
   ['VPN', st.vpn_instance ? 'set up'+(st.vpn_instance.port?', port '+st.vpn_instance.port:'') : (ui.managerOpen ? 'not set up yet (the manager has a VPN tab)' : st.light ? 'not set up yet (run this setup again: the Reach home step sets it up)' : 'not set up yet (it comes with the manager, in beta 2)')],
   ['Name lookups', 'answered by the firewall only. When testing DNS, only 1.1.1.1 and 1.0.0.1 can be reached directly.'],
   ...zoneWifiLine(st),
   ...(ui.done.hotspot ? [['If the internet goes down', 'switch your phone’s hotspot on; the firewall joins it within about half a minute and lets it go once the internet is back. '+HOTSPOT_HOWTO.map(([who,what])=>who+': '+what).join(' ')]] : []),
   ['The manager', ui.managerOpen ? (ui.managerUrl || 'opens from the button below') : 'comes in beta 2; run this setup again any time to change things']]).forEach(([a,b])=>{ const li=el('li'); li.append(el('strong',a+': '), document.createTextNode(b)); ul.append(li); });
  card.append(ul);
  const asOf=new Date().toLocaleString();
  card.append(el('p','As of '+asOf+'. Passwords and keys are never shown here.','mut'));
  body.append(card);
  // The card goes to the box too (no secrets on it), so the phone can show it later; and setup is done as far as the box's screen is concerned.
  try{ post('/api/box/access_card',{lines: Array.from(ul.children).map(li=>({label: li.firstChild.textContent.replace(/:\s*$/,''), value: li.lastChild.textContent})), as_of: asOf, brand: ui.platform==='hanbi'?'Hanbi':'Pazuzu'}).catch(()=>{}); }catch(e){}
  tellBox({step:0, of:0, title:'', do:'', done:true});
  if(ui.phone){   // BUILD 477: no manager window on the phone; the app keeps the card (the box holds it) and takes over
    await reportEmailCard(body, st);   // BUILD 508: the status-email choice, lost with the lean last page in 0.6.78
    body.append(el('p','Done. Your Hanbi keeps this card; the Pazuzu app shows it any time. You can close this now.','mut'));
    return; }
  const pr=el('button','Print or save as PDF','quiet'); pr.onclick=()=>{ try{ window.print(); }catch(e){} };
  if(!ui.managerOpen){   // BUILD 493: beta 1 ends here; the manager comes in beta 2
    const fin=el('button','I’ve saved this'); fin.onclick=()=>{ ui.at='after'; saveUi(); refresh().catch(fail); };   // BUILD 503: the page after setup
    body.append(bar('', pr, fin)); return; }
  const done=el('button','I’ve saved this — close and open the manager');
  done.onclick=()=>{ const w=openBlank(); act(done, async()=>{ try{ await openManagerNow(w); }catch(e){ if(w) try{ w.close(); }catch(x){} throw e; } try{ window.close(); }catch(e){} }); };
  body.append(bar('', pr, done));
}

// BUILD 503 (the maintainer, 11 Nov 2026): where beta 1 goes after the access card. The manager is not in this build; this page
// carries what a tester needs: let a blocked device through (the manager's own offers, the same passkey and Undo), the
// firewall's own screen, Send report, and what beta 2 adds. Run the setup steps again from here at any time.
const BETA2=[
  ['Blocks','every block, by device and name, each with Allow for 30 seconds or always'],
  ['Devices','names, makers, fixed addresses and quarantine for a device that misbehaves'],
  ['Reach home','the VPN, its phones and laptops, and the name your firewall is reached by'],
  ['Countries','turn away whole countries at the firewall'],
  ['Reports','a daily summary, by email if you want one'],
  ['Screen','what the firewall’s own display shows, and what it can do']
];
async function afterStep(body, st, job){
  body.append(head(4,'Your firewall is set up','What you can do here in beta 1, and what beta 2 adds.'));
  const done=writeResult(st, ['write-block-allow','write-promote-port','write-undo']); if(done) body.append(done);
  const busy=busyCard('Reading your firewall…'); body.append(busy);
  let af=null; try{ af=await get('/api/after'); }catch(e){ af=null; }
  busy.remove();
  const np=ui.pluginOffered===false;      // BUILD 513: blocked devices and the screen are the plugin's; beta 1 has none
  const bc=el('div',undefined,'card'); bc.dataset.afterOffers='1';
  bc.append(el('h2','Devices that are being stopped'));
  if(np){ }
  else if(!af || !af.box){ bc.append(el('p',(af&&af.why)||'Could not read this just now.','mut')); }
  else if(!af.offers.length){ bc.append(el('p','Nothing is asking for something Pazuzu could let through. A device that keeps being stopped shows up here within a few minutes, with one button to let it through.','mut')); }
  else {
    bc.append(el('p','Each one is something a device keeps asking for and the rules stop. Letting it through asks for your passkey, and Undo takes it back.','mut'));
    af.offers.forEach(x=>{
      const row=el('div',undefined,'offer'); row.append(el('p',x.text));
      const go=el('button',x.label||'Allow it');
      go.onclick=()=>act(go, async()=>{ if(x.promote) await post('/api/after/promote',x.promote); else await post('/api/after/allow',x.allow); });
      row.append(go);
      if(x.allow){ const no=el('button','Ignore','quiet'); no.onclick=()=>act(no, async()=>{ await post('/api/after/ignore',{allow:x.allow}); }); row.append(no); }
      bc.append(row);
    });
  }
  if(!np) body.append(bc);
  if(af && (af.names||[]).length){   // BUILD 503: a fixed address whose name stops the firewall's name server
    const nc=el('div',undefined,'card unsafe'); nc.dataset.badNames='1';
    nc.append(el('h2','A device name will stop the firewall’s name lookups'));
    nc.append(el('p','The firewall’s name server (Unbound) will not start while one of these names is there, and then nothing on your network can look up a name.','mut'));
    const ul=el('ul'); af.names.forEach(n=>ul.append(el('li','The fixed address '+n.ip+' is named “'+n.hostname+'”: '+n.why+'. Change it to “'+n.fix+'”.'))); nc.append(ul);
    nc.append(el('p','Where: Services, Kea DHCP, Kea DHCPv4, Reservations. Open the reservation, fix its Hostname, Save, then Apply. (“Add reservation” on the Leases page copies a Windows PC’s name with a dot at the end.)','mut'));
    body.append(nc);
  }
  if(af && (af.kea_missing||[]).length){   // BUILD 508: Kea will not start while a port it listens on is unplugged
    const kc=el('div',undefined,'card unsafe'); kc.dataset.keaMissing='1';
    kc.append(el('h2','Addresses are not being handed out'));
    const ul=el('ul'); af.kea_missing.forEach(k=>ul.append(el('li',k.name+(k.device?' ('+k.device+')':'')+' is not plugged in.'))); kc.append(ul);
    kc.append(el('p','The firewall\u2019s address service (Kea) is set to serve that port and will not start without it, so no device on any network gets an address. Devices keep working until their address runs out, then drop off one by one.','mut'));
    kc.append(el('p','Either plug it back in, then restart Kea (Services, Kea DHCP). Or, to run without it: Services, Kea DHCP, Kea DHCPv4, Settings, take it out of Interfaces, Save and Apply; add it back when the port returns.','mut'));
    body.append(kc);
  }
  const sc=el('div',undefined,'card'); sc.dataset.afterScreen='1';
  sc.append(el('h2','The firewall’s own screen'), el('p','The same readings its display shows: services, devices online, blocked lookups, traffic, and the top talkers.','mut'));
  if(af && af.screen){ const o=el('button','Open the screen','quiet'); o.onclick=()=>{ try{ window.open('/api/box/screen','_blank','noopener'); }catch(e){} }; sc.append(o); }
  else sc.append(el('p','It opens once the Pazuzu plugin is on the firewall and linked.','mut'));
  if(!np) body.append(sc);
  if(np){ const ok=el('div',undefined,'card'); ok.dataset.afterDone='1'; ok.append(el('h2','Nothing more to do here'),
    el('p','The rules are on and the firewall is doing the work. Keep your access card somewhere safe. To change a port, the name or the VPN, run the setup steps again: they read first and change only what you approve.','mut')); body.append(ok); }
  // BUILD 529 (the maintainer, 12 Nov 2026: "the biggest hurdle now is how to communicate what QUIC does and why it may seem slow
  // at first", "more like the first time you go to a site", "last page")
  { const qc=el('div',undefined,'card'); qc.dataset.quicNote='1'; qc.append(el('h2','Why a site may pause the first time you visit it'),
      el('p','Many sites can send pages a newer way, called QUIC. Packet inspection and the block lists can\u2019t see inside it, so Pazuzu turns it away and your devices use ordinary secure web traffic instead, which they can check.','mut'),
      el('p','The first time you go to a site that offers QUIC, your browser or app may try it, get refused at once, and switch over. That can make the first visit hesitate for a moment. After that the site loads as usual.','mut'),
      el('p','Nothing is broken, and no site is blocked by this.','mut')); body.append(qc); }
  const fb=el('div',undefined,'card'); fb.append(el('h2','Something not right?'), el('p','Send a report: it says which build and step, and anything you add. A screenshot is sent only if you attach one.','mut'));
  const rep=el('button','Send report','quiet'); rep.onclick=()=>feedbackSheet(''); fb.append(rep); body.append(fb);
  const b2=el('div',undefined,'card'); b2.dataset.beta2='1'; b2.append(el('h2','Coming in beta 2: the manager'));
  const ul=el('ul',undefined,'plain'); BETA2.forEach(([a,t])=>{ const li=el('li'); li.append(el('strong',a+': '), document.createTextNode(t)); ul.append(li); }); b2.append(ul);
  { const pic=document.createElement('img'); pic.src='/manager_preview.gif'; pic.alt='The manager: the firewall\u2019s own screen, and the overview of what is enforced'; pic.className='preview'; pic.loading='lazy';
    pic.onerror=()=>{ pic.remove(); note.remove(); };      // BUILD 526 (the maintainer: "a gif mock up for now?"): a look at what is coming
    const note=el('p','A recording of the manager, on made-up readings. It is not part of this build.','mut'); b2.append(pic, note); }
  b2.append(el('p','Until then, this page and the setup steps do it: the setup reads first and changes only what you approve.','mut'));
  body.append(b2);
  const again=el('button','Run the setup steps again','quiet'); again.onclick=()=>{ ui.at=''; saveUi(); refresh().catch(fail); };
  const card=el('button','Show my access card','quiet'); card.onclick=()=>{ ui.at='access'; saveUi(); refresh().catch(fail); };
  body.append(bar('', fwLink('Open the firewall\u2019s own page','/'), card, again));   // BUILD 525 (the maintainer: "add button to open gui")
  body.append(creditsCard());
}
// BUILD 508 (the maintainer, 11 Nov 2026: "10. yes"): the daily report by email, offered on the phone's access card again. The
// report is always made on the firewall; the email is off until the person gives an address and their own mail server.
async function reportEmailCard(body, st){
  let rp=null; try{ rp=await get('/api/report'); }catch(e){ rp=null; }
  const c=el('div',undefined,'card'); c.dataset.reportEmail='1'; c.append(el('h2','A daily status email'));
  const done=writeResult(st,['write-report']); if(done) body.append(done);
  if(!rp || !rp.can){ c.append(el('p',(rp&&rp.why)||'Could not read this just now.','mut')); body.append(c); return; }
  const cur=rp.settings||{};
  c.append(el('p', cur.enabled ? 'On: sent every day at '+String(cur.hour==null?7:cur.hour).padStart(2,'0')+':'+String(cur.minute||0).padStart(2,'0')+' to '+(cur.to||'your address')+'.' : 'Off. Your firewall makes a short report every day either way; it can also email it to you, through your own mail server.','mut'));
  const f=(ph,val,type)=>{ const i=el('input'); i.type=type||'text'; i.placeholder=ph; i.value=val==null?'':val; i.autocomplete='off'; return i; };
  const to=f('Send it to (your email address)',cur.to), host=f('Your mail server (for example smtp.fastmail.com)',cur.host), port=f('Port',cur.port||587),
        user=f('Mail user name',cur.username), pw=f('Mail password (kept on the firewall, never shown again)','','password');
  const box=el('details'); box.append(el('summary', cur.enabled?'Change it':'Switch it on')); box.append(to,host,port,user,pw);
  const save=el('button','Save and switch on'); save.onclick=()=>act(save, async()=>{ const p=pw.value; pw.value='';
    const s={enabled:true,to:to.value.trim(),host:host.value.trim(),port:parseInt(port.value,10)||587,username:user.value.trim(),hour:cur.hour==null?7:cur.hour,minute:cur.minute||0};
    if(!s.to||!s.host) throw new Error('Give the address to send to and your mail server.');
    if(p) s.password=p;
    await post('/api/report/change',{action:'save',settings:s}); });
  box.append(save); c.append(box);
  if(cur.enabled){ const off=el('button','Switch the email off','quiet'); off.onclick=()=>act(off, async()=>{ await post('/api/report/change',{action:'off'}); }); c.append(off);
    const t=el('button','Send a test now','quiet'); t.onclick=()=>act(t, async()=>{ await post('/api/report/change',{action:'test'}); }); c.append(t); }
  body.append(c);
}
// A window opened in the click itself (so the browser allows it), sent to the manager once it is running.
function openBlank(){ let w=null; try{ w=window.open('about:blank','_blank'); if(w) w.opener=null; }catch(e){ w=null; } return w; }
async function openManagerNow(w){
  const r=await post('/api/manager/start',{}); ui.managerUrl=r.url;
  if(w){ try{ w.location.href=r.url; return r; }catch(e){} }
  try{ window.open(r.url,'_blank','noopener'); }catch(e){}
  return r;
}
function passkeyStep(body){
  body.append(head(1,'Register your passkey','It approves every change. Lose it and you reset the firewall.'));
  const c=el('div',undefined,'card'); const box=el('input'); box.type='text'; box.maxLength=40; box.value='Pazuzu admin'; box.placeholder='Name this passkey, for example "my laptop"';
  c.append(box); body.append(c);
  // The browser can say now whether this device has a sign-in of its own (Windows Hello, Touch ID, a screen-lock PIN).
  // Without one it offers only a phone or a security key, which looks like the page is broken.
  const hello=el('div',undefined,'card'); hello.id='hello-note'; hello.style.display='none';
  hello.append(el('p','This device does not report a sign-in of its own (Windows Hello, Touch ID or a screen-lock PIN), so the browser will offer only a phone or a security key. To use this device, set one up first (on Windows: Settings, Accounts, Sign-in options, then Windows Hello PIN), then come back. A phone or a security key works as well.','mut'));
  body.append(hello);
  (async()=>{ let ok=true; try{ ok = !!(window.PublicKeyCredential && PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable && await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()); }catch(e){ ok=true; }
    if(!ok) hello.style.display=''; })();
  const btn=el('button','Create passkey'); btn.onclick=()=>act(btn,()=>registerPasskey(box.value));
  body.append(bar('', btn));
}

function portLabel(i){
  const id=(i.identifier||'').toLowerCase();
  const role={lan:'Trusted Network (LAN)',wan:'Internet side (WAN)'}[id]||(i.description||(id?id.toUpperCase():(/^(wlan|iwm|iwn|iwx|ath|bwfm|rtwn|run|urtwn|mt7)/.test(i.device)?'Wi-Fi':'Spare port')));
  const st=(i.status||'').toLowerCase();
  const wifi=/^(wlan|iwm|iwn|iwx|iwlwifi|ath|bwfm|rtwn|run|urtwn|mt7)/.test(i.device);
  const real=!/^(lo|enc|pflog|pfsync|wg|tun|tap|ovpn|gif|gre|bridge|lagg|vlan|ipsec|ppp|ng|epair)/.test(i.device)&&(i.physical!==false||wifi);
  const cable=!real||!i.assigned?'':/no carrier|down/.test(st)?'no cable':/up|active|full|1000|100base|10base/.test(st)?'cable plugged in':'';
  const kind=wifi?'Wi-Fi card':/^lo/.test(i.device)?'virtual loopback':(i.assigned?'':'not set up on the firewall yet');
  return role+' · '+i.device+[cable,kind].filter(Boolean).map(t=>' · '+t).join('');
}
const ZONE_NAMES={wan:'Internet (wan)',management:'Management',trusted:'Trusted Network',iot:'Smart devices (iot)',guest:'Guests',kids:'KidsNet',dmz:'Public servers (dmz)',quarantine:'Quarantine',wireguard_admin:'Remote admin (VPN)'};
async function apOnboard(body, st){
  // Fold an existing OpenWrt access point on a port into the ecosystem: scan for it, read it (weak-password / IPv6 audit),
  // then tag each of its Wi-Fi networks onto a zone's VLAN. All reads until the final tag; that one is tested and self-undoes.
  const card=el('div',undefined,'card'); card.dataset.ap='1';
  card.append(el('h2','OpenWrt access point'));
  card.append(el('p','Pazuzu folds an OpenWrt access point into your networks: it creates your zone Wi-Fi on it — each SSID on its own scrambled VLAN — flags a weak password or IPv6 left on, and keeps it reachable for admin on its own network. Your devices then move over to the new networks. First this app has to be able to reach it.','mut'));
  { const ol=el('ol');
    [['Wired to your LAN','Plug it into a LAN port (where this device already is); it answers at its own address — scan below, or type that address.'],
     ['On a port you set up here','Set the access point to get its address automatically (DHCP), give a port a zone below and press Set these up, then plug it in; it takes a 10.x address and shows up in the scan.'],
     ['Over its own Wi-Fi','Join the access point’s own Wi-Fi from this device, then type its address below (often 192.168.1.1); this device reaches it over that Wi-Fi.'],
    ].forEach(([t,w])=>{ const li=el('li'); li.append(el('strong',t+': '), document.createTextNode(nopk(w))); ol.append(li); });
    card.append(fold('three ways to reach the access point to set it up', ol)); }
  // BUILD 556 (the maintainer, 17 Nov 2026: "agreed"): a cabled access point is found first; joining its own Wi-Fi with a spare radio
  // is the other way, under a fold. An access point's usual starting state is a cabled one.
  const wf=el('div'); let signBox=null, jnBox=null;
  { const cb=el('div',undefined,'card'); cb.dataset.apSignin='1'; cb.append(el('h3','Its admin sign-in'),
      el('p','A brand-new OpenWrt has root with no password: leave the password blank to try that first. It is used for this setup only.','mut'));
    const mk=(to,label,hint,key,type)=>{ const cb=to; cb.append(el('div',label,'mut')); const i=el('input'); i.type=type||'text'; i.autocomplete='off'; if(hint)i.placeholder=hint; i.value=(ui[key]!==undefined&&ui[key]!==null)?ui[key]:(key==='apUser'?'root':''); i.oninput=()=>{ ui[key]=i.value; }; cb.append(i); return i; };
    // Wi-Fi name: a scanned dropdown with Rescan, like a phone's Wi-Fi picker.
    { const cb=wf; cb.append(el('div','Wi-Fi name (SSID)','mut'));
      const nets=((ui.apScan&&ui.apScan.networks)||[]);
      const row=el('div'); row.style.display='flex'; row.style.gap='8px'; row.style.alignItems='center';
      const sel=el('select'); sel.style.flex='1'; sel.dataset.apSsid='1';
      sel.append(new Option(nets.length?'Pick the access point’s network…':'Press Rescan to list networks','', !ui.apJoinSsid, !ui.apJoinSsid));
      nets.forEach(n=>{ const o=new Option((n.name||'')+(n.signal?' · '+n.signal+'%':''), n.name); if(ui.apJoinSsid===n.name) o.selected=true; sel.append(o); });
      const oth=new Option('Other / hidden network…','__other__'); if(ui.apSsidOther) oth.selected=true; sel.append(oth);
      sel.onchange=()=>{ if(sel.value==='__other__'){ ui.apSsidOther=true; refresh().catch(fail); } else { ui.apSsidOther=false; ui.apJoinSsid=sel.value; } };
      const rescan=el('button','Rescan','quiet'); rescan.type='button'; rescan.dataset.apScan='1'; rescan.onclick=()=>act(rescan, async()=>{ ui.apScan=await post('/api/ap/scan',{}); });
      row.append(sel, rescan); cb.append(row);
      if(ui.apScan&&ui.apScan.why) cb.append(el('div',ui.apScan.why,'mut'));
      if(ui.apSsidOther){ const i=el('input'); i.type='text'; i.autocomplete='off'; i.placeholder='Type the Wi-Fi name'; i.value=ui.apJoinSsid||''; i.oninput=()=>{ ui.apJoinSsid=i.value; }; cb.append(i); } }
    mk(wf,'Wi-Fi password','','apJoinPw','password');
    mk(cb,'Admin user','OpenWrt’s admin is root','apUser');
    mk(cb,'Admin password','leave blank to try the default (root, no password)','apPw','password');
    signBox=cb; }
  { // Reach it over the air (no cable): the SSID dropdown above is the scanner; join the picked network, then read.
    const jn=el('div');
    jn.append(el('p','A spare radio joins the network picked above — no cable — as a plain station (no gateway, routing untouched). Then read it; hand the radio back once it’s on your scheme.','mut'));
    if(ui.apJoinSsid || ui.apSsidOther){
      // BUILD 468: a typed (hidden) name gets its Join button too, and the access point is read straight after joining,
      // so the zones below default to it without another press (lab, 3 Nov 2026: no button after typing).
      const jgo=el('button',ui.apSsidOther?'Join this network':'Join “'+ui.apJoinSsid+'”'); jgo.dataset.apJoin='1';   // BUILD 512: the one thing to press here, so not a quiet button
      jgo.onclick=()=>act(jgo, async()=>{ const ss=(ui.apJoinSsid||'').trim(); if(!ss) throw new Error('Type the access point’s Wi-Fi name first.');
        await post('/api/ap/join',{ssid:ss, passphrase:ui.apJoinPw||''}); ui.apJoined=true;
        try{ const pass=ui.apPw||''; ui.apRead=await post('/api/ap/read',{ip:(ui.apManIp||'192.168.1.1').trim(), password:pass}); ui.apPwSent=pass; }
        catch(e){ ui.apRead=null; } });
      jn.append(bar('Uses the Wi-Fi password typed above. Once joined, Pazuzu reads the access point and offers it for the zones below.', jgo));
    }
    if(ui.apJoined && !ui.apRead){
      jn.append(el('p','Joined. Read it now — on its own Wi-Fi its address is usually 192.168.1.1:','mut'));
      const rip=el('input'); rip.type='text'; rip.autocomplete='off'; rip.value=ui.apManIp||'192.168.1.1'; rip.oninput=()=>{ ui.apManIp=rip.value; };
      const rgo=el('button','Read it','quiet'); rgo.dataset.apJoinRead='1';
      rgo.onclick=()=>act(rgo, async()=>{ const pass=ui.apPw||''; ui.apRead=await post('/api/ap/read',{ip:(ui.apManIp||'192.168.1.1').trim(), password:pass}); ui.apPwSent=pass; });
      jn.append(rip, bar('', rgo));
    }
    jnBox=jn; }
  { // The main way: find it on a port the firewall knows, or type a fixed address.
    const other=el('div');
    const find=el('button','Find it'); find.dataset.apFind='1';   // BUILD 556: the main button of this card
    find.onclick=()=>act(find, async()=>{ ui.apFound=await post('/api/ap/find',{}); ui.apRead=null; });
    other.append(el('p','Plug the access point into your firewall or switch and give it a minute. The firewall finds it by the address it handed it.','mut'), find);
    const f=ui.apFound;
    if(f){
      // BUILD 556: a device that calls itself OpenWrt and does not answer is most likely cabled by its WAN port
      (f.silent||[]).forEach(q=>{ const w=el('div',undefined,'card'); w.dataset.apSilent='1';
        w.append(el('p','A device called '+(q.name||'OpenWrt')+' is on your network at '+q.ip+' but does not answer as an access point.'),
          el('p','Most often its cable is in its WAN (internet) port, where OpenWrt answers nothing: move the cable to one of its LAN ports, give it a minute, and press Find it again. Or its web page is switched off.','mut'));
        other.append(w); });
      if(f.why) other.append(el('p',f.why,'mut'));
      else if(!(f.found||[]).length) other.append(el('p','No OpenWrt access point answered among the '+(f.tried||0)+' device'+(f.tried===1?'':'s')+' the firewall knows. A fixed-address access point won’t show here — type its address below instead.','mut'));
      else (f.found||[]).forEach(a=>{
        const row=el('div',undefined,'opt'); const m=el('div',undefined,'grow');
        m.append(el('div',(a.name||a.vendor||'OpenWrt access point')+' · '+a.ip,'vt'), el('div',a.no_password?'No password set on it yet.':'Uses the admin password from the sign-in above.','mut'));
        const pick=el('button','Read it','quiet');
        pick.onclick=()=>act(pick, async()=>{ const pass=a.no_password?'':(ui.apPw||''); ui.apRead=await post('/api/ap/read',{ip:a.ip, password:pass}); ui.apPwSent=pass; });
        row.append(m, pick); other.append(row);
      });
    }
    const man=el('div',undefined,'opt'); const mm=el('div',undefined,'grow');
    mm.append(el('div','Know its address?','vt'), el('div','Type its address; it uses the admin password from the sign-in above.','mut'));
    const mip=el('input'); mip.type='text'; mip.autocomplete='off'; mip.placeholder='Its address, e.g. 192.168.1.50'; mip.value=ui.apManIp||''; mip.oninput=()=>{ ui.apManIp=mip.value; };
    mm.append(mip);
    const mgo=el('button','Read it','quiet'); mgo.dataset.apManRead='1';
    mgo.onclick=()=>act(mgo, async()=>{ const pass=ui.apPw||''; ui.apRead=await post('/api/ap/read',{ip:(ui.apManIp||'').trim(), password:pass}); ui.apPwSent=pass; });
    man.append(mm, mgo); other.append(man);
    other.dataset.apWired='1';
    card.append(el('h3','Find it on your network'), other, signBox);
    { const fo=fold('no cable: join its own Wi-Fi with a spare radio', wf, jnBox); if(ui.apJoinSsid||ui.apSsidOther||ui.apJoined) fo.open=true; card.append(fo); } }
  body.append(card);
  const r=ui.apRead;
  if(!r) return;
  const box=el('div',undefined,'card');
  box.append(el('h2','What Pazuzu read'), el('p',(r.model||'Access point')+(r.release?' · '+r.release:'')+' · '+r.ip,'mut'));
  if(r.https_only) box.append(el('p','Its own page is https only, so Pazuzu talks to it that way. Its certificate is one it made itself.','mut'));   // BUILD 556
  (r.notes||[]).forEach(t=>box.append(el('p',t,'mut')));
  // BUILD 555: a check that failed had a tick beside it ("✓ No root password: anyone on the network can change this access point")
  if((r.checks||[]).length){ const ul=el('ul'); (r.checks||[]).forEach(c=>ul.append(el('li',((c.level==='stop'||c.ok===false)?'✗ ':c.level==='warn'?'⚠ ':'✓ ')+(c.text||'')))); const sc=el('div',undefined,'scroll'); sc.append(ul); box.append(el('h2','Security check'), sc); }
  { // Guide to strong passwords: name the weak ones from the check, and hand over a strong one to use.
    const weak=(r.checks||[]).some(c=>c.level!=='ok' && /password|key|wpa|psk|admin|root|open/i.test(c.text||''));
    box.append(el('h2','Make its passwords strong'));
    box.append(el('p',(r.no_password?'It has no admin password — set a strong one on the access point. ':'')+(weak?'The check above flags a weak or open Wi-Fi/admin password. ':'')+'Use a strong one for both its admin login and every Wi-Fi network. A fresh suggestion to copy:','mut'));
    const gen=()=>{ const a='abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789', b=new Uint32Array(20); crypto.getRandomValues(b); let o=''; b.forEach((x,i)=>{ o+=a[x%a.length]; if(i===5||i===11||i===17) o+='-'; }); return o; };
    if(!ui.apStrongPw) ui.apStrongPw=gen();
    box.append(el('div',ui.apStrongPw,'fp mono'));
    const again=el('button','New suggestion','quiet'); again.onclick=()=>{ ui.apStrongPw=gen(); refresh().catch(fail); };
    box.append(again); }
  if(ui.apJoined){ // Hand the spare radio back once the access point is on our scheme (undo the transient join link).
    // BUILD 556: only when a radio was joined to it in this visit. For a cabled access point there is no link to undo,
    // and this button's undo would have taken back whatever the last change was.
    const rel=el('button','Hand the radio back (undo the Wi-Fi link)','quiet'); rel.dataset.apRelease='1';
    rel.onclick=()=>act(rel, async()=>{ await post('/api/write/undo',{}); ui.apRead=null; ui.apScan=null; });
    box.append(el('p','When the access point is on your VLANs, hand the spare radio back to its other roles:','mut'), bar('', rel)); }
  { box.append(el('h2','When you set it up'));
    const f6=el('label'); f6.style.display='block'; f6.style.margin='4px 0 2px'; const cb6=el('input'); cb6.type='checkbox'; cb6.checked=ui.apIpv6Off!==false; cb6.onchange=()=>{ ui.apIpv6Off=cb6.checked; }; f6.append(cb6, document.createTextNode(' Switch IPv6 off on it (part of the baseline)')); box.append(f6);
    const fd=el('label'); fd.style.display='block'; fd.style.margin='2px 0 6px'; const cbd=el('input'); cbd.type='checkbox'; cbd.checked=ui.apDhcpOff!==false; cbd.onchange=()=>{ ui.apDhcpOff=cbd.checked; }; fd.append(cbd, document.createTextNode(' Stop it handing out addresses — the firewall does, on the VLAN')); box.append(fd); }
  box.append(el('p','Now, in “Zones with no port” below, pick “Its Wi-Fi on the access point” for each zone it should broadcast (Smart devices, Guests). Set these up creates those networks on it, each on the zone’s scrambled VLAN — then move your devices over to them. Its own existing Wi-Fi is left alone, it stays reachable on its own network for admin, and management is never put on it.','mut'));
  body.append(box);
}

async function zonesStep(body, st, job){
  if(job && job.kind==='write-zone-vlans' && job.state==='done' && !ui.sawZoneVlans){
    rail(1); body.append(backLink('zones'));
    body.append(head(4,'Done — your zones are set up','Each got its own random network and VLAN. Review, then continue.',true));   // BUILD 517: it said step 2
    const rc=el('div',undefined,'card'); rc.append(el('h2','What Pazuzu set up'));
    const ls=((job.result&&job.result.lines)||[]);
    if(ls.length){ const ul=el('ul'); ls.forEach(t=>ul.append(el('li',t))); rc.append(ul); } else rc.append(el('p','The zones were set up.','mut'));
    body.append(rc);
    await kidsCard(body, st);          // BUILD 537: a KidsNet just made gets its family DNS filter picked here
    const cont=el('button','Continue'); cont.onclick=()=>{ ui.sawZoneVlans=true; ui.done.zones=true; ui.force=null; ui.apRead=null; ui.apScan=null; saveUi(); refresh().catch(fail); };
    const again=el('button','Set up more','quiet'); again.onclick=()=>{ ui.sawZoneVlans=true; ui.apRead=null; ui.apScan=null; refresh().catch(fail); };
    body.append(bar('Your zones — and the access point, if you set one up — are in place. Next: Wi-Fi.', cont, again));
    return;
  }
  body.append(backLink('zones'));
  body.append(head(2,'Which port is which?','Optional — assign ports to zones if you want, or skip and set zones up any time in the manager. Nothing is changed on the firewall until you press Save and continue or Set these up.'));
  let data; try{ data=await get('/api/interfaces'); }catch(e){ fail(e); return; }
  body.append(means('a zone is the job a port does, and the job decides what its devices may reach. The Trusted Network is your own devices. Management is the only side that can open the firewall’s settings. Smart devices and Guests get the internet and nothing else, and are kept away from your own devices. Public servers are kept away from your private networks. Quarantine is cut off completely. A zone you leave off simply has no port.'));
  const card=el('div',undefined,'card'); const tbl=el('table'); const hr=el('tr');
  ['ZONE','INTERFACE'].forEach(t=>hr.append(el('th',t))); tbl.append(hr);
  const picks={};
  // BUILD 507 (the maintainer, 11 Nov 2026: "zones with no ports seems more logical", "like it"): each zone is set in one place.
  // This table shows the zones with a real port to pick: the internet and the trusted network, a zone that already has a
  // port, and every zone when a spare port has its cable plugged in (a wired IoT port is not forced into a VLAN). The
  // rest are set up below, under Zones with no port.
  const cabled=(data.spare||[]).filter(p=>/plugged in/.test(p.link||''));
  const hasPort=z=>{ const a=st.zones&&st.zones.assignments&&st.zones.assignments[z]; return !!(a&&a.device&&(data.interfaces.find(i=>i.device===a.device)||{}).assigned) || !!(data.later&&data.later[z]); };
  const shownZones=data.zones.filter(z=>z==='wan'||z==='trusted'||cabled.length||hasPort(z));
  data.zones.forEach(z=>{ if(shownZones.indexOf(z)<0) picks[z]=''; });
  shownZones.forEach(z=>{
    const tr=el('tr'); tr.append(el('td',ZONE_NAMES[z]||z)); const sel=el('select');
    const optional=z!=='wan';
    if(optional) sel.append(new Option('Leave off',''));
    data.interfaces.forEach(i=>sel.append(new Option(portLabel(i), i.device)));
    const prev=st.zones&&st.zones.assignments&&st.zones.assignments[z]; if(prev&&prev.device&&prev.state!=='pending_assignment'&&prev.state!=='pending_creation'&&(data.interfaces.find(i=>i.device===prev.device)||{}).assigned) sel.value=prev.device;   // an earlier pick the firewall had not set up is not kept
    else if(z!=='wan'&&data.later&&data.later[z]&&data.interfaces.find(i=>i.device===data.later[z])) sel.value=data.later[z];   // a port picked before the firewall had it
    else if(z==='wan'||z==='trusted'){ const m=data.interfaces.find(i=>i.identifier===z||i.identifier==='lan'&&z==='trusted'); if(m) sel.value=m.device; }
    const td=el('td'); td.append(sel); tr.append(td); 
    sel.onchange=()=>{ picks[z]=sel.value; };
    picks[z]=sel.value; tbl.append(tr);
  });
  card.append(tbl);
  if(shownZones.length<data.zones.length) card.append(el('p','The other zones are set up below, under Zones with no port.','mut'));
  body.append(card);
  // A zone's port whose network holds only the firewall itself (a /32 or /31): its devices would match no rule.
  const small=el('div'); body.append(small);
  const tooSmall=()=>{ small.replaceChildren(); const bad=Object.keys(picks).filter(z=>z!=='wan'&&picks[z]&&(data.too_small||{})[picks[z]]);
    if(!bad.length) return;
    const c=el('div',undefined,'card unsafe'); c.dataset.tooSmall='1'; c.append(el('h2','A network with no room for devices'));
    bad.forEach(z=>c.append(el('p',(ZONE_NAMES[z]||z)+': '+picks[z]+' is '+data.too_small[picks[z]]+'. That network holds only the firewall itself, so every rule for this zone matches the firewall alone and its devices get no way out. On the firewall, open this port’s page and change the number after the slash to 24, then Save and Apply.')));
    small.append(c); };
  card.querySelectorAll('select').forEach(sel=>sel.addEventListener('change',()=>setTimeout(tooSmall,0)));
  tooSmall();
  await apOnboard(body, st);   // the access point and its sign-in come first: read it here, then it shows in the set-up list below and Set these up folds it in one pass
  // Zones with no port: a spare port first (Management gets the first one), else a VLAN of its own. Pazuzu puts it on
  // the firewall with a random private network, hands out addresses there with Kea, and saves the zone to it.
  if(st.passkeys>0||st.light){
    const PZ=['management','iot','guest','kids','dmz','quarantine'].filter(z=>z!=='kids'||data.kids!==false); const spare=(data.spare||[]); const radios=(data.radios||[]).filter(r=>r.free);
    const sug=data.suggest||{}; const WIFI_NAME={iot:'IoT',guest:'Guests',kids:'KidsNet'};
    const vc=el('div',undefined,'card'); vc.dataset.vlans='1';
    vc.append(el('h2','Zones with no port: set them up for you'));
    vc.append(el('p','Pazuzu suggests a home for each zone from this box’s own ports and Wi-Fi cards; change any of them before you press Set these up. A spare port or a Wi-Fi network of its own needs nothing else. A VLAN needs your switch or access point to carry the same number — on an OpenWrt access point, the manager’s Wi-Fi section tags it for you after setup. Each gets a random private network, the firewall’s address on it and addresses handed out by Kea. If a step is refused, everything is taken back.','mut'));
    { const sl=el('label'); sl.style.display='block'; sl.style.margin='4px 0 4px'; const scb=el('input'); scb.type='checkbox'; scb.checked=ui.scramble!==false; scb.onchange=()=>{ ui.scramble=scb.checked; };
      sl.append(scb, document.createTextNode(' Scramble the network — random subnets and VLAN numbers (recommended; part of the baseline)')); vc.append(sl);
      const sn=el('div','Uncheck only for testing: you get fixed, repeatable addresses, and the manager flags the network as not-done until you scramble.','mut'); sn.style.fontSize='13px'; sn.style.margin='0 0 12px'; vc.append(sn); }
    const rnd=()=>{ const a='abcdefghjkmnpqrstuvwxyz23456789', b=new Uint32Array(15); crypto.getRandomValues(b); let o=''; b.forEach((x,i)=>{ o+=a[x%a.length]; if(i===4||i===9) o+='-'; }); return o; };
    const chooser={}, extra={}, why={}; const tbl2=el('table');
    PZ.forEach(z=>{ const tr=el('tr'); const name=el('td'); name.append(el('div',ZONE_NAMES[z]||z)); why[z]=el('div','','mut'); why[z].style.fontSize='13px'; name.append(why[z]); tr.append(name);
      const sel=el('select'); sel.append(new Option('Leave off',''));   // BUILD 507: the one place for these zones
      spare.forEach(p=>sel.append(new Option('Use '+p.label+(p.link?' · '+p.link:''),'port:'+p.device)));
      if(z==='iot'||z==='guest'||z==='kids') radios.forEach(r=>sel.append(new Option('Its own Wi-Fi on '+r.label,'wifi:'+r.card)));
      if((z==='iot'||z==='guest'||z==='kids'||z==='dmz') && ui.apRead) ((ui.apRead.radios)||[]).forEach(r=>sel.append(new Option('Its Wi-Fi on the access point'+(r.band?' · '+r.band:''),'ap:'+r.name)));   // create this zone's SSID on the OpenWrt access point, on the zone's scrambled VLAN
      if(z!=='management') sel.append(new Option('A VLAN of its own','vlan'));
      chooser[z]=sel; const td=el('td'); td.append(sel);
      // A Wi-Fi network of its own: a name and a password, made here (shown, so it can be copied to the devices).
      const wf=el('div'); wf.dataset.wifiFields=z; wf.style.marginTop='6px';
      const ssid=el('input'); ssid.value=WIFI_NAME[z]||''; ssid.maxLength=32; ssid.setAttribute('aria-label',(ZONE_NAMES[z]||z)+' Wi-Fi name');
      const pw=el('input'); pw.value=rnd(); pw.maxLength=63; pw.setAttribute('aria-label',(ZONE_NAMES[z]||z)+' Wi-Fi password'); pw.autocomplete='off';
      const again=el('button','New password','quiet'); again.type='button'; again.onclick=()=>{ pw.value=rnd(); };
      wf.append(el('div','Wi-Fi name','mut'),ssid,el('div','Wi-Fi password (WPA2; write it down or copy it to your devices)','mut'),pw,again);
      extra[z]={box:wf, ssid:ssid, pw:pw}; td.append(wf);
      sel.addEventListener('change',()=>{ sel.dataset.touched='1'; show(); });
      tr.append(td); tbl2.append(tr); });
    const show=()=>PZ.forEach(z=>{ const v=chooser[z].disabled?'':chooser[z].value; extra[z].box.style.display=(v.startsWith('wifi:')||v.startsWith('ap:'))?'':'none'; });
    const suggest=()=>{
      PZ.forEach(z=>{ const sel=chooser[z]; const has=!!picks[z]||hasPort(z); sel.disabled=has;   // BUILD 555: KidsNet is not in the table above, so its row never said "Already has a port" and Set these up was refused ("These zones already have a port: kids")
        // BUILD 556 (the maintainer, 17 Nov 2026: "it used to"): a zone that already has its VLAN can still get its Wi-Fi on an access
        // point that was read: its row offers only that, and the zone itself is not changed.
        const aD=((st.zones&&st.zones.assignments&&st.zones.assignments[z])||{}).device||'';
        if(has && ui.apRead && /^vlan/.test(aD) && (z==='iot'||z==='guest'||z==='kids'||z==='dmz') && [...sel.options].some(o=>o.value.startsWith('ap:'))){
          sel.disabled=false; sel.dataset.onAp='1'; sel.title='';
          [...sel.options].forEach(o=>{ const ok=o.value===''||o.value.startsWith('ap:'); o.hidden=!ok; o.disabled=!ok; if(o.value==='') o.textContent='Leave as it is'; });
          if(!sel.dataset.touched || !(sel.value===''||sel.value.startsWith('ap:'))) sel.value='';
          why[z].textContent='Already has its network. Its Wi-Fi can go on the access point.'; return; }
         if(has){ sel.value=''; sel.title='This zone already has a port.'; why[z].textContent='Already has a port.'; return; } sel.title='';
        const s0=sug[z]||{}; why[z].textContent=s0.why||'';
        if(!sel.dataset.touched){ let want=s0.pick||'';
          if(ui.apRead && (z==='iot'||z==='guest')){ const rs=(ui.apRead.radios)||[]; const r=rs.find(x=>/2\.?4/.test(x.band||''))||rs[0]; if(r){ want='ap:'+r.name; why[z].textContent='On your access point ('+(r.band||'Wi-Fi')+').'; } }   // an AP is read: default its Wi-Fi zones onto the access point, firewall radios as the fallback
          const taken=PZ.filter(o=>o!==z&&chooser[o].value&&chooser[o].value===want&&want!=='vlan'&&!String(want).startsWith('ap:'));   // zones may share the access point (one radio hosts several SSIDs); a firewall port/card cannot
          sel.value = (want && !taken.length && [...sel.options].some(o=>o.value===want)) ? want : ''; } });
      show(); };
    card.querySelectorAll('select').forEach(sel=>sel.addEventListener('change',()=>setTimeout(suggest,0))); suggest();
    vc.append(tbl2);
    if(ui.apRead){
      const hint=el('div',undefined,'mut'); hint.style.margin='8px 0'; hint.style.fontSize='13px';
      hint.textContent='OpenWrt access point read ('+((ui.apRead.model)||'access point')+'). Its Wi-Fi zones below are set to live on it (switch any to a firewall radio if you’d rather). Set these up creates each on the access point, on its zone’s scrambled VLAN; it stays reachable on its own network for admin, and management is never put on it.';
      vc.append(hint);
    } else if(ui.apJoinSsid){
      const warn=el('div',undefined,'mut'); warn.style.margin='8px 0'; warn.style.fontSize='13px';
      warn.textContent='You picked an access point (“'+ui.apJoinSsid+'”) but haven’t read it yet. Join and Read it in the access-point card above, then its radios appear here and these Wi-Fi zones move onto it. Until then they are set up on this firewall’s own radios.';
      vc.append(warn);
    }
    if(data.dhcp_server==='dnsmasq'){   // BUILD 499: asked each time, Kea recommended
      if(ui.dhcpPick!=='kea' && ui.dhcpPick!=='dnsmasq') ui.dhcpPick='kea';
      const dc=el('div'); dc.dataset.dhcpPick='1'; dc.append(el('h3','Who hands out addresses'),
        el('p','This firewall hands out addresses with dnsmasq, the one OPNsense starts with. Pazuzu works best with Kea, OPNsense\u2019s newer DHCP server: its checks and fixed addresses are built around it. Moving keeps every device\u2019s address, and Undo puts dnsmasq back.','mut'));
      const opt=(val, title, txt)=>{ const l=el('label',undefined,'opt '+(ui.dhcpPick===val?'sel':'')); const r=el('input'); r.type='radio'; r.name='dhcpPick'; r.checked=ui.dhcpPick===val;
        const t=el('div'); t.append(el('div',title), el('div',txt,'mut')); l.append(r,t);
        r.onchange=()=>{ ui.dhcpPick=val; saveUi(); dc.querySelectorAll('label.opt').forEach(x=>x.className='opt'); l.className='opt sel'; }; return l; };
      dc.append(opt('kea','Move to Kea (recommended)','Your current ranges and fixed addresses move over, then the new networks are added there.'),
                opt('dnsmasq','Keep dnsmasq','The new networks get their ranges in dnsmasq. You can move to Kea later.'));
      vc.append(dc);
    }
    const mk=el('button','Set these up'); mk.onclick=()=>act(mk, async()=>{ const ports={}, zones=[], wifi={}, apNets=[];
      PZ.forEach(z=>{ const v=chooser[z].disabled?'':chooser[z].value;
        if(v.startsWith('port:')) ports[z]=v.slice(5);
        else if(v.startsWith('wifi:')) wifi[z]={card:v.slice(5), ssid:extra[z].ssid.value.trim(), passphrase:extra[z].pw.value};
        else if(v.startsWith('ap:')){ zones.push(z); apNets.push({zone:z, radio:v.slice(3), ssid:extra[z].ssid.value.trim(), passphrase:extra[z].pw.value}); }   // this zone's Wi-Fi is created on the access point, riding the zone's scrambled VLAN
        else if(v==='vlan') zones.push(z); });
      const used=Object.values(ports); if(new Set(used).size!==used.length) throw new Error('The same port is picked for two zones.');
      const cards=Object.values(wifi).map(w=>w.card); if(new Set(cards).size!==cards.length) throw new Error('The same Wi-Fi card is picked for two zones; each card hosts one network.');
      for(const [z,w] of Object.entries(wifi)){ if(!w.ssid) throw new Error((ZONE_NAMES[z]||z)+': give the Wi-Fi a name.'); if(w.passphrase.length<8||w.passphrase.length>63) throw new Error((ZONE_NAMES[z]||z)+': a Wi-Fi password must be 8 to 63 characters.'); }
      for(const n of apNets){ if(!n.ssid) throw new Error((ZONE_NAMES[n.zone]||n.zone)+': give the access point Wi-Fi a name.'); if(n.passphrase.length<8||n.passphrase.length>63) throw new Error((ZONE_NAMES[n.zone]||n.zone)+': a Wi-Fi password must be 8 to 63 characters.'); }
      if(!used.length&&!zones.length&&!cards.length) throw new Error('Pick a port, a Wi-Fi card, a VLAN, or the access point for at least one zone.');
      const ap = (ui.apRead && apNets.length) ? {ip:ui.apRead.ip, password:ui.apPwSent||'', networks:apNets, ipv6_off:ui.apIpv6Off!==false, dhcp_off:ui.apDhcpOff!==false} : null;
      ui.sawZoneVlans=false;
      await post('/api/zones/vlans',{zones:zones,ports:ports,wifi:wifi,scramble:ui.scramble!==false,ap:ap,trusted:picks.trusted||'',dhcp:data.dhcp_server==='dnsmasq'?(ui.dhcpPick||'kea'):null}); await refresh(); });   // BUILD 450: the Trusted port as picked above, saved or not
    // BUILD 515 (the maintainer, live disc on plain 26.7): said here, before the button, when this firewall's port form cannot do it
    // BUILD 516 (the maintainer, 12 Nov 2026: "set these up should just be update (a dead end requiring back)", "let them update"):
    // when this firewall's port form cannot do it, the button here IS the update, on a live disc too.
    let zoneBtn=mk;
    if(data.port_form===false){ const ow=el('div',undefined,'card unsafe'); ow.dataset.oldPortForm='1';
      ow.append(el('h3','This firewall has to be updated first'), el('p',
        'It is on an older 26.7 whose own port form cannot switch a port on or give it an address, so these zones cannot be set up on it yet. Update it now runs the firewall\u2019s own updater: a few minutes, and this page carries on by itself.'
        + (st.trial ? ' On a live disc the update lasts only until the firewall restarts, so do not restart it afterwards. Or press Skip below and try the rest without zones.' : ''),'mut'));
      vc.append(ow);
      zoneBtn=el('button','Update it now'); zoneBtn.dataset.zonesUpdate='1';
      zoneBtn.onclick=()=>act(zoneBtn, async()=>{ delete ui.done.plugin; delete ui.skipped.plugin; ui.force=null; ui.fwAuto=false; saveUi(); await post('/api/firmware/update',{}); }); }
    vc.append(bar('',zoneBtn)); body.append(vc);
    await kidsCard(body, st);
  }
  { const rs=el('div',undefined,'card'); rs.append(el('h2','Random subnets'));
    rs.append(el('p','Every zone Pazuzu sets up above gets its own random private 10.x network (not the usual 192.168.1.x), so no two installs look alike, and the firewall hands out addresses on it with Kea. Your Trusted network keeps the address you’re connected on now — rolling that one to a random 10.x changes the address you reach the firewall at, so it’s done from the manager with a reconnect, never silently here.','mut'));
    body.append(rs); }
  const more=el('div'); more.append(
    el('p','Every port is listed. One the firewall has not set up yet is remembered, and its zone stays off until it has. To set one up now: open the firewall’s Interfaces, Assignments page, add the port, tick Enable on its page, then Save and Apply. Come back and press Check again.','mut'));
  const lnk=fwLink('Open the Assignments page','/interfaces_assign.php'); lnk.className='';
  const chk=el('button','Check again','quiet'); chk.onclick=()=>refresh();
  const mr=el('div'); mr.append(lnk,document.createTextNode('  '),chk); more.append(mr); body.append(fold('need another port in this list?', more));
  body.append(ispHelp());
  const save=el('button','Save and continue');
  save.onclick=()=>act(save, async()=>{
    const isSet=d=>!!(data.interfaces.find(i=>i.device===d)||{}).assigned;
    const later={}; Object.keys(picks).forEach(z=>{ if(z!=='wan'&&picks[z]&&!isSet(picks[z])) later[z]=picks[z]; });   // a port the firewall has not set up yet: remembered, the zone stays off for now
    const sel={}; Object.keys(picks).forEach(z=>{ sel[z]= picks[z]&&!later[z]? {method:'existing',device:picks[z]} : {method:'unconfigured'}; });
    ['wan'].forEach(z=>{ if(!picks[z]) throw new Error('The internet zone needs an interface.'); });
    Object.keys(sel).forEach(z=>{ if(data.optional.includes(z)&&sel[z].method==='unconfigured') delete sel[z]; });
    const z=await post('/api/zones',sel);
    await post('/api/zones/later',later);
    if(!z.deployable){
      const bad=Object.entries(z.assignments||{}).filter(([k,a])=>a&&(a.state==='pending_assignment'||a.state==='pending_creation')).map(([k,a])=>(ZONE_NAMES[k]||k)+' is set to '+(a.device||'a port')+', which the firewall has not set up yet');
      throw new Error((bad.length?bad.join('; ')+'. Pick a port the firewall has set up, or leave that zone off.':'Some of those choices are not ready yet. An interface must be assigned and enabled on the firewall first.'));
    }
    ui.done.zones=true; ui.force=null; saveUi();
  });
  const skipZones=el('button','Skip — set zones up later','quiet'); skipZones.onclick=()=>mark('zones','skip');   // this whole step is optional: skipping reaches the manager, where zones can be set up any time
  body.append(bar('Assign what you want now, or skip — this step is optional and you can set zones up any time in the manager.', save, skipZones));
}

const SHIELDS=['Firewall-only DNS','Packet inspection (IPS)','Block lists','Ad lists'];
const LEVELS=[
  {key:'critical',name:'Critical',mood:'You’re on your own',on:[0,0,0,0],says:'All shields down. Devices can use DNS servers other than the firewall, packet inspection is off, and blocked sites are reachable.'},
  {key:'warning',name:'Warning',mood:'worried',on:[1,0,0,0],says:'Ad lists, block lists and packet inspection are down.'},
  {key:'caution',name:'Caution',mood:'easy now',on:[1,1,0,0],says:'Ad lists and block lists are down.'},
  {key:'secure',name:'Secure',mood:'calm',on:[1,1,1,0],says:'Only the ad lists are down.'},
  {key:'normal',name:'Normal',mood:'happy',on:[1,1,1,1],says:'All baselines met.'}];
async function internetCard(st, job){
  const c=el('div',undefined,'card'); c.append(el('h2','Internet and the tests'));
  let n; try{ n=await get('/api/internet'); }catch(e){ c.append(el('p','Could not read this: '+(e.message||e),'mut')); c.dataset.problem='1'; return c; }
  const w=n.wan;
  if((w && !w.address) || n.link==='down' || (n.route && n.route.commands)) c.dataset.problem='1';        // something to act on: it stays on the screen
  c.append(el('p', w ? 'Internet-side port: '+(w.device||'?')+', '+(w.address?('address '+w.address):'no address yet')+(n.link==='down'?' (no cable)':n.link==='up'?' (cable in)':'') : 'Internet-side port: not read yet.','mut'));
  if(w && !w.address && n.link!=='down') c.append(el('p','The firewall has no address on its internet side, so it may not be able to look up names or sync its clock. Those tests then fail and each stage is undone.','mut'));
  if(n.gateway) { const said=[n.gateway.address, n.gateway.status, n.gateway.delay].map(x=>String(x||'').trim()).filter(x=>x && x!=='~');   // BUILD 526: the firewall writes "~" for no reading
    if(said.length) c.append(el('p','Next router: '+said.join(' \u00b7 '),'mut')); }
  if(job && job.kind==='internet-test' && job.state==='done'){
    const rs=job.result||{}; const ls=(rs.lines&&rs.lines.length)?rs.lines:['The firewall reached the internet.'];
    ls.forEach(l=>c.append(el('p',l, rs.reached===false?'mut':undefined)));
    if(rs.reached===false){ c.dataset.problem='1'; c.append(el('p','You can carry on: switching the rules on does not need the internet. Updates and block lists do.','mut')); }
  }
  const t=el('button','Test the internet from the firewall','quiet'); t.onclick=()=>act(t,()=>post('/api/internet/test',{}));
  c.append(el('p','The outside tests need the internet-side port plugged into a router that has the internet. A temporary link is fine.','mut'), t);
  const r=n.route||{};
  if(r.detail) c.append(el('p',r.detail,'mut'));
  if(r.commands){
    const d=el('details'); d.append(el('summary','Show the route lines'));
    const pre=el('pre'); pre.textContent=r.commands.join('\n'); const pre2=el('pre'); pre2.textContent=r.remove.join('\n');
    d.append(el('p',r.note||'','mut'), pre, el('p','To take it away again:','mut'), pre2); c.append(d);
    const chk=el('button','Check the route again','quiet'); chk.onclick=()=>refresh().catch(fail); c.append(chk);
  }
  return c;
}
// "Reach home from outside": a name that follows the home address (DuckDNS, token only), then the VPN behind it, on one page.
function reachApps(){
  const d=el('div',undefined,'mut'); d.dataset.wgApps='1';
  d.append(document.createTextNode('Get the WireGuard app: '));
  [['App Store',web('apps.apple.com/app/wireguard/id1441195209')],['Google Play',web('play.google.com/store/apps/details?id=com.wireguard.android')]].forEach(([t,u],i)=>{
    if(i) d.append(document.createTextNode(' · '));
    const a=el('a',t); a.href=u; a.target='_blank'; a.rel='noopener noreferrer'; d.append(a); });
  return d;
}
// BUILD 547 (an iPhone run: the VPN's picture "shows only on the firewall's console (a tester's
// OPNsense usually has no screen)"; the maintainer, 16 Nov: "go"). The WireGuard app on a phone takes a picture or a file, not pasted
// text, so the app this page runs in is handed the settings as a file and passes it on (its share sheet). The page only
// offers it when the app says it can: iOS window.webkit.messageHandlers.hanbiFile.postMessage({name, text}), Android
// window.HanbiApp.shareFile(name, text). The settings stay what they were: in this page only, never saved on the firewall.
function appTakesFile(){ try{ if(window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.hanbiFile) return 'ios'; if(window.HanbiApp && typeof window.HanbiApp.shareFile==='function') return 'android'; }catch(e){} return ''; }
function giveAppFile(name, text){ const how=appTakesFile(); if(how==='ios') window.webkit.messageHandlers.hanbiFile.postMessage({name:name, text:text}); else if(how==='android') window.HanbiApp.shareFile(name, text); return !!how; }
function reachFileCard(r){
  const d=el('div'); d.dataset.wgFile='1';
  d.append(el('h2','Add it to WireGuard on this phone'));
  d.append(reachApps());
  // BUILD 554 (WireGuard on Android takes a file through its own "Import from file or archive",
  // not the share sheet, so the app there saves the file; "Press the button below and choose WireGuard" is right on the
  // iPhone only).
  const droid=appTakesFile()==='android';
  const ol=el('ol'); (droid ? ['Install the WireGuard app first, if it is not on this phone yet.','Press the button below and save the file.','In WireGuard, tap + and choose Import from file or archive, then pick that file.','Use the VPN while you\u2019re away; at home, leave it off.']
    : ['Install the WireGuard app first, if it is not on this phone yet.','Press the button below and choose WireGuard.','Allow it to add the VPN. Use it while you\u2019re away; at home, leave it off.']).forEach(t=>ol.append(el('li',t))); d.append(ol);
  const b=el('button', droid ? 'Save the VPN file' : 'Open in WireGuard'); b.onclick=()=>{ giveAppFile((ui.platform==='hanbi'?'hanbi':'pazuzu')+'-home.conf', r.config||''); }; d.append(b);
  d.append(el('p', droid ? 'The file holds the VPN\u2019s key. Once WireGuard has it, delete the file from this phone. The settings are never saved on the firewall.' : 'The settings go from this page to the WireGuard app. They are never saved on the firewall.','mut'));
  return d;
}
function reachQr(r){
  const c=el('div',undefined,'card'); c.dataset.reachQr='1';
  if(ui.phone && appTakesFile() && r.config){ c.append(reachFileCard(r)); const or=el('details'); or.append(el('summary','Or scan it from your Hanbi\u2019s screen with another phone')); or.append(el('p','The picture is on your Hanbi\u2019s screen while this page is open, for a firewall that has one.','mut')); c.append(or); }
  if(ui.phone){
    // BUILD 481: a phone cannot scan its own screen, so the picture goes on the box's (the same as the one-time code)
    // 0.6.83 (the maintainer's newcomer run): switched on at home, the VPN took the phone's way to the box with it. Use it away.
    ui.boxQr={qr:r.config||'', qr_words:'Scan with the WireGuard app', title:'Reach home from outside',
      steps:stepList(['Open the WireGuard app and press +', 'Scan from QR code: point it at this screen', 'Save it. Use it while you\u2019re away'])};
    tellBox({step:6, of:LIGHT_STEPS.length, title:'Reach home from outside', do:'Scan this with the WireGuard app. Use it while you\u2019re away.', qr:ui.boxQr.qr, qr_words:ui.boxQr.qr_words, steps:ui.boxQr.steps});
    if(!appTakesFile()){
    c.append(el('h2','Scan the picture on your Hanbi\u2019s screen'));
    c.append(reachApps());
    const ol=el('ol'); ['Open the WireGuard app on this phone and press +.','Choose Scan from QR code and point it at your Hanbi\u2019s screen.','Name it and save it. Use it while you\u2019re away; at home, leave it off.'].forEach(t=>ol.append(el('li',t))); c.append(ol);
    c.append(el('p','The picture is on the screen only while this page is open. It is never saved.','mut')); }
  } else {
  c.append(el('h2','Scan this with the WireGuard app'));
  const pic=el('div',undefined,'qrbox'); pic.append(document.importNode(new DOMParser().parseFromString(r.svg,'image/svg+xml').documentElement,true)); c.append(pic);
  c.append(reachApps());
  const ol=el('ol'); ['Open the WireGuard app on your phone and press +.','Choose Scan from QR code and point it at the picture.','Name it, switch it on, and try it away from your home Wi-Fi.'].forEach(t=>ol.append(el('li',t))); c.append(ol);
  c.append(el('p','This picture is shown here only. It is never saved and is gone when you close or reload this page.','mut'));
  }
  const det=el('details'); det.append(el('summary','Cannot scan? Use the settings as text')); const pre=el('pre'); pre.textContent=r.config||''; det.append(pre, copyButton(r.config||'','Copy the settings')); c.append(det);
  const hide=el('button','Hide it now','quiet'); hide.onclick=()=>{ ui.vpnPeer=null; ui.boxQr=null; refresh().catch(fail); }; c.append(hide);
  return c;
}
async function reachStep(body, st, job){
  // BUILD 481: a device the firewall did not take has no picture to scan (it showed beside the red line on the lab box)
  if(job && job.kind==='write-peer' && job.state==='failed' && ui.vpnPeer){ ui.vpnPeer=null; ui.boxQr=null; }
  body.append(backLink('reach'));
  body.append(head(6,'Reach home from outside','A name that follows your home internet address, and a VPN behind it. Nothing here switches a rule on.',true));
  const warn=el('div',undefined,'card'); warn.append(el('h2','Why the name comes first'), el('p','A VPN is only as dependable as the name in front of it. If your home IP address changes and the name doesn’t follow, the VPN stops answering.')); body.append(warn);
  const wr=writeResult(st,['write-ddns','write-vpn','write-peer']); if(wr) body.append(wr);
  // BUILD 514 (the maintainer, live disc, 12 Nov 2026: "maybe grey out the dydns plugin button until updated"): when the version
  // step saw an update waiting, this card is here from the start and the install button below stays greyed until then.
  const mustUp = installRefused(job) || !!ui.fwWaiting;
  { const sc=staleInstall(job, 'reach', !!ui.fwWaiting); if(sc) body.append(sc); }
  if(ui.fwFrom==='reach' && job && (job.kind==='firmware-update'||job.kind==='firmware-reboot'||job.kind==='firmware-check') && job.state==='done'){
    let f=null; try{ f=await get('/api/firmware'); }catch(e){}
    const uc=el('div',undefined,'card'); uc.append(el('h2','Updating the firewall')); firmwareActions(uc, f, job);
    if(job.kind==='firmware-update') uc.append(el('p','When it is done, press the install button below again.','mut')); body.append(uc);
  }
  let r; try{ r=await get('/api/reach/state'); }catch(e){
    const c=el('div',undefined,'card unsafe'); c.append(el('h2','Could not read this'), el('p',String(e.message||e),'mut')); body.append(c);
    const again=el('button','Look again'); again.onclick=()=>refresh().catch(fail); const later=el('button','Not now','quiet'); later.onclick=()=>mark('reach','skip'); body.append(bar('', again, later)); return;
  }
  const dd=r.ddns||{}, v=r.vpn||{};
  const named=!!(r.name||dd.host), current=dd.choice==='current';
  const nameCard=el('div',undefined,'card'); nameCard.dataset.reachName='1'; nameCard.append(el('h2','1. A name for home'));
  if(!named && !current) nameCard.append(means('your internet provider changes your home address from time to time. A home name always points at the current one, so your phone can find home by name.'));
  const waitBtns=()=>{
    const row=el('div',undefined,'btnrow');
    const chk=el('button','Check the internet again'); chk.onclick=()=>act(chk, async()=>{ await post('/api/internet/test',{}); });
    const carry=el('button','Carry on, finish this later','quiet'); carry.onclick=()=>{ ui.skipped.reach='waiting'; delete ui.done.reach; saveUi(); ui.force=null; refresh().catch(fail); };
    row.append(chk, carry); return row;
  };
  if(named){
    nameCard.append(el('p','✓ Your home name: '+(r.name||dd.host),'mut'));
    // BUILD 519 (the maintainer, 12 Nov 2026: "or was this checked?"): the tick means saved on the firewall. Nothing here looks the
    // name up to see that it has caught up with the home address; that check is for beta 2, and the page says so.
    nameCard.append(el('p','Saved on the firewall, which now keeps the name pointed at your home address. Whether the name has caught up yet is not checked here: that check comes in beta 2. To look yourself, the firewall\u2019s Services, Dynamic DNS page shows when it last updated.','mut'));
  } else if(current){
    nameCard.append(el('p','✓ Using your internet address as it is today. If it changes, the VPN stops answering until you give your phone the new one.','mut'));
  } else if(r.internet==='down' || r.internet==='no'){
    nameCard.dataset.waiting='1';
    nameCard.append(el('p', r.internet==='down' ? 'Waiting for the internet. The internet-side port shows no cable.' : 'Waiting for the internet. The firewall could not reach it when it was last tested.'),
      el('p','The name service, and the plugin that keeps the name up to date, both need the firewall to reach the internet. Plug the internet-side port into your router, then check again. If you carry on, this stays on the last page as still open.','mut'), waitBtns());
  } else if(!dd.plugin_there){
    nameCard.append(el('p','The firewall needs a small plugin to keep a name pointed at your home.'), el('p', dd.why || 'It has not been checked yet.', 'mut'));
    const row=el('div',undefined,'btnrow');
    const inst=el('button','Put the name plugin on the firewall'); inst.dataset.ddnsInstall='1'; inst.onclick=()=>act(inst, async()=>{ await post('/api/ddns/install',{}); });
    const re=el('button','Check this firewall again','quiet'); re.onclick=()=>act(re, async()=>{ await post('/api/probe',{}); });
    if(mustUp){ inst.disabled=true; inst.className='quiet'; inst.title='Update the firewall first: the card above.'; inst.dataset.needsUpdate='1'; }
    row.append(inst, re); nameCard.append(row);
    if(mustUp) nameCard.append(el('p','Greyed until the firewall is updated: it installs nothing before that.','mut'));
  } else {
    if(!ui.reachSug){ try{ ui.reachSug=await get('/api/ddns/suggest'); }catch(e){ ui.reachSug={label:'',host:''}; } }
    const sg=ui.reachSug;
    nameCard.append(el('p','A free name from DuckDNS. It follows your home IP address by itself. You only need its token.'), el('p','The firewall reads your home IP address straight off its internet port when the port holds it (otherwise it asks a web lookup service), and tells DuckDNS when it changes.','mut'));
    const pick=el('div',undefined,'btnrow'); pick.append(el('code',sg.host)); pick.dataset.reachSuggest='1';
    const other=el('button','Try another','quiet'); other.onclick=async()=>{ try{ ui.reachSug=await get('/api/ddns/suggest'); }catch(e){} refresh().catch(fail); };
    pick.append(copyButton(sg.label,'Copy the name'), other); nameCard.append(pick);
    const ol=el('ol');
    ol.append(el('li','Open duckdns.org and sign in. It is free, and Google, GitHub and others work.'));
    ol.append(el('li','Type the name above (without .duckdns.org) in the domain box and press add domain.'));
    ol.append(el('li','Copy the token shown at the top of their page and paste it below.'));
    nameCard.append(ol);
    boxSteps(['Open duckdns.org and sign in', 'Add the domain: '+sg.label, 'Copy the token at the top of their page',
      'Paste it in the app and press Save the name on the firewall']);   // 0.6.83 (the maintainer: the token step was not apparent)
    const row=el('div',undefined,'btnrow'); const a=el('a','Open duckdns.org','btn'); a.href=web('www.duckdns.org'); a.target='_blank'; a.rel='noopener noreferrer'; row.append(a); nameCard.append(row);
    const tok=el('input'); tok.type='password'; tok.autocomplete='off'; tok.placeholder='Your DuckDNS token'; tok.dataset.duckToken='1';
    const save=el('button','Save the name on the firewall');
    // BUILD 535 (the maintainer: "add duckdns token length verification"): 36 characters, 8-4-4-4-12, checked here and again on the PC.
    const tokSay=el('p','','mut'); tokSay.dataset.duckTokenSay='1';
    const tokBad=t=>{ t=t.trim(); if(!t) return ''; if(t.length!==36) return 'That token is '+t.length+' characters long. A DuckDNS token is 36: copy the whole token from the top of the DuckDNS page.'; if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(t)) return 'That is not the shape of a DuckDNS token: letters a to f, digits and four dashes. Copy the token, not the name.'; return ''; };
    tok.oninput=()=>{ const b=tokBad(tok.value); tokSay.textContent=b||(tok.value.trim()?'That looks like a DuckDNS token.':''); save.disabled=!!b; };
    save.onclick=()=>{ const t=tok.value.trim(); const b=tokBad(t)||(t?'':'Give the token DuckDNS shows at the top of its page.'); if(b){ tokSay.textContent=b; return; } tok.value=''; tokSay.textContent=''; act(save, async()=>{ await post('/api/write/ddns',{provider:'duckdns', hostname:sg.host, password:t}); }); };
    const sr=el('div',undefined,'btnrow'); sr.append(tok, save); nameCard.append(sr, tokSay);
    nameCard.append(el('p','The token goes to the firewall in this one request. It is not kept, shown or written to any file.','mut'));
    const more=el('details'); more.append(el('summary','Use something else'));
    const own=el('input'); own.type='text'; own.autocomplete='off'; own.placeholder='A name you already have, like home.example.net';
    const useOwn=el('button','Use this name','quiet'); useOwn.onclick=()=>act(useOwn, async()=>{ await post('/api/ddns/choose',{choice:'domain', hostname:own.value}); });
    const useNow=el('button','Use my address as it is today','quiet'); useNow.onclick=()=>act(useNow, async()=>{ await post('/api/ddns/choose',{choice:'current'}); });
    more.append(el('p','Your own name must already point home, or be kept pointed at it by something else. Pazuzu only remembers it for the VPN.','mut'), own, useOwn, el('p','Your address as it is today works until your provider changes it. Then the VPN stops answering.','mut'), useNow);
    nameCard.append(more);
  }
  body.append(nameCard);
  // The VPN follows once the name is settled.
  const vpnCard=el('div',undefined,'card'); vpnCard.dataset.reachVpn='1'; vpnCard.append(el('h2','2. The VPN'));
  if(!(r.vpn&&r.vpn.instance)) vpnCard.append(means('a private tunnel from your phone to your home. With it on, your phone acts as if it were at home, even on mobile data or someone else’s Wi-Fi.'));
  const settled=named||current;
  const hasDevice=(v.devices||[]).length>0;
  if(!settled){
    vpnCard.append(el('p','The VPN comes right after the name, so it never points at an address that moves.','mut'));
    body.append(vpnCard);
    const later=el('button','Not now','quiet'); later.onclick=()=>mark('reach','skip');
    body.append(bar(r.internet==='down'||r.internet==='no' ? '' : 'You can do this later in the manager.', later)); return;
  }
  if(!v.instance){
    if(!v.can_make){
      vpnCard.append(el('p','The VPN cannot be made yet.'), el('p', v.why||'Check what this firewall supports first.','mut'));
      const re=el('button','Check this firewall again','quiet'); re.onclick=()=>act(re, async()=>{ await post('/api/probe',{}); }); vpnCard.append(re);
    } else {
      const sg=v.suggest||{name:'home',port:'51820',address:'10.91.5.1/24'};
      vpnCard.append(el('p','A VPN on the firewall, on port '+sg.port+' (UDP). Your phone dials it using the name above.'));
      const mk=el('button','Make the VPN'); mk.dataset.vpnMake='1'; mk.onclick=()=>act(mk, async()=>{ await post('/api/write/vpn-instance',{name:sg.name, port:sg.port, tunneladdress:sg.address}); });
      vpnCard.append(mk);
    }
  } else {
    vpnCard.append(el('p','✓ The VPN is on the firewall ('+(v.instance.name||'home')+', port '+v.instance.port+').','mut'));
    if(ui.vpnPeer){ /* the picture is its own card, below */ }
    else {
      vpnCard.append(el('p', hasDevice ? 'Devices so far: '+v.devices.map(d=>d.name).join(', ')+'.' : 'Now add your phone. The keys are made here, and the picture is shown once.', 'mut'));
      const nm=el('input'); nm.type='text'; nm.autocomplete='off'; nm.placeholder='A name for the device, like phone'; nm.value=ui.vpnDev||'phone'; nm.oninput=()=>{ ui.vpnDev=nm.value; };
      const add=el('button', hasDevice?'Add another device':'Add my phone and show the picture'); add.dataset.vpnDevice='1';
      add.onclick=()=>act(add, async()=>{ ui.vpnPeer=await post('/api/vpn/device',{name:nm.value||'phone', host:dd.host||r.name||v.host_guess||'', full:false}); });
      const row=el('div',undefined,'btnrow'); row.append(nm, add); vpnCard.append(row);
      if(!v.can_device) vpnCard.append(el('p', v.why||'This firewall has no page for adding a device yet.','mut'));
    }
  }
  body.append(vpnCard);
  if(ui.vpnPeer) body.append(reachQr(ui.vpnPeer));
  const finished=!!(v.instance && (hasDevice||ui.vpnPeer));
  const done=el('button','Done'); done.onclick=()=>{ ui.vpnPeer=null; ui.boxQr=null; mark('reach','done'); };
  const later=el('button','Not now','quiet'); later.onclick=()=>{ ui.vpnPeer=null; ui.boxQr=null; mark('reach','skip'); };
  body.append(bar(finished?'The name and the VPN are in place. Check the VPN from outside your home Wi-Fi when you can.':'You can do this later in the manager.', finished?done:null, later));
}
// The three runs, in order: the allow rules, the old allow-everything rules off, the blocking rules. One press starts the
// first and the others follow by themselves; a stage that fails its test is undone and the run stops there.
const LIGHT_RUNS={
  allow:{at:6, title:'Switch the rules on', sub:'Three parts, one press. Part 1 adds Pazuzu’s rules, all switched off, then switches on the ones that let your devices work: the way into the firewall, names and time, and the internet. Part 2 switches off the old allow-everything rules. Part 3 switches on the blocking rules. Each stage is tested from this device and undone by itself if a test fails, and then the run stops so you can see why.', go:'Switch the rules on', note:'One press runs all three parts. A stage that fails its test is undone and the run stops there.'},
  stock:{at:6, title:'Rules, part 2 of 3: switch off the old allow-everything rules', sub:'This is the part that can cut a device off, so it comes after the plugin, Wi-Fi, the name and the VPN. It first adds one rule that keeps the plugin reachable. It is tested from this device and undone by itself if a test fails. The blocking rules follow by themselves.', go:'Switch the old rules off, then the blocking rules', note:'If the test fails, the old rules come back on by themselves and the run stops.'},
  block:{at:6, title:'Rules, part 3 of 3: blocking rules', sub:'Last of all: Pazuzu’s own block rules, switched on once everything that must keep working has been tested without the old rules. Tested, and undone by itself if a test fails.', go:'Switch on the blocking rules', note:'If the test fails, they go back off by themselves.'}
};
// BUILD 493 (the maintainer, 10 Nov 2026: the wizard alone switches the rules on; the manager is beta 2): the careful way's words.
// Each part asks for the passkey, so each is its own press.
const CAREFUL_RUNS={
  allow:{title:'Switch the rules on', sub:'Three parts. Part 1 switches on the rules that let your devices work: the way into the firewall, names and time, and the internet. Part 2 switches off the old allow-everything rules. Part 3 switches on the blocking rules. Each part is tested from this device and undone by itself if a test fails.', go:'Switch on part 1', note:'Your passkey approves it. A stage that fails its test is undone and the run stops there.'},
  stock:{title:'Rules, part 2 of 3: switch off the old allow-everything rules', sub:'This is the part that can cut a device off, so it is tested from this device and undone by itself if a test fails.', go:'Switch the old rules off', note:'If the test fails, the old rules come back on by themselves.'},
  block:{title:'Rules, part 3 of 3: blocking rules', sub:'Last: Pazuzu’s own block rules, switched on once everything that must keep working has been tested without the old rules.', go:'Switch on the blocking rules', note:'If the test fails, they go back off by themselves.'}
};
// BUILD 493 (the maintainer: "ask for the way-in port when there isn't one"): on a firewall that is already running, the ports are
// usually assigned, so the ports page is skipped and nothing asked for a way in; the rules then could not be switched
// on, and only the manager said why. A spare port for Management (or one the firewall has not set up yet) is picked
// here, as the manager's Get ready does; the VPN or Bluetooth counts too.
async function wayInStep(body, st, job){
  body.append(head(3,'Your way in','Before the rules go on: the way you reach the firewall’s page, kept open so a rule can never lock you out.'));
  if(job && job.kind==='write-zone-vlans' && job.state==='running'){ body.append(busyCard('Setting the port up on the firewall…')); schedule(); return; }
  const busyR=busyCard('Reading the firewall’s ports…'); body.append(busyR);
  let r=null; try{ r=await get('/api/ready'); }catch(e){ busyR.remove(); fail(e); return; }
  busyR.remove();
  if(r.way && r.way.ok){ return mark('wayin','done'); }
  const z=r.zones;
  const c=el('div',undefined,'card');
  c.append(el('h2','Pick a management port'));
  c.append(el('p','A spare port to plug your computer into when you manage the firewall. Pazuzu keeps it open, so a rule can never lock you out. Nothing changes on your other ports.','mut'));
  const later=el('button','Do this later','quiet'); later.onclick=()=>mark('wayin','skip');
  if(!z){ c.append(el('p', r.zones_error ? 'Could not read the ports: '+r.zones_error : 'Could not read the ports.','vt')); body.append(c);
    const again=el('button','Check again'); again.onclick=()=>refresh().catch(fail);
    body.append(bar('Without a way in, the rules are added but left off.', later, again)); return; }
  const okDev=new Set(z.way_in || (z.interfaces||[]).map(i=>i.device));
  const choices=(z.interfaces||[]).filter(i=>okDev.has(i.device));
  if(!choices.length){
    c.append(el('p','There is no spare port to pick: every port is already used for another network. Add a port (a USB network adapter works), or set up the VPN later; until then the rules are added but left off.','vt'));
    body.append(c); body.append(bar('Without a way in, the rules are added but left off.', later)); return; }
  const sel=el('select'); sel.setAttribute('aria-label','Management port');
  choices.forEach(i=>sel.append(new Option(i.label+(i.link?' · '+i.link:''), i.device)));
  if(z.suggested_management && choices.some(i=>i.device===z.suggested_management)) sel.value=z.suggested_management;
  c.append(sel);
  c.append(el('p','A port the firewall has not set up yet is set up for you: its own network, and an address handed to the computer you plug in.','mut'));
  body.append(c);
  const use=el('button','Use this port');
  use.onclick=()=>act(use, async()=>{
    const dev=sel.value, i=(z.interfaces||[]).find(x=>x.device===dev);
    if(i && !i.assigned) await post('/api/zones/vlans',{ports:{management:dev}});
    else await post('/api/zone/set',{zone:'management', device:dev});
  });
  body.append(bar('Then the rules are added, and switched on one part at a time.', later, use));
}
// The three parts as the box's screen lists them (plugin 0.6.83).
const RULE_PARTS=[['allow','Part 1: the rules your devices need, on'],['stock','Part 2: the old allow-everything rules, off'],['block','Part 3: the blocking rules, on']];
// What a finished run says about each of its stages, one line each.
function stageLines(r){ return ((r&&r.stages)||[]).map(x=>{ const d=String(x.detail||''), s=String(x.state||'');
  const same = s && d.toLowerCase().startsWith(s.toLowerCase());     // BUILD 525: "kept. Kept. 3 of 3 tests passed." said it twice
  return x.title+': '+(same ? d.charAt(0).toLowerCase()+d.slice(1) : s+(d?'. '+d:''))+(x.note?' '+x.note:''); }); }
async function lightRules(body, st, job){
  body.append(backLink('rules'));
  // The plugin and the version first: the server refuses anything else, and this says why.
  let ctl={ok:true}; if(st.light){ try{ ctl=await get('/api/control'); }catch(e){ ctl={ok:true}; } }
  if(!ctl.ok){
    rail(6,true); body.append(head(7,'The rules wait for the plugin',undefined,true));
    const c=el('div',undefined,'card unsafe'); c.append(el('h2','Nothing is added or switched on yet'), el('p',ctl.why||'Put the plugin on the firewall and read its version first.','mut')); body.append(c);
    const back=el('button','Go to the plugin'); back.onclick=()=>{ delete ui.skipped.plugin; delete ui.done.plugin; saveUi(); ui.force=null; refresh().catch(fail); };
    body.append(bar('The plugin is what keeps a way in from the inside.', back)); return;
  }
  let plan=null; try{ plan=await get('/api/plan'); }catch(e){ plan=null; }
  const isDone=(id)=>{ const x=plan&&plan.stages.find(y=>y.id===id); if(!plan) return false; if(!x) return true;
    return x.status==='done' || (x.status==='blocked' && x.blockers.length>0 && x.blockers.every(t=>/nothing to switch off|no blocking/i.test(t))); };
  const group = !['lifeline','core_services','outbound'].every(isDone) ? 'allow' : !isDone('stock_disable') ? 'stock' : !isDone('blocking') ? 'block' : null;
  const showResult = job && job.kind==='plan' && job.state==='done' && job.result && !ui.sawPlan;
  // One press runs all three parts: after a part that was kept, the next one starts by itself. A stage that stopped ends the
  // run; so does a part that made no progress (the same part would only come round again).
  if(showResult && job.result.outcome!=='stopped' && group && ui.chain && ui.chainFrom!==group){
    ui.chainFrom=group; ui.chainLines=(ui.chainLines||[]).concat(stageLines(job.result)); ui.sawPlan=true; ui.lightGo=true; return refresh();
  }
  if(!group && !showResult){ if(st.light) ui.done.rules=true; else ui.at='access'; ui.lightGo=false; ui.runAt=null; ui.chain=false; ui.chainFrom=''; ui.chainLines=[]; saveUi(); return refresh(); }   // rules finished: on to Admin (the last step before the hand-off); the careful way: on to the access card
  const run=(st.light?LIGHT_RUNS:CAREFUL_RUNS)[group||'block']; ui.runAt=run.at;
  if(st.light){ rail(run.at,true); body.append(head(run.at+1, run.title, run.sub, true)); }
  else { rail(2); body.append(head(3, run.title, run.sub)); }      // BUILD 493: the careful way, step 3 of 4
  { const gi=RULE_PARTS.findIndex(r=>r[0]===(group||'block')); const stoppedNow=showResult && job.result.outcome==='stopped';   // 0.6.83
    boxSteps(RULE_PARTS.map((r,k)=>[r[1], k<gi?'done':k>gi?'todo':showResult?(stoppedNow?'failed':'done'):'now'])); }
  if(showResult){
    const stopped=job.result.outcome==='stopped';
    const c=el('div',undefined,'card'+(stopped?' unsafe':'')); c.append(el('h2', stopped ? 'It stopped, and nothing is left half done' : 'Done: each stage was tested and kept'));
    const ul=el('ul'); (ui.chainLines||[]).concat(stageLines(job.result)).forEach(t=>ul.append(el('li',t))); c.append(ul);
    if(job.result.internet) c.append(el('p', (job.result.internet_ok===true ? '\u2713 ' : '') + job.result.internet, 'mut'));
    if((job.result.stages||[]).some(x=>x.id==='ipv6' && (x.state==='stopped'||x.state==='undone'))){
      const row=el('div',undefined,'btnrow'); row.append(fwLink('Open Interfaces, Settings','/ui/interfaces/settings'), fwLink('Open the WAN page','/interfaces.php?if=wan')); c.append(row);
    }
    body.append(c);
    // BUILD 493: a careful run stopped only because a check still needs you shows those checks right here (the manager
    // is beta 2, so this page is where they live now). Each is run from this device; one that did not pass can be
    // carried past, and the skip is written down.
    if(!st.light && stopped && (job.result.stages||[]).some(x=>/waits for these checks/.test((x.detail||'')+(x.note||'')))){
      const cc=el('div',undefined,'card'); cc.append(el('h2','The checks it waits for'));
      const rows=(ui.svc&&ui.svc.rows)||null;
      if(rows){ rows.forEach(r=>{ const d=el('div'); d.style.margin='8px 0';
          const skipped=(ui.svc.skipped||[]).indexOf(r.id)>=0, acked=(ui.svc.acked||[]).indexOf(r.id)>=0;
          d.append(el('div',(r.status==='good'?'✓ ':skipped?'→ ':acked?'✓ ':r.status==='unknown'?'? ':'✗ ')+r.title
            +(skipped?' — carried past (written down)':acked?' — you confirmed it':'')));
          if(r.detail && r.status!=='good' && !skipped && !acked) d.append(el('div',r.detail,'mut'));
          if(r.how && r.status!=='good' && !skipped && !acked) d.append(el('div',r.how,'mut'));
          if(r.status==='attention' && !skipped){ const sk=el('button','Carry on without it','quiet');
            sk.onclick=()=>act(sk, async()=>{ const ids=(ui.svc.skipped||[]).concat([r.id]); ui.svc=await post('/api/services/skip',{ids:ids}); });
            d.append(sk); }
          if(r.status==='unknown' && !acked){ const ok=el('button','I checked it myself: it is set','quiet');
            ok.onclick=()=>act(ok, async()=>{ const ids=(ui.svc.acked||[]).concat([r.id]); ui.svc=await post('/api/services/ack',{ids:ids}); });
            d.append(ok); }
          cc.append(d); });
        if(ui.svc.ok) cc.append(el('p','The checks are handled. Press Try again below.','mut')); }
      const runBtn=el('button', rows?'Run the checks again':'Run the checks');
      runBtn.onclick=()=>act(runBtn, async()=>{ ui.svc=await post('/api/services/test',{}); });
      cc.append(el('div',undefined,'btnrow')); cc.lastChild.append(runBtn);
      body.append(cc);
    }
    // After a stage was undone, Try again runs the same step again straight away, once the cause is fixed.
    const undone=stopped && (job.result.stages||[]).some(x=>x.state==='undone');
    const again=el('button', undone?'Try again':stopped?'Look again':'Continue'); again.onclick=()=>{ ui.sawPlan=true; if(undone) ui.lightGo=true; if(!stopped){ ui.chain=false; ui.chainFrom=''; ui.chainLines=[]; } refresh().catch(fail); };
    body.append(bar(stopped?(undone?'Fix what it says, then press Try again.':'Fix what it says, then look again.'):'Next.', again)); return;
  }
  const busyR=busyCard('Reading your firewall…'); body.append(busyR);
  let p={new_rules:0}; if(group==='allow'){ try{ p=await post('/api/rules/preview',{limit:ui.limit}); }catch(e){ busyR.remove(); fail(e); return; } }
  let pv=null, why='';
  if(!p.new_rules){ try{ pv=await post('/api/plan/preview',{group}); }catch(e){ why=String(e.message||e); } }
  busyR.remove();
  if(!p.new_rules && !pv && /Nothing is left to switch on|Handled/.test(why)){ ui.sawPlan=false; return refresh(); }
  const c=el('div',undefined,'card');
  const groups=(p.groups||[]);
  if(p.new_rules){ c.append(el('h2','What Pazuzu will do'), el('p','Add '+p.new_rules+' safety rules, all switched off. Then the allow rules are switched on, one stage at a time.','mut')); groups.forEach(g=>{ const d=el('div'); d.append(el('div',g.title)); if(g.why) d.append(el('div',g.why,'mut')); c.append(d); }); }
  else if(pv){ c.append(el('h2','Ready'), el('p','These stages are next:','mut')); const ul=el('ul'); pv.stages.forEach(x=>ul.append(el('li',x.title))); c.append(ul);
    if((pv.notes||[]).length){ const nc=el('div',undefined,'card unsafe'); nc.append(el('h2','Worth a look before you start')); pv.notes.forEach(n=>{ const mine=st.light && /^IPv6 is switched on for the WAN/.test(n) && n.indexOf(' Switch it off')>0;   // BUILD 525: the run does this itself
      if(mine){ nc.append(el('p', n.slice(0,n.indexOf(' Switch it off'))+' The first part of this run switches it off for you (IPv6 Configuration Type: None, on the WAN and the LAN), and reads it back to check.')); return; }
      nc.append(el('p',n)); if(/IPv6/.test(n)){ const row=el('div',undefined,'btnrow'); row.append(fwLink('Open the WAN page','/interfaces.php?if=wan')); nc.append(row); } }); body.append(nc); } }
  else { c.append(el('h2','Not ready yet'), el('p',why||'The firewall did not say what is left.','mut')); }
  body.append(p.new_rules||pv ? fold('what will be switched on', c) : c);
  if(group!=='stock'){ const ic=await internetCard(st, job); body.append(ic.dataset.problem ? ic : fold('the internet and the tests', ic)); }
  if(!p.new_rules && pv && ui.lightGo && st.light){ ui.lightGo=false; act(null, async()=>{ await post('/api/plan/run',{digest:pv.digest, group}); }); return; }   // the careful way: each part is its own press (its own passkey)
  const go=el('button', p.new_rules ? 'Add the rules' : (pv ? run.go : 'Check again'));
  go.onclick=()=>{
    if(p.new_rules||pv){ ui.chain=true; ui.chainFrom=''; ui.chainLines=[]; }
    if(p.new_rules){ ui.lightGo=true; ui.total=p.new_rules||0; act(go,()=>post('/api/rules/apply',{limit:ui.limit})); }
    else if(pv){ act(go, async()=>{ await post('/api/plan/run',{digest:pv.digest, group}); }); }
    else refresh().catch(fail);
  };
  const off=st.light?null:el('button','Leave them off for now','quiet');      // BUILD 493: the careful way may stop here
  if(off) off.onclick=()=>{ ui.at='access'; ui.chain=false; ui.chainFrom=''; ui.chainLines=[]; saveUi(); refresh().catch(fail); };
  body.append(bar(p.new_rules?'Adds the rules switched off. Then the allow rules go on, each tested.':(pv?run.note:'Fix what it says, then check again.'), ...(off?[off]:[]), go));
}
async function rulesStep(body, st, job){
  if(st.light) return lightRules(body, st, job);
  body.append(backLink('rules'));
  body.append(head(3,'Applying these safety settings'));
  if(ui.mode==='audit'){ const an=el('div',undefined,'card'); an.append(el('h2','Your existing rules')); const sc=el('div',undefined,'scroll'); sc.append(el('p','We read first and never change a rule of yours without your approval. Allows you made can’t be accounted for. We don’t move your interfaces.','mut')); an.append(sc); body.append(an); }
  const next=el('button','Continue','quiet'); next.onclick=()=>{ ui.at='allset'; refresh(); };
  if(job && job.kind==='apply-rules' && job.state==='done' && !ui.sawApply){
    const c=el('div',undefined,'card'); c.append(el('h2','Done'), jobCard(job)); body.append(c);
    const go=el('button','Continue'); go.onclick=()=>{ ui.sawApply=true; refresh(); };
    body.append(bar('The rules were added, switched off. Next they are switched on.', go)); return;
  }
  const busyR=busyCard('Reading the rules on your firewall…'); body.append(busyR);
  let p; try{ p=await post('/api/rules/preview',{limit:ui.limit}); }catch(e){ busyR.remove(); fail(e); return; }
  busyR.remove();
  if(!p.new_rules){ const done=el('div',undefined,'card'); done.append(el('h2', p.new_rules===null ? 'We could not tell which rules are on your firewall' : 'All '+p.already_there+' rules Pazuzu needs are on your firewall')); if(p.new_rules!==null) done.append(el('p','Nothing was added or changed just now. Any that are still switched off are switched on in the next step, one part at a time.','mut')); if(p.new_rules===null){ const sk=el('div',undefined,'scroll'); (p.lines||[]).filter(l=>/^skipped /.test(l)).forEach(l=>sk.append(el('p',l,'mut'))); done.append(sk); } body.append(done); const om2=await stagesBlock(body, st, job); let allOn2=false; try{ const pl=await get('/api/plan'); allOn2=pl.stages.length>0 && pl.stages.every(x=>x.status==='done'); }catch(e){} next.className=allOn2?'':'quiet'; next.textContent='Continue'; body.append(bar(allOn2?'The rules are switched on.':'They are switched on in the manager.', om2, next)); return; }
  let ug={items:[]}; try{ ug=await get('/api/unguarded'); }catch(e){ ug={items:[{title:'Could not read your current setup',why:'',state:'unchecked'}]}; }
  // BUILD 529: this column said "Not checked" for packet inspection, the lists and the admin
  // password while the same page, lower down, had read all three. It uses those readings now.
  let shv=null; try{ shv=await get('/api/shields'); }catch(e){ shv=null; }
  { const f0=(shv&&shv.ready&&shv.flags)?shv.flags:null; const ownAdmin=!!(st.admin_user||ui.done.admin);
    ug.items=(ug.items||[]).map(i=>{
      if(i.state!=='unchecked') return i;
      if(i.title==='Packet inspection (IPS)' && f0) return f0.ips ? null : {title:i.title, why:'It is off.', state:'unsafe'};
      if(i.title==='Ad lists and block lists' && f0) return (f0.block&&f0.ads) ? null : {title:i.title, why:(f0.block?'The ad lists are off.':f0.ads?'The block lists are off.':'Both are off.'), state:'unsafe'};
      if(/admin password$/.test(i.title) && ownAdmin) return null;
      return i; }).filter(Boolean); }
  const two=el('div',undefined,'row');
  const left=el('div',undefined,'card unsafe'); left.append(el('h2','Unguarded on your firewall now'));
  if(!ug.items.length) left.append(el('p','Nothing was found open.','mut'));
  ug.items.forEach(i=>{ const d=el('div'); d.style.margin='10px 0'; d.append(el('div',(i.state==='unsafe'?'Open: ':'Not checked: ')+i.title)); if(i.why) d.append(el('div',i.why,'mut')); left.append(d); });
  const right=el('div',undefined,'card'); right.append(el('h2','What Pazuzu will apply'));
  (p.groups||[]).forEach(g=>{ const d=el('div'); d.style.margin='10px 0'; d.append(el('div',g.title)); if(g.why) d.append(el('div',g.why,'mut')); right.append(d); });
  two.append(left,right); body.append(two);
  const t=el('div',undefined,'tiles');
  [[p.new_rules,'rules to add, all switched off'],[p.already_there,'rules already in place']].forEach(([n,l])=>{ const x=el('div',undefined,'tile'); x.append(el('div',n===null?'?':String(n),'big'), el('div',l,'mut')); t.append(x); });
  body.append(t);
  let allOn=false; try{ const pl=await get('/api/plan'); allOn = pl.stages.length>0 && pl.stages.every(x=>x.status==='done'); }catch(e){}
  let ids={state:'unknown',detail:'Not checked yet.'}; try{ ids=await get('/api/ids'); }catch(e){}
  // The three shields the firewall runs itself, read from its own settings (26.7's block-list grid included). What
  // could not be read stays "not checked" and is never counted as down.
  const f=(shv&&shv.ready&&shv.flags)?shv.flags:null;
  const lists=(shv&&shv.lists)||{};
  const onOff=(v,names)=>v?('On'+(names&&names.length?' ('+names.slice(0,3).join(', ')+(names.length>3?', …':'')+')':'')):'Off';
  const notChecked='Not checked'+(shv&&shv.why?': '+shv.why:' yet');
  const state=[allOn?1:0, f?(f.ips?1:0):null, f?(f.block?1:0):null, f?(f.ads?1:0):null];
  let detected=0; while(detected<SHIELDS.length && state[detected]===1) detected++;
  const known = detected===SHIELDS.length || state[detected]!==null;     // the first shield that is not on was really read
  const sh=el('div',undefined,'card'); sh.append(el('h2','Shields on your firewall now'));
  const shl=el('ul',undefined,'plain');
  [['Firewall-only DNS', allOn?'On':'Not switched on by Pazuzu yet'],['Packet inspection (IPS)', f?onOff(f.ips):ids.detail],
   ['Block lists', f?onOff(f.block,lists.block):notChecked],['Ad lists', f?onOff(f.ads,lists.ads):notChecked],
   ['Alerts and logging', ui.done.alerts?'Set up':'Not set up']].forEach(([a,b])=>shl.append(el('li',a+': '+b)));
  sh.append(shl); body.append(sh);
  if(ui.level===null||ui.level===undefined) ui.level=detected;
  const lv=LEVELS[ui.level];   // no happiness tint in the wizard; the colour belongs to the manager's happiness index
  const pick=el('div',undefined,'card'); const lsel=el('select');
  LEVELS.forEach((l,i)=>lsel.append(new Option(l.name+' ('+l.mood+')'+(known&&i===detected?' — where your firewall is now':''),String(i)))); lsel.value=String(ui.level);
  lsel.onchange=()=>{ ui.level=parseInt(lsel.value,10); refresh(); };
  pick.append(el('h2','Protection level'), el('p', known ? 'This starts where your firewall is now. Move it toward happy to see what we would switch on.'
    : 'Some shields could not be read yet, so where your firewall is now is not known. Nothing is counted as down that was not checked.','mut'), lsel);
  body.append(pick);
  // BUILD 529: "All shields down" sat above a list saying three of the four were on. The level counts from the first shield that is off.
  const laterOn = known && ui.level===detected && detected<SHIELDS.length && state.some((x,i)=>i>detected && x===1);
  const says = laterOn ? SHIELDS[detected]+' is not on yet. The level is counted from the first shield that is off, so it reads '+lv.name+' even though others further down are on.' : lv.says;
  const pl=el('div',undefined,'card lvcard'); pl.append(el('div',lv.name+' · '+lv.mood,'lvname'), el('p',says,'lvsay'));
  const ul=el('ul'); SHIELDS.forEach((n,i)=>{ const now=state[i]===null?' (not checked on your firewall yet)':state[i]?' (on now)':' (off now)'; ul.append(el('li',(lv.on[i]?'On':'Down')+': '+n+now)); }); pl.append(ul);
  pl.append(el('p','The VPN is always a trusted network, at every level.','mut'));
  if(ui.level>detected){
    pl.append(el('h2','To get there we would'));
    const st=el('ul'); for(let i=detected+1;i<=ui.level;i++){ const n=SHIELDS[i-1]; st.append(el('li', i===1 ? 'Turn on firewall-only DNS (the rules below).' : 'Turn on '+n.toLowerCase()+'. (Not available from this screen yet.)')); } pl.append(st);
  } else if(ui.level<detected) pl.append(el('p','Moving down is done in the app after setup, with your passkey, and ends by itself.','mut'));
  body.append(pl);
  const c=el('details',undefined,'card'); c.append(el('summary','Technical details')); const pre=el('pre'); pre.textContent=p.lines.join('\n'); c.append(pre); body.append(c);
  if(!p.new_rules){
    const om=await stagesBlock(body, st, job);
    next.className=allOn?'':'quiet'; next.textContent='Continue';
    body.append(bar(allOn ? 'The rules are on your firewall and switched on.' : 'The rules are on your firewall but switched off, so they aren’t protecting you yet. Switch them on in the manager.', om, next));
    return;
  }
  const go=el('button','Add the rules');
  go.onclick=()=>{ ui.total=p.new_rules||0; act(go,()=>post('/api/rules/apply',{limit:ui.limit})); };
  body.append(bar('You’ll be asked for your passkey. A rollback receipt is saved.', next, go));
}

function armedStep(body, g){
  rail(2);
  body.append(head(3,'A change is waiting for you','Can you still reach your firewall? Then choose.'));
  const left=g.seconds_left||0;
  const c=el('div',undefined,'card');
  c.append(el('div',Math.floor(left/60)+':'+String(left%60).padStart(2,'0'),'big warn'));
  const ul=el('ul'); (g.steps||[]).forEach(x=>ul.append(el('li',(x.name||STEP_WORDS[x.kind]||x.kind.replace('_',' '))+': '+(STEP_STATE[x.status]||x.status)))); const sc=el('div',undefined,'scroll'); sc.append(ul); c.append(sc);
  body.append(c);
  const keep=el('button','Keep these changes'); keep.onclick=()=>act(keep,()=>post('/api/guard/decide',{decision:'keep'}));
  const undo=el('button','Undo now','quiet'); undo.onclick=()=>act(undo,()=>post('/api/guard/decide',{decision:'undo'}));
  const back=ui.managerUrl?el('button','Back to the manager','quiet'):null; if(back) back.onclick=()=>window.open(ui.managerUrl,'pazuzu-manager');
  body.append(bar('Undoing never asks for a passkey.', ...(back?[back]:[]), undo, keep));
  schedule();
}

async function stagesBlock(body, st, job){
  body.append(el('h2','What Pazuzu applies'));
  let plan; try{ plan=await get('/api/plan'); }catch(e){ fail(e); return; }
  const t=el('div',undefined,'tiles wrap');
  const todo=plan.stages.filter(s=>s.status!=='done');
  if(!todo.length) body.append(el('p','Everything Pazuzu applies is switched on.','mut'));
  plan.stages.forEach((s,i)=>{ if(s.status==='done') return;
    const x=el('div',undefined,'tile'+(s.status==='done'?' done':''));
    x.append(el('div',s.status==='done'?'✓':String(i+1),'big'), el('div',s.title,'vt'),
             el('span',s.status==='done'?'Done':'In the manager','chip'+(s.status==='done'?'':' mute')));
    t.append(x);
  });
  body.append(t);
  body.append(el('p','Continue. The manager switches these on, one guarded step at a time, and tests each one for you.','mut'));
  return null;
}

// The live window: only polls while it is open.
(function(){
  const box=document.getElementById('live'), out=document.getElementById('livelog'); let timer=null;
  const draw=async()=>{ try{ const r=await get('/api/activity'); const lines=(r.items||[]).map(x=>x.t+'  '+x.text); out.textContent=lines.length?lines.join('\n'):'Nothing yet.'; out.scrollTop=out.scrollHeight; }catch(e){} };
  box.addEventListener('toggle',()=>{ if(timer){ clearInterval(timer); timer=null; } if(box.open){ draw(); timer=setInterval(draw,1500); } });
})();
if(location.hash==='#wayback') ui.force='wayback';
if(location.hash==='#zones') ui.force='zones';
if(location.hash==='#admin') ui.force='admin';
refresh().catch(fail);
// The manager can ask for a passkey or open a change while this page sits idle: notice and show it.
let watchKey=null;
setInterval(async()=>{ if(document.hidden) return; try{
  const s=await get('/api/state'); const g=s.wizard.guard||{};
  const key=(s.passkey.pending?s.passkey.pending.digest:'')+'|'+(g.active?g.state:'');
  if(watchKey!==null && key!==watchKey && !(s.wizard.job&&s.wizard.job.state==='running')) await refresh();
  watchKey=key; }catch(e){} }, 2000);
</script></body></html>
"""


# --- the server ------------------------------------------------------------------

def make_handler(wizard: Wizard, port_getter: Callable[[], int]):
    service = wizard.passkeys

    def route_state(_d=None):
        state = service.state()
        if wizard.phone:
            state = dict(state, passkeys=[PHONE_LABEL], pending=None)
        return {"wizard": wizard.status(), "passkey": state}

    class Handler(BaseHTTPRequestHandler):
        server_version = "HanbiWizard"
        sys_version = ""

        def log_message(self, fmt, *args):
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

        def _send(self, code, body: bytes, ctype, nonce=""):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            script = f"script-src 'nonce-{nonce}'" if nonce else "script-src 'none'"
            style = f"style-src 'nonce-{nonce}'" if nonce else "style-src 'none'"
            self.send_header(
                "Content-Security-Policy",
                f"default-src 'none'; {script}; {style}; connect-src 'self'; img-src 'self'; "
                "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code, payload):
            self._send(code, json.dumps(payload).encode("utf-8"),
                       "application/json; charset=utf-8")

        def _own_host(self):
            return f"localhost:{port_getter()}"

        def _host_ok(self):
            if wizard.phone and not hmac.compare_digest(
                    (self.headers.get("X-Hanbi-Engine") or "").encode(), wizard.engine_secret.encode()):
                # On the box only the feed passes requests on, after it checked the phone's passkey session.
                self._json(403, {"error": "sign in with your passkey in the Pazuzu app"})
                return False
            if (self.headers.get("Host") or "").strip().lower() == self._own_host():
                return True
            self._json(421, {"error": f"open http://{self._own_host()}/ "
                                      "(passkeys only work on the name localhost)"})
            return False

        def _guarded(self, work):
            try:
                self._json(200, work())
            except (WizardError, pk.PasskeyError) as exc:
                self._json(400, {"error": str(exc)})
            except (ValueError, KeyError, TypeError, UnicodeDecodeError):
                self._json(400, {"error": "that request was not understood"})
            except OSError:
                self._json(500, {"error": "could not save a file"})
            except Exception as exc:  # never drop the request without an answer
                import sys
                import traceback
                print("wizard: unexpected " + type(exc).__name__ + " on " + self.path,
                      file=sys.stderr)
                traceback.print_exc(file=sys.stderr)
                what = type(exc).__name__ + (": " + str(getattr(exc, "name", "") or "")     # BUILD 517: which one
                                             if isinstance(exc, ModuleNotFoundError) else "")
                self._json(500, {"error": "Something unexpected stopped this step ("
                                          + what + "). The details are in "
                                          "the window running the wizard."})

        GETS = {
            "/api/state": lambda: route_state(),
            "/api/fingerprint": lambda: wizard.fingerprint(),
            "/api/interfaces": lambda: wizard.interfaces(),
            "/api/plan": lambda: wizard.plan(),
            "/api/ready": lambda: wizard.ready(),           # BUILD 493: the careful path's way in, as the manager's Get ready
            "/api/verify": lambda: wizard.run_checks(),
            "/api/unguarded": lambda: wizard.unguarded(),
            "/api/firmware": lambda: wizard.firmware(),
            "/api/internet": lambda: wizard.internet_state(),
            "/api/control": lambda: wizard.control_state(),
            "/api/box/state": lambda: wizard.box_state(),
            "/api/happy/left": lambda: wizard.happy_left(),
            "/api/kids": lambda: wizard.kids_state(),              # BUILD 537: KidsNet
            "/api/console/state": lambda: wizard.console_facts(),
            "/api/ssh/state": lambda: wizard.ssh_state(),
            "/api/reach/state": lambda: wizard.reach_state(),
            "/api/ddns/suggest": lambda: wizard.ddns_suggest(),
            "/api/plugin/state": lambda: wizard.plugin_state(),
            "/api/otp-server": lambda: wizard.otp_server_state(),
            "/api/time-zone": lambda: wizard.time_zone_state(),
            "/api/hardware": lambda: wizard.hardware_state(),
            "/api/wifi/state": lambda: wizard.wifi_state(),
            "/api/hotspot": lambda: wizard.hotspot_state(),
            "/api/after": lambda: wizard.after_state(),
            "/api/report": lambda: wizard.report_state(),
            "/api/ids": lambda: wizard.ids_state(),
            "/api/shields": lambda: wizard.levels_state(),
            "/api/plugins": lambda: wizard.plugins(),
            "/api/activity": lambda: __import__("pazuzu_core.activity", fromlist=["recent"]).recent(),
        }

        def do_GET(self):  # noqa: N802
            if not self._host_ok():
                return
            if self.path in ("/", "/index.html"):
                nonce = secrets.token_urlsafe(16)
                self._send(200, PAGE.replace("NONCE", nonce).encode("utf-8"),
                           "text/html; charset=utf-8", nonce)
                return
            if self.path == "/manager_preview.gif":     # BUILD 526: a recording of the manager on made-up data, for the last page
                try:
                    pic = (Path(__file__).resolve().parent / "manager_preview.gif").read_bytes()
                except OSError:
                    self._json(404, {"error": "no preview in this build"})
                    return
                self._send(200, pic, "image/gif")
                return
            if self.path == "/api/box/screen":          # BUILD 503: the firewall's own screen, by redirect only
                link = wizard.screen_link()
                if link is None:
                    self._json(404, {"error": "the plugin on the firewall is not linked"})
                    return
                self.send_response(302)
                self.send_header("Location", link)
                self.send_header("Cache-Control", "no-store")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            work = self.GETS.get(self.path)
            if work is None:
                self._json(404, {"error": "not found"})
                return
            self._guarded(work)

        POSTS = {
            "/api/register/begin": lambda d: service.register_begin(),
            "/api/register/finish": lambda d: service.register_finish(
                d.get("label"), d["attestation"], d["client"]),
            "/api/approve/begin": lambda d: service.approve_begin(d.get("purpose")),
            "/api/approve/finish": lambda d: service.approve_finish(
                d.get("purpose"), d["id"], d["client"], d["auth"], d["sig"]),
            "/api/approve/cancel": lambda d: wizard.approval_cancel(),
            "/api/enroll": lambda d: wizard.enroll(
                d.get("role"), d.get("use_default") is True, d.get("password"),
                d.get("fingerprint"), d.get("username"), d.get("also_installer") is True),
            "/api/zones": lambda d: wizard.save_zones(d),
            "/api/zones/later": lambda d: wizard.zones_later(d),
            "/api/zones/auto": lambda d: wizard.auto_zones(),
            "/api/resolver": lambda d: wizard.resolver_set(d.get("choice")),
            "/api/blocklists": lambda d: wizard.blocklists_set(d),
            "/api/otp/new": lambda d: wizard.otp_new(d.get("account")),
            "/api/otp/check": lambda d: wizard.otp_check(d.get("seed"), d.get("code")),
            "/api/find": lambda d: wizard.find_firewall(d.get("address")),
            "/api/find/use": lambda d: wizard.use_firewall(d.get("url")),
            "/api/keys/aside": lambda d: wizard.keys_aside(),
            "/api/keys/check": lambda d: {"state": wizard.check_keys(), "note": getattr(wizard, "keys_note", "")},
            "/api/find/harder": lambda d: wizard.find_harder(d.get("address")),
            "/api/plugin/install": lambda d: wizard.plugin_install(d.get("name")),
            "/api/firmware/check": lambda d: wizard.firmware_check(),
            "/api/firmware/update": lambda d: wizard.firmware_update(),
            "/api/firmware/reboot": lambda d: wizard.firmware_reboot(),
            "/api/probe": lambda d: wizard.probe_run(),
            "/api/write/admin": lambda d: wizard.write_admin(d),
            "/api/admin/adopt": lambda d: wizard.adopt_admin(d),
            "/api/write/root-off": lambda d: wizard.write_root_off(d),
            "/api/admin/finish": lambda d: wizard.admin_finish(d),
            "/api/write/root-password": lambda d: wizard.write_root_password(d),
            "/api/admin/forget": lambda d: wizard.admin_forget(),
            "/api/write/ddns": lambda d: wizard.write_ddns(d),
            "/api/ddns/fix": lambda d: wizard.ddns_fix_address(d),
            "/api/ddns/force": lambda d: wizard.ddns_force(d),
            "/api/cert/page-undo": lambda d: wizard.gui_cert_undo(d),
            "/api/ddns/install": lambda d: wizard.ddns_install(),
            "/api/ddns/choose": lambda d: wizard.ddns_choose(d),
            "/api/vpn/device": lambda d: wizard.vpn_device(d),
            "/api/write/vpn-instance": lambda d: wizard.write_vpn_instance(d),
            "/api/write/vpn-peer": lambda d: wizard.write_vpn_peer(d),
            "/api/write/gateway": lambda d: wizard.write_gateway(d),
            "/api/write/country-block": lambda d: wizard.write_country_block(d),
            "/api/write/country-block/change": lambda d: wizard.write_country_block_change(d),
            "/api/write/country-block/remove": lambda d: wizard.write_country_block_remove(),
            "/api/write/undo": lambda d: wizard.write_undo(),
            "/api/report/change": lambda d: wizard.report_change(d),       # BUILD 508: the phone's access card
            "/api/after/allow": lambda d: wizard.block_allow(d),          # BUILD 503: the page after setup (beta 1)
            "/api/after/promote": lambda d: wizard.promote_port(d),
            "/api/after/ignore": lambda d: wizard.ignore_offer(d),
            "/api/manager/start": lambda d: wizard.manager_start(),
            "/api/happy/shields": lambda d: wizard.levels_set(4),          # BUILD 477: the setup's last step
            "/api/happy/finish": lambda d: wizard.happy_finish_start(),
            "/api/happy/ipv6": lambda d: wizard.ipv6_off_start(),
            "/api/happy/ssh": lambda d: wizard.ssh_fix_start({"action": "off"}),       # BUILD 480: the app's last part
            "/api/console/shell": lambda d: wizard.console_shell_start(),
            "/api/console/sudo": lambda d: wizard.console_sudo_start(d),
            "/api/box/offer": lambda d: wizard.box_offer(),
            "/api/box/open-port": lambda d: wizard.plugin_port_open(),
            "/api/box/root-install": lambda d: wizard.box_root_install(d),
            "/api/plugin/update": lambda d: wizard.plugin_update(),
            "/api/otp-server/change": lambda d: wizard.otp_server_change(d), "/api/otp-switch/change": lambda d: wizard.otp_switch_change(d),
            "/api/time-zone/change": lambda d: wizard.time_zone_change(d),
            "/api/wifi/prepare": lambda d: wizard.wifi_prepare(),
            "/api/hotspot/set": lambda d: wizard.hotspot_set(d), "/api/hotspot/finish": lambda d: wizard.hotspot_finish(),
            "/api/backup/usb/set": lambda d: wizard.usb_backup_set(d),
            "/api/zones/vlans": lambda d: wizard.zone_vlans_start(d),
            "/api/kids/apply": lambda d: wizard.kids_apply(d),     # BUILD 537: KidsNet's family DNS and rules
            "/api/zone/set": lambda d: wizard.zone_set(d.get("zone"), d.get("device")),   # BUILD 493: the way-in port
            "/api/ap/find": lambda d: wizard.ap_find(),
            "/api/ap/scan": lambda d: wizard.ap_wifi_scan(),
            "/api/ap/read": lambda d: wizard.ap_read(d),
            "/api/ap/join": lambda d: wizard.ap_join(d),
            "/api/ap/options": lambda: wizard.ap_vlan_options(),
            "/api/ap/vlans": lambda d: wizard.ap_vlans_start(d),
            "/api/ap/join-network": lambda d: wizard.ap_join_network(d),
            "/api/country/narrow": lambda d: wizard.country_narrow_start(),
            "/api/trial": lambda d: wizard.trial_set(d.get("on")),
            "/api/mode": lambda d: wizard.mode_set(d.get("mode")),
            "/api/control/skip": lambda d: wizard.control_skip(),
            "/api/services/test": lambda d: wizard.services_test(),         # BUILD 493: part 2's checks, in the wizard
            "/api/services/skip": lambda d: wizard.services_skip(d.get("ids")),
            "/api/services/ack": lambda d: wizard.services_ack(d.get("ids")),
            "/api/feedback": lambda d: wizard.feedback_save(d),
            "/api/feedback/send": lambda d: wizard.feedback_send(d),     # BUILD 497: to hanbi.net, consent each time
            "/api/internet/test": lambda d: wizard.internet_test(),
            "/api/plan/preview": lambda d: wizard.plan_preview(group=d.get("group")),
            "/api/plan/run": lambda d: wizard.plan_run(d.get("digest"), group=d.get("group")),
            "/api/legal": lambda d: wizard.legal_save(d.get("terms"), d.get("consent")),
            "/api/box/setup_step": lambda d: wizard.box_setup_step(d),
            "/api/homewifi/plan": lambda d: wizard.home_wifi_plan(d),          # BUILD 482: Hanbi's own Wi-Fi
            "/api/homewifi/start": lambda d: wizard.home_wifi_start(d),
            "/api/homewifi/state": lambda d: wizard.home_wifi_state(),
            "/api/box/access_card": lambda d: wizard.box_access_card(d),
            "/api/rules/preview": lambda d: wizard.preview_rules(d.get("limit")),
            "/api/rules/apply": lambda d: wizard.apply_rules(d.get("limit")),
            "/api/stage/preview": lambda d: wizard.stage_preview(
                d.get("stage"), d.get("services_checked")),
            "/api/stage/run": lambda d: wizard.stage_run(
                d.get("stage"), d.get("digest"), d.get("services_checked")),
            "/api/guard/decide": lambda d: wizard.decide(d.get("decision")),
            "/api/guard/clear": lambda d: wizard.guard_clear(),
        }

        def do_POST(self):  # noqa: N802
            if not self._host_ok():
                return
            if self.headers.get("Origin") != f"http://{self._own_host()}":
                self._json(403, {"error": "this request did not come from the page"})
                return
            if (self.headers.get("Content-Type") or "").split(";")[0].strip() \
                    != "application/json":
                self._json(415, {"error": "JSON only"})
                return
            route = self.POSTS.get(self.path)
            if route is None:
                self._json(404, {"error": "not found"})
                return
            try:
                size = int(self.headers.get("Content-Length") or "")
            except ValueError:
                self._json(411, {"error": "length needed"})
                return
            # BUILD 497: a feedback report may carry a screenshot (5 MB, sent base64); every other route keeps 64 KB
            if not 0 < size <= (7 * 1024 * 1024 if self.path == "/api/feedback/send" else ps.MAX_BODY):
                self._json(413, {"error": "request too large"})
                return

            def work():
                data = json.loads(self.rfile.read(size).decode("utf-8"))
                if not isinstance(data, dict):
                    raise ValueError
                return route(data)

            self._guarded(work)

        def _refuse(self):
            self.close_connection = True
            self._json(405, {"error": "not allowed"})

        do_PUT = do_DELETE = do_PATCH = _refuse  # noqa: N815

    return Handler


def port_answers(port: int, timeout: float = 0.5) -> bool:
    """BUILD 526: is something already answering on this device's port? On Windows a second wizard can start on a port an
    older one still holds, and the browser then shows the older build (the maintainer, 12 Nov 2026, twice)."""
    import socket
    try:
        with socket.create_connection(("127.0.0.1", int(port)), timeout=timeout):
            return True
    except OSError:
        return False


PORT_TAKEN = ("Something is already answering on port {port} of this computer, most likely an earlier Pazuzu setup that is "
              "still running. Stop it first (Ctrl+C in its window, or close that window), then start this one again. "
              "To run both, add --port with another number.")


def make_server(wizard: Wizard, port: int = ps.DEFAULT_PORT) -> ThreadingHTTPServer:
    holder: dict[str, ThreadingHTTPServer] = {}
    server = ps.QuietServer(
        ("127.0.0.1", port),
        make_handler(wizard, lambda: holder["s"].server_address[1]))
    holder["s"] = server
    return server


# OPNsense's own factory address, from its documentation: the very last place to start, used only when this
# computer has no gateway to go by. Otherwise the wizard starts from this device's own network.
FACTORY_ADDRESS = "https://192.168.1.1"


def _firewall_detail(host: str, port: int) -> dict:
    """What tells one firewall from another, read from its certificate. For display only; nothing is trusted from it."""
    from pazuzu_core.enroll_safety import fetch_cert_name, fetch_fingerprint
    from pazuzu_core.startup_search import Sighting
    out = {"fingerprint_start": "", "cert_name": ""}
    try:
        fp = fetch_fingerprint(host, port, 4)
        out["fingerprint_start"] = Sighting(host, port, "", fp).start_of_fingerprint() if fp else ""
    except Exception:
        pass
    out["cert_name"] = fetch_cert_name(host, port, 4)
    return out


def _gateway_guess(network=None) -> str:
    """This device's own gateway when it is on a private network: the best first guess at where its firewall is."""
    from pazuzu_core import find_firewall as ff
    try:
        gateways = (network or ff.default_gateways)()
    except Exception:
        return ""
    for g in gateways:
        if ff.private_only(g):
            return g
    return ""


def _is_a_terminal() -> bool:
    try:
        return bool(sys.stdin and sys.stdin.isatty())
    except (OSError, ValueError):
        return False


def _base_for(host: str, port: int) -> str:
    return f"https://{host}" + ("" if port == 443 else f":{port}")


def _fresh_folder(key_dir, host: str) -> str:
    """A key folder name beside the old one, named for the firewall it will belong to."""
    p = Path(str(key_dir))
    tag = re.sub(r"[^0-9A-Za-z]+", "_", str(host)).strip("_") or "new"
    out = str(p.with_name(p.name + "_" + tag))
    return f'"{out}"' if " " in out else out


def default_key_dir(firewall: str = "", home: Path | None = None) -> Path:
    """BUILD 460: with no --dir, the key folder named for the firewall given (.pazuzu_192_168_1_1 for 192.168.1.1, the
    name the wizard itself suggests for another firewall) when it exists, else .pazuzu. So one launch line serves
    every box: only the address changes."""
    home = home or Path.home()
    host = str(firewall or "").strip()
    host = host.rsplit(":", 1)[0] if host.count(":") == 1 else host           # 192.168.50.1:8443 -> its address
    tag = re.sub(r"[^0-9A-Za-z]+", "_", host).strip("_")
    if tag and (home / (".pazuzu_" + tag)).is_dir():
        return home / (".pazuzu_" + tag)
    return home / ".pazuzu"


def key_dir_for_host(host: str, home: Path | None = None) -> Path:
    """BUILD 470: the key folder for a firewall picked at the start: the folder whose stamp names it (.pazuzu or a
    .pazuzu_<something>), else .pazuzu when that has no firewall yet, else a new .pazuzu_<address> (made on first use)."""
    home = home or Path.home()
    for d in [home / ".pazuzu"] + sorted(p for p in home.glob(".pazuzu_*") if p.is_dir()):
        stamp = read_stamp(d / KEY_STAMP)
        if stamp and stamp[0] == host:
            return d
    if read_stamp(home / ".pazuzu" / KEY_STAMP) is None:
        return home / ".pazuzu"
    return home / (".pazuzu_" + (re.sub(r"[^0-9A-Za-z]+", "_", host).strip("_") or "new"))


def _keys_belong_elsewhere(stamp, host: str, key_dir) -> str:
    return (f"The keys in {key_dir} were made on the firewall at {stamp[0]}, and keys only work on the firewall "
            f"that made them. You named {host}. Start with another key folder, or leave the name off to use "
            f"{stamp[0]}. For another key folder, run this (it makes the folder):\n"
            f"    python -m pazuzu_core.wizard_server --dir {_fresh_folder(key_dir, host)} --firewall {host}")


def startup_target(environ, firewall=None, key_dir=None, network=None) -> tuple[str, "bool | str", str]:
    """Where to start looking for the firewall, and how to check its certificate.

    A firewall named with --firewall wins, and is always checked by fingerprint on the sign-in step. With
    OPNSENSE_BASE_URL set, exactly as before. With neither, a key folder that already belongs to a firewall
    starts at that one; a new folder starts where this device's own network points (its gateway; the search that
    runs first, and the page's Find my firewall button, cover the rest) and says so. Only a computer with no gateway
    at all starts at OPNsense's factory address. A key folder is never pointed at a firewall other than its own.
    `network` hands in the gateways, for tests.
    """
    stamp = read_stamp(Path(key_dir) / KEY_STAMP) if key_dir is not None else None
    named = str(firewall or "").strip()
    if named:
        host, port = Wizard._parse_address(named)
        if stamp and stamp[0] != host:
            raise WizardError(_keys_belong_elsewhere(stamp, host, key_dir))
        return _base_for(host, port), False, f"The wizard will talk to the firewall you named: {host}."
    if not (environ.get("OPNSENSE_BASE_URL") or "").strip():
        if stamp:
            return (_base_for(*stamp), False,
                    f"The keys in this folder belong to the firewall at {stamp[0]}, so the wizard starts there.")
        guess = _gateway_guess(network)
        if guess:
            return (_base_for(guess, 443), False,
                    f"No firewall address was given, so the wizard looks at this device's network first, and "
                    f"otherwise starts at {guess}, this device's gateway. If yours is somewhere else, press "
                    "Find my firewall on the first step, or start with --firewall and its address.")
        return (FACTORY_ADDRESS, False,
                f"No firewall address was given and this device has no gateway to go by, so the wizard starts at "
                f"{FACTORY_ADDRESS.split('//')[1]}, OPNsense's own factory address. If yours is somewhere else, "
                "press Find my firewall on the first step, or start with --firewall and its address.")
    from pazuzu_core.opnsense_client import _base_url, _tls_setting
    base, verify = _base_url(), _tls_setting()
    if stamp:
        host = base_host_port(base)[0]
        if host != stamp[0]:
            raise WizardError(_keys_belong_elsewhere(stamp, host, key_dir))
    return base, verify, ""


def main(argv: list[str] | None = None, *, looker: Callable | None = None) -> int:
    parser = argparse.ArgumentParser(prog="wizard_server")
    parser.add_argument("--port", type=int, default=ps.DEFAULT_PORT)
    parser.add_argument("--dir", default="",
                        help="the key folder (default: .pazuzu in your home folder, or .pazuzu_<address> when one "
                             "exists for the firewall named with --firewall)")
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--firewall", default="",
                        help="the firewall's address, as numbers (for example 192.168.2.1, or 192.168.2.1:8443)")
    parser.add_argument("--no-search", action="store_true",
                        help="do not look around the networks for firewalls before starting")
    parser.add_argument("--phone", action="store_true",
                        help="run on the box for the Pazuzu app (plugin 0.6.53): the box's feed checks the phone's "
                             "passkey and passes requests on with HANBI_ENGINE_SECRET; implies --no-browser")
    parser.add_argument("--manager", action="store_true",
                        help="open the manager as before beta 1 locked it away (the maker's own switch: it still needs the "
                             "sign-in and the plugin, and the pazuzu_manager folder, which the beta build does not have)")
    parser.add_argument("--box", default="",
                        help="connect straight to an already-installed plugin, as ADDRESS#CODE "
                             "(for example http://192.168.1.1:8787#<code>). On a real Hanbi box the box's "
                             "screen shows this as a QR; this flag stands in for that while it is built.")
    args = parser.parse_args(argv)
    phone_secret = os.environ.get("HANBI_ENGINE_SECRET", "") if args.phone else ""
    if args.phone and len(phone_secret) < 24:
        print("--phone is started by the box's feed, which hands over HANBI_ENGINE_SECRET.")
        return 2
    if args.port and port_answers(args.port):       # BUILD 526: before anything is read or asked
        print(PORT_TAKEN.format(port=args.port))
        return 2
    if not pk.HAVE_CRYPTO and not args.phone:          # on the box the phone's passkey is checked by the feed instead
        print("Passkeys need the 'cryptography' package: pip install cryptography")
        return 2
    if os.environ.get("OPNSENSE_API_KEY") or os.environ.get("OPNSENSE_API_SECRET"):
        print("Key variables are set in this window. Start the wizard in a window "
              "without them: it reads its own key files.")
        return 2
    key_dir = Path(args.dir) if args.dir else default_key_dir(args.firewall)
    if not args.dir and key_dir != Path.home() / ".pazuzu":
        print(f"Key folder for {args.firewall.strip()}: {key_dir}")
    try:
        base, verify, note = startup_target(os.environ, firewall=args.firewall, key_dir=key_dir)
    except WizardError as exc:
        print(str(exc))
        return 2
    except RuntimeError as exc:
        print(f"Check OPNSENSE_BASE_URL (and OPNSENSE_TLS_VERIFY): {exc}")
        return 2
    # Start the way a person would on a new install: look at what is there first, then choose.
    outcome = None
    if not args.no_search and not (os.environ.get("OPNSENSE_BASE_URL") or "").strip():
        from pazuzu_core import startup_search as sse
        named = Wizard._parse_address(args.firewall) if args.firewall.strip() else None
        # BUILD 470: no --firewall and no --dir: look around and let the person pick (with more than one answering),
        # then use that firewall's own key folder. One launch line, every box.
        choose = named is None and not args.dir and not args.phone
        try:
            outcome = (looker or sse.look_around)(
                named, None if choose else read_stamp(key_dir / KEY_STAMP), ask=input if _is_a_terminal() else None,
                pin=None if choose else load_pin(key_dir))
            if choose and outcome.chosen is not None:
                key_dir = key_dir_for_host(outcome.chosen.host)
                print(f"Key folder for {outcome.chosen.host}: {key_dir}")
        except sse.KeysElsewhere as exc:
            print(str(exc))
            print("The wizard opens anyway and lets you look again, pick another firewall, or set the old keys aside.")
            outcome = exc.outcome
        except sse.StartupError as exc:
            print(str(exc))
            return 2
        if outcome.chosen is not None:
            base, note = _base_for(outcome.chosen.host, outcome.chosen.port), outcome.why
    if note:
        print(note)
    if verify is False:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        # BUILD 511: what a tester reads at start. A home firewall's certificate is its own (self-signed), so it cannot be
        # checked against a public authority; the first step shows its fingerprint to compare, and it is pinned after.
        print("Note: your firewall's certificate is its own (self-signed), so it is checked by its fingerprint. "
              "The first step shows it for you to compare.")
    try:
        service = ps.Service(key_dir / pk.CREDENTIALS_FILE, ps.origin_for(args.port))
        wizard = Wizard(key_dir, base, verify, service, manifest=args.manifest)
        if args.manager:
            wizard.manager_override = True              # BUILD 495 (the maintainer, 10 Nov 2026: "what was the switch for opening manager for me?")
        if args.phone:
            wizard.phone, wizard.engine_secret = True, phone_secret
            args.no_browser = True
            link = os.environ.get("HANBI_BOX_LINK", "")      # the feed that started this wizard: its own plugin
            url, _, tok = link.partition("#")
            if url.strip() and tok.strip():
                wizard._save_box_link(url.strip(), tok.strip())
        server = make_server(wizard, args.port)
    except (OSError, pk.PasskeyError) as exc:
        print(f"Could not start: {exc}")
        return 1
    if args.box.strip():                                # connect to an already-installed plugin (stand-in for the QR)
        url, _, tok = args.box.strip().partition("#")
        if url.strip() and tok.strip():
            wizard._save_box_link(url.strip(), tok.strip())
            print("Will connect to the plugin already on the box at " + url.strip() + ".")
        else:
            print("--box wants ADDRESS#CODE, for example http://192.168.1.1:8787#<code>. Ignoring it.")
    fresh = ""
    if outcome is not None and outcome.chosen is not None:
        fresh = wizard.fresh_check(outcome.chosen.fingerprint)
        wizard.startup = dict(outcome.as_dict(), fresh=fresh)
    if args.firewall.strip() or (outcome is not None and outcome.chosen is not None):
        wizard.stamp_keys()                         # the firewall chosen owns this key folder from now on
    for line in (fresh, wizard.claim_scan_results(), wizard.recover_stale_guard()):
        if line:
            print(line)
    try:                                            # BUILD 471: the admin page's certificate renewed: follow it by name
        from pazuzu_core.enroll_safety import refresh_pin
        gui_name = wizard._recall("gui_name")
        if gui_name and base.startswith("https://"):
            h, pt = base_host_port(base)
            if refresh_pin(key_dir, h, pt, str(gui_name)):
                print(f"The admin page shows its renewed certificate for {gui_name}; it is trusted from here on.")
    except Exception:  # noqa: BLE001
        pass
    real_port = server.server_address[1]
    service.origin = ps.origin_for(real_port)
    wizard.keys_checking = True
    threading.Thread(target=wizard.check_keys, daemon=True).start()
    url = ps.origin_for(real_port) + "/"
    print(f"Pazuzu setup is at {url}  (Ctrl+C to stop)")
    if not args.no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
