"""A read-only probe of the firewall: which questions does this version answer, and for whom?

It sends GET requests only, to a fixed list of paths that read settings, and it changes
nothing. For each path it records the answer's kind (answered, not allowed for this
account, not on this version, error), the NAMES of the fields in the answer, and a few
plain facts (a version, an on/off flag, a count). It never records an address, a name,
a password or any other value, so the report is safe to paste into a chat.

Why: several things the app would like to do (set the session timeout, move the web GUI or
SSH port, read the DHCP time-server option, turn router advertisements off, set block-list
levels, set up dynamic DNS, renumber an interface, add a Wi-Fi interface) rest on endpoints
nobody has confirmed on 26.7. This asks the firewall instead of guessing, and the answers
decide what gets built. A path listed here is a guess about where a READ lives; a wrong
guess is a 404, which is itself an answer.

Every network call goes through one injected function, so the tests run with no network.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

# (id, path, what it would tell us). Every last segment is a read verb: see READ_VERBS.
PROBES: tuple[tuple[str, str, str], ...] = (
    ("firmware", "/api/core/firmware/status", "version, updates, reboot needed (known to work)"),
    ("firmware_info", "/api/core/firmware/info", "installed packages and plugins"),
    ("system", "/api/core/system/status", "system health"),
    ("services", "/api/core/service/search", "which services exist and run"),
    ("menu", "/api/core/menu/search", "which settings pages exist, and whether each is API-backed"),
    ("interfaces_settings", "/api/interfaces/settings/get", "the IPv6 allowance (known to work)"),
    ("interfaces_info", "/api/interfaces/overview/interfaces_info/true", "ports and their state (known)"),
    ("wan_assignment", "/api/interfaces/assignment/get_item", "an interface's own settings, where the WAN's IPv6 type may live (a guess)"),
    ("wan_overview", "/api/interfaces/overview/get_interface", "one interface's state, to see whether the WAN has an IPv6 address (a guess)"),
    ("rules", "/api/firewall/filter/search_rule", "firewall rules (known to work)"),
    ("aliases", "/api/firewall/alias/search_item", "aliases (known to work)"),
    ("unbound", "/api/unbound/settings/get", "DNS resolver settings, including the block-list type"),
    ("unbound_service", "/api/unbound/service/status", "is the resolver running"),
    ("unbound_forward", "/api/unbound/settings/search_forward", "upstream resolvers"),
    ("unbound_dot", "/api/unbound/settings/search_dot", "DNS-over-TLS upstreams (Unbound's forwards of type dot)"),
    ("unbound_dnsbl_grid", "/api/unbound/settings/search_dnsbl", "DNS block-list entries (the grid on newer versions)"),
    ("unbound_dnsbl_form", "/api/unbound/settings/get_dnsbl", "the empty block-list entry form: its fields and pick-list"),
    ("geoip", "/api/firewall/alias/get_geo_i_p", "where country lists are downloaded from (the page's name is a guess)"),
    ("dnsmasq_options", "/api/dnsmasq/settings/search_option", "DHCP options on the stock DHCP server (dnsmasq)"),
    ("kea", "/api/kea/dhcpv4/get", "DHCP server settings"),
    ("kea_subnets", "/api/kea/dhcpv4/search_subnet", "DHCP subnets, and where the time-server option lives"),
    ("kea_service", "/api/kea/service/status", "is the DHCP server running"),
    ("vlan_devices", "/api/interfaces/vlan_settings/search_item", "VLAN devices (a guess)"),
    ("vlan_form", "/api/interfaces/vlan_settings/get_item", "the empty VLAN form: the field names a new VLAN takes"),
    ("dnsmasq_ranges", "/api/dnsmasq/settings/search_range", "DHCP ranges on the stock DHCP server (dnsmasq)"),
    ("dnsmasq_range_form", "/api/dnsmasq/settings/get_range", "the empty DHCP range form: the field names a new range takes"),
    ("loopback_devices", "/api/interfaces/loopback_settings/search_item", "loopback devices (a guess)"),
    ("ntp", "/api/ntpd/settings/get", "time service settings (a guess)"),
    ("ntp_service", "/api/ntpd/service/status", "is the time service running (a guess)"),
    ("radvd", "/api/radvd/settings/search_entry", "router advertisements (a guess)"),
    ("radvd_service", "/api/radvd/service/status", "are router advertisements running (a guess)"),
    ("ids", "/api/ids/settings/get", "intrusion detection settings and rule sets"),
    ("ids_service", "/api/ids/service/status", "is intrusion detection running"),
    ("wg_general", "/api/wireguard/general/get", "VPN on or off"),
    ("wg_servers", "/api/wireguard/server/search_server", "VPN instances"),
    ("wg_clients", "/api/wireguard/client/search_client", "VPN peers"),
    ("wg_service", "/api/wireguard/service/show", "VPN handshakes"),
    ("auth_users", "/api/auth/user/search", "the user list, and which fields a user has (login shell, OTP seed)"),
    ("auth_groups", "/api/auth/group/search", "groups, and whether Pazuzu's account can be told apart"),
    ("routing_gateways", "/api/routing/settings/search_gateway", "gateways, for a backup internet link"),
    ("gateway_status", "/api/routes/gateway/status", "which gateways are up (a guess)"),
    ("ddns", "/api/dyndns/settings/get", "dynamic DNS plugin installed, and its settings"),
    ("ddns_accounts", "/api/dyndns/accounts/search_item", "dynamic DNS accounts"),
    ("dnat_rules", "/api/firewall/d_nat/search_rule", "port forwards and DNS redirects (Destination NAT, 26.7)"),
    ("unbound_acl", "/api/unbound/settings/search_acl", "who may ask the firewall's DNS (Unbound access lists)"),
    ("unbound_hosts", "/api/unbound/settings/search_host_override", "names answered inside the house (Unbound host overrides)"),
)

READ_VERBS = ("get", "search", "status", "info", "show", "interfaces_info")
_SUBNET_FOLLOW = re.compile(r"^/api/kea/dhcpv4/get_subnet/[0-9a-fA-F-]{36}$")
MAX_BYTES = 2_000_000
PARALLEL = 5
KEY_CAP = 40


def allowed_path(path: str) -> bool:
    """Only the fixed probe paths, and the one follow-up that reads a DHCP subnet by id."""
    return path in {p for _i, p, _w in PROBES} or bool(_SUBNET_FOLLOW.match(path))


def verb_ok(path: str) -> bool:
    parts = [p for p in path.split("/") if p]
    tail = parts[-2] if parts and parts[-1] == "true" else parts[-1]
    return tail.startswith(READ_VERBS) or bool(_SUBNET_FOLLOW.match(path)) or tail == "get_subnet"


Fetch = Callable[[str], "tuple[int | None, str | None, str | None]"]
"""fetch(path) -> (http status or None, body text or None, short error text or None)."""


@dataclass
class Result:
    id: str
    path: str
    status: int | None
    kind: str                      # answered | denied | missing | error | unreachable | not_json
    keys: list[str] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)
    note: str = ""

    def as_dict(self) -> dict:
        return {"id": self.id, "path": self.path, "status": self.status, "kind": self.kind,
                "keys": self.keys, "facts": self.facts, "note": self.note}


def _kind(status: int | None, error: str | None) -> str:
    if status is None:
        return "unreachable"
    if status == 200:
        return "answered"
    if status in (401, 403):
        return "denied"
    if status == 404:
        return "missing"
    return "error"


_ID_LIKE = re.compile(
    r"^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r"|(?:\d{1,3}\.){3}\d{1,3}(?:/\d+)?|(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})$")


def _safe(key: Any) -> str:
    """A field name, unless it is really a value used as a name (an id, an address): then <id>."""
    text = str(key)
    return "<id>" if _ID_LIKE.match(text) or len(text) > 48 else text


def _names(node: Any) -> list[str]:
    """The field names at the top of an answer, and one level down. Names only, never values."""
    out: list[str] = []
    if isinstance(node, dict):
        for k, v in node.items():
            top = _safe(k)
            out.append(top)
            if isinstance(v, dict):
                out.extend(f"{top}.{_safe(kk)}" for kk in v)
            elif isinstance(v, list) and v and isinstance(v[0], dict):
                out.extend(f"{top}[].{_safe(kk)}" for kk in v[0])
    elif isinstance(node, list) and node and isinstance(node[0], dict):
        out.extend(f"[].{_safe(k)}" for k in node[0])
    seen: set[str] = set()
    return [n for n in out if not (n in seen or seen.add(n))][:KEY_CAP]


def _deep_names(node: Any, prefix: str = "", depth: int = 4) -> list[str]:
    """Field names down to a few levels (for one small answer). Still names only."""
    out: list[str] = []
    if depth and isinstance(node, dict):
        for k, v in node.items():
            name = f"{prefix}{_safe(k)}"
            out.append(name)
            out.extend(_deep_names(v, name + ".", depth - 1))
    return out


def _selected(option_map: Any) -> list[str]:
    """OPNsense option maps look like {"key": {"value": "..", "selected": 1}}. The chosen keys."""
    if not isinstance(option_map, dict):
        return []
    return sorted(str(k) for k, v in option_map.items()
                  if isinstance(v, dict) and str(v.get("selected")) in ("1", "true", "True"))


def _dig(node: Any, *path: str) -> Any:
    for p in path:
        if not isinstance(node, dict):
            return None
        node = node.get(p)
    return node


def _facts(probe_id: str, body: Any) -> dict[str, Any]:
    """A few plain facts. Whitelisted by probe, so nothing else can ride along."""
    f: dict[str, Any] = {}
    if probe_id == "firmware" and isinstance(body, dict):
        for k in ("product_version", "product_name", "product_series"):
            v = _dig(body, "product", k)
            if isinstance(v, (str, int, float)):
                f[k] = v
        for k in ("status", "needs_reboot", "upgrade_needs_reboot"):
            if isinstance(body.get(k), (str, bool, int)):
                f[k] = body[k]
    elif probe_id == "unbound" and isinstance(body, dict):
        dnsbl = _dig(body, "unbound", "dnsbl")
        if isinstance(dnsbl, dict):
            f["dnsbl_enabled"] = dnsbl.get("enabled")
            f["dnsbl_types_selected"] = _selected(dnsbl.get("type"))[:30]
        general = _dig(body, "unbound", "general")
        if isinstance(general, dict):
            f["unbound_enabled"] = general.get("enabled")
    elif probe_id in ("ids", "wg_general", "ntp", "kea") and isinstance(body, dict):
        for path in (("ids", "general", "enabled"), ("general", "enabled"), ("ntpd", "enabled"),
                     ("dhcpv4", "general", "enabled")):
            v = _dig(body, *path)
            if isinstance(v, (str, bool, int)):
                f["enabled"] = v
                break
    elif probe_id == "ddns" and isinstance(body, dict):
        f["answers"] = True
    elif probe_id == "geoip":
        def url_of(node):
            if isinstance(node, dict):
                for k, v in node.items():
                    if str(k).lower() == "url" and not isinstance(v, (dict, list)):
                        return str(v or "").strip()
                for v in node.values():
                    got = url_of(v)
                    if got is not None:
                        return got
            return None
        got = url_of(body)
        if got is not None:
            f["source_set"] = bool(got)          # whether there is one, never the address itself
    if probe_id.endswith("_service") or probe_id in ("wg_service",):
        status = body.get("status") if isinstance(body, dict) else None
        if isinstance(status, (str, bool, int)):
            f["status"] = status
    if isinstance(body, dict):
        for k in ("rowCount", "total"):
            if isinstance(body.get(k), int):
                f[k] = body[k]
        if isinstance(body.get("rows"), list):
            f["rows"] = len(body["rows"])
    elif isinstance(body, list):
        f["items"] = len(body)
    return f


# Words the menu is searched for, to say whether each page is API-backed.
MENU_WORDS = (
    "administration", "firmware", "wireless", "assignments", "settings", "dynamic dns", "dyndns",
    "router advertisement", "dhcpv4", "dhcpv6", "network time", "ntp", "intrusion", "wireguard",
    "general", "access", "users", "[lan]", "lan", "dns over tls",
)


def _walk_menu(node: Any, trail: tuple[str, ...] = ()) -> Iterable[tuple[str, str]]:
    """(page name path, address) pairs from a menu answer. Tolerant of the exact layout."""
    if isinstance(node, dict):
        low = {str(k).lower(): v for k, v in node.items()}
        name = next((str(low[k]) for k in ("visiblename", "name", "title", "id") if low.get(k)), "")
        url = next((str(low[k]) for k in ("url", "href", "path") if isinstance(low.get(k), str)), "")
        here = trail + ((name,) if name else ())
        if url:
            yield " > ".join(here), url
        for v in node.values():
            if isinstance(v, (dict, list)):
                yield from _walk_menu(v, here)
    elif isinstance(node, list):
        for v in node:
            yield from _walk_menu(v, trail)


def classify_url(url: str) -> str:
    u = url.lower()
    if u.startswith("/ui/"):
        return "api-backed page"
    if ".php" in u:
        return "legacy page (no API)"
    return "other"


def menu_findings(body: Any) -> list[dict[str, str]]:
    """Which settings pages the menu lists, and whether each is API-backed. Page names only."""
    seen: dict[str, dict[str, str]] = {}
    for name, url in _walk_menu(body):
        lowered = name.lower()
        if any(w in lowered for w in MENU_WORDS):
            seen.setdefault(name, {"page": name, "kind": classify_url(url),
                                   "address": url.split("?")[0]})
    return sorted(seen.values(), key=lambda d: d["page"])[:60]


def run_probe(fetch: Fetch, *, only: Iterable[str] | None = None) -> dict[str, Any]:
    """Ask each question once. A failure on one never stops the rest."""
    wanted = set(only) if only is not None else None
    results: list[Result] = []
    bodies: dict[str, Any] = {}
    todo = [(i, p) for i, p, _w in PROBES if wanted is None or i in wanted]
    # A slow firewall answers each read in a second or more, so ask several at once (reads only).
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=PARALLEL) as pool:
        answers = list(pool.map(lambda ip: fetch(ip[1]), todo))
    for (probe_id, path), (status, text, error) in zip(todo, answers):
        res = Result(probe_id, path, status, _kind(status, error), note=(error or "")[:120])
        if res.kind == "answered":
            try:
                body = json.loads(text or "")
            except ValueError:
                res.kind, res.note = "not_json", "answered, but not in the usual format"
            else:
                bodies[probe_id] = body
                res.keys = _names(body)
                res.facts = _facts(probe_id, body)
        results.append(res)

    # One follow-up: the first DHCP subnet, read by id, to see where option 42 (time servers) is kept.
    subnets = bodies.get("kea_subnets")
    rows = subnets.get("rows") if isinstance(subnets, dict) else None
    if isinstance(rows, list) and rows and isinstance(rows[0], dict):
        uuid = str(rows[0].get("uuid") or "")
        path = f"/api/kea/dhcpv4/get_subnet/{uuid}"
        if _SUBNET_FOLLOW.match(path):
            status, text, error = fetch(path)
            res = Result("kea_subnet_one", "/api/kea/dhcpv4/get_subnet/<id>", status, _kind(status, error),
                         note=(error or "")[:120])
            if res.kind == "answered":
                try:
                    body = json.loads(text or "")
                except ValueError:
                    res.kind = "not_json"
                else:
                    res.keys = _deep_names(body)[:KEY_CAP]
                    found = [k for k in _deep_names(body) if re.search(r"ntp|time|option", k, re.I)]
                    res.facts = {"time_or_option_fields": found[:20]}
            results.append(res)

    out: dict[str, Any] = {
        "kind": "pazuzu-probe",
        "read_only": True,
        "results": [r.as_dict() for r in results],
        "menu": menu_findings(bodies["menu"]) if "menu" in bodies else None,
    }
    out["version"] = next((r.facts.get("product_version") for r in results
                           if r.id == "firmware" and r.facts.get("product_version")), None)
    return out


def table(report: dict[str, Any]) -> list[str]:
    """The plain-text version a person can paste. Names and numbers, no values."""
    label = {"answered": "answered", "denied": "not allowed for this account", "missing": "not on this version",
             "error": "error", "unreachable": "no answer", "not_json": "odd answer"}
    lines = [f"Pazuzu read-only probe · firewall version {report.get('version') or 'unknown'} · "
             "GET only, nothing was changed", ""]
    width = max((len(r["path"]) for r in report["results"]), default=10)
    for r in report["results"]:
        head = f"{r['status'] if r['status'] is not None else '---'}  {r['path']:<{width}}  {label[r['kind']]}"
        extra = []
        if r["facts"]:
            extra.append(json.dumps(r["facts"], sort_keys=True))
        if r["keys"]:
            extra.append("fields: " + ", ".join(r["keys"][:12]) + (" …" if len(r["keys"]) > 12 else ""))
        lines.append(head + ("   " + "   ".join(extra) if extra else ""))
    menu = report.get("menu")
    lines.append("")
    if menu is None:
        lines.append("Menu: not readable with this account (so API-backed or legacy is not known).")
    else:
        lines.append("Settings pages in the menu:")
        for m in menu:
            lines.append(f"  {m['kind']:<22} {m['page']}  ({m['address']})")
    return lines
