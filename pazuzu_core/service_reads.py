"""Reads for the two firewall services the manager used to ask you to confirm: the time service, and the DHCP
option that hands the firewall out as the time server. Reads only. Each one is True, False, or None (not read:
the page was not there, was refused, or answered in a shape not recognised, in which case you still confirm it)."""
from __future__ import annotations

import json
import re
from typing import Any, Callable, Mapping

NTP_STATUS = "/api/ntpd/service/status"
SERVICES = "/api/core/service/search"                 # the firewall's own list of services and whether each one runs
_TIME_NAMES = ("ntpd", "chronyd", "chrony", "openntpd")
OPTION_PAGES = ("/api/dnsmasq/settings/search_option?rowCount=-1",
                "/api/kea/dhcpv4/search_option?rowCount=-1")
_OPTION = re.compile(r"(^|[^0-9a-z])(42|ntp[-_ ]?servers?)($|[^0-9a-z])", re.I)
_KEYS = ("option", "name", "code", "option_code", "description")


def ntp_running(body: Any) -> bool | None:
    if not isinstance(body, Mapping):
        return None
    word = str(body.get("status", body.get("result", ""))).strip().lower()
    if word == "running" or word.startswith("ntpd is running"):
        return True
    if word in ("stopped", "disabled") or "not running" in word or word.startswith("ntpd is not"):
        return False
    return None


def time_service_listed(body: Any) -> bool | None:
    """From the firewall's own service list: True when a time service is listed and running, False when one is listed
    and none runs, None when the list was not readable or lists no time service."""
    rows = body.get("rows") if isinstance(body, Mapping) else None
    if not isinstance(rows, list):
        return None
    listed = None
    for r in rows:
        if not isinstance(r, Mapping):
            continue
        name = (str(r.get("name") or "") + " " + str(r.get("id") or "")).lower()
        if any(t in name for t in _TIME_NAMES):
            if str(r.get("running")).strip().lower() in ("1", "true"):
                return True
            listed = False
    return listed


TABLES = "/api/firewall/alias/get_table_size"       # {"status": "ok", "details": {alias: {"count": n, ...}}}
GEOIP = "/api/firewall/alias/get_geo_ip"            # {"alias": {"geoip": {"url", "address_count", ...}}}


def table_count(body: Any, name: str) -> dict | None:
    """{"present": bool, "entries": int} for one alias, from the firewall's table sizes: the same number its Aliases
    page shows as Loaded. None when the answer is not in the usual shape (the caller then asks the plugin)."""
    details = body.get("details") if isinstance(body, Mapping) and body.get("status") == "ok" else None
    if not isinstance(details, Mapping):
        return None
    row = details.get(name)
    if row is None:
        return {"present": False, "entries": 0}
    n = row.get("count") if isinstance(row, Mapping) else None
    if isinstance(n, int) and not isinstance(n, bool) and n >= 0:
        return {"present": True, "entries": n}
    return None


def geoip_ranges(body: Any) -> int | None:
    """How many country ranges the firewall holds in all, from its GeoIP settings. The link (with the person's key)
    is in the same answer and is never read."""
    node = body.get("alias") if isinstance(body, Mapping) else None
    node = node.get("geoip") if isinstance(node, Mapping) else None
    n = node.get("address_count") if isinstance(node, Mapping) else None
    return n if isinstance(n, int) and not isinstance(n, bool) and n >= 0 else None


_ZEN_NAMES = ("zenarmor", "eastpect", "sensei")


def _flag(row: Mapping, key: str) -> bool:
    return str(row.get(key)).strip().lower() in ("1", "true", "yes")


def zenarmor_pick(body: Any) -> tuple[Mapping | None, str]:
    """(row, why): the row of the firewall's service list that is Zenarmor's engine, found by its names. None, with the
    reason, when the list was not readable, lists no Zenarmor service, or lists several and none is plainly the engine
    (the app does not guess which one to start)."""
    rows = body.get("rows") if isinstance(body, Mapping) else None
    if not isinstance(rows, list):
        return None, "The firewall's service list could not be read."
    mine = [r for r in rows if isinstance(r, Mapping)
            and any(t in (str(r.get("name") or "") + " " + str(r.get("id") or "") + " " + str(r.get("description") or "")).lower()
                    for t in _ZEN_NAMES)]
    if not mine:
        return None, "The firewall's service list shows no Zenarmor service."
    engine = [r for r in mine if "engine" in str(r.get("description") or "").lower()
              or str(r.get("name") or "").lower() == "eastpect"]
    pool = engine if len(engine) == 1 else mine if len(mine) == 1 else None
    if pool is None:
        names = ", ".join(str(r.get("description") or r.get("name") or r.get("id")) for r in mine[:6])
        return None, f"The firewall lists several Zenarmor services ({names}), so the app did not guess which one to start."
    return pool[0], ""


def zenarmor_running(body: Any) -> bool | None:
    """Whether the service list says Zenarmor's engine is running; None when it cannot be told."""
    row, _why = zenarmor_pick(body)
    return None if row is None else _flag(row, "running")


def ntp_state(getter: Callable[[str], Any]) -> bool | None:
    """Is the firewall's time service running? Its own status page first; when that answers in a shape not recognised
    (or not at all), the firewall's service list, which says the same thing for every service."""
    try:
        got = ntp_running(getter(NTP_STATUS))
    except Exception:
        got = None
    if got is not None:
        return got
    try:
        return time_service_listed(getter(SERVICES))
    except Exception:
        return None


def _is_time_option(row: Mapping) -> bool:
    if str(row.get("enabled", "1")).lower() in ("0", "false") or str(row.get("disabled", "0")) == "1":
        return False
    return any(isinstance(row.get(k), (str, int)) and _OPTION.search(str(row[k])) for k in _KEYS if k in row)


def dhcp_time_option(bodies: list[Any]) -> bool | None:
    """True when any DHCP option page lists a time-server option; False when a page answered and none does;
    None when no page answered."""
    answered = False
    for body in bodies:
        rows = body.get("rows") if isinstance(body, Mapping) else None
        if not isinstance(rows, list):
            continue
        answered = True
        if any(isinstance(r, Mapping) and _is_time_option(r) for r in rows):
            return True
    return False if answered else None


KEA_SUBNETS = "/api/kea/dhcpv4/search_subnet?rowCount=-1"
KEA_SUBNET = "/api/kea/dhcpv4/get_subnet/"


def _plain(node: Any) -> str:
    """A form field's value: plain text, or the picked entries of a pick-list, joined."""
    if isinstance(node, Mapping):
        return ",".join(str(k) for k, v in node.items() if isinstance(v, Mapping) and str(v.get("selected")) in ("1", "True", "true"))
    return "" if node is None else str(node).strip()


def kea_subnets(getter: Callable[[str], Any]) -> list[dict] | None:
    """[{"uuid", "subnet", "ntp", "has_field"}] for each Kea DHCPv4 subnet, read from the firewall's own subnet form.
    None when Kea's pages are not there or did not answer; [] when Kea has no subnet."""
    try:
        rows = (getter(KEA_SUBNETS) or {}).get("rows")
    except Exception:
        return None
    if not isinstance(rows, list):
        return None
    out = []
    for r in rows[:32]:
        uuid = str(r.get("uuid") or "") if isinstance(r, Mapping) else ""
        if not re.fullmatch(r"[0-9a-fA-F-]{36}", uuid):
            continue
        try:
            body = getter(KEA_SUBNET + uuid)
        except Exception:
            return None
        form = next(iter(body.values()), None) if isinstance(body, Mapping) and len(body) == 1 else None
        if not isinstance(form, Mapping):
            return None
        od = form.get("option_data")
        has = isinstance(od, Mapping) and "ntp_servers" in od
        out.append({"uuid": uuid, "subnet": _plain(form.get("subnet")), "has_field": has,
                    "ntp": _plain(od.get("ntp_servers")) if has else ""})
    return out


def read(getter: Callable[[str], Any]) -> dict[str, Any]:
    """What the firewall says about its time service and DHCP time option, each read on its own."""
    out: dict[str, Any] = {"ntp_running": None, "dhcp_ntp": None}
    out["ntp_running"] = ntp_state(getter)
    bodies = []
    for page in OPTION_PAGES:
        try:
            bodies.append(getter(page))
        except Exception:
            continue
    out["dhcp_ntp"] = dhcp_time_option(bodies)
    kea = kea_subnets(getter)
    if kea:                                   # Kea hands out addresses here: each of its subnets must name a time server
        out["dhcp_ntp"] = all(s["ntp"] for s in kea if s["has_field"]) if any(s["has_field"] for s in kea) else out["dhcp_ntp"]
        out["kea_subnets"] = kea
    return out
