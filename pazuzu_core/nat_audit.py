"""A read-only look at the firewall's port forwards and redirects (Firewall, NAT, Destination NAT; "Port Forward"
before 26.7). Nothing here writes.

What it says, in plain words, for each switched-on entry:
  - a DNS redirect on an inside network (port 53 or 853 sent to the firewall itself): good, it keeps devices with a
    hard-coded DNS server on the firewall's filtered DNS. Sent to 127.0.0.1 it is flagged: on a firewall whose DNS does
    not listen on that address the lookups fail (seen on a production firewall, 28 Oct 2026; pointing it at the
    firewall's own address on that network fixed it).
  - a forward from the internet to a device in the public-servers network (DMZ): listed, that is what the DMZ is for.
  - a forward from the internet to a device on any other inside network: flagged. It opens that device to the whole
    internet; move it to the DMZ or close the forward.
And for each isolated network with a port (smart devices, guests, public servers, quarantine) that has no DNS
redirect: "not yet". The baseline blocks outside DNS there, so a device with its own DNS server is cut off rather
than sent to the firewall.

The rows are the firewall's own answer to search_rule; their field names differ between releases, so each value is
looked for under the names seen so far, and an entry that cannot be read plainly is listed as such, never guessed.
"""
from __future__ import annotations

import ipaddress
from typing import Callable, Iterable, Mapping

from pazuzu_core.country_block import DNAT, _pick

try:                                    # KidsNet (kids_net.py) is its own file; the audit works without it
    from pazuzu_core import kids_net
except ImportError:                     # pragma: no cover
    kids_net = None

DNS_PORTS = {"53", "853", "domain", "dns"}
NTP_PORTS = {"123", "ntp"}
ISOLATED = ("iot", "guest", "dmz", "quarantine")
ZONE_WORDS = {"iot": "smart devices (IoT)", "guest": "guests", "dmz": "public servers (DMZ)",
              "quarantine": "quarantine", "trusted": "your home network", "management": "management",
              "wan": "the internet side", "kids": "KidsNet"}


def _ip(text: str):
    try:
        return ipaddress.ip_address(str(text).strip())
    except ValueError:
        return None


def entry(row: Mapping) -> dict:
    """One row in plain fields. `on` is False for a switched-off entry."""
    off = _pick(row, "disabled") in ("1", "true", "True") or _pick(row, "enabled") in ("0", "false", "False")
    return {"on": not off,
            "interface": _pick(row, "interface").lower(),
            "protocol": _pick(row, "protocol").upper() or "?",
            "port": _pick(row, "destination_port", "destination.port", "dstport", "dst_port"),
            "target": _pick(row, "target", "redirect_target", "local_ip"),
            "local_port": _pick(row, "local-port", "local_port", "localport"),
            "name": _pick(row, "descr", "description")[:80]}


def _zone_of_interface(iface: str, zones: Mapping[str, Mapping]) -> str | None:
    names = {p.strip() for p in iface.split(",") if p.strip()}
    for zone, a in zones.items():
        if not isinstance(a, Mapping):
            continue
        keys = {str(a.get(k) or "").lower() for k in ("identifier", "device", "description")} - {""}
        if names & keys:
            return zone
    return None


def _zone_of_ip(ip, nets: Mapping[str, Iterable]) -> str | None:
    for zone, ns in nets.items():
        if any(ip in n for n in ns):
            return zone
    return None


def _is_dns(e: dict) -> bool:
    return e["port"] in DNS_PORTS or e["local_port"] in DNS_PORTS


def _is_ntp(e: dict) -> bool:
    """A time redirect: UDP 123 sent to a real address. A target of "*" or nothing (the fields swapped by hand, seen on
    a real firewall) or 127.0.0.1 does not count: it catches nothing."""
    t = _ip(e["target"])
    return (e["port"] in NTP_PORTS or e["local_port"] in NTP_PORTS) and t is not None and not t.is_loopback


def redirected(rows: list, zones: Mapping[str, Mapping], kind: str = "dns") -> set[str]:
    """The zones that have a switched-on redirect of this kind ("dns": any target; "ntp": to a real address)."""
    test = _is_ntp if kind == "ntp" else _is_dns
    out: set[str] = set()
    for row in rows or []:
        if isinstance(row, Mapping):
            e = entry(row)
            zone = _zone_of_interface(e["interface"], zones) if e["on"] and test(e) else None
            if zone:
                out.add(zone)
    return out


def missing(rows: list, zones: Mapping[str, Mapping], kind: str = "dns") -> list[str]:
    """The isolated zones with a port and no redirect of this kind yet, in a fixed order."""
    have = redirected(rows, zones, kind)
    return [z for z in ISOLATED
            if isinstance(zones.get(z), Mapping) and zones[z].get("state") == "bound" and z not in have]


def audit(rows: list, zones: Mapping[str, Mapping], nets: Mapping[str, Iterable], firewall_ips: set[str]) -> dict:
    """{"status", "lines"} for the 'What we checked' list. `zones` is the saved port choice by zone (identifier,
    device, state), `nets` each zone's networks, `firewall_ips` the firewall's own addresses."""
    attention, good, info = [], [], []
    for row in rows or []:
        if not isinstance(row, Mapping):
            continue
        e = entry(row)
        if not e["on"]:
            continue
        zone = _zone_of_interface(e["interface"], zones) or ("wan" if "wan" in e["interface"] else None)
        where = ZONE_WORDS.get(zone, e["interface"] or "an unknown port")
        label = f"{e['name']}: " if e["name"] else ""
        if _is_dns(e):
            t = _ip(e["target"])
            if t is not None and t.is_loopback:
                attention.append(f"{label}DNS on {where} is sent to {e['target']}. If the firewall's DNS does not listen "
                                 "there, lookups fail: send it to the firewall's own address on that network instead.")
            elif zone == "kids" and kids_net is not None and e["target"] in kids_net.SERVERS:
                good.append(f"DNS on KidsNet is sent to {kids_net.PROVIDERS[kids_net.SERVERS[e['target']]]['name']} "
                            f"({e['target']}), the family filter picked for it.")
            elif e["target"] in firewall_ips:
                good.append(f"DNS on {where} is sent to the firewall ({e['target']}), so a device with its own DNS server "
                            "still gets filtered answers.")
            else:
                attention.append(f"{label}DNS on {where} is sent to {e['target'] or 'somewhere unreadable'}, not to the "
                                 "firewall, so those lookups are not filtered.")
            continue
        if zone == "wan":
            t = _ip(e["target"])
            inside = _zone_of_ip(t, nets) if t is not None else None
            what = f"{e['protocol']} {e['port'] or '?'} to {e['target'] or '?'}" + (f":{e['local_port']}" if e["local_port"] and e["local_port"] != e["port"] else "")
            if inside == "dmz":
                info.append(f"{label}Open from the internet: {what}, a public server in the DMZ.")
            elif inside:
                attention.append(f"{label}Open from the internet: {what}, on {ZONE_WORDS.get(inside, inside)}. That puts "
                                 "the device in reach of anyone on the internet: move it to the DMZ, or close the forward.")
            else:
                attention.append(f"{label}Open from the internet: {what}. Pazuzu cannot tell which network that is on.")
            continue
        info.append(f"{label}{e['protocol']} {e['port'] or '?'} on {where} is sent to {e['target'] or '?'}.")
    not_yet = [f"No DNS redirect on {ZONE_WORDS[z]} yet. Outside DNS is blocked there, so a device with its own DNS "
               "server is cut off instead of being sent to the firewall. Finish getting to Happy (Normal) in the "
               "manager adds it." for z in missing(rows, zones)]
    status = "attention" if attention else "not_yet" if not_yet else "good"
    lines = attention + not_yet + good + info
    if not lines:
        lines = ["No port forwards or redirects are switched on."]
    return {"status": status, "lines": lines}


def rows_of(getter: Callable[[str], dict]) -> list:
    got = getter(DNAT)
    rows = got.get("rows") if isinstance(got, Mapping) else None
    if not isinstance(rows, list):
        raise ValueError("the firewall did not list its port forwards")
    return rows


def ports(getter: Callable[[str], dict], zones: Mapping[str, Mapping]) -> tuple[dict, dict, set]:
    """(zones, addresses, every address of the firewall's own). The saved port choice knows each zone's device (igc2) but a NAT entry names the firewall's
    short name for it (opt1), so each zone gets its `identifier` from the firewall's interface list. `addresses` is
    {zone: [the firewall's own IPv4 interfaces there]}. Reads only; an unreadable list leaves both as they were."""
    try:
        info = getter("/api/interfaces/overview/interfaces_info/true")
        irows = info.get("rows") if isinstance(info, Mapping) else info
    except Exception:  # noqa: BLE001 - forwards then cannot be placed in a network
        irows = []
    ident, by_dev, every = {}, {}, set()
    for r in irows if isinstance(irows, list) else []:
        if not isinstance(r, Mapping):
            continue
        if r.get("identifier"):
            ident[str(r.get("device"))] = str(r["identifier"]).lower()
        addrs = r.get("addr4") if isinstance(r.get("addr4"), list) else [r.get("addr4")]
        for c in addrs:
            try:
                iface = ipaddress.ip_interface(str(c))
            except ValueError:
                continue
            every.add(str(iface.ip))
            if iface.version == 4:
                by_dev.setdefault(str(r.get("device")), []).append(iface)
    out, where = {}, {}
    for zone, a in zones.items():
        if not isinstance(a, Mapping):
            continue
        a = dict(a)
        dev = str(a.get("device") or "")
        if not a.get("identifier") and dev in ident:
            a["identifier"] = ident[dev]
        out[zone] = a
        if dev in by_dev:
            where[zone] = by_dev[dev]
    return out, where, every


def read(getter: Callable[[str], dict], zones: Mapping[str, Mapping]) -> dict:
    """Read the rows and the networks with the look-only account, then audit them."""
    rows = rows_of(getter)
    zones, where, fw_ips = ports(getter, zones)
    nets = {z: [i.network for i in ifs] for z, ifs in where.items()}
    return audit(rows, zones, nets, fw_ips)
