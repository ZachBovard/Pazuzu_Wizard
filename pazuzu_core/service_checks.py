"""The four checks before the stock rules go, done by the app.

Where the firewall's own API can say, it says. Where it cannot be read, the row
says so and the person confirms that one by hand; the app never ticks it. The
endpoint names are from the OPNsense documentation and are not proven on 26.7,
so every reading is defensive and a failed read is "unknown", never "good".
"""
from __future__ import annotations

from typing import Any, Callable, Iterable

from pazuzu_core import lan_tests as lt

GOOD, ATTENTION, UNKNOWN = lt.GOOD, lt.ATTENTION, lt.UNKNOWN

TITLES = {
    "ntp": "The firewall's own time service is running and synced",
    "dhcp_ntp": "DHCP hands out the firewall as the time server",
    "ra_dhcpv6": "Router advertisements and the DHCPv6 server are off",
    "ipv6_none": "No IPv6 address on your networks",
}
HOW = {
    "ntp": "Services, Network Time: turn it on, add upstream servers.",
    "dhcp_ntp": "Your DHCP service, each network: set NTP servers to the firewall's own address.",
    "ra_dhcpv6": "Services, Router Advertisements: Disabled. DHCPv6 off. Do the same in Dnsmasq if you use it.",
    "ipv6_none": "Interfaces, each network: IPv6 Configuration Type = None.",
}
_TIME_NAMES = ("ntpd", "chronyd", "chrony", "openntpd")
_V6_NAMES = ("radvd", "dhcp6", "dhcpd6", "kea_dhcp6", "kea-dhcp6")


def _services(getter) -> dict[str, bool] | None:
    try:
        data = getter("/api/core/service/search")
    except Exception:
        return None
    rows = data.get("rows") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        return None
    out = {}
    for r in rows:
        name = r.get("id") or r.get("name") if isinstance(r, dict) else None
        if name:
            out[str(name).lower()] = str(r.get("running")).lower() in {"1", "true"}
    return out or None


def _dhcp_time_option(getter) -> bool | None:
    """True when a DHCP option page lists a time-server option, False when a page answered and none does, None when
    no page answered. The same reading the manager uses for its own time-option control."""
    from pazuzu_core import service_reads as sr
    bodies = []
    for page in sr.OPTION_PAGES:
        try:
            bodies.append(getter(page))
        except Exception:
            continue
    return sr.dhcp_time_option(bodies)


def _ipv6_on_networks(getter, devices: Iterable[str]) -> list[str] | None:
    """Devices among `devices` that hold a real (not link-local) IPv6 address; None if unreadable."""
    try:
        data = getter("/api/interfaces/overview/interfaces_info/true")
    except Exception:
        return None
    rows = data.get("rows") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        return None
    mine, bad = set(devices), []
    for r in rows:
        if not isinstance(r, dict) or str(r.get("device")) not in mine:
            continue
        for a in (r.get("ipv6") or []):
            addr = str(a.get("ipaddr") if isinstance(a, dict) else a).split("/")[0].lower()
            if addr and not addr.startswith("fe80"):
                bad.append(str(r["device"]))
                break
    return bad


def run(getter: Callable[[str], Any] | None, devices: Iterable[str], firewall: str,
        time_fn=lt.sntp) -> list[dict]:
    devices = list(devices)
    svc = _services(getter) if getter else None
    rows = []

    # 1. time service: the app asks it for the time, which proves it answers and is synced
    t = time_fn(firewall)
    running = None if svc is None else any(svc.get(n) for n in _TIME_NAMES)
    if t and 1 <= t["stratum"] <= 15 and t["leap"] != 3:
        rows.append(_mk("ntp", GOOD, "It answered a time request and says its clock is synced (stratum %d)." % t["stratum"]))
    elif t:
        rows.append(_mk("ntp", ATTENTION, "It answers, but says its own clock is not synced yet. Give it a minute, or check its upstream servers."))
    elif running is False:
        rows.append(_mk("ntp", ATTENTION, "The time service is not running."))
    else:
        rows.append(_mk("ntp", ATTENTION, "It did not answer a time request from this device."))

    # 2. DHCP time-server option: read the same way the manager reads it. Only a page that did not answer
    #    leaves it to be confirmed by hand.
    option = _dhcp_time_option(getter) if getter else None
    if option is True:
        rows.append(_mk("dhcp_ntp", GOOD, "A DHCP option gives out a time server."))
    elif option is False:
        rows.append(_mk("dhcp_ntp", ATTENTION, "No DHCP option gives out a time server."))
    else:
        rows.append(_mk("dhcp_ntp", UNKNOWN, "Cannot be read from the firewall. Check it on the firewall, then confirm here."))

    # 3. router advertisements and DHCPv6
    if svc is None:
        rows.append(_mk("ra_dhcpv6", UNKNOWN, "The service list could not be read. Check it on the firewall, then confirm here."))
    else:
        on = sorted(n for n, up in svc.items() if up and any(k in n for k in _V6_NAMES))
        rows.append(_mk("ra_dhcpv6", ATTENTION, "Running: " + ", ".join(on) + ".") if on
                    else _mk("ra_dhcpv6", GOOD, "Neither is running. (If you use Dnsmasq, its own router advertisements are not read yet.)"))

    # 4. IPv6 address on the networks
    bad = _ipv6_on_networks(getter, devices) if getter else None
    if bad is None:
        rows.append(_mk("ipv6_none", UNKNOWN, "The port list could not be read. Check it on the firewall, then confirm here."))
    elif bad:
        rows.append(_mk("ipv6_none", ATTENTION, "These ports hold an IPv6 address: " + ", ".join(bad) + "."))
    else:
        rows.append(_mk("ipv6_none", GOOD, "None of your networks' ports holds an IPv6 address."))
    return rows


def _mk(check_id: str, status: str, detail: str) -> dict:
    return {"id": check_id, "title": TITLES[check_id], "status": status,
            "detail": detail, "how": HOW[check_id]}


def passed(rows: list[dict], acked: Iterable[str], skipped: Iterable[str] = ()) -> bool:
    """Every check is good, or unreadable and confirmed by a person, or skipped by a person
    who chose to carry on. A skipped check is never the same as a good one: the caller shows it."""
    ok, skip = set(acked), set(skipped)
    return bool(rows) and all(r["status"] == GOOD or r["id"] in skip
                              or (r["status"] == UNKNOWN and r["id"] in ok)
                              for r in rows)
