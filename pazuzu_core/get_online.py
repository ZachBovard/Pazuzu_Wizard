"""The "get me online" check for a freshly installed firewall. Pure functions.

Reads the interface overview the firewall already reports and says, in plain
words, where the internet connection stands and what to do next. It never
writes, never pings, and never echoes an address back: only counts and words.

Verdicts, in the order they are checked:
  no_wan        the firewall has no interface called WAN
  disabled      the WAN is switched off
  no_cable      no link on the WAN port
  wrong_network the WAN address is inside the firewall's own home network
  no_address    link is up but the WAN has no address yet
  no_gateway    address but no way out (gateway)
  no_dns        way out but no DNS server learned
  online_reads  address, gateway and DNS all present (a ping is still needed)
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, Mapping

ONLINE = "online_reads"


@dataclass(frozen=True)
class Verdict:
    code: str
    ok: bool
    say: str                     # one plain sentence
    next: tuple[str, ...] = ()   # what to try, in order


def _rows(payload: Any) -> list[Mapping]:
    rows = payload.get("rows") if isinstance(payload, Mapping) else None
    return [r for r in rows or [] if isinstance(r, Mapping)]


def _row(rows: list[Mapping], identifier: str) -> Mapping | None:
    for r in rows:
        if r.get("identifier") == identifier:
            return r
    return None


def _networks(row: Mapping | None) -> list:
    out = []
    for item in (row or {}).get("ipv4") or []:
        text = item.get("ipaddr") if isinstance(item, Mapping) else None
        try:
            out.append(ipaddress.ip_interface(text))
        except (TypeError, ValueError):
            continue
    return out


def _linked(row: Mapping) -> bool:
    flags = row.get("flags") or []
    if "lower_up" in flags or "running" in flags:
        return True
    return str(row.get("status", "")).lower() in ("up", "active")


def check_wan(interfaces: Any, connection_type: str | None = None) -> Verdict:
    rows = _rows(interfaces)
    wan = _row(rows, "wan")
    if wan is None:
        return Verdict("no_wan", False,
                       "This firewall has no internet port set up yet.",
                       ("Assign a port as WAN, then run this check again.",))
    if wan.get("enabled") is False:
        return Verdict("disabled", False, "The internet port is switched off.",
                       ("Switch the WAN on, then run this check again.",))
    if not _linked(wan):
        return Verdict("no_cable", False,
                       "No cable signal on the internet port.",
                       ("Plug the cable from your modem or ONT into the "
                        "port labelled for the internet.",
                        "Try another cable, then restart the modem."))

    addrs = _networks(wan)
    lan_nets = [a.network for a in _networks(_row(rows, "lan"))]
    if any(a.network.overlaps(n) for a in addrs for n in lan_nets):
        return Verdict("wrong_network", False,
                       "The internet port has an address from your own home "
                       "network, so its cable is probably in the wrong place.",
                       ("Move the cable from the home-network port or switch "
                        "to the modem.",
                        "Then clear the old address and run this check again."))
    if not addrs:
        dhcp = (connection_type in (None, "dhcp")
                and str((wan.get("config") or {}).get("ipaddr", "dhcp")) == "dhcp")
        return Verdict("no_address", False,
                       "The cable is in but the provider has not given an "
                       "address yet.",
                       ("Restart the modem or gateway, wait two minutes, run "
                        "this check again.",
                        "If it stays empty, ask what your provider needs "
                        "(device address, login or VLAN).") if dhcp else
                       ("Check the login or address details for your "
                        "connection type.",))
    if not (wan.get("gateways") or wan.get("ifctl.router")):
        return Verdict("no_gateway", False,
                       "The port has an address but no way out to the internet.",
                       ("Check the gateway for this connection.",))
    if not wan.get("ifctl.nameserver"):
        return Verdict("no_dns", False,
                       "A way out is set but no DNS server was learned.",
                       ("Set a DNS server on the firewall, then run this "
                        "check again.",))
    return Verdict(ONLINE, True,
                   "The internet port has an address, a way out and DNS. "
                   "A live test from the firewall is the last check.",
                   ("Run a ping and a name lookup from the firewall.",))
