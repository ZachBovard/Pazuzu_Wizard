"""Drift check for the strict-outbound decisions. Read-only, pure functions.

Four controls, each with the same target (the enforced state):

  ipv6         IPv6 is off, always, everywhere: no enabled pass rule may
               use IPv6.
  client_ntp   clients do not reach NTP servers on the internet.
  dns_bypass   clients reach no DNS or DNS-over-TLS (53/853) off the firewall.
  quic         no UDP 443 to the internet.

A pass rule that sits after Pazuzu's own outside-DNS block (PZ-DNS-010, on for TCP and UDP) on the same interface does
not count for dns_bypass: the block is matched first, so that rule never lets DNS out.

A control is DRIFTED when an enabled pass rule permits it, ENFORCED when
none does, and UNVERIFIED when some rule could not be understood (an alias
whose contents are unknown). An "allow everything" rule, such as the stock
LAN allow-all, permits all four: it is drift until it is disabled.

Settings no verified endpoint can read yet (the firewall's time service,
DHCP's time-server option, IPv6 on interfaces and router advertisements)
are reported UNVERIFIED, never enforced.

What it looks at: enabled pass rules, direction in, not on the WAN (except
for IPv6, which is checked everywhere), and not a rule whose source is only the
firewall itself (its own traffic is not a device going around it; IPv6 still
counts those). A rule "reaches the internet" when
its destination is any, or is "everything except" something. Destinations
that are the firewall itself or a local network are not internet. Any other
destination alias is unknown, so the rule is unchecked.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

from pazuzu_core.posture import DRIFTED, ENFORCED, UNVERIFIED, Posture, overall

IPV6 = "ipv6"
CLIENT_NTP = "client_ntp"
DNS_BYPASS = "dns_bypass"
QUIC = "quic"
CONTROLS = (IPV6, CLIENT_NTP, DNS_BYPASS, QUIC)

UNREADABLE_SETTINGS = (
    ("ntp_service", "the firewall serves time and syncs upstream"),
    ("ntp_dhcp_option", "DHCP gives out the firewall as the time server"),
    ("ipv6_interfaces", "IPv6 off on every interface: no addresses, router advertisements or DHCPv6"),
    ("ipv6_system_setting", "the firewall-wide IPv6 allowance is off"),
)

_LOCAL_DEST = re.compile(r"^(lan|wan|opt\d+)(ip)?$")
_ALL = "all"


def _flag(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes"}


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip().lower()


def _enabled_pass(row: Mapping[str, Any]) -> bool:
    return (
        _text(row.get("action")) == "pass"
        and _flag(row.get("enabled"))
        and not _flag(row.get("disabled"))
    )


def _reaches_internet(row: Mapping[str, Any]) -> bool | None:
    """True, False, or None when the destination cannot be judged."""
    destination = _text(row.get("destination_net"))
    negated = _flag(row.get("destination_not"))
    if negated:
        # "everything except X" always includes the internet unless X is any.
        return destination not in ("", "any")
    if destination in ("", "any"):
        return True
    if destination == "(self)" or _LOCAL_DEST.match(destination):
        return False
    return None


def _protocols(row: Mapping[str, Any]) -> set[str] | None:
    proto = _text(row.get("protocol"))
    if proto in ("", "any"):
        return {"tcp", "udp"}
    parts = {p.strip() for p in re.split(r"[/,]", proto) if p.strip()}
    if parts and parts <= {"tcp", "udp"}:
        return parts
    return set() if parts else None


def _ports(value: Any, aliases: Mapping[str, Any]):
    """Set of port numbers, _ALL, or None when unknown."""
    text = _text(value)
    if text in ("", "any"):
        return _ALL
    ports: set[int] = set()
    # BUILD 474: the rule's field is read lowercased (_text), so the lists are looked up the same way: "IoT_cloud_ports"
    # was never found under "iot_cloud_ports", and every rule using it could not be judged
    aliases = {str(k).strip().lower(): v for k, v in (aliases or {}).items()}
    tokens = [t for t in re.split(r"[,\s]+", text) if t]
    for token in tokens:
        if token.isdigit():
            ports.add(int(token))
        elif re.fullmatch(r"\d+-\d+", token):
            low, high = (int(p) for p in token.split("-"))
            if low > high or high - low > 65535:
                return None
            ports.update({p for p in (53, 123, 443, 853) if low <= p <= high})
        elif token in aliases:
            inner = aliases[token]
            inner = inner if isinstance(inner, str) else ",".join(map(str, inner))
            sub = _ports(inner.replace("\n", ","), {})
            if sub is None:
                return None
            if sub == _ALL:
                return _ALL
            ports |= sub
        else:
            return None
    return ports


def _covers(ports: Any, wanted: int) -> bool:
    return ports == _ALL or (isinstance(ports, set) and wanted in ports)


_ICMP6 = {"ipv6-icmp", "icmp6", "icmpv6", "ipv6icmp"}


def _icmp6_housekeeping(row: Mapping[str, Any]) -> bool:
    """The firewall's own built-in ICMPv6 rules ("IPv6 RFC4890 requirements (ICMP)") and any other pass rule that
    lets nothing but ICMPv6 through. IPv6 needs these messages to work at all, but they carry no devices' traffic."""
    if _text(row.get("ipprotocol")) != "inet6":
        return False
    return _text(row.get("description")).startswith("ipv6 rfc4890") or _text(row.get("protocol")) in _ICMP6


_SELF_SOURCES = {"(self)", "this firewall", "this_firewall"}


def _firewall_only_source(row: Mapping[str, Any]) -> bool:
    """True when the rule's source is only the firewall itself ("This Firewall", not negated). That is the firewall's
    own traffic (its own lookups, its own time sync), not a device on the network going around it."""
    if _flag(row.get("source_not")):
        return False
    tokens = [t.strip() for t in _text(row.get("source_net")).split(",") if t.strip()]
    return bool(tokens) and all(t in _SELF_SOURCES for t in tokens)


def _permits(control: str, row, aliases) -> bool | None:
    """Does this enabled pass rule permit the thing the control forbids?"""
    if control == IPV6:
        if _icmp6_housekeeping(row):
            return False
        return _text(row.get("ipprotocol")) in ("inet6", "inet46")

    if _firewall_only_source(row):
        return False
    if _text(row.get("interface")) == "wan":
        return False
    if _text(row.get("direction")) not in ("", "in"):
        return False
    reach = _reaches_internet(row)
    if reach is False:
        return False
    protocols = _protocols(row)
    if protocols is None:
        return None
    ports = _ports(row.get("destination_port"), aliases)
    if not protocols:
        return False
    # BUILD 474: time and QUIC are UDP, so a rule that lets no UDP through cannot touch them, whatever its ports
    if control in (CLIENT_NTP, QUIC) and "udp" not in protocols:
        hit = False
    elif control == CLIENT_NTP:
        hit = _covers(ports, 123) if ports is not None else None
    elif control == QUIC:
        hit = _covers(ports, 443) if ports is not None else None
    else:
        if ports is None:
            hit = None
        else:
            hit = (
                ("tcp" in protocols or "udp" in protocols) and _covers(ports, 53)
            ) or ("tcp" in protocols and _covers(ports, 853))
    if hit is False:
        return False
    if reach is None or hit is None:
        return None
    return True


def _label(row: Mapping[str, Any]) -> dict[str, Any]:
    return {"uuid": row.get("uuid"), "description": str(row.get("description") or "")}


def ipv6_allowance(settings: Any) -> bool | None:
    """True when the firewall-wide IPv6 allowance is off (disableipv6 = 1), False when it is on, None when it was
    not read. Takes the firewall's own answer ({"settings": {...}}) or the inner map."""
    if not isinstance(settings, Mapping):
        return None
    inner = settings.get("settings", settings)
    if not isinstance(inner, Mapping):
        return None
    value = _text(inner.get("disableipv6"))
    if value in ("1", "true", "yes"):
        return True
    if value in ("0", "false", "no"):
        return False
    return None


def _service_verdict(name: str, services: Mapping[str, Any] | None):
    """(status, detail, findings) for the two services the firewall can now be asked about, else None."""
    if not isinstance(services, Mapping):
        return None
    if name == "ntp_service" and services.get("ntp_running") is not None:
        if services["ntp_running"]:
            return ENFORCED, "the firewall's time service is running", []
        return DRIFTED, "the firewall's time service is not running", [
            {"uuid": "", "description": "The time service is not running (Services, Network Time: turn it on)"}]
    if name == "ntp_dhcp_option" and services.get("dhcp_ntp") is not None:
        if services["dhcp_ntp"]:
            return ENFORCED, "DHCP gives out a time server", []
        return DRIFTED, "no DHCP option gives out a time server", [
            {"uuid": "", "description": "No DHCP option hands out the firewall as the time server (Services, DHCP, Options)"}]
    if name == "ipv6_interfaces" and services.get("ipv6_global") is not None:
        held = [r for r in services["ipv6_global"] if isinstance(r, Mapping)]
        if not held:
            return ENFORCED, "no port holds an IPv6 address", []
        return DRIFTED, f"{len(held)} port address(es) are IPv6", [
            {"uuid": "", "description": f"{r.get('iface', '?')} has the IPv6 address {r.get('addr', '?')} "
                                        "(its IPv6 Configuration Type should be None)"} for r in held[:10]]
    return None


ADMIN_SESSION_MINUTES = 15            # the idle timeout the baseline asks for


def admin_session_verdict(services: Mapping[str, Any] | None):
    """(status, detail, findings) for the admin session idle timeout when the plugin read it from the firewall's
    configuration, else None (the person then confirms it by hand). services["admin_session"] is the plugin's own
    answer: {"state": "ok", "set": bool, "minutes": int|None}. No timeout saved means the firewall's default (hours);
    0 means a session never expires; both are drift, whatever anyone said."""
    got = services.get("admin_session") if isinstance(services, Mapping) else None
    if not isinstance(got, Mapping) or got.get("state") != "ok":
        return None
    where = "(System, Settings, Administration: set Session Timeout to %d minutes)" % ADMIN_SESSION_MINUTES
    if not got.get("set"):
        return DRIFTED, "no session timeout is saved, so the firewall's default of hours applies", [
            {"uuid": "", "description": "No session timeout is saved, so the firewall's default of hours applies " + where}]
    minutes = got.get("minutes")
    if isinstance(minutes, bool) or not isinstance(minutes, int) or minutes < 0:
        return None
    if minutes == 0:
        return DRIFTED, "admin sessions never expire", [
            {"uuid": "", "description": "Admin sessions never expire " + where}]
    if minutes > ADMIN_SESSION_MINUTES:
        return DRIFTED, f"the session timeout is {minutes} minutes", [
            {"uuid": "", "description": f"The session timeout is {minutes} minutes " + where}]
    return ENFORCED, f"the session timeout is {minutes} minutes", []


_DNS_BLOCK = re.compile(r"^PAZUZU:PZ-DNS-010:")


def _seq(row: Mapping[str, Any]) -> int | None:
    text = str(row.get("sequence") if row.get("sequence") is not None else "").strip()
    return int(text) if text.isdigit() else None


def dns_blocks_before(all_rows) -> dict[str, int]:
    """{interface: order number} where Pazuzu's own outside-DNS block (PZ-DNS-010) is switched on for both TCP and UDP;
    the number is the later of the two, so a pass rule numbered after it is evaluated after both."""
    seen: dict[str, dict[str, int]] = {}
    for r in all_rows:
        if not isinstance(r, Mapping) or not _DNS_BLOCK.match(str(r.get("description") or "")):
            continue
        if _text(r.get("action")) not in ("block", "reject") or not _flag(r.get("enabled")) or _flag(r.get("disabled")):
            continue
        n = _seq(r)
        proto = _text(r.get("protocol"))
        iface = _text(r.get("interface"))
        if n is None or proto not in ("tcp", "udp") or not iface:
            continue
        got = seen.setdefault(iface, {})
        got[proto] = max(got.get(proto, n), n)
    return {i: max(p.values()) for i, p in seen.items() if set(p) == {"tcp", "udp"}}


def _shadowed_dns(row: Mapping[str, Any], blocks: Mapping[str, int]) -> bool:
    """A pass rule that sits after Pazuzu's own outside-DNS block on the same interface never gets to let DNS out: the
    block (quick) is matched first. Only for a rule whose source is that interface's devices (the interface's own network,
    or addresses written as numbers), since the block covers that network."""
    iface = _text(row.get("interface"))
    n, limit = _seq(row), blocks.get(iface)
    if n is None or limit is None or n <= limit or _flag(row.get("source_not")):
        return False
    tokens = [t.strip() for t in _text(row.get("source_net")).split(",") if t.strip()]
    if not tokens:
        return False
    for t in tokens:
        if t == iface or t == iface + "net":
            continue
        try:
            import ipaddress
            ipaddress.ip_network(t, strict=False)
        except ValueError:
            return False
    return True


_VPN_BLOCK = "pazuzu: vpn no "


def vpn_blocks_before(all_rows) -> list[dict[str, Any]]:
    """Pazuzu's own VPN blocks (vpn_access, BUILD 442): switched-on block rules to the internet, each with the
    controls it closes ("dns53", "dns853", "ntp", "quic"), its interface, source and order number."""
    out = []
    for r in all_rows:
        if not isinstance(r, Mapping) or not _text(r.get("description")).startswith(_VPN_BLOCK):
            continue
        if _text(r.get("action")) not in ("block", "reject") or not _flag(r.get("enabled")) or _flag(r.get("disabled")):
            continue
        n = _seq(r)
        if n is None or not _reaches_internet(r):
            continue
        protos = _protocols(r) or set()
        port = _text(r.get("destination_port"))
        closes = set()
        if port == "53" and protos >= {"tcp", "udp"}:
            closes.add("dns53")
        if port == "853" and "tcp" in protos:
            closes.add("dns853")
        if port == "123" and "udp" in protos:
            closes.add("ntp")
        if port == "443" and "udp" in protos:
            closes.add("quic")
        if closes:
            out.append({"iface": _text(r.get("interface")), "source": _text(r.get("source_net")), "seq": n,
                        "closes": closes})
    return out


def _shadowed_vpn(control: str, row: Mapping[str, Any], blocks: list[dict[str, Any]]) -> bool:
    """A pass rule on the same interface, from the same source, numbered after Pazuzu's VPN blocks never lets that
    traffic out: the blocks are matched first (quick)."""
    n = _seq(row)
    if n is None or _flag(row.get("source_not")):
        return False
    iface, src = _text(row.get("interface")), _text(row.get("source_net"))
    closed = set()
    for b in blocks:
        if b["iface"] == iface and b["source"] == src and b["seq"] < n:
            closed |= b["closes"]
    need = {DNS_BYPASS: {"dns53", "dns853"}, CLIENT_NTP: {"ntp"}, QUIC: {"quic"}}.get(control)
    return bool(need) and need <= closed


def evaluate(
    inventory: Mapping[str, Any],
    aliases: Mapping[str, Any] | None = None,
    settings: Mapping[str, Any] | None = None,
    services: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    rows = inventory.get("rows")
    if not isinstance(rows, list):
        raise ValueError("Inventory rows must be an array")
    blocks = dns_blocks_before(rows)
    vblocks = vpn_blocks_before(rows)
    rows = [r for r in rows if isinstance(r, dict) and _enabled_pass(r)]
    aliases = dict(aliases or {})

    controls: list[dict[str, Any]] = []
    postures: list[Posture] = []
    for control in CONTROLS:
        findings, unchecked = [], []
        for row in rows:
            verdict = _permits(control, row, aliases)
            if verdict is not False and control == DNS_BYPASS and _shadowed_dns(row, blocks):
                verdict = False                      # Pazuzu's DNS block comes first on its interface: it never lets DNS out
            if verdict is not False and vblocks and _shadowed_vpn(control, row, vblocks):
                verdict = False                      # Pazuzu's VPN blocks come first: the full tunnel never lets it out
            if verdict is True:
                findings.append(_label(row))
            elif verdict is None:
                unchecked.append(_label(row))
        if findings:
            status, detail = DRIFTED, f"{len(findings)} enabled rule(s) permit it"
        elif unchecked:
            status, detail = UNVERIFIED, f"{len(unchecked)} rule(s) could not be judged"
        else:
            status, detail = ENFORCED, "no enabled rule permits it"
        controls.append({"control": control, "status": status, "detail": detail,
                         "findings": findings, "unchecked": unchecked})
        postures.append(Posture(control, status, len(findings), 0, detail))

    off = ipv6_allowance(settings)
    for name, meaning in UNREADABLE_SETTINGS:
        if name == "ipv6_system_setting" and off is not None:
            status = ENFORCED if off else DRIFTED
            detail = ("IPv6 is switched off for the whole firewall" if off
                      else "IPv6 is allowed for the whole firewall")
            found = [] if off else [{"uuid": "", "description": "IPv6 is allowed firewall-wide "
                                     "(Interfaces, Settings: the Turn off IPv6 box is not ticked)"}]
            controls.append({"control": name, "status": status, "detail": detail,
                             "findings": found, "unchecked": []})
            postures.append(Posture(name, status, len(found), 0, detail))
            continue
        seen = _service_verdict(name, services)
        if seen is not None:
            status, detail, found = seen
            controls.append({"control": name, "status": status, "detail": detail,
                             "findings": found, "unchecked": []})
            postures.append(Posture(name, status, len(found), 0, detail))
            continue
        reason = "no verified endpoint reads this yet"
        controls.append({"control": name, "status": UNVERIFIED, "detail": f"{meaning}: {reason}",
                         "findings": [], "unchecked": []})
        postures.append(Posture(name, UNVERIFIED, None, 0, reason))

    return {"mode": "read_only", "rules_considered": len(rows),
            "controls": controls, "summary": overall(postures)}
