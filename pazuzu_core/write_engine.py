"""The one place the app adds things to the firewall that have no verified recipe yet.

Nothing here guesses an address. A write path is built only from a READ path the probe has already
seen the firewall answer, the way every OPNsense settings page names its pieces: the page that
answers `search_server` also has `get_server`, `add_server`, `set_server` and `del_server`. When the
probe has not seen the read page answer, the feature is off and says why.

Before anything is sent:
  * the firewall's own empty form (its `get`) is read, and every field we mean to set must be in it;
  * a field that is a pick-list on the firewall must be given one of the firewall's own choices;
  * the same name must not already exist;
  * a passkey touch approves the exact plan (secrets never appear in what is approved or shown).
After it is sent, the new row is read back and compared, and an undo for exactly that row is kept.
Undo never waits for a person.

The network is one injected session (requests-like: .get/.post returning .status_code and .json()), so
the tests run against a small pretend firewall.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import quote

from pazuzu_core.passkey_gate import plan_digest

TIMEOUT = 15.0
# BUILD 463: Applying the block lists makes Unbound load every list again. On a real firewall that took over a minute,
# names went unanswered meanwhile, and Pazuzu's 15-second wait said "not applied" while it went on.
DNSBL_APPLY_TIMEOUT = 300.0
DNSBL_NOTE = "Applying the block lists reloads them: names stop answering for about a minute while it does"
STALE_TYPE = re.compile(r"Option \[([^\]]+)\] not in list")
MAX_TEXT = 255
HEADERS = {"X-Requested-With": "XMLHttpRequest"}
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


class WriteError(Exception):
    """A problem a person can read. Nothing was changed unless the message says so."""


@dataclass(frozen=True)
class Cap:
    """One thing the app can add. `probe` is the read page that must have answered."""
    id: str
    title: str
    probe: str                       # id from probe.PROBES whose answer unlocks this
    read: str                        # the probed read path, e.g. /api/auth/user/search
    kind: str                        # "item" (add/set/del a row) or "settings" (get/set one page)
    fields: frozenset                # the only fields this feature will ever send
    secret: frozenset = frozenset()  # fields that are never shown, logged or approved by value
    key: str = "name"                # the field that names a row (read-back and duplicate check)
    apply: str | None = None         # None, "routing", "filter", or a read path whose folder has /reconfigure
    free: frozenset = frozenset()    # fields whose value is free text or a list, not one of the form's pick-list
    reversible: bool = False         # a settings page whose old values are kept so a set can be put back
    query: str = ""                  # a query added to the empty form, the list and the add (none use it now)


CAPS: dict[str, Cap] = {c.id: c for c in (
    Cap("user", "Add a person who can manage the firewall", "auth_users", "/api/auth/user/search", "item",
        frozenset({"name", "password", "descr", "email", "otp_seed", "disabled", "shell",
                   "group_memberships", "comment"}), frozenset({"password", "otp_seed"})),
    Cap("wg_general", "Switch the VPN on", "wg_general", "/api/wireguard/general/get", "settings",
        frozenset({"enabled"}), apply="/api/wireguard/service/show"),
    Cap("wg_server", "Make the VPN instance", "wg_servers", "/api/wireguard/server/search_server", "item",
        frozenset({"enabled", "name", "pubkey", "privkey", "port", "tunneladdress", "dns", "mtu",
                   "disableroutes", "peers"}), frozenset({"privkey"}), apply="/api/wireguard/service/show",
        free=frozenset({"tunneladdress", "dns"})),
    Cap("wg_client", "Add a device to the VPN", "wg_clients", "/api/wireguard/client/search_client", "item",
        frozenset({"enabled", "name", "pubkey", "psk", "tunneladdress", "serveraddress", "serverport",
                   "keepalive", "servers"}), frozenset({"psk"}), apply="/api/wireguard/service/show",
        free=frozenset({"tunneladdress", "serveraddress"})),
    Cap("ddns_general", "Switch the changing-address name service on", "ddns", "/api/dyndns/settings/get",
        "settings", frozenset({"general.enabled", "general.backend"}), apply="/api/dyndns/service/status"),
    Cap("ddns_account", "Add a changing-address name", "ddns_accounts", "/api/dyndns/accounts/search_item",
        "item", frozenset({"enabled", "service", "username", "password", "hostnames", "zone", "checkip", "interface",
                           "ttl", "description"}),
        frozenset({"password"}), key="description", apply="/api/dyndns/service/status",
        free=frozenset({"username", "hostnames", "zone"})),
    # Packet inspection and the DNS block lists. Field names are dotted paths into the firewall's own form;
    # a name its form does not have is refused before anything is sent. Old values are kept for the undo.
    Cap("ids_general", "Switch packet inspection (IPS)", "ids", "/api/ids/settings/get", "settings",
        frozenset({"general.enabled", "general.ips", "general.mode"}), apply="/api/ids/service/status", reversible=True),
    # The DHCP option that hands the firewall out as the time server. The stock DHCP server only; the form is read
    # first and any field it lacks is refused before anything is sent.
    Cap("dhcp_time_option", "Give out the firewall as the time server (DHCP option)", "dnsmasq_options",
        "/api/dnsmasq/settings/search_option", "item",
        frozenset({"type", "option", "interface", "value", "force", "description"}), key="description",
        apply="/api/dnsmasq/service/status", free=frozenset({"value", "interface"})),
    Cap("unbound_dnsbl", "Choose the DNS block lists", "unbound", "/api/unbound/settings/get", "settings",
        frozenset({"dnsbl.enabled", "dnsbl.type", "dnsbl.whitelists"}), apply="/api/unbound/service/status", reversible=True,
        free=frozenset({"dnsbl.whitelists"})),
    # Newer firewalls (26.7) keep the block lists as a grid of entries, one row each, instead of one setting.
    Cap("dnsbl_entry", "Add a DNS block list", "unbound_dnsbl_grid", "/api/unbound/settings/search_dnsbl", "item",
        frozenset({"enabled", "type", "description", "allowlists"}), key="description", apply="/api/unbound/service/dnsbl",
        free=frozenset({"allowlists"})),
    Cap("gateway", "Add a backup internet gateway", "routing_gateways", "/api/routing/settings/search_gateway",
        "item", frozenset({"disabled", "name", "descr", "interface", "ipprotocol", "gateway", "defaultgw",
                           "monitor_disable", "monitor", "weight", "priority"}), apply="routing"),
    Cap("geo_alias", "Make the list of blocked countries", "aliases", "/api/firewall/alias/search_item", "item",
        frozenset({"enabled", "name", "type", "proto", "content", "description"}),
        apply="/api/firewall/alias/search_item", free=frozenset({"content"})),
    # A Kea DHCP network's time server (its option_data.ntp_servers): only ever set by "Finish getting to Happy", to the
    # firewall's own address on that network, and put back by Undo. Kept here so Undo knows how to put it back.
    Cap("kea_subnet", "Hand out the firewall as the time server (Kea DHCP)", "kea_subnets",
        "/api/kea/dhcpv4/search_subnet", "item", frozenset({"option_data.ntp_servers"}), key="subnet",
        apply="/api/kea/service/reconfigure", free=frozenset({"option_data.ntp_servers"})),
    Cap("fw_rule", "Add a firewall rule", "rules", "/api/firewall/filter/search_rule", "item",
        frozenset({"enabled", "sequence", "action", "interface", "direction", "ipprotocol", "protocol",
                   "source_net", "destination_net", "destination_not", "destination_port", "log", "description"}),
        key="description", apply="filter",
        free=frozenset({"source_net", "destination_net", "destination_port"})),
    # One device's own list (its hardware address), so an Always allow follows it whatever address it gets (block_allow).
    Cap("dev_alias", "Name a device for an allow", "aliases", "/api/firewall/alias/search_item", "item",
        frozenset({"enabled", "name", "type", "content", "description"}),
        apply="/api/firewall/alias/search_item", free=frozenset({"content", "description"})),
    # The quarantine list: hardware (MAC) addresses, so it follows a device whatever address it gets (quarantine.py).
    Cap("q_alias", "Hold a device in quarantine", "aliases", "/api/firewall/alias/search_item", "item",
        frozenset({"enabled", "name", "type", "content", "description"}),
        apply="/api/firewall/alias/search_item", free=frozenset({"content"})),
    # What smart devices need from the internet beyond the web (iot_cloud.py, BUILD 424): a port list, and the
    # hardware addresses of the doorbells and cameras recognised by name. Only these two names, only these kinds.
    Cap("cloud_alias", "Let smart devices reach their clouds", "aliases", "/api/firewall/alias/search_item", "item",
        frozenset({"enabled", "name", "type", "content", "description"}),
        apply="/api/firewall/alias/search_item", free=frozenset({"content"})),
    # Who may ask the firewall's DNS. Unbound answers only the networks of the ports it knows; the VPN's network is not
    # one (the phone's lookups reached the firewall's own address and were never answered), so it gets one entry.
    Cap("unbound_acl", "Let the VPN ask the firewall's DNS", "unbound_acl", "/api/unbound/settings/search_acl", "item",
        frozenset({"enabled", "name", "action", "networks", "description"}), key="name",
        apply="/api/unbound/service/status", free=frozenset({"name", "networks", "description"})),
    # A DNS redirect on an isolated network (Firewall, NAT, Destination NAT): any lookup a device there sends to an
    # outside server on port 53 is answered by the firewall instead. Only ever made by "Finish getting to Happy", named
    # PZ-NAT-DNS, in the shape proved on a production firewall (28 Oct 2026). Applying the filter reloads NAT too.
    # "pass" is the forward's own "Firewall rule" setting (26.7): Pass admits its traffic with the translation, ahead of
    # every rule, so the baseline's internet-side deny cannot bury a forward the person already had (BUILD 430).
    Cap("dnat_rule", "Send a network's DNS (or time) to the firewall", "dnat_rules", "/api/firewall/d_nat/search_rule", "item",
        frozenset({"disabled", "interface", "ipprotocol", "protocol", "destination.network", "destination.port",
                   "target", "local-port", "descr", "pass"}), key="descr", apply="filter",
        free=frozenset({"destination.network", "destination.port", "target", "local-port", "descr"})),
    # KidsNet (kids_net.py, the maintainer 14 Nov 2026): its DNS redirect goes to the family DNS service the person picked, one of
    # the servers pinned there and nothing else, on its own pass; and the list of public DNS servers it may not use.
    Cap("kids_dnat", "Send KidsNet's DNS to its family filter", "dnat_rules", "/api/firewall/d_nat/search_rule", "item",
        frozenset({"disabled", "interface", "ipprotocol", "protocol", "destination.network", "destination.port",
                   "target", "local-port", "descr", "pass"}), key="descr", apply="filter",
        free=frozenset({"destination.network", "destination.port", "target", "local-port", "descr"})),
    Cap("kids_alias", "Keep KidsNet on its DNS filter", "aliases", "/api/firewall/alias/search_item", "item",
        frozenset({"enabled", "name", "type", "content", "description"}),
        apply="/api/firewall/alias/search_item", free=frozenset({"content"})),
    # A host override in the firewall's resolver: a forwarded box's public name answered with its inside address, so the
    # name works indoors (the firewall does not loop a connection back to its own internet address). BUILD 430.
    Cap("unbound_host", "Name a forwarded box inside the house", "unbound_hosts", "/api/unbound/settings/search_host_override",
        "item", frozenset({"enabled", "hostname", "domain", "rr", "server", "description"}), key="description",
        apply="/api/unbound/service/status", free=frozenset({"hostname", "domain", "server", "description"})),
    # DNS over TLS for the firewall's own lookups. On 26.7 these are Unbound's forwards with type dot, reached through
    # the *_dot calls: the controller's __call turns search_dot into searchForwardAction with its type set to "dot"
    # (read from a production firewall's source, 29 Oct 2026). A *_forward call is always type "forward", whatever
    # is sent, so the add forces "forward" there.
    Cap("unbound_dot", "Encrypt the firewall's own lookups (DNS over TLS)", "unbound_dot",
        "/api/unbound/settings/search_dot", "item",
        frozenset({"enabled", "type", "domain", "server", "port", "verify"}), key="server",
        apply="/api/unbound/service/status", free=frozenset({"domain", "server", "port", "verify"})),
)}


def probe_ready(report: Mapping | None, cap: Cap) -> tuple[bool, str]:
    """On only when the probe saw the firewall answer this feature's read page."""
    if not isinstance(report, Mapping) or not report.get("results"):
        return False, "Check what this firewall supports first (it only reads)."
    for r in report["results"]:
        if r.get("id") == cap.probe:
            if r.get("kind") == "answered":
                return True, ""
            who = str(report.get("account") or "this account")
            why = {"missing": "this firewall version does not have that page",
                   "denied": f"{who} is not allowed to read that page (the firewall answered {r.get('status') or 'no'})",
                   }.get(r.get("kind"), "the firewall did not answer for that page")
            tail = ""
            if r.get("kind") == "denied" and str(r.get("status")) == "401" and "installer" in who:
                tail = (" The installer account closes itself after a day, so its key has probably stopped working. "
                        "Make it again on the setup page.")
            return False, "Not available: " + why + "." + tail
    return False, "The check did not look at that page."


def readiness(report: Mapping | None) -> dict[str, dict]:
    out = {}
    for cid, cap in CAPS.items():
        ok, why = probe_ready(report, cap)
        out[cid] = {"title": cap.title, "ready": ok, "why": why}
    return out


def _derive(read_path: str, verb: str) -> str:
    """get_server / add_server / set_server / del_server from search_server (same ending)."""
    head, _, tail = read_path.rpartition("/")
    for word in ("search", "get"):
        if tail.startswith(word):
            return f"{head}/{verb}{tail[len(word):]}"
    raise WriteError("This feature has no read page to build from.")


def _clean_text(name: str, value: Any) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (list, tuple)):
        value = ",".join(str(v) for v in value)
    if isinstance(value, int):
        value = str(value)
    if name == "content" and isinstance(value, str) and "\n" in value:
        # A country list is one code per line; the lines may not hold anything else.
        if len(value) > 1500 or any(_CONTROL.search(line) for line in value.split("\n")):
            raise WriteError("content must be a short list, one entry per line.")
        return value
    if not isinstance(value, str) or len(value) > MAX_TEXT or _CONTROL.search(value):
        raise WriteError(f"{name} must be text of at most {MAX_TEXT} characters.")
    return value


# --- per-feature sanity checks, applied before the firewall's own
_NAME = re.compile(r"^[a-z][a-z0-9_.-]{0,31}$")
_B32 = re.compile(r"^[A-Z2-7]{16,64}$")
_KEY44 = re.compile(r"^[A-Za-z0-9+/]{43}=$")
_HOST = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}$")


def _check_values(cap: Cap, v: dict[str, str]) -> None:
    if cap.id == "user":
        if not _NAME.match(v.get("name", "")):
            raise WriteError("A user name is lower-case letters, digits, dot, dash or underscore, "
                             "starting with a letter.")
        if v["name"] == "root" or v["name"].startswith("pazuzu-"):
            raise WriteError("That name is kept for the firewall itself and for Pazuzu's own accounts.")
        if "password" in v and len(v["password"]) < 12:
            raise WriteError("The password must be at least 12 characters.")
        if "otp_seed" in v and not _B32.match(v["otp_seed"]):
            raise WriteError("The one-time code seed is not in the usual letters-and-digits form.")
    elif cap.id in ("wg_server", "wg_client"):
        for k in ("pubkey", "privkey", "psk"):
            if k in v and not _KEY44.match(v[k]):
                raise WriteError(f"{k} is not a WireGuard key.")
        if "tunneladdress" in v:
            for part in v["tunneladdress"].split(","):
                try:
                    net = ipaddress.ip_interface(part.strip()).network
                except ValueError:
                    raise WriteError("The tunnel address must look like 10.8.0.1/24.")
                if not net.is_private:
                    raise WriteError("The tunnel address must be a private one.")
        for k in ("port", "serverport"):
            if k in v and not (v[k].isdigit() and 1024 <= int(v[k]) <= 65535):
                raise WriteError("A port is a number from 1024 to 65535.")
    elif cap.id == "gateway":
        if "priority" in v and not (v["priority"].isdigit() and 1 <= int(v["priority"]) <= 255):
            raise WriteError("A gateway priority is a number from 1 to 255.")
        if "gateway" in v and v["gateway"] not in ("", "dynamic"):
            try:
                ipaddress.ip_address(v["gateway"])
            except ValueError:
                raise WriteError("The gateway must be an address, or dynamic.")
    elif cap.id == "geo_alias":
        if not re.match(r"^PZ_[A-Za-z0-9_]{1,28}$", v.get("name", "")):
            raise WriteError("The country list must be named PZ_ and then letters, digits or underscores.")
        if v.get("type") != "geoip":
            raise WriteError("The country list must be a GeoIP list.")
        codes = [c for c in re.split(r"[,\n]", v.get("content", "")) if c]
        if not codes or len(codes) > 250 or any(not re.match(r"^[A-Z]{2}$", c) for c in codes):
            raise WriteError("The country list must be two-letter country codes.")
    elif cap.id == "fw_rule":
        if v.get("action") not in ("pass", "block"):
            raise WriteError("A rule here is either pass or block.")
        if not v.get("description", "").startswith("Pazuzu"):
            raise WriteError("Pazuzu's rules must say they are Pazuzu's.")
        if "sequence" in v and not v["sequence"].isdigit():
            raise WriteError("A rule's order is a number.")
        if "destination_port" in v and v["destination_port"] != "IoT_cloud_ports" and not (
                v["destination_port"].isdigit() and 1 <= int(v["destination_port"]) <= 65535):
            raise WriteError("A port is a number from 1 to 65535.")
    elif cap.id in ("ids_general", "unbound_dnsbl"):
        for k, val in v.items():
            if k.endswith(("enabled", "ips")) and val not in ("0", "1"):
                raise WriteError("On or off.")
    elif cap.id == "dhcp_time_option":
        if not v.get("description", "").startswith("Pazuzu"):
            raise WriteError("Pazuzu's entries must say they are Pazuzu's.")
    elif cap.id == "dnsbl_entry":
        if v.get("enabled", "1") not in ("0", "1"):
            raise WriteError("On or off.")
        if not v.get("type"):
            raise WriteError("Pick which block list this entry uses.")
        if not v.get("description", "").startswith("Pazuzu"):
            raise WriteError("Pazuzu's entries must say they are Pazuzu's.")
    elif cap.id == "unbound_acl":
        if v.get("action") != "allow" or not v.get("name", "").startswith("Pazuzu"):
            raise WriteError("Pazuzu only adds its own allow entry here.")
        try:
            nets = [ipaddress.ip_network(x.strip(), strict=True) for x in v.get("networks", "").split(",") if x.strip()]
        except ValueError:
            raise WriteError("The entry names networks, like 192.168.222.0/24.")
        if not nets or any(not n.is_private or n.prefixlen < 16 for n in nets):
            raise WriteError("Only a private network of your own (a VPN's) is let in here.")
    elif cap.id == "dev_alias":
        if not re.match(r"^PZ_dev_[0-9a-f]{12}$", v.get("name", "")) or v.get("type", "mac") != "mac":
            raise WriteError("A device's list is PZ_dev_ and its hardware address, a list of that one address.")
        if v.get("content", "") != ":".join(v["name"][7:][i:i + 2] for i in range(0, 12, 2)):
            raise WriteError("A device's list holds only that device's hardware address.")
        if not v.get("description", "").startswith("Pazuzu"):
            raise WriteError("Pazuzu's entries must say they are Pazuzu's.")
    elif cap.id == "cloud_alias":
        kind = {"IoT_cloud_ports": "port", "IoT_cameras": "mac"}.get(v.get("name", ""))
        if kind is None or v.get("type", kind) != kind:
            raise WriteError("Only IoT_cloud_ports (ports) and IoT_cameras (hardware addresses) are made here.")
        for x in [y for y in v.get("content", "").split("\n") if y]:
            ok = (x.isdigit() and 1 <= int(x) <= 65535) if kind == "port" else bool(re.match(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", x))
            if not ok:
                raise WriteError("A port list holds port numbers; a camera list holds full hardware (MAC) addresses only.")
        if "description" in v and not v["description"].startswith("Pazuzu"):
            raise WriteError("Pazuzu's entries must say they are Pazuzu's.")
    elif cap.id == "q_alias":
        if v.get("name") != "PZ_quarantine" or v.get("type", "mac") != "mac":
            raise WriteError("The quarantine list is PZ_quarantine, a list of hardware (MAC) addresses.")
        for m in [x for x in v.get("content", "").split("\n") if x]:
            if not re.match(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", m):
                raise WriteError("The quarantine list holds hardware (MAC) addresses only.")
        if "description" in v and not v["description"].startswith("Pazuzu"):
            raise WriteError("Pazuzu's entries must say they are Pazuzu's.")
    elif cap.id == "kids_dnat":
        from pazuzu_core import kids_net
        pid = kids_net.SERVERS.get(v.get("target", ""))
        if pid is None or v.get("descr") != kids_net.NAT_PREFIX + kids_net.PROVIDERS[pid]["name"]:
            raise WriteError("KidsNet's DNS goes only to one of the family DNS services offered, named for it.")
        if v.get("destination.port") != "53" or v.get("local-port") != "53" or v.get("destination.network") != "any":
            raise WriteError("KidsNet's redirect catches DNS (port 53) to any server, nothing else.")
        if v.get("pass") != "pass":
            raise WriteError("KidsNet's redirect carries its own pass.")
    elif cap.id == "kids_alias":
        from pazuzu_core import kids_net
        kind, allowed = {kids_net.BYPASS_ALIAS: ("host", kids_net.BYPASS),
                         kids_net.HOME_ALIAS: ("network", kids_net.PRIVATE_NETWORKS)}.get(v.get("name", ""), (None, ()))
        if kind is None or v.get("type", kind) != kind:
            raise WriteError("Only KidsNet's own two lists are made here.")
        if any(x not in allowed for x in v.get("content", "").split("\n") if x):
            raise WriteError("KidsNet's lists hold only the addresses pinned for them.")
        if "description" in v and not v["description"].startswith("Pazuzu"):
            raise WriteError("Pazuzu's entries must say they are Pazuzu's.")
    elif cap.id == "dnat_rule":
        ntp = v.get("descr", "").startswith("PZ-NAT-NTP ")       # a time redirect (BUILD 424): UDP 123 only
        if not ntp and not v.get("descr", "").startswith("PZ-NAT-DNS "):
            raise WriteError("Pazuzu's redirects must say they are Pazuzu's (PZ-NAT-DNS or PZ-NAT-NTP).")
        if ntp and (v.get("destination.port") != "123" or v.get("local-port") != "123" or v.get("protocol") != "udp"):
            raise WriteError("A time redirect is UDP port 123 in and port 123 on the firewall, nothing else.")
        if not ntp and (v.get("destination.port") != "53" or v.get("local-port") != "53"):
            raise WriteError("A DNS redirect is port 53 in and port 53 on the firewall, nothing else.")
        if v.get("destination.network") != "any":
            raise WriteError("A DNS redirect catches lookups to any outside server.")
        try:
            target = ipaddress.ip_address(v.get("target", ""))
        except ValueError:
            raise WriteError("A DNS redirect goes to the firewall's own address on that network.")
        if target.version != 4 or not target.is_private or target.is_loopback:
            raise WriteError("A DNS redirect goes to the firewall's own private address on that network, "
                             "never 127.0.0.1 (seen failing on a real firewall).")
    elif cap.id == "unbound_dot":
        if v.get("type") != "dot":
            raise WriteError("Only DNS over TLS entries are made here.")
        if v.get("enabled", "1") not in ("0", "1"):
            raise WriteError("On or off.")
        if v.get("port", "853") != "853":
            raise WriteError("DNS over TLS is port 853.")
        if v.get("domain", ""):
            raise WriteError("Pazuzu's DNS over TLS entry covers every name, so it names no domain.")
        try:
            server = ipaddress.ip_address(v.get("server", ""))
        except ValueError:
            raise WriteError("The server must be an address.")
        if not server.is_global:
            raise WriteError("The server must be a public resolver.")
        if not _HOST.match(v.get("verify", "")):
            raise WriteError("Give the name the resolver's certificate is checked against.")
    elif cap.id in ("wg_general", "ddns_general"):
        if "general.enabled" in v or cap.id == "wg_general":
            if v.get("general.enabled" if cap.id == "ddns_general" else "enabled") not in ("0", "1"):
                raise WriteError("Enabled is on or off.")
        if cap.id == "ddns_general" and v.get("general.backend", "ddclient") not in ("ddclient", "opnsense"):
            raise WriteError("The name service runs on ddclient or the firewall's own (native) updater.")
    elif cap.id == "ddns_account":
        for name in [h for h in v.get("hostnames", "").split(",") if h]:
            # "@.example.com" is the domain itself (its zone root): the form takes it, and ddclient's GoDaddy updater
            # makes "@" of it. BUILD 463.
            if not _HOST.match(name[2:] if name.startswith("@.") else name):
                raise WriteError("A name looks like home.example.net: letters, digits, dots and dashes.")
        if not v.get("hostnames"):
            raise WriteError("Give the name that will point at your home.")
        if not v.get("password"):
            raise WriteError("The name service needs the password or token you made with it.")
        if not v.get("description", "").startswith("Pazuzu"):
            raise WriteError("Pazuzu's entries must say they are Pazuzu's.")


_ON = ("1", "True", "true")


def _option_items(node: Any) -> list[tuple[str, dict]] | None:
    """A pick-list as (key, option) pairs in the firewall's order, else None. The firewall sends one as
    {"key": {"value": "Label", "selected": 0}}. When its keys are 0, 1, 2 ... in order (the port's VLAN hardware
    filter is one) PHP writes the very same thing as a plain list, [{"value": "Label", "selected": 0}, ...], and the
    key is the place in the list."""
    if isinstance(node, dict) and node and all(isinstance(x, dict) and "value" in x for x in node.values()):
        return [(str(k), x) for k, x in node.items()]
    if isinstance(node, list) and node and all(isinstance(x, dict) and "value" in x and "selected" in x for x in node):
        return [(str(i), x) for i, x in enumerate(node)]
    return None


def _options(node: Any) -> list[str] | None:
    """The keys of a pick-list, else None."""
    items = _option_items(node)
    return None if items is None else [k for k, _x in items]


def _option_labels(node: Any) -> dict[str, str] | None:
    """Like _options, but keeps each choice's shown name: {key: label}."""
    items = _option_items(node)
    return None if items is None else {k: str(x.get("value")) for k, x in items}


def _selected_keys(node: Any) -> list[str]:
    """The keys a pick-list has chosen (none for anything that is not a pick-list)."""
    return [k for k, x in (_option_items(node) or []) if str(x.get("selected")) in _ON]


_MISSING = object()


def _dig(form: Any, path: str) -> Any:
    """A value inside the firewall's form by dotted path (a name with no dot is just a key)."""
    node = form
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return _MISSING
        node = node[part]
    return node


def _nest(flat: Mapping[str, str]) -> dict:
    out: dict = {}
    for path, value in flat.items():
        node = out
        parts = path.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value
    return out


def _value_of(node: Any) -> str:
    """What the form holds, as the text the firewall takes back: a pick-list gives its selected keys."""
    if _option_items(node) is not None:
        return ",".join(_selected_keys(node))
    return "" if node is None else str(node)


@dataclass
class Plan:
    cap: str
    paths: dict[str, str]
    payload: dict[str, Any]                 # the real body, secrets included; never shown
    shown: dict[str, str]                   # the same fields with secrets masked
    lines: list[str]
    digest: str
    wrapper: str
    flat: dict | None = None                # the same values by dotted path, when any name has a dot


@dataclass
class Outcome:
    cap: str
    uuid: str | None = None
    saved: bool = False
    applied: bool | None = None
    verified: bool = False
    lines: list[str] = field(default_factory=list)
    undo_path: str | None = None
    undo_body: dict | None = None     # None: the undo is a delete; a body: the undo is a set that puts it back



def _error_words(response) -> str:
    """What a server error says, in a few plain words (never what was sent): its own message if it gave one, else the
    first of its text with tags and extra spaces taken out. Empty when there is nothing readable."""
    try:
        body = response.json()
        if isinstance(body, dict):
            for key in ("errorMessage", "message", "error", "errors", "status"):
                if body.get(key):
                    text = str(body[key])
                    break
            else:
                text = ""
        else:
            text = ""
    except Exception:  # noqa: BLE001
        text = ""
    if not text:
        try:
            text = re.sub(r"<[^>]+>", " ", str(getattr(response, "text", "") or ""))
        except Exception:  # noqa: BLE001
            text = ""
    text = " ".join(text.split())
    return text[:200]

class Engine:
    def __init__(self, session, base: str, report: Mapping | None, *, timeout: float = TIMEOUT):
        self.s, self.base, self.report, self.timeout = session, base.rstrip("/"), report, timeout
        self._previous: dict[str, dict] = {}          # BUILD 455: a change's old values, by plan digest, for its undo

    def _req(self, method: str, path: str, timeout: float | None = None, **kw) -> Any:
        try:
            r = getattr(self.s, method)(self.base + path, timeout=timeout or self.timeout, headers=HEADERS,
                                        allow_redirects=False, **kw)
        except Exception as exc:
            raise WriteError(f"Could not reach the firewall ({type(exc).__name__}).")
        if r.status_code in (401, 403):
            raise WriteError("The firewall did not allow that account to do this.")
        if r.status_code == 404:
            raise WriteError("This firewall version does not have that page. Nothing was changed.")
        if r.status_code != 200:
            said = _error_words(r) if r.status_code >= 500 else ""
            raise WriteError(f"The firewall answered {r.status_code}." + (f" It said: {said}" if said else ""))
        try:
            return r.json()
        except ValueError:
            raise WriteError("The firewall's answer was not understood.")

    def ready(self, cap_id: str) -> tuple[bool, str]:
        cap = CAPS.get(cap_id)
        return probe_ready(self.report, cap) if cap else (False, "Unknown feature.")

    def _template(self, cap: Cap) -> tuple[str, dict]:
        body = self._req("get", _derive(cap.read, "get") + (f"?{cap.query}" if cap.query else ""))
        if not isinstance(body, dict) or len(body) != 1:
            raise WriteError("The firewall's empty form was not in the usual shape. Nothing was changed.")
        (wrapper, form), = body.items()
        if not isinstance(form, dict):
            raise WriteError("The firewall's empty form was not in the usual shape. Nothing was changed.")
        return str(wrapper), form

    def choices(self, cap_id: str, name: str) -> dict[str, str]:
        """The firewall's own pick-list for one field of a feature's empty form, as {key: label}
        (empty when that field is not a pick-list). Reads only."""
        cap = CAPS.get(cap_id)
        ok, why = self.ready(cap_id)
        if cap is None or not ok:
            raise WriteError(why or "Unknown feature.")
        _wrapper, form = self._template(cap)
        return _option_labels(form.get(name)) or {}

    def _rows(self, cap: Cap, phrase: str = "") -> list[dict]:
        body = self._req("get", _derive(cap.read, "search") + (f"?{cap.query}&" if cap.query else "?") + "rowCount=-1&searchPhrase="
                         + quote(phrase, safe=""))
        rows = body.get("rows") if isinstance(body, dict) else None
        return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []

    def leftovers(self, cap_id: str, prefix: str) -> list[str]:
        """The names of rows of this kind that start with `prefix` (reads only)."""
        cap = CAPS.get(cap_id)
        if cap is None or cap.kind != "item":
            return []
        return [str(r.get(cap.key)) for r in self._rows(cap, prefix) if str(r.get(cap.key, "")).startswith(prefix)]

    def exists(self, cap_id: str, value: str) -> bool:
        """True when a row of this kind with this name is already on the firewall (reads only)."""
        cap = CAPS.get(cap_id)
        if cap is None or cap.kind != "item":
            return False
        return any(str(r.get(cap.key)) == str(value) for r in self._rows(cap, str(value)))

    # -- build a plan without changing anything
    def build(self, cap_id: str, values: Mapping[str, Any]) -> Plan:
        cap = CAPS.get(cap_id)
        if cap is None:
            raise WriteError("Unknown feature.")
        ok, why = self.ready(cap_id)
        if not ok:
            raise WriteError(why)
        if not isinstance(values, Mapping) or not values:
            raise WriteError("Nothing was given to add.")
        extra = sorted(set(values) - cap.fields)
        if extra:
            raise WriteError("Not something this feature may set: " + ", ".join(map(str, extra)))
        clean = {k: _clean_text(k, v) for k, v in values.items()}
        _check_values(cap, clean)
        wrapper, form = self._template(cap)
        for k, v in clean.items():
            node = _dig(form, k)
            if node is _MISSING:
                raise WriteError(f"This firewall's own form has no field called {k}. Nothing was changed.")
            labels = None if k in cap.free else _option_labels(node)
            if labels is not None:
                # The firewall may name a choice by an id and show its name as the label: accept either.
                fixed = []
                for part in (p for p in v.split(",") if p != ""):
                    if part in labels:
                        fixed.append(part)
                        continue
                    hit = [key for key, label in labels.items() if label.lower() == part.lower()]
                    if len(hit) != 1:
                        offered = ", ".join(sorted({lab for lab in labels.values() if lab})[:12])
                        raise WriteError(f"{part!r} is not one of the firewall's choices for {k}"
                                         + (f" (it offers: {offered})" if offered else "") + ". Nothing was changed.")
                    fixed.append(hit[0])
                clean[k] = ",".join(fixed)
        if cap.kind == "item" and cap.key in clean:
            if any(str(r.get(cap.key)) == clean[cap.key] for r in self._rows(cap, clean[cap.key])):
                raise WriteError(f"There is already one called {clean[cap.key]}. Nothing was changed.")
        paths = {"send": _derive(cap.read, "add" if cap.kind == "item" else "set") + (f"?{cap.query}" if cap.query else "")}
        if cap.kind == "item":
            paths["del"] = _derive(cap.read, "del")
        shown = {k: ("(set, not shown)" if k in cap.secret else v) for k, v in clean.items()}
        lines = [cap.title] + [f"{k}: {shown[k]}" for k in sorted(shown)]
        if cap.id in ("dnsbl_entry", "unbound_dnsbl"):
            lines.append(DNSBL_NOTE)
        dotted = any("." in k for k in clean)
        return Plan(cap_id, paths, {wrapper: _nest(clean) if dotted else clean}, shown, lines,
                    plan_digest("write-" + cap_id, {"paths": paths, "fields": shown}), wrapper,
                    flat=dict(clean) if dotted else None)

    # -- BUILD 455: change some fields of one row that is already there (Pazuzu's own rows only)
    def change(self, cap_id: str, uuid: str, values: Mapping[str, Any], title: str = "", anyone: bool = False) -> Plan:
        """A plan that sets `values` on the existing row `uuid`; the undo puts the old values back. Only rows whose
        name (the cap's key) says they are Pazuzu's are changed, except with `anyone` (BUILD 461: names added to a
        block list's allow list, on the person's own entry too, since an allow list only covers its own entry)."""
        cap = CAPS.get(cap_id)
        if cap is None or cap.kind != "item":
            raise WriteError("Unknown feature.")
        ok, why = self.ready(cap_id)
        if not ok:
            raise WriteError(why)
        if not _UUID.match(str(uuid or "")):
            raise WriteError("Which row was not clear. Nothing was changed.")
        extra = sorted(set(values) - cap.fields)
        if extra or not values:
            raise WriteError("Not something this feature may set: " + ", ".join(map(str, extra)))
        get_path = f"{_derive(cap.read, 'get')}/{uuid}"
        body = self._req("get", get_path)
        if not isinstance(body, dict) or len(body) != 1:
            raise WriteError("The firewall's answer for that row was not in the usual shape. Nothing was changed.")
        (wrapper, form), = body.items()
        if not isinstance(form, dict) or (not anyone and not _value_of(form.get(cap.key)).startswith("Pazuzu")):
            raise WriteError("Pazuzu only changes its own entries. Nothing was changed.")
        if anyone and set(values) - {"allowlists"}:
            raise WriteError("On an entry of yours, Pazuzu only adds to its allow list. Nothing was changed.")
        clean = {k: _clean_text(k, v) for k, v in values.items()}
        for k, v in clean.items():
            node = form.get(k, _MISSING)
            if node is _MISSING:
                raise WriteError(f"This firewall's own form has no field called {k}. Nothing was changed.")
            labels = None if k in cap.free else _option_labels(node)
            if labels is not None and v and v not in labels:
                hit = [key for key, label in labels.items() if label.lower() == v.lower()]
                if len(hit) != 1:
                    raise WriteError(f"{v!r} is not one of the firewall's choices for {k}. Nothing was changed.")
                clean[k] = hit[0]
        previous = {k: _value_of(form.get(k)) for k in clean}
        paths = {"send": f"{_derive(cap.read, 'set')}/{uuid}", "update": uuid, "get": get_path}
        shown = {k: ("(set, not shown)" if k in cap.secret else v) for k, v in clean.items()}
        name = _value_of(form.get(cap.key))
        lines = [(title or cap.title) + ": " + name] + [f"{k}: {previous[k] or '(empty)'} to {shown[k] or '(empty)'}"
                                                       for k in sorted(shown)]
        if cap_id == "dnsbl_entry":
            # BUILD 463: an entry naming a list this firewall no longer offers cannot be saved at all (such as "atf"), so
            # such a list is taken out in the same save; it blocks nothing any more.
            lines.append("A list type this firewall no longer offers is taken out of the entry, if it has one "
                         "(it blocks nothing)")
            lines.append(DNSBL_NOTE)
        plan = Plan(cap_id, paths, {wrapper: clean}, shown, lines,
                    plan_digest("change-" + cap_id, {"uuid": uuid, "fields": shown}), wrapper)
        self._previous[plan.digest] = {wrapper: previous}
        return plan

    def _apply_change(self, cap: Cap, plan: Plan) -> Outcome:
        out = Outcome(plan.cap, uuid=plan.paths["update"])
        res = self._req("post", plan.paths["send"], json=plan.payload)
        stale = self._stale_types(cap, res)
        if stale:
            # The entry names a list the firewall no longer offers: send it again without it (the plan said so). The
            # undo puts the allow list back, not the dead list: the firewall would refuse that again.
            body = self._req("get", plan.paths["get"])
            form = next(iter(body.values()), {}) if isinstance(body, dict) and len(body) == 1 else {}
            keep = [k for k in _value_of((form or {}).get("type")).split(",") if k and k not in stale]
            payload = {plan.wrapper: dict(plan.payload[plan.wrapper], type=",".join(keep))}
            res = self._req("post", plan.paths["send"], json=payload)
            if isinstance(res, dict) and str(res.get("result", "")) == "saved":
                out.lines.append("Took out list types this firewall no longer offers: " + ", ".join(stale) + ".")
        if not (isinstance(res, dict) and str(res.get("result", "")) == "saved"):
            bad = res.get("validations") if isinstance(res, dict) else None
            if isinstance(bad, dict) and bad:
                said = "; ".join(f"{str(k).split('.')[-1]}: {v}" for k, v in list(bad.items())[:4])
                raise WriteError("The firewall did not accept it (" + said + "). Nothing was changed.")
            raise WriteError("The firewall did not save it. Nothing was changed.")
        out.saved = True
        out.undo_path, out.undo_body = plan.paths["send"], self._previous.get(plan.digest)
        out.lines.append("Saved on the firewall.")
        try:
            now = self._req("get", plan.paths["get"])
            form = next(iter(now.values()), {}) if isinstance(now, dict) and len(now) == 1 else {}
            sent = plan.payload[plan.wrapper]
            out.verified = all(_value_of(form.get(k)) == v for k, v in sent.items() if k not in cap.secret)
        except WriteError:
            out.verified = False
        out.lines.append("Read it back and it matches." if out.verified
                         else "Saved, but it could not be read back to check. Look at the firewall's own page.")
        if cap.apply:
            out.applied = self._reconfigure(cap)
            out.lines.append("Applied." if out.applied else
                             "Saved but not applied yet. Press Apply on the firewall's own page.")
        return out

    @staticmethod
    def _stale_types(cap: Cap, res) -> list[str]:
        """The list types a block-list entry names that the firewall says are not in its list (BUILD 463)."""
        if cap.id != "dnsbl_entry" or not isinstance(res, dict):
            return []
        bad = res.get("validations")
        if not isinstance(bad, dict):
            return []
        out = []
        for k, v in bad.items():
            if str(k).split(".")[-1] == "type":
                out += STALE_TYPE.findall(str(v))
        return sorted(set(out))

    # -- send it, check it, keep the undo
    def apply(self, plan: Plan, gate: Callable[[str, Sequence[str]], bool]) -> Outcome:
        cap = CAPS[plan.cap]
        if not gate(plan.digest, plan.lines):
            raise WriteError("Not approved with a passkey. Nothing was changed.")
        if "update" in plan.paths:
            return self._apply_change(cap, plan)
        out = Outcome(plan.cap)
        previous = None
        if cap.kind == "settings" and cap.reversible:
            wrapper, form = self._template(cap)
            previous = {}
            for k in (plan.flat or plan.payload[plan.wrapper]):
                node = _dig(form, k)
                if node is _MISSING:
                    raise WriteError(f"This firewall's own form has no field called {k}. Nothing was changed.")
                previous[k] = _value_of(node)
        res = self._req("post", plan.paths["send"], json=plan.payload)
        if not (isinstance(res, dict) and str(res.get("result", "")) == "saved"):
            bad = res.get("validations") if isinstance(res, dict) else None
            if isinstance(bad, dict) and bad:
                said = "; ".join(f"{str(k).split('.')[-1]}: {v}" for k, v in list(bad.items())[:4])
                raise WriteError("The firewall did not accept it (" + said + "). Nothing was changed.")
            raise WriteError("The firewall did not save it. Nothing was changed.")
        out.saved = True
        if cap.kind == "item":
            uuid = str(res.get("uuid", ""))
            if not _UUID.match(uuid):
                raise WriteError("The firewall saved something but did not say which row; "
                                 "look at its own page.")
            out.uuid, out.undo_path = uuid, f"{plan.paths['del']}/{uuid}"
        if previous is not None:
            out.undo_path = plan.paths["send"]
            out.undo_body = {plan.wrapper: _nest(previous)}
        out.lines.append("Saved on the firewall.")
        try:
            out.verified = self._verify(cap, plan, out)
        except WriteError:
            out.verified = False
        out.lines.append("Read it back and it matches." if out.verified
                         else "Saved, but it could not be read back to check. Look at the firewall's own page.")
        if cap.apply:
            out.applied = self._reconfigure(cap)
            out.lines.append("Applied." if out.applied else
                             "Saved but not applied yet. Press Apply on the firewall's own page.")
        return out

    def apply_many(self, plans: Sequence[Plan], gate: Callable[[str, Sequence[str]], bool]) -> list[Outcome]:
        """Several plans that belong together, approved with ONE touch. If one is refused by the
        firewall, the ones already saved are undone, so a half-made thing is not left behind."""
        if not plans:
            raise WriteError("Nothing was given to add.")
        digest = plan_digest("write-many", [p.digest for p in plans])
        lines = [ln for p in plans for ln in p.lines]
        if not gate(digest, lines):
            raise WriteError("Not approved with a passkey. Nothing was changed.")
        done: list[Outcome] = []
        try:
            for p in plans:
                done.append(self.apply(p, lambda d, l: True))
        except WriteError as exc:
            undone = 0
            for o in reversed(done):
                try:
                    undone += 1 if self.undo(o) else 0
                except WriteError:
                    pass
            tail = (f" The {undone} thing(s) already saved were removed again." if undone
                    else (" Something was saved before it stopped; look at the firewall's own page." if done else ""))
            raise WriteError(str(exc) + tail)
        return done

    # -- turn root's sign-in off, only once another admin is there to take over
    def disable_root(self, keep: str, gate: Callable[[str, Sequence[str]], bool]) -> Outcome:
        """Sets root's own "disabled" box, nothing else. Refused unless `keep` is a different, enabled
        user on the firewall, so this can never leave the firewall with no one to sign in. The undo
        (switching root back on) never waits for a person."""
        cap = CAPS["user"]
        ok, why = self.ready("user")
        if not ok:
            raise WriteError(why)
        if not isinstance(keep, str) or not _NAME.match(keep) or keep == "root":
            raise WriteError("Name the other admin user who stays on.")
        rows = self._rows(cap)
        mine = [r for r in rows if str(r.get("name")) == keep]
        if len(mine) != 1 or str(mine[0].get("disabled", "0")) in ("1", "true"):
            raise WriteError(f"There is no switched-on user called {keep} on the firewall, so root stays on. "
                             "Nothing was changed.")
        roots = [r for r in rows if str(r.get("name")) == "root"]
        if len(roots) != 1 or not _UUID.match(str(roots[0].get("uuid", ""))):
            raise WriteError("The firewall did not show a root user to change. Nothing was changed.")
        uuid = str(roots[0]["uuid"])
        body = self._req("get", f"{_derive(cap.read, 'get')}/{uuid}")
        if not isinstance(body, dict) or len(body) != 1:
            raise WriteError("The firewall's answer for root was not in the usual shape. Nothing was changed.")
        (wrapper, form), = body.items()
        if not isinstance(form, dict) or "disabled" not in form:
            raise WriteError("This firewall's own form for a user has no Disabled box. Nothing was changed.")
        if str(form.get("disabled")) == "1":
            raise WriteError("Root is already switched off.")
        lines = ["Switch root's sign-in off", "root: disabled",
                 "After this, root cannot sign in to the web page or SSH.", f"Stays on: {keep}"]
        if not gate(plan_digest("write-root-off", {"uuid": uuid, "keep": keep}), lines):
            raise WriteError("Not approved with a passkey. Nothing was changed.")
        out = Outcome("user", uuid)
        send = f"{_derive(cap.read, 'set')}/{uuid}"
        res = self._req("post", send, json={wrapper: {"disabled": "1"}})
        if not (isinstance(res, dict) and str(res.get("result", "")) == "saved"):
            raise WriteError("The firewall did not save it. Nothing was changed.")
        out.saved, out.undo_path, out.undo_body = True, send, {wrapper: {"disabled": "0"}}
        out.lines.append("Saved on the firewall.")
        try:
            now = [r for r in self._rows(cap) if str(r.get("uuid")) == uuid]
            out.verified = len(now) == 1 and str(now[0].get("disabled")) == "1"
        except WriteError:
            out.verified = False
        out.lines.append("Read it back: root is switched off." if out.verified
                         else "Saved, but it could not be read back to check. Look at the firewall's own page.")
        return out

    # -- give root a new password (the factory one is the first thing anyone tries)
    def set_root_password(self, new: str, gate: Callable[[str, Sequence[str]], bool]) -> Outcome:
        """Sets root's password, nothing else, with the same call that changes any user (set on the user's row).
        Refused when the firewall's own form for a user has no Password field. The password is never shown, logged or
        approved by value. There is no undo: the old password is not something this app can read."""
        cap = CAPS["user"]
        ok, why = self.ready("user")
        if not ok:
            raise WriteError(why)
        new = _clean_text("password", new)
        if len(new) < 12:
            raise WriteError("The password must be at least 12 characters.")
        rows = self._rows(cap)
        roots = [r for r in rows if str(r.get("name")) == "root"]
        if len(roots) != 1 or not _UUID.match(str(roots[0].get("uuid", ""))):
            raise WriteError("The firewall did not show a root user to change. Nothing was changed.")
        uuid = str(roots[0]["uuid"])
        body = self._req("get", f"{_derive(cap.read, 'get')}/{uuid}")
        if not isinstance(body, dict) or len(body) != 1:
            raise WriteError("The firewall's answer for root was not in the usual shape. Nothing was changed.")
        (wrapper, form), = body.items()
        if not isinstance(form, dict) or "password" not in form:
            raise WriteError("This firewall's own form for a user has no Password field. Nothing was changed.")
        lines = ["Give root a new password", "root: password (set, not shown)",
                 "The factory password stops working for root."]
        if not gate(plan_digest("write-root-password", {"uuid": uuid}), lines):
            raise WriteError("Not approved with a passkey. Nothing was changed.")
        out = Outcome("user", uuid)
        res = self._req("post", f"{_derive(cap.read, 'set')}/{uuid}", json={wrapper: {"password": new}})
        if not (isinstance(res, dict) and str(res.get("result", "")) == "saved"):
            bad = res.get("validations") if isinstance(res, dict) else None
            if isinstance(bad, dict) and bad:
                said = "; ".join(f"{str(k).split('.')[-1]}: {v}" for k, v in list(bad.items())[:4])
                raise WriteError("The firewall did not accept it (" + said + "). Nothing was changed.")
            raise WriteError("The firewall did not save it. Nothing was changed.")
        out.saved = True
        out.lines.append("Saved on the firewall. Keep the new password safe: this app cannot read it back.")
        return out

    # -- change or remove something Pazuzu made earlier, found by its name; the same passkey gate as adding
    def _one_row(self, cap: Cap, name: str) -> dict | None:
        rows = [r for r in self._rows(cap, name) if str(r.get(cap.key)) == name]
        if len(rows) > 1:
            raise WriteError(f"There is more than one called {name} on the firewall, so Pazuzu left it alone.")
        if rows and not _UUID.match(str(rows[0].get("uuid", ""))):
            raise WriteError("The firewall did not give that row a usual id. Nothing was changed.")
        return rows[0] if rows else None

    def change_text(self, cap_id: str, name: str, field: str, new: str,
                    gate: Callable[[str, Sequence[str]], bool], say: str | None = None) -> Outcome | None:
        """Replace one text field of the row called `name` (a list of lines, for a country list). Returns None
        when the row is not there. The undo puts the old text back and never waits for a person."""
        cap = CAPS[cap_id]
        ok, why = self.ready(cap_id)
        if not ok:
            raise WriteError(why)
        if field not in cap.fields:
            raise WriteError("Not something this feature may set.")
        new = _clean_text(field, new)
        row = self._one_row(cap, name)
        if row is None:
            return None
        return self._change_uuid(cap, str(row["uuid"]), field, new, gate, f"Change {name}", say)

    def change_by_uuid(self, cap_id: str, uuid: str, field: str, new: str,
                       gate: Callable[[str, Sequence[str]], bool], label: str, say: str | None = None,
                       expect: str | None = None) -> Outcome:
        """The same as change_text, for a row found by its id (a rule of the person's own has no name to find it by).
        `expect`: the value the field must hold now, or nothing is changed (so a change meant for one kind of rule can
        never land on another)."""
        cap = CAPS[cap_id]
        ok, why = self.ready(cap_id)
        if not ok:
            raise WriteError(why)
        if field not in cap.fields:
            raise WriteError("Not something this feature may set.")
        if not _UUID.match(str(uuid or "")):
            raise WriteError("That is not a usual id. Nothing was changed.")
        return self._change_uuid(cap, str(uuid), field, _clean_text(field, new), gate, label, say, expect)

    def _change_uuid(self, cap: Cap, uuid: str, field: str, new: str, gate, label: str, say: str | None,
                     expect: str | None = None) -> Outcome:
        cap_id = cap.id
        body = self._req("get", f"{_derive(cap.read, 'get')}/{uuid}")
        if not isinstance(body, dict) or len(body) != 1:
            raise WriteError("The firewall's answer was not in the usual shape. Nothing was changed.")
        (wrapper, form), = body.items()
        node = form.get(field, _MISSING) if isinstance(form, dict) else _MISSING
        if node is _MISSING:
            raise WriteError(f"This firewall's own form has no field called {field}. Nothing was changed.")
        labels = _option_labels(node)
        before = "\n".join(_selected_keys(node)) if labels is not None else _value_of(node)
        if expect is not None and before != expect:
            raise WriteError("The firewall's rule is not as it was read a moment ago, so nothing was changed. Look again.")
        lines = [label, say or f"{field}: {new.replace(chr(10), ', ') or '(empty)'}"]
        if not gate(plan_digest("write-change-" + cap_id, {"uuid": uuid, "field": field, "new": new}), lines):
            raise WriteError("Not approved with a passkey. Nothing was changed.")
        send = f"{_derive(cap.read, 'set')}/{uuid}"
        res = self._req("post", send, json={wrapper: {field: new}})
        if not (isinstance(res, dict) and str(res.get("result", "")) == "saved"):
            bad = res.get("validations") if isinstance(res, dict) else None
            if isinstance(bad, dict) and bad:
                said = "; ".join(f"{str(k).split('.')[-1]}: {v}" for k, v in list(bad.items())[:4])
                raise WriteError("The firewall did not accept it (" + said + "). Nothing was changed.")
            raise WriteError("The firewall did not save it. Nothing was changed.")
        out = Outcome(cap_id, uuid, saved=True, undo_path=send, undo_body={wrapper: {field: before}})
        out.lines.append("Saved on the firewall.")
        try:
            again = self._req("get", f"{_derive(cap.read, 'get')}/{uuid}")
            node2 = next(iter(again.values()), {}).get(field) if isinstance(again, dict) and len(again) == 1 else None
            now = "\n".join(_selected_keys(node2)) if _option_labels(node2) is not None else _value_of(node2)
            out.verified = set(now.split("\n")) - {""} == set(new.split("\n")) - {""}
        except (WriteError, AttributeError):
            out.verified = False
        out.lines.append("Read it back and it matches." if out.verified
                         else "Saved, but it could not be read back to check. Look at the firewall's own page.")
        if cap.apply:
            out.applied = self._reconfigure(cap)
            out.lines.append("Applied." if out.applied else
                             "Saved but not applied yet. Press Apply on the firewall's own page.")
        return out

    def remove_named(self, cap_id: str, names: Sequence[str],
                     gate: Callable[[str, Sequence[str]], bool]) -> list[str]:
        """Delete the rows called `names` (the ones that exist), after one passkey approval. Returns the names
        removed. A rule that is still in use by another row is refused by the firewall and left, plainly."""
        cap = CAPS[cap_id]
        ok, why = self.ready(cap_id)
        if not ok:
            raise WriteError(why)
        found = []
        for n in names:
            row = self._one_row(cap, n)
            if row is not None:
                found.append((n, str(row["uuid"])))
        if not found:
            return []
        lines = ["Remove from the firewall"] + [n for n, _ in found]
        if not gate(plan_digest("write-remove-" + cap_id, {"uuids": [u for _, u in found]}), lines):
            raise WriteError("Not approved with a passkey. Nothing was changed.")
        gone = []
        for n, uuid in found:
            res = self._req("post", f"{_derive(cap.read, 'del')}/{uuid}", json={})
            if not (isinstance(res, dict) and str(res.get("result", "")) == "deleted"):
                said = ", ".join(gone)
                raise WriteError(f"The firewall would not remove {n}."
                                 + (f" Already removed: {said}." if said else "") + " Look at the firewall's own page.")
            gone.append(n)
        if cap.apply:
            self._reconfigure(cap)
        return gone

    def remove_uuids(self, cap_id: str, items: Sequence[tuple[str, str]],
                     gate: Callable[[str, Sequence[str]], bool]) -> list[str]:
        """Delete these rows, given as (what to call it, id), after one passkey approval: for copies, which share a name,
        so remove_named cannot tell them apart. Returns the ids removed; stops at the first the firewall refuses."""
        cap = CAPS[cap_id]
        ok, why = self.ready(cap_id)
        if not ok:
            raise WriteError(why)
        items = [(str(n), str(u)) for n, u in items if _UUID.match(str(u or ""))]
        if not items:
            return []
        lines = ["Remove from the firewall"] + [f"{n} (id {u[:8]})" for n, u in items]
        if not gate(plan_digest("write-remove-" + cap_id, {"uuids": [u for _, u in items]}), lines):
            raise WriteError("Not approved with a passkey. Nothing was changed.")
        gone: list[str] = []
        for n, uuid in items:
            res = self._req("post", f"{_derive(cap.read, 'del')}/{uuid}", json={})
            if not (isinstance(res, dict) and str(res.get("result", "")) == "deleted"):
                if gone and cap.apply:
                    self._reconfigure(cap)
                raise WriteError(f"The firewall would not remove {n} (id {uuid[:8]}). {len(gone)} removed before it. "
                                 "Look at the firewall's own page.")
            gone.append(uuid)
        if cap.apply:
            self._reconfigure(cap)
        return gone

    def _verify(self, cap: Cap, plan: Plan, out: Outcome) -> bool:
        sent = plan.flat or plan.payload[plan.wrapper]
        if cap.kind == "settings":
            now = self._req("get", _derive(cap.read, "get"))
            form = next(iter(now.values()), {}) if isinstance(now, dict) and len(now) == 1 else {}
            if not isinstance(form, dict):
                return False
            for k, v in sent.items():
                if k in cap.secret:
                    continue
                node = _dig(form, k)
                if node is _MISSING:
                    return False
                if _option_labels(node) is not None:
                    if set(p for p in _value_of(node).split(",") if p) != set(p for p in v.split(",") if p):
                        return False
                elif not isinstance(node, dict) and str(node) != v:
                    return False
            return True
        rows = [r for r in self._rows(cap, sent.get(cap.key, "")) if str(r.get("uuid")) == out.uuid]
        if len(rows) != 1:
            return False
        row = rows[0]
        loose = {"type"} if cap.id == "dnsbl_entry" else set()      # the grid shows the list's name, the form sends its key
        if cap.id == "ddns_account":                                # BUILD 455: the grid shows the port's name
            loose = {"interface", "checkip"}
        if cap.id in ("dnat_rule", "kids_dnat", "unbound_dot"):     # the grids show names for pick-list keys
            loose = set(sent) - {cap.key, "target"}
        return all(str(row.get(k)) == v for k, v in sent.items()
                   if k not in cap.secret and k not in loose and k in row and not isinstance(row[k], (dict, list)))

    GEOIP_READS = ("/api/firewall/alias/get_geo_i_p", "/api/firewall/alias/get_geo_ip")

    def geoip_source(self) -> str | None:
        """The address the firewall downloads country lists from: "" when none is set, None when it cannot be
        told (the firewall has no such page, or answered in a shape not recognised). Reads only."""
        def find(node: Any) -> str | None:
            if isinstance(node, dict):
                for k, val in node.items():
                    if str(k).lower() == "url" and not isinstance(val, (dict, list)):
                        return str(val or "").strip()
                for val in node.values():
                    got = find(val)
                    if got is not None:
                        return got
            elif isinstance(node, list):
                for val in node:
                    got = find(val)
                    if got is not None:
                        return got
            return None
        for path in self.GEOIP_READS:
            try:
                got = find(self._req("get", path))
            except WriteError:
                continue
            if got is not None:
                return got
        return None

    # -- two plain reads the country-block plan needs
    def interface_id(self, device: str | None) -> str | None:
        """The firewall's own short name (wan, opt3) for a port, read from its interface overview."""
        if not device:
            return None
        body = self._req("get", "/api/interfaces/overview/interfaces_info/true")
        rows = body.get("rows") if isinstance(body, dict) else body
        for r in rows if isinstance(rows, list) else []:
            if isinstance(r, dict) and str(r.get("device")) == device and re.match(r"^[a-z][a-z0-9_]{0,31}$", str(r.get("identifier", ""))):
                return str(r["identifier"])
        return None

    def network_of(self, address: str | None) -> str | None:
        """The network (CIDR) the firewall has an address on that contains `address`, or None."""
        import ipaddress
        try:
            want = ipaddress.ip_address(str(address))
        except ValueError:
            return None
        body = self._req("get", "/api/interfaces/overview/interfaces_info/true")
        rows = body.get("rows") if isinstance(body, dict) else body
        for r in rows if isinstance(rows, list) else []:
            if not isinstance(r, dict):
                continue
            addrs = r.get("addr4") if isinstance(r.get("addr4"), list) else [r.get("addr4")]
            for a in addrs:
                try:
                    net = ipaddress.ip_interface(str(a)).network
                except ValueError:
                    continue
                if want in net:
                    return str(net)
        return None

    def interface_for(self, address: str | None) -> str | None:
        """The firewall's own short name (lan, opt1) for the network an address belongs to, or None."""
        import ipaddress
        try:
            want = ipaddress.ip_address(str(address))
        except ValueError:
            return None
        body = self._req("get", "/api/interfaces/overview/interfaces_info/true")
        rows = body.get("rows") if isinstance(body, dict) else body
        for r in rows if isinstance(rows, list) else []:
            if not isinstance(r, dict) or not re.match(r"^[a-z][a-z0-9_]{0,31}$", str(r.get("identifier", ""))):
                continue
            addrs = r.get("addr4") if isinstance(r.get("addr4"), list) else [r.get("addr4")]
            for a in addrs:
                try:
                    if a and want in ipaddress.ip_interface(str(a)).network:
                        return str(r["identifier"])
                except ValueError:
                    continue
        return None

    def vpn_port(self) -> str | None:
        """The listening port of the VPN, or None when there is no VPN instance yet."""
        ok, _why = self.ready("wg_server")
        if not ok:
            return None
        rows = [r for r in self._rows(CAPS["wg_server"]) if str(r.get("enabled", "1")) != "0"]
        if not rows:
            return None
        ports = sorted({str(r.get("port", "")) for r in rows if str(r.get("port", "")).isdigit()})
        if not ports:
            raise WriteError("Pazuzu could not read the VPN's port, so nothing was changed.")
        return ports[0]

    def _reconfigure(self, cap: Cap) -> bool:
        path = ("/api/routing/settings/reconfigure" if cap.apply == "routing"
                else "/api/firewall/filter/apply" if cap.apply == "filter"
                else cap.apply if cap.apply.endswith("/service/dnsbl")      # the block-list page's own Apply
                else cap.apply.rpartition("/")[0] + "/reconfigure")
        slow = path.endswith("/service/dnsbl") or cap.id in ("dnsbl_entry", "unbound_dnsbl")
        try:
            res = self._req("post", path, json={}, timeout=DNSBL_APPLY_TIMEOUT if slow else None)
        except WriteError:
            return False
        ok = isinstance(res, dict) and str(res.get("status", "ok")).strip().lower() in ("ok", "done", "")
        if ok and path.endswith("/service/dnsbl"):
            # Seen on a real firewall: the lists were saved and fetched, but did not block until the page's own Apply.
            # The fetch only writes the lists; Unbound takes them in when it is reconfigured, so that is asked for too.
            try:
                again = self._req("post", path.rpartition("/")[0] + "/reconfigure", json={}, timeout=DNSBL_APPLY_TIMEOUT)
            except WriteError:
                return False
            ok = isinstance(again, dict) and str(again.get("status", "ok")).strip().lower() in ("ok", "done", "")
        return ok

    # -- undo is not gated: it only ever removes the row this run made
    def undo(self, out: Outcome) -> bool:
        cap = CAPS[out.cap]
        if not out.undo_path:
            return False
        if not (cap.kind == "settings" and cap.reversible) and (not out.uuid or not _UUID.match(out.uuid)):
            return False
        res = self._req("post", out.undo_path, json=out.undo_body if out.undo_body is not None else {})
        done = isinstance(res, dict) and str(res.get("result")) == ("saved" if out.undo_body is not None else "deleted")
        if done and cap.apply:
            self._reconfigure(cap)
        return done
