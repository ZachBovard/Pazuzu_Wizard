"""Baseline lines the plugin on the firewall reads for the manager's board, beyond the rules and the services the
firewall's own pages answer for. Each one is judged from a reading in services[...], and a missing or unclear reading is
"can't check", never a guess.

Zenarmor is part of the baseline: it must be installed and its engine running.
The country block is judged only once the person has picked countries: the firewall must hold ranges for them, or the
block matches nothing. The ranges come from a source the person sets up (a free IPinfo, MaxMind or IPLocate account).
"""
from __future__ import annotations

from typing import Any, Mapping

from pazuzu_core.posture import DRIFTED, ENFORCED, UNVERIFIED

ZENARMOR = "zenarmor"
IDS_RULESETS = "ids_rulesets"
LIST_REFRESH = "lists_refresh"
OTP = "otp"
DHCP_ZONES = "dhcp_zones"
SSH = "ssh"
CONSOLE = "console"
ROOT = "root_password"
COUNTRY = "country_block"
CERT = "certificate"
DNS_REDIRECTS = "dns_redirects"
DNS_TLS = "dns_tls"
NTP_REDIRECTS = "ntp_redirects"
IOT_CLOUD = "iot_cloud"
FORWARDS = "forwards"              # BUILD 430: the person's own port forwards still reach their boxes
VPN_ACCESS = "vpn_access"
TITLES = {VPN_ACCESS: "The VPN reaches the firewall and the internet (full tunnel)",
          DNS_REDIRECTS: "Each isolated network's DNS is sent to the firewall",
          NTP_REDIRECTS: "Each isolated network's time is asked of the firewall",
          IOT_CLOUD: "Smart devices reach their clouds, and only the internet",
          FORWARDS: "Your port forwards still reach their boxes from the internet",
          DNS_TLS: "The firewall's own lookups are encrypted (DNS over TLS)",
          ZENARMOR: "Zenarmor is installed and running", COUNTRY: "Country ranges are loaded, so the block works",
          IDS_RULESETS: "Packet inspection has its rulesets switched on",
          LIST_REFRESH: "The downloaded lists are refreshed every night",
          OTP: "Signing in to the firewall asks for a one-time code",
          DHCP_ZONES: "Every zone's network hands out addresses",
          ROOT: "Root is switched off",
          SSH: "Secure Shell is off, or open only to management and the VPN",
          CONSOLE: "Your own sign-in works at the console",
          CERT: "The home's name has a certificate that renews itself"}
NOT_READ = "The app could not read this from the firewall yet; the plugin there has to be up to date and answering"


def zenarmor_verdict(services: Mapping[str, Any] | None):
    """(status, detail, findings). services["zenarmor"] is {"installed": bool, "running": bool|None}, taken from the
    plugin's own reading of the firewall (its package list, and whether Zenarmor's engine process is up)."""
    got = services.get("zenarmor") if isinstance(services, Mapping) else None
    if not isinstance(got, Mapping) or not isinstance(got.get("installed"), bool):
        return UNVERIFIED, NOT_READ, []
    if not got["installed"] and got.get("source_only"):
        return DRIFTED, "Zenarmor is not installed yet", [
            "Zenarmor is not installed yet: only its package source is on the firewall (an install may still be running)"]
    if not got["installed"]:
        return DRIFTED, "Zenarmor is not installed", [
            "Zenarmor is not installed (the setup page's Extras page installs it)"]
    running = got.get("running")
    if running is True:
        return ENFORCED, "Zenarmor is installed and running", []
    if running is False:
        return DRIFTED, "Zenarmor is installed but not running", [
            "Zenarmor is installed but its engine is not running. Its own setup may be waiting for you to accept its terms"]
    return UNVERIFIED, NOT_READ, []


def country_verdict(services: Mapping[str, Any] | None):
    """None when no country has been picked (nothing to judge). Otherwise (status, detail, findings).
    services["country_picked"] is whether the person picked countries; services["country_block"] is the plugin's
    reading: {"present": bool|None, "entries": int|None} for the firewall table holding the country list."""
    if not isinstance(services, Mapping) or services.get("country_picked") is not True:
        return None
    got = services.get("country_block")
    present = got.get("present") if isinstance(got, Mapping) else None
    entries = got.get("entries") if isinstance(got, Mapping) else None
    if present is False or (present is True and entries == 0):
        return DRIFTED, "No country ranges are loaded on the firewall, so no country is being blocked", [
            "The firewall has no country ranges loaded, so no country is being blocked. It needs a source for them "
            "(a free IPinfo, MaxMind or IPLocate account)"]
    if present is True and isinstance(entries, int) and not isinstance(entries, bool) and entries > 0:
        return ENFORCED, "%s country ranges are loaded" % format(entries, ","), []
    return UNVERIFIED, NOT_READ, []


def ids_verdict(services: Mapping[str, Any] | None):
    """None when the rulesets could not be read. services["ids_rulesets"] is {"wanted": n, "missing": [file names]}."""
    got = services.get("ids_rulesets") if isinstance(services, Mapping) else None
    if not isinstance(got, Mapping) or not isinstance(got.get("missing"), list):
        return None
    left = [str(x) for x in got["missing"]]
    if not left:
        return ENFORCED, "the baseline's rulesets are switched on", []
    return DRIFTED, f"{len(left)} of the baseline's rulesets are switched off", [
        f"Switched off: {', '.join(left[:8])}. Finish getting to Happy (Normal) switches them on and downloads them"]


def refresh_verdict(services: Mapping[str, Any] | None):
    """None when the firewall's scheduler could not be read. services["list_refresh"] is {"missing": [keys]}."""
    from pazuzu_core.list_refresh import WORDS
    got = services.get("list_refresh") if isinstance(services, Mapping) else None
    if not isinstance(got, Mapping) or not isinstance(got.get("missing"), list):
        return None
    left = [str(x) for x in got["missing"]]
    if not left:
        return ENFORCED, "each list has its nightly job", []
    return DRIFTED, "not refreshed: " + ", ".join(WORDS.get(k, k) for k in left), [
        "No nightly job for " + ", ".join(WORDS.get(k, k) for k in left) + ", so they go stale. Finish getting to Happy "
        "(Normal) adds one each on the firewall's own scheduler"]


def otp_verdict(services: Mapping[str, Any] | None):
    """None when the plugin could not say. services["otp"] is {"in_use", "present", "skipped"}."""
    got = services.get("otp") if isinstance(services, Mapping) else None
    if not isinstance(got, Mapping) or not isinstance(got.get("in_use"), bool):
        return None
    if got["in_use"]:
        return ENFORCED, "the firewall's sign-in asks for a one-time code", []
    if got.get("skipped"):
        return UNVERIFIED, "skipped for testing: the sign-in does not ask for a one-time code", [
            "Skipped for testing. Take the skip back to have it counted again"]
    return DRIFTED, "the firewall's sign-in does not ask for a one-time code", [
        "Signing in needs only a password" + ("" if got.get("present") else " (the code server is not on the firewall yet)")
        + ". The setup page's Admin step adds it and switches the sign-in over, with a safety timer"]


def dhcp_verdict(services: Mapping[str, Any] | None):
    """None when it could not be read. services["dhcp_zones"] is {"missing": [{"zone", "network"}]}."""
    got = services.get("dhcp_zones") if isinstance(services, Mapping) else None
    if not isinstance(got, Mapping) or not isinstance(got.get("missing"), list):
        return None
    left = [m for m in got["missing"] if isinstance(m, Mapping)]
    part = [m for m in (got.get("incomplete") or []) if isinstance(m, Mapping)]
    stray = [m for m in (got.get("strays") or []) if isinstance(m, Mapping)]
    if not (left or part or stray):
        return ENFORCED, "each zone's network hands out addresses, with the firewall as router and name server", []
    found, said = [], []
    if left:
        words = [f"{m.get('zone')} ({m.get('network')})" for m in left]
        said.append(f"{len(left)} zone network(s) hand out no addresses")
        found.append("No address handout on " + ", ".join(words[:6]) + ". Their devices get no address. The app adds one "
                     "for each")
    if part:
        words = [f"{m.get('label')} ({m.get('subnet')})" for m in part]
        said.append(f"{len(part)} hand out no router or name server")
        found.append("No router or name server handed out on " + ", ".join(words[:6]) + ". Devices there get an address "
                     "but no way out. The app sets the firewall's own address for both")
    if stray:
        words = [f"{m.get('label')} ({m.get('subnet')})" for m in stray]
        said.append(f"{len(stray)} left over from an earlier try")
        found.append("Left over from an earlier try, on none of the firewall's ports: " + ", ".join(words[:6])
                     + ". The app removes it")
    return DRIFTED, "; ".join(said), found


def cert_verdict(services: Mapping[str, Any] | None):
    """None when it could not be read. services["cert"] is {"name", "plugin", "issued", "renews", "words", "behind"}."""
    got = services.get("cert") if isinstance(services, Mapping) else None
    if not isinstance(got, Mapping):
        return None
    if not got.get("name"):
        return DRIFTED, "set up the home's name first (Dynamic DNS)", [
            "A certificate is for the home's name, and there is none yet. Set up Dynamic DNS, then come back"]
    name = got["name"]
    dns = got.get("method") == "dns01"
    if got.get("behind") and not dns:
        return DRIFTED, "the firewall is behind another router", [
            f"Let's Encrypt has to reach port 80 at {name}, and the firewall sits behind another router. Forward port 80 "
            "on that router to the firewall first"]
    if got.get("port80_taken") and not dns and not (got.get("issued") and got.get("renews")):
        return DRIFTED, "port 80 is forwarded to a box of yours", [
            f"Let's Encrypt's check over port 80 would land on {', '.join(got['port80_taken'])}, not the firewall. A DuckDNS "
            "name is proved through DNS instead and needs no port; with this name, the forward has to step aside while "
            "the certificate is asked for"]
    if got.get("plugin") is False:
        return DRIFTED, "the certificate plugin is not installed", [
            f"No certificate for {name} yet. The app installs the firewall's certificate plugin (os-acme-client), then "
            "gets one"]
    if got.get("plugin") is None:
        return None
    if got.get("issued") and got.get("renews"):
        return ENFORCED, f"{name} has a certificate; the firewall renews it", []
    if got.get("issued"):
        return DRIFTED, f"{name} has a certificate, but it does not renew itself", [
            "Automatic renewal is off. The app switches it on"]
    return DRIFTED, f"no certificate for {name} yet" + (f" ({got['words']})" if got.get("words") else ""), [
        f"The app gets one from Let's Encrypt for {name}, proved over port 80, which the firewall opens only while it "
        "checks and closes straight after, then renews it by itself"]


def root_verdict(services: Mapping[str, Any] | None):
    got = services.get("root") if isinstance(services, Mapping) else None
    if not isinstance(got, Mapping) or not isinstance(got.get("factory"), bool):
        return None
    if got.get("off"):
        return ENFORCED, "root is switched off", []
    if not got["factory"]:
        # BUILD 442: root still signing in is drift, not "can't check" (the box reads it). Happy means root is off:
        # one well-known name with every power is the first thing anything guessing at scale tries.
        return DRIFTED, "root still signs in (with a password of its own)", [
            "Root still signs in. Switch it off on the Admin step once your own sign-in works on the web page and at "
            "the console (that proof is asked for first, so you cannot lock yourself out)"]
    return DRIFTED, "CRITICAL: root still has the factory password", [
        "Critical: anyone who knows OPNsense's factory password can sign in as root. Change it now"]


def ssh_verdict(services: Mapping[str, Any] | None):
    """None when the plugin could not say. services["ssh"] is the plugin's reading plus "allowed" (the management and
    VPN ports) and "port_plan" (this install's random SSH port)."""
    got = services.get("ssh") if isinstance(services, Mapping) else None
    if not isinstance(got, Mapping) or not isinstance(got.get("enabled"), bool):
        return None
    if not got["enabled"]:
        return ENFORCED, "Secure Shell is off", []
    bad = []
    if got.get("root_login"):
        bad.append("root may log in")
    if got.get("password_login"):
        bad.append("passwords are allowed (keys only is the baseline)")
    plan = got.get("port_plan")
    if got.get("port") in (22, None) or (isinstance(plan, int) and got.get("port") != plan):
        bad.append(f"it is on port {got.get('port')}" + (f", not this install's own port {plan}" if plan else ""))
    allowed = set(got.get("allowed") or [])
    ifaces = list(got.get("interfaces") or [])
    if not ifaces:
        bad.append("it listens on every port")
    else:
        extra = [i for i in ifaces if i not in allowed]
        if extra:
            bad.append("it listens on " + ", ".join(extra) + " (only management and the VPN are allowed)")
    if not bad:
        return ENFORCED, "Secure Shell is on, open only to management and the VPN", []
    return DRIFTED, "Secure Shell is on and " + "; ".join(bad), [
        "Secure Shell: " + "; ".join(bad) + ". Switch it off (the baseline), or keep it on, tightened"]


def console_verdict(services: Mapping[str, Any] | None):
    got = services.get("console") if isinstance(services, Mapping) else None
    if not isinstance(got, Mapping) or not got.get("user"):
        return None
    if not got.get("real"):
        return DRIFTED, f"{got['user']} cannot sign in at the console (no login shell)", [
            f"{got['user']} has no login shell, so only root can sign in at the firewall's console. Give it one before root "
            "goes off"]
    if got.get("sudo") is False:
        return DRIFTED, "admins may not use sudo, so the console menu stays out of reach", [
            "On the firewall: System, Settings, Administration, Sudo: Ask password, group admins, then Save. Without it, "
            f"{got['user']} signs in at the console but cannot open the menu (sudo opnsense-shell)"]
    if got.get("proved"):
        return ENFORCED, f"{got['user']} signs in at the console", []
    return UNVERIFIED, f"{got['user']} has a login shell; sign in at the console once to prove it", [
        f"At the firewall's console, sign in as {got['user']}, then type sudo opnsense-shell for the menu. With one-time codes "
        "on, type the password with the 6-digit code straight after it (no space). Tick it when it works"]


def redirects_verdict(services: Mapping[str, Any] | None):
    """None when it could not be read. services["dns_guard"]["redirects"] is {"missing": [zones], "plan", "notes"}."""
    from pazuzu_core.nat_audit import ZONE_WORDS
    guard = services.get("dns_guard") if isinstance(services, Mapping) else None
    got = guard.get("redirects") if isinstance(guard, Mapping) else None
    if not isinstance(got, Mapping) or not isinstance(got.get("missing"), list):
        return None
    left = [str(z) for z in got["missing"]]
    if not left:
        return ENFORCED, "each isolated network's DNS is sent to the firewall", []
    words = ", ".join(ZONE_WORDS.get(z, z) for z in left)
    return DRIFTED, "no DNS redirect on " + words, [
        "No DNS redirect on " + words + ". A device there with its own DNS server is cut off instead of getting the "
        "firewall's filtered answers. Finish getting to Happy (Normal) adds one each"]


def ntp_verdict(services: Mapping[str, Any] | None):
    """None when it could not be read. services["dns_guard"]["ntp_redirects"] is {"missing": [zones], "plan", "notes"}."""
    guard = services.get("dns_guard") if isinstance(services, Mapping) else None
    got = guard.get("ntp_redirects") if isinstance(guard, Mapping) else None
    if not isinstance(got, Mapping) or not isinstance(got.get("missing"), list):
        return None
    if not got["missing"]:
        return ENFORCED, "every isolated network's time comes from the firewall", []
    from pazuzu_core.nat_audit import ZONE_WORDS
    words = ", ".join(ZONE_WORDS.get(z, z) for z in got["missing"])
    return DRIFTED, "no time redirect on " + words, [
        "No time redirect on " + words + ". A device there with its own time server (smart lights often ask Alibaba's "
        "or Google's) is blocked again and again instead of getting the firewall's time. Finish getting to Happy "
        "(Normal) adds one each"]


def iot_cloud_verdict(services: Mapping[str, Any] | None):
    """None when there is no IoT network (or it could not be read). services["iot_cloud"] is iot_cloud.state."""
    from pazuzu_core import iot_cloud
    got = services.get("iot_cloud") if isinstance(services, Mapping) else None
    if not isinstance(got, Mapping) or "ports_missing" not in got:
        return None
    if iot_cloud.done(got):
        return ENFORCED, "smart devices reach their clouds, internet only" + (
            f"; {len(got['cams'])} doorbell or camera recognised" if got.get("cams") else ""), []
    return DRIFTED, "some smart devices cannot reach their clouds", iot_cloud.findings(got)


def forwards_verdict(services: Mapping[str, Any] | None):
    """None when there is no forward of the person's own on the internet side (or it could not be read).
    services["forwards"] is the forwards.forwards list."""
    from pazuzu_core import forwards as fwd
    got = services.get("forwards") if isinstance(services, Mapping) else None
    if not isinstance(got, list) or not got:
        return None
    groups = fwd.by_target(got)
    if not fwd.buried(got):
        return ENFORCED, (f"{len(got)} forward{'s' if len(got) != 1 else ''} to {len(groups)} box"
                          f"{'es' if len(groups) != 1 else ''}, each admitting its own traffic"), []
    return DRIFTED, "a forward of yours is buried under the internet-side deny", fwd.findings(got)


def tls_verdict(services: Mapping[str, Any] | None):
    """None when it could not be read. services["dns_guard"]["dot"] is dns_guard.dot_state."""
    guard = services.get("dns_guard") if isinstance(services, Mapping) else None
    got = guard.get("dot") if isinstance(guard, Mapping) else None
    if not isinstance(got, Mapping) or not isinstance(got.get("on"), bool):
        return None
    if got["on"]:
        servers = got.get("servers") or []
        return ENFORCED, ("the firewall asks " + ", ".join(servers) + " over TLS" if servers
                          else "the firewall's own lookups leave encrypted (DNS over TLS)"), []
    if got.get("switch"):
        return DRIFTED, "encrypted, but not to your choice", [str(got.get("why") or "")]
    if got.get("add") or got.get("enable"):
        return DRIFTED, "the firewall's own lookups go out unencrypted", [
            "The firewall asks the internet in plain text, so anyone on the way can read every name looked up. Finish "
            "getting to Happy (Normal) adds DNS over TLS" + (" to " + ", ".join(str(x[0]) for x in got["add"]) if got.get("add") else "")]
    return DRIFTED, "the firewall's own lookups go out unencrypted", [
        str(got.get("why") or "The firewall asks the internet in plain text")]


def vpn_verdict(services: Mapping[str, Any] | None):
    """None when there is no VPN (or it could not be read). services["vpn_access"] is {"missing": [names], "net"}."""
    got = services.get("vpn_access") if isinstance(services, Mapping) else None
    if not isinstance(got, Mapping) or not isinstance(got.get("missing"), list):
        return None
    left = [str(x).replace("Pazuzu: VPN ", "") for x in got["missing"]]
    if not left:
        return ENFORCED, "the VPN reaches the firewall's page, the box, its DNS and the internet", []
    return DRIFTED, "the VPN connects but cannot reach " + ("anything" if len(left) >= 4 else "everything"), [
        "A phone on the VPN connects and then everything it sends is dropped (" + "; ".join(left) + "). Finish getting "
        "to Happy (Normal) adds the rules, from the VPN's own network only"]


def rows(services: Mapping[str, Any] | None) -> list[tuple[str, str, str, str, list[str]]]:
    """[(id, title, status, detail, findings)] for each line this module adds to the board."""
    out = []
    status, detail, found = zenarmor_verdict(services)
    out.append((ZENARMOR, TITLES[ZENARMOR], status, detail, found))
    country = country_verdict(services)
    if country is not None:
        out.append((COUNTRY, TITLES[COUNTRY]) + country)
    ids = ids_verdict(services)
    if ids is not None:
        out.append((IDS_RULESETS, TITLES[IDS_RULESETS]) + ids)
    root = root_verdict(services)
    if root is not None:
        out.insert(0, (ROOT, TITLES[ROOT]) + root)
    con = console_verdict(services)
    if con is not None:
        out.append((CONSOLE, TITLES[CONSOLE]) + con)
    sh = ssh_verdict(services)
    if sh is not None:
        out.append((SSH, TITLES[SSH]) + sh)
    otp = otp_verdict(services)
    if otp is not None:
        out.append((OTP, TITLES[OTP]) + otp)
    ce = cert_verdict(services)
    if ce is not None:
        out.append((CERT, TITLES[CERT]) + ce)
    dz = dhcp_verdict(services)
    if dz is not None:
        out.append((DHCP_ZONES, TITLES[DHCP_ZONES]) + dz)
    for cid, verdict in ((DNS_REDIRECTS, redirects_verdict), (NTP_REDIRECTS, ntp_verdict), (DNS_TLS, tls_verdict),
                         (VPN_ACCESS, vpn_verdict), (IOT_CLOUD, iot_cloud_verdict), (FORWARDS, forwards_verdict)):
        got = verdict(services)
        if got is not None:
            out.append((cid, TITLES[cid]) + got)
    fresh = refresh_verdict(services)
    if fresh is not None:
        out.append((LIST_REFRESH, TITLES[LIST_REFRESH]) + fresh)
    out += unread_rows(services, {r[0] for r in out})
    return out


def unread_rows(services: Mapping[str, Any] | None, shown: set) -> list[tuple[str, str, str, str, list[str]]]:
    """A line the firewall would not let Pazuzu read stays on the board as "can't check", with the reason, instead of
    vanishing (prod, 30 Oct 2026: the morning the installer account closed, the VPN and DNS cards were simply gone)."""
    if not isinstance(services, Mapping):
        return []
    why = dict(services.get("unread") or {}) if isinstance(services.get("unread"), Mapping) else {}
    guard = services.get("dns_guard")
    if isinstance(guard, Mapping):                    # read, but one of its two parts was refused
        if guard.get("redirects") is None:
            why.setdefault(DNS_REDIRECTS, "the firewall's port forwards could not be read")
        if "ntp_redirects" in guard and guard.get("ntp_redirects") is None:
            why.setdefault(NTP_REDIRECTS, "the firewall's port forwards could not be read")
        if guard.get("dot") is None:
            why.setdefault(DNS_TLS, "the firewall's DNS settings could not be read")
    out = []
    for cid in (DNS_REDIRECTS, NTP_REDIRECTS, DNS_TLS, VPN_ACCESS, IOT_CLOUD, IDS_RULESETS, LIST_REFRESH):
        if cid in why and cid not in shown:
            out.append((cid, TITLES[cid], UNVERIFIED, "can't read this right now",
                        [f"Can't read this right now: {why[cid]}. If the installer account has closed itself, make it "
                         "again on the setup page; that also gives Pazuzu's own accounts these pages for good"]))
    return out
