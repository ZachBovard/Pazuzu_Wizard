"""How your devices find your home: a name that follows a changing address.

The pieces that need no firewall: the provider list, picking the firewall's own name for a
provider out of the choices the firewall itself offers, checking the name a person typed, and
the plain steps for doing it by hand when the firewall cannot be written to yet.

Nothing here talks to the network. The provider's password never appears in this file's outputs.
"""

from __future__ import annotations

import re

PLUGIN = "os-ddclient"
DESCRIPTION_PREFIX = "Pazuzu name for home: "

# key, name shown, what to call the login, what to call the secret, extra field (or None), where to make one
PROVIDERS = (
    {"id": "duckdns", "name": "DuckDNS", "login": "", "secret": "Your DuckDNS token",
     "needs_login": False, "extra": None, "match": ("duckdns",), "prefer": ("duckdns",),
     "site": "www.duckdns.org", "suffix": ".duckdns.org", "recommended": True,
     "why": "Free, no expiry, and you sign in with an account you already have"},
    {"id": "dyndns", "name": "DynDNS", "login": "Your DynDNS user name", "secret": "Your DynDNS password",
     "needs_login": True, "extra": None, "match": ("dyndns",), "prefer": ("dyndns2", "dyndns"),
     "site": "account.dyn.com"},
    {"id": "noip", "name": "No-IP", "login": "Your No-IP user name (or the update username it gave you)",
     "secret": "Your No-IP password (or the update password it gave you)",
     "needs_login": True, "extra": None, "match": ("noip",), "prefer": ("noip", "noip2", "noipv2"),
     "site": "www.noip.com/sign-up"},
    {"id": "cloudflare", "name": "Cloudflare", "login": "Your Cloudflare email (or the word token)",
     "secret": "A Cloudflare API token that may edit that name's DNS",
     "needs_login": True, "extra": {"key": "zone", "label": "The domain it belongs to, like example.com"},
     "match": ("cloudflare",), "prefer": ("cloudflare",), "site": "dash.cloudflare.com"},
    # BUILD 451: a domain of your own at GoDaddy (hanbi.net, a business's own name). The bare domain works too: type
    # the domain itself as the name. One key covers every domain in the account; it must be a Production key.
    {"id": "godaddy", "name": "GoDaddy", "login": "Your GoDaddy API key (a Production key, not OTE)",
     "secret": "Its API secret (GoDaddy shows it once, when the key is made)",
     "needs_login": True, "extra": {"key": "zone", "label": "The domain it belongs to, like example.com"},
     "match": ("godaddy",), "prefer": ("godaddy",), "site": "developer.godaddy.com/keys",
     "why": "For a domain of your own registered at GoDaddy, the bare domain or a name under it"},
)
BY_ID = {p["id"]: p for p in PROVIDERS}

_HOST = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}$")


class DdnsError(Exception):
    """A problem a person can read."""


# BUILD 452: services that keep a domain of your own pointing home (offered under "I have my own domain name");
# the rest give a free name of their own.
OWN_DOMAIN = ("cloudflare", "godaddy")
# BUILD 453: services only the firewall's ddclient updater has (its own "native" updater lists no GoDaddy). Picking
# one switches the firewall's Dynamic DNS backend to ddclient, in the same passkey-approved change; every name then
# runs on ddclient, which also has DuckDNS, DynDNS, No-IP and Cloudflare.
DDCLIENT_ONLY = ("godaddy",)
BACKEND_LINE = ("Dynamic DNS backend: native to ddclient (the firewall's own updater has no {name}; every name, "
                "the ones already there too, then runs on ddclient)")


def public_providers() -> list[dict]:
    """What the page needs to draw the form. No secrets, nothing that depends on the firewall."""
    return [{"id": p["id"], "name": p["name"], "login": p["login"], "secret": p["secret"],
             "needs_login": p["needs_login"], "extra": p["extra"], "site": p.get("site", ""),
             "suffix": p.get("suffix", ""), "recommended": bool(p.get("recommended")), "why": p.get("why", ""),
             "own_domain": p["id"] in OWN_DOMAIN}
            for p in PROVIDERS]


# BUILD 535 (the maintainer, 13 Nov 2026: "add duckdns token length verification"): a DuckDNS token is 36 characters, in the
# 8-4-4-4-12 shape of hex digits and dashes that DuckDNS shows at the top of its page.
DUCKDNS_TOKEN = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def duckdns_token_problem(token) -> str | None:
    """None if the token has DuckDNS's shape; otherwise what to say. The token itself is never in what is said."""
    t = token.strip() if isinstance(token, str) else ""
    if not t:
        return "Give the token DuckDNS shows at the top of its page, after you sign in."
    if len(t) != 36:
        return ("That token is " + str(len(t)) + " characters long. A DuckDNS token is 36, like "
                "a1b2c3d4-0000-1111-2222-333344445555: copy the whole token from the top of the DuckDNS page.")
    if not DUCKDNS_TOKEN.match(t):
        return ("That is not the shape of a DuckDNS token: 36 characters, letters a to f, digits and four dashes, like "
                "a1b2c3d4-0000-1111-2222-333344445555. Copy the token from the top of the DuckDNS page, not the name.")
    return None


def full_name(provider_id, value) -> str:
    """The name as typed, with the service's own ending added when only the first part was typed
    ("quiet-maple-4821" is quiet-maple-4821.duckdns.org at DuckDNS)."""
    name = str(value or "").strip().lower().rstrip(".")
    suffix = (BY_ID.get(str(provider_id or "")) or {}).get("suffix") or ""
    if suffix and name and "." not in name:
        name += suffix
    return name


def clean_hostname(value) -> str:
    name = str(value or "").strip().lower().rstrip(".")
    if name.startswith(("http://", "https://")):
        name = name.split("//", 1)[1].split("/", 1)[0]
    if not _HOST.match(name):
        raise DdnsError("A name looks like home.example.net: letters, digits, dots and dashes, "
                        "with at least one dot.")
    return name


def _squash(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def resolve_service(choices: dict[str, str], provider_id: str) -> str:
    """The firewall's own key for a provider, taken from the list the firewall itself gives."""
    prov = BY_ID.get(provider_id)
    if prov is None:
        raise DdnsError("Pick one of the name services in the list.")
    if not choices:
        raise DdnsError("This firewall's form did not list any name services. Nothing was changed.")
    hits = {k: lab for k, lab in choices.items()
            if any(m in _squash(k) or m in _squash(lab) for m in prov["match"])}
    if not hits:
        raise DdnsError(f"This firewall's list has no {prov['name']}. Nothing was changed.")
    if len(hits) == 1:
        return next(iter(hits))
    for want in prov["prefer"]:
        for k in hits:
            if _squash(k) == want:
                return k
    raise DdnsError(f"This firewall lists more than one {prov['name']} and Pazuzu cannot tell which "
                    "you mean. Use Services, then Dynamic DNS on the firewall itself.")


# How the firewall learns its own public address. The firewall requires one; these are web lookups from its own list,
# tried in this order, so it still works behind another router (the firewall's own port would show a private address).
CHECKIP_PREFER = ("web_ipify-ipv4", "web_icanhazip", "web_cloudflare")
# BUILD 455: the names those web lookups use. Ad and tracker block lists carry some of them (api.ipify.org:
# the firewall's own DNS answered 0.0.0.0, so no name was updated after the lists went on). Pazuzu puts
# them on the block lists' allow list whenever it turns lists on, and on request for lists already on.
CHECKER_HOSTS = ("api.ipify.org", "icanhazip.com", "one.one.one.one")
# A firewall whose internet port holds the public address reads it there: no web lookup, nothing to block.
CHECKIP_PORT = "if"
# GoDaddy's API refuses a record time-to-live under 600 seconds; the firewall's form starts at 300.
MIN_TTL = {"godaddy": 600}
PORT_INTERFACE = "wan"


# BUILD 461: where each service takes its updates (and its own site), so the block lists let them through. Prod,
# 3 Nov 2026: www.duckdns.org answered 0.0.0.0 from the firewall's DNS, and DuckDNS takes updates there.
UPDATE_HOSTS = {
    "duckdns": ("www.duckdns.org", "duckdns.org"),
    "godaddy": ("api.godaddy.com", "developer.godaddy.com"),
    "cloudflare": ("api.cloudflare.com",),
    "noip": ("dynupdate.no-ip.com", "www.noip.com"),
    "dyndns": ("members.dyndns.org", "account.dyn.com"),
}


def service_id(service: str) -> str:
    """Pazuzu's id for a firewall service key ("dyndns2" -> "dyndns")."""
    s = re.sub(r"[^a-z0-9]", "", str(service or "").lower())
    for p in PROVIDERS:
        if any(m in s for m in p["match"]):
            return p["id"]
    return s


ZONE_ROOT = {"godaddy"}      # BUILD 463: services whose updater wants the domain itself written as "@.<domain>"


def firewall_hostname(provider_id: str, host: str, zone: str) -> str:
    """The name as the firewall's form should hold it. ddclient's GoDaddy updater takes the record's name by cutting
    ".<zone>" off the end, so the domain itself must be "@.<zone>" (it becomes "@"). Prod, 3 Nov 2026: "hanbi.net"
    with zone hanbi.net was sent as the record "hanbi.net.hanbi.net" and refused every five minutes."""
    if provider_id in ZONE_ROOT and zone and host == zone:
        return "@." + zone
    return host


def shown_name(hostnames: str) -> str:
    """The name as a person reads it: "@.hanbi.net" is hanbi.net."""
    return ",".join(h[2:] if h.startswith("@.") else h for h in str(hostnames or "").split(","))


def allow_hosts(services, names=()) -> tuple:
    """The names to let through the block lists: the address lookups, each service's update host and site, and (BUILD
    462) the home's own names. Prod, 3 Nov 2026: Hagezi's "Dynamic DNS blocking" list answered 0.0.0.0 for
    www.duckdns.org and for the home's own DuckDNS name, so a phone inside could not look the VPN's name up either."""
    out = list(CHECKER_HOSTS)
    for svc in services or ():
        for h in UPDATE_HOSTS.get(service_id(svc), ()):
            if h not in out:
                out.append(h)
    for raw in names or ():
        for n in shown_name(raw).split(","):
            n = n.strip().lower().rstrip(".")
            if n and _HOST.match(n) and n not in out:
                out.append(n)
    return tuple(out)


def pick_checkip(choices: dict[str, str], port_public: bool) -> str:
    """The port itself when it holds a public address and the firewall offers that, else a web lookup."""
    if port_public and CHECKIP_PORT in (choices or {}):
        return CHECKIP_PORT
    return resolve_checkip(choices)


def merge_allow(current: str, hosts=None) -> str:
    """The allow list as the firewall keeps it (comma separated), with the given names (the checker names when none
    are given) added once. Nothing already there is taken out."""
    have = [x.strip() for x in str(current or "").replace("\n", ",").split(",") if x.strip()]
    return ",".join(have + [h for h in (hosts or CHECKER_HOSTS) if h not in have])


def resolve_checkip(choices: dict[str, str]) -> str:
    """The firewall's own key for an address lookup, taken from the list the firewall itself gives."""
    for key in CHECKIP_PREFER:
        if key in (choices or {}):
            return key
    offered = ", ".join(sorted({lab for lab in (choices or {}).values() if lab})[:12])
    raise DdnsError("This firewall's list has no web address lookup Pazuzu uses"
                    + (f" (it offers: {offered})" if offered else "") + ". Nothing was changed.")


def manual_steps(provider_id: str, hostname: str) -> list[str]:
    """What to enter by hand, in the firewall's own words. Never includes a password."""
    prov = BY_ID.get(provider_id) or PROVIDERS[0]
    steps = ["On the firewall, open Services, then Dynamic DNS. If it is not there, install the plugin os-ddclient "
             "under System, then Firmware, then Plugins.",
             "Switch Dynamic DNS on, then add an account.",
             f"Service: {prov['name']}.",
             f"Hostname: {hostname or 'the name you made with them'}."]
    if prov["needs_login"]:
        steps.append("Username: the one your provider gave you.")
    steps.append("Password: the password or token your provider gave you. Type it on the firewall, not here.")
    if prov["extra"]:
        steps.append(prov["extra"]["label"] + ".")
    steps.append("Save, then press Apply. Then come back and press \"Use this name\".")
    return steps
