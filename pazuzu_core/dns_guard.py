"""Keeping every lookup on the firewall, and the firewall's own lookups encrypted. Done by Pazuzu, through the same
guarded write path as everything else (write_engine), only from "Finish getting to Happy".

Two things:
  - A DNS redirect on each isolated network (smart devices, guests, public servers, quarantine) that has a port:
    a device there that asks an outside server on port 53 is answered by the firewall instead, so it still gets
    filtered answers rather than being cut off by the baseline's block on outside DNS. The entry is the one proved on
    a production firewall (28 Oct 2026): Destination NAT on that port, TCP/UDP, IPv4, to any address on port 53,
    sent to the firewall's own address on that network (never 127.0.0.1, which failed there), port 53, named
    "PZ-NAT-DNS <network> to firewall".
  - DNS over TLS to the resolver picked on the setup page, so the firewall's own questions to the internet are
    encrypted. On 26.7 these are Unbound's forwards with type dot, through the *_dot calls. All three choices offer it:
    Quad9, Cloudflare, and OpenDNS (Cisco's resolvers have taken DNS over TLS since January 2022; an earlier build here
    wrongly said OpenDNS had none).
    A DNS over TLS entry already there for every name counts, whoever made it.

This file reads and plans. The writes are in wizard_server's happy_finish_start, one passkey for the lot.
"""
from __future__ import annotations

from typing import Any, Callable, Mapping

from pazuzu_core import nat_audit

DOT = {
    "quad9": (("9.9.9.9", "dns.quad9.net"), ("149.112.112.112", "dns.quad9.net")),
    "cloudflare": (("1.1.1.1", "cloudflare-dns.com"), ("1.0.0.1", "cloudflare-dns.com")),
    "opendns": (("208.67.222.222", "dns.opendns.com"), ("208.67.220.220", "dns.opendns.com")),
}
DEFAULT = "quad9"                    # the first choice on the setup page, and the one proved on a production firewall
NO_DOT: dict = {}                   # a choice with no DNS over TLS (none now): nothing is added, the board says why
FORWARDS = "/api/unbound/settings/search_dot?rowCount=-1&searchPhrase="     # *_dot: the forwards of type dot
NAMES = {"iot": "IoT", "guest": "Guest", "dmz": "DMZ", "quarantine": "Quarantine"}
PREFIX = "PZ-NAT-DNS"
NTP_PREFIX = "PZ-NAT-NTP"           # BUILD 424: time asked of any outside server goes to the firewall too


def _on(v: Any) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _is_dot(row: Mapping) -> bool:
    t = str(row.get("type", "")).strip().lower()
    return t in ("dot", "dns over tls", "dns-over-tls")


KNOWN = {s: pid for pid, pairs in DOT.items() for s, _v in pairs}      # each offered server -> its provider
WORDS = {"quad9": "Quad9", "cloudflare": "Cloudflare", "opendns": "OpenDNS"}


def dot_state(rows: Any, choice: str | None) -> dict:
    """What DNS over TLS is on, against what was chosen (Quad9 when nothing was: the default, decided 29 Oct 2026).

    {"on": True | False | None, "servers": [the switched-on ones], "add": [(server, verify)], "enable": [uuid],
     "off": [uuid], "switch": bool, "why": text}. `rows` is the search_dot list. "on" when the chosen provider's servers
    are all switched on for every name (no domain), or when servers of someone's own (not one of the three) are in use:
    those are never touched. When another of the three providers is on instead, it is a switch: the chosen one's
    servers are added (or switched back on), then the other's are switched off (kept, so Undo can put them back).
    None when it cannot be told: rows that do not say their type."""
    if not isinstance(rows, list):
        return {"on": None, "servers": [], "add": [], "enable": [], "off": [], "switch": False,
                "why": "The firewall did not list its DNS forwards"}
    rows = [r for r in rows if isinstance(r, Mapping)]
    if rows and not any("type" in r for r in rows):
        return {"on": None, "servers": [], "add": [], "enable": [], "off": [], "switch": False,
                "why": "The firewall's DNS forwards do not say which are DNS over TLS"}
    want = choice if choice in DOT else DEFAULT
    pairs = DOT[want]
    want_servers = {s for s, _v in pairs}
    every = [r for r in rows if _is_dot(r) and not str(r.get("domain") or "").strip()]
    live = [r for r in every if _on(r.get("enabled", "1"))]
    live_servers = [str(r.get("server", "")) for r in live]
    if live and (want_servers <= set(live_servers) or any(x not in KNOWN for x in live_servers)):
        return {"on": True, "servers": live_servers, "add": [], "enable": [], "off": [], "switch": False, "why": ""}
    present = {str(r.get("server", "")): r for r in every}
    add = [(x, v) for x, v in pairs if x not in present]
    enable = [str(present[x].get("uuid")) for x, _v in pairs
              if x in present and not _on(present[x].get("enabled", "1")) and present[x].get("uuid")]
    off = [str(r.get("uuid")) for r in live if str(r.get("server")) not in want_servers and r.get("uuid")]
    if live:
        was = sorted({WORDS[KNOWN[x]] for x in live_servers if x in KNOWN} - {WORDS[want]}) or ["part of " + WORDS[want]]
        return {"on": False, "servers": live_servers, "add": add, "enable": enable, "off": off, "switch": True,
                "why": f"The firewall asks {', '.join(was)}, not your choice ({WORDS[want]}). Finish getting to Happy "
                       "switches it"}
    why = "" if (add or enable) else ("A DNS over TLS entry is there but only for some names. Add one for every name "
                                      "under Services, Unbound DNS, DNS over TLS")
    return {"on": False, "servers": [], "add": add, "enable": enable, "off": [], "switch": False, "why": why}


def redirect_plan(rows: list, zones: Mapping[str, Mapping], where: Mapping[str, list],
                  kind: str = "dns") -> tuple[list, list, list]:
    """(missing zones, [{"zone", "interface", "target", "kind"}], notes). A zone whose short name or address the
    firewall did not show is left out, with a note: a guess is never written. `kind` is "dns" or "ntp"."""
    gone = nat_audit.missing(rows, zones, kind)
    plan, notes = [], []
    for z in gone:
        ident = str((zones.get(z) or {}).get("identifier") or "")
        ips = [i for i in where.get(z, []) if getattr(i, "version", 4) == 4]
        if not ident or not ips:
            notes.append(f"No {'time' if kind == 'ntp' else 'DNS'} redirect was planned for {nat_audit.ZONE_WORDS[z]}: "
                         "the firewall did not show its port's name and address.")
            continue
        plan.append({"zone": z, "interface": ident, "target": str(ips[0].ip), "kind": kind})
    return gone, plan, notes


def box_dot(status: Any) -> bool | None:
    """The plugin's own reading of DNS over TLS (it reads the firewall's config.xml, proven on a production firewall):
    its critical row "Encrypted DNS upstream". None when the plugin did not say."""
    rows = status.get("services") if isinstance(status, Mapping) else None
    for r in rows if isinstance(rows, list) else []:
        if isinstance(r, Mapping) and r.get("name") == "Encrypted DNS upstream" and isinstance(r.get("up"), bool):
            return r["up"]
    return None


def read(getter: Callable[[str], Any], zones: Mapping[str, Mapping], choice: str | None,
         plugin_dot: bool | None = None) -> dict:
    """Both, read only: {"redirects": {"missing", "plan", "notes"} | None, "dot": dot_state | None}. A part that
    cannot be read is None, never a guess. `plugin_dot` is the plugin's own reading (box_dot): when it says DNS over
    TLS is on, it is on, and nothing is added, whatever the forwards list looked like through the API."""
    out: dict = {"redirects": None, "ntp_redirects": None, "dot": None}
    try:
        rows = nat_audit.rows_of(getter)
        z, where, _ips = nat_audit.ports(getter, zones)
        gone, plan, notes = redirect_plan(rows, z, where)
        out["redirects"] = {"missing": gone, "plan": plan, "notes": notes}
        gone, plan, notes = redirect_plan(rows, z, where, "ntp")
        out["ntp_redirects"] = {"missing": gone, "plan": plan, "notes": notes}
    except Exception:  # noqa: BLE001
        pass
    try:
        got = getter(FORWARDS)
        out["dot"] = dot_state(got.get("rows") if isinstance(got, Mapping) else None, choice)
    except Exception:  # noqa: BLE001
        pass
    dot = out["dot"] or {}
    if plugin_dot is True and dot.get("on") is not True and not dot.get("servers"):
        out["dot"] = {"on": True, "servers": [], "add": [], "enable": [], "off": [], "switch": False, "why": "",
                      "seen_by": "plugin"}
    elif out["dot"] is None and plugin_dot is False:
        out["dot"] = {"on": False, "servers": [], "add": [], "enable": [], "off": [], "switch": False, "why": ""}
    out["choice"] = choice
    return out


def redirect_values(p: Mapping) -> dict:
    """The fields of one redirect, as write_engine's dnat_rule takes them. A time redirect is the same shape, on UDP 123
    (Govee lights on an IoT network asked Alibaba's and Google's time servers ~3,500 times each)."""
    if p.get("kind") == "ntp":
        return {"disabled": "0", "interface": p["interface"], "ipprotocol": "inet", "protocol": "udp",
                "destination.network": "any", "destination.port": "123", "target": p["target"], "local-port": "123",
                "descr": f"{NTP_PREFIX} {NAMES.get(p['zone'], p['zone'])} to firewall"}
    return {"disabled": "0", "interface": p["interface"], "ipprotocol": "inet", "protocol": "tcp/udp",
            "destination.network": "any", "destination.port": "53", "target": p["target"], "local-port": "53",
            "descr": f"{PREFIX} {NAMES.get(p['zone'], p['zone'])} to firewall"}


def _what(p: Mapping) -> str:
    return "time asked of any outside server" if p.get("kind") == "ntp" else "DNS asked of any outside server"


def dot_values(server: str, verify: str) -> dict:
    """One DNS over TLS entry, made switched OFF: it is switched on only once the firewall has read back as DNS over
    TLS (a plain forward to port 853 would break every lookup)."""
    return {"enabled": "0", "type": "dot", "domain": "", "server": server, "port": "853", "verify": verify}


def lines(todo: Mapping) -> list[str]:
    """What the passkey screen says for these two."""
    out = []
    for p in todo.get("dnat") or []:
        out.append(f"{nat_audit.ZONE_WORDS.get(p['zone'], p['zone'])}: send {_what(p)} to the firewall ({p['target']})")
    if todo.get("dot") or todo.get("dot_enable"):
        out.append("Encrypt the firewall's own lookups (DNS over TLS)"
                   + (" to " + ", ".join(x for x, _v in todo["dot"]) if todo.get("dot") else ""))
    if todo.get("dot_off"):
        out.append(f"Switch off the other provider's DNS over TLS entries ({len(todo['dot_off'])}); they are kept for Undo")
    return out


def apply(engine, todo: Mapping) -> tuple[list, list[str]]:
    """Make them, after the one passkey approval for "Finish getting to Happy" (so each write here is passed through).
    Returns (outcomes for Undo, plain lines). A part the firewall refuses is said, and the other part still goes."""
    from pazuzu_core import write_engine as we
    outs: list = []
    said: list[str] = []
    yes = lambda _d, _l: True                                # noqa: E731 - approved above, with the rest
    if todo.get("dnat"):
        try:
            got = engine.apply_many([engine.build("dnat_rule", redirect_values(p)) for p in todo["dnat"]], yes)
            outs += got
            for p, o in zip(todo["dnat"], got):
                said.append(f"{nat_audit.ZONE_WORDS.get(p['zone'], p['zone'])}: {_what(p)[0].upper() + _what(p)[1:]} now "
                            f"goes to the firewall ({p['target']})." + ("" if o.applied is not False else
                            " Saved, but not applied yet: press Apply on Firewall, NAT, Destination NAT."))
        except we.WriteError as exc:
            said.append(f"The redirects were not made: {exc}")
    if todo.get("dot") or todo.get("dot_enable") or todo.get("dot_off"):
        made: list = []

        def form_of(uuid):
            body = engine._req("get", f"/api/unbound/settings/get_dot/{uuid}")
            if not isinstance(body, dict) or len(body) != 1:
                raise we.WriteError("The firewall's DNS over TLS entry was not in the usual shape.")
            (wrapper, form), = body.items()
            if not isinstance(form, dict) or we._value_of(form.get("type")) != "dot":
                raise we.WriteError("The firewall saved it as a plain forward, not DNS over TLS.")
            return wrapper, form

        def flip(uuid, value):
            """One entry on ("1") or off ("0"), read back; the Outcome's undo flips it back."""
            wrapper, _form = form_of(uuid)
            res = engine._req("post", f"/api/unbound/settings/set_dot/{uuid}", json={wrapper: {"enabled": value}})
            if not (isinstance(res, dict) and str(res.get("result")) == "saved"):
                raise we.WriteError("The firewall did not switch a DNS over TLS entry " + ("on." if value == "1" else "off."))
            _wrapper, form = form_of(uuid)
            if we._value_of(form.get("enabled")) != value:
                raise we.WriteError("A DNS over TLS entry did not read back " + ("on." if value == "1" else "off."))
            return we.Outcome("unbound_dot", uuid, saved=True, undo_path=f"/api/unbound/settings/set_dot/{uuid}",
                              undo_body={wrapper: {"enabled": "0" if value == "1" else "1"}})

        flipped: list = []
        try:
            if todo.get("dot"):
                made = engine.apply_many([engine.build("unbound_dot", dot_values(x, v)) for x, v in todo["dot"]], yes)
                for o in made:                               # each must read back as DNS over TLS before it goes on
                    flip(o.uuid, "1")
            for uuid in todo.get("dot_enable") or []:        # the chosen provider's entries, already there but off
                flipped.append(flip(uuid, "1"))
            for uuid in todo.get("dot_off") or []:           # the other provider's, only once the new ones are on
                flipped.append(flip(uuid, "0"))
            applied = engine._reconfigure(we.CAPS["unbound_dot"])
            outs += made + flipped
            if todo.get("dot"):
                said.append("The firewall's own lookups now go encrypted (DNS over TLS) to "
                            + ", ".join(f"{x} ({v})" for x, v in todo["dot"]) + ".")
            elif todo.get("dot_enable"):
                said.append("The firewall's own lookups go encrypted (DNS over TLS) again: its entries are switched back on.")
            if todo.get("dot_off"):
                said.append("The other provider's DNS over TLS entries are switched off, not deleted: Undo puts them back.")
            if not applied:
                said.append("Saved, but not applied yet: press Apply on Services, Unbound DNS.")
        except we.WriteError as exc:
            back = 0
            for o in reversed(made + flipped):
                try:
                    back += 1 if engine.undo(o) else 0
                except we.WriteError:
                    pass
            said.append(f"DNS over TLS was not set: {exc}" + (" What was changed was put back." if back else ""))
    return outs, said
