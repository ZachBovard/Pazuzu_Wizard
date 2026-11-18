"""A network of its own for each zone that has no port yet, made as a VLAN on the port the existing VLANs already use.

For each zone asked for, through the firewall's own pages and in the order its web page does it by hand:

  1. a VLAN device (Interfaces, Devices, VLAN) on that port, with a random VLAN number no other VLAN there uses;
  2. a port for it (Interfaces, Assignments), switched on, with the firewall's address on a random private /24
     (address_plan: 10.x.y.1, never overlapping a network already there);
  3. its address handout with Kea (OPNsense's newer DHCP server, the one Pazuzu uses): a subnet with a pool (.100 to
     .199), the firewall as its router and name server, and Kea told to listen on it. A new firewall hands out addresses
     with dnsmasq instead; then the handout is first moved to Kea (kea_takeover: each dnsmasq range becomes a Kea subnet
     with the same pool, fixed addresses come along, then Kea is switched on). dnsmasq is used as it is (a range on that
     port, and dnsmasq told to answer there) when the person picks it on the page, or when Kea cannot be read.

A zone can instead get its own Wi-Fi network, on a USB Wi-Fi card of the firewall that can host one (Interfaces,
Wireless: an access point, WPA2 with the password the person chose), which is then given a port exactly like a spare
one. One network per card: the cards this box takes (Ralink run, Realtek rtwn) host one each. Each card gets its own
channel (1, 11, then 6), so they do not talk over one another.

The zone is then saved to that port (on this device), so the rules step adds the zone's rules like any other. Existing
VLANs are never renumbered or changed. Each form is read from the firewall first and only named fields are changed; a
field the form lacks is refused before anything is sent. If a step is refused, everything already done is taken back.
"""
from __future__ import annotations

import ipaddress
import re
import secrets
from typing import Any, Callable, Sequence

from pazuzu_core import write_engine as we
from pazuzu_core.address_plan import plan_addresses
from pazuzu_core.passkey_gate import plan_digest
from pazuzu_core.wifi_backup import AS, Hotspot, Plan, Step, _flat

VL = "/api/interfaces/vlan_settings"
KEA = "/api/kea/dhcpv4"
KEA_APPLY = "/api/kea/service/reconfigure"
DNSMASQ = "/api/dnsmasq/settings"
DNSMASQ_APPLY = "/api/dnsmasq/service/reconfigure"
INFO = "/api/interfaces/overview/interfaces_info/true"

# BUILD 515 (the maintainer, a live disc on plain 26.7, 12 Nov 2026: "This firewall's own form for the port has no field called
# enable"). The trace showed that version's port form (interfaces/assignment/get_item) holds only descr, identifier,
# icon, optgroup, if and lock: it can name a port but not switch it on or give it an address. A later 26.7 update adds
# enable, type4 and ipaddr, which every zone's port needs. Judged by the form itself, not by a version number.
PORT_FORM_FIELDS = ("enable", "type4", "ipaddr")
_V6_CHOICE = re.compile(r"^(DHCPv6|SLAAC)$", re.I)          # the firewall's own names for two IPv6 Configuration Types
OLD_PORT_FORM = ("This firewall is on an older 26.7 whose own port form cannot switch a port on or give it an address, so "
                 "a zone cannot be given a network on it yet. Update the firewall (the version step), then press Set "
                 "these up again. Nothing was changed.")
OFFERED = ("iot", "guest", "kids", "dmz", "quarantine")      # zones a home has use for that can live on a VLAN
PORT_ZONES = ("management",) + OFFERED                       # zones that can be given a spare port (management first)
LABELS = {"management": "PZ_Mgmt", "iot": "PZ_IoT", "guest": "PZ_Guest", "kids": "PZ_KidsNet", "dmz": "PZ_DMZ",
          "quarantine": "PZ_Quarantine"}
WORDS = {"management": "Management", "iot": "Smart devices", "guest": "Guests", "kids": "KidsNet", "dmz": "Public servers",
         "quarantine": "Quarantine"}
WIFI_ZONES = ("iot", "guest", "kids")                        # zones offered their own Wi-Fi network on the firewall
HOSTABLE = ("run", "rtwn")       # card drivers seen hosting a network on this firewall (one network per card)
CHANNELS = (1, 11, 6)            # 2.4 GHz channels that do not overlap, in the order cards get them
SSIDS = {"iot": "IoT", "guest": "Guests", "kids": "KidsNet"}
WL = "/api/interfaces/wireless_settings"
MGMT_POOL = (100, 119)       # the management port's handout: a computer plugged in gets an address by itself
TAG_LOW, TAG_HIGH = 100, 3999
_DEV = re.compile(r"^[A-Za-z0-9_.]{1,24}$")


def device_of(vlanif) -> str:
    """The VLAN's device name from the firewall's VLAN list, which shows it with the port's name after it:
    "vlan01 [PZ_Guest]" is vlan01."""
    return str(vlanif or "").strip().split(" ")[0]


def _network_of(row: dict) -> tuple[str, str] | None:
    """(network, firewall address) of a port from the firewall's interface overview row; None without an IPv4 one."""
    vals = row.get("addr4") if isinstance(row.get("addr4"), list) else [row.get("addr4")]
    for c in vals:
        try:
            iface = ipaddress.ip_interface(str(c))
        except ValueError:
            continue
        if iface.version == 4:
            return str(iface.network), str(iface.ip)
    return None


def _host_label(name) -> str:
    """A hostname Kea and the name server both take: letters, digits and dashes, no dots (a dot made the name server
    refuse to start once: "desktop..example.arpa")."""
    n = re.sub(r"[^a-z0-9-]", "-", str(name or "").strip().lower().split(".")[0]).strip("-")
    return n[:63]


def can_host(card: str) -> bool:
    """A Wi-Fi card this firewall can make an access point on (by its driver: run0, rtwn1...)."""
    m = re.match(r"^([a-z]+)\d{1,3}$", str(card or ""))
    return bool(m) and m.group(1) in HOSTABLE


def ssid_problem(text) -> str | None:
    if not isinstance(text, str) or not 1 <= len(text.encode("utf-8")) <= 32:
        return "A Wi-Fi name must be 1 to 32 characters."
    if any(not 32 <= ord(ch) <= 126 for ch in text) or text != text.strip():
        return "Use ordinary letters, numbers and symbols in the Wi-Fi name, with no spaces at the start or end."
    return None


def suggest(spare: Sequence[str], radios: Sequence[str], taken: Sequence[str] = ()) -> dict:
    """A first plan for the zones that have no port yet, from this box's own spare ports and Wi-Fi cards, with why:
    {zone: {"pick": "port:igc2" | "wifi:run0" | "vlan" | "", "why": "..."}}. Only a suggestion: the page shows it, the
    person changes what they like. `taken` are zones that already have a port (left out)."""
    ports, cards, out = list(spare), [c for c in radios if can_host(c)], {}

    def take(lst):
        return lst.pop(0) if lst else ""
    if "management" not in taken:
        p = take(ports)
        out["management"] = ({"pick": "port:" + p, "why": "A cable you plug in only when you need the admin pages."} if p
                             else {"pick": "", "why": "No spare port: the VPN is the way in to the admin pages."})
    if "iot" not in taken:
        c = take(cards)
        out["iot"] = ({"pick": "wifi:" + c, "why": "Most smart devices use 2.4 GHz Wi-Fi. A network of their own on the "
                       "firewall, so no VLAN is needed."} if c else
                      {"pick": "vlan", "why": "Kept apart from your own devices on a VLAN; your access point carries it."})
    if "guest" not in taken:
        c = take(cards)
        out["guest"] = ({"pick": "wifi:" + c, "why": "Guests get the internet on a Wi-Fi network of their own, and "
                         "nothing of yours."} if c else
                        {"pick": "vlan", "why": "Guests get the internet on a VLAN, and nothing of yours."})
    if "kids" not in taken:            # never built unless the person picks it (the maintainer, 14 Nov 2026)
        out["kids"] = {"pick": "", "why": "Optional: a network for the kids' devices, with a family DNS filter and a "
                       "bedtime. Pick a home for it to build one."}
    if "dmz" not in taken:
        p = take(ports)
        out["dmz"] = ({"pick": "port:" + p, "why": "Only if you run something people reach from the internet; ready for "
                       "when you do."} if p else
                      {"pick": "vlan", "why": "Only if you run something people reach from the internet; ready for "
                       "when you do."})
    if "quarantine" not in taken:
        out["quarantine"] = {"pick": "vlan", "why": "Rarely used: a place to put a device you no longer trust."}
    return out


def _default_rng(low: int, high: int) -> int:
    return low + secrets.randbelow(high - low + 1)


def pick_tags(n: int, used: Sequence[int], rng: Callable[[int, int], int] | None = None) -> list[int]:
    """`n` VLAN numbers, random, none already used and none of the round ones people pick by hand (10, 20, 100...)."""
    pick = rng or _default_rng
    taken, out = set(int(u) for u in used), []
    for _ in range(n):
        for _try in range(2000):
            t = pick(TAG_LOW, TAG_HIGH)
            if t not in taken and t % 10:
                break
        else:
            raise we.WriteError("Could not find a free VLAN number. Nothing was changed.")
        taken.add(t)
        out.append(t)
    return out


class ZoneVlans(Hotspot):
    """Reuses the hotspot's careful form handling (read, change only named fields, take back on refusal)."""

    def __init__(self, engine: we.Engine, rng: Callable[[int, int], int] | None = None, **kw):
        super().__init__(engine, **kw)
        self.rng = rng

    # ------------------------------------------------------------------ reads
    def vlans(self) -> list[dict]:
        out = []
        for r in self._rows(VL + "/search_item"):
            try:
                tag = int(str(r.get("tag")))
            except ValueError:
                continue
            out.append({"uuid": str(r.get("uuid") or ""), "parent": str(r.get("if") or ""), "tag": tag,
                        "device": device_of(r.get("vlanif")), "descr": str(r.get("descr") or "")})
        return out

    def networks(self) -> list[str]:
        """Every IPv4 network the firewall's ports already have, so a new one never overlaps them."""
        out = []
        for r in self._ports():
            vals = r.get("addr4") if isinstance(r.get("addr4"), list) else [r.get("addr4")]
            for c in vals:
                try:
                    net = ipaddress.ip_interface(str(c)).network
                except ValueError:
                    continue
                if net.version == 4:
                    out.append(str(net))
        return out

    def parent(self, existing: list[dict], fallback: str) -> str:
        """The port the existing VLANs are on (all of them on one), else the Trusted Network's port."""
        parents = sorted({v["parent"] for v in existing if v["parent"]})
        if len(parents) == 1:
            return parents[0]
        if len(parents) > 1:
            raise we.WriteError("The firewall's VLANs are on more than one port (" + ", ".join(parents) + "), so Pazuzu "
                                "cannot tell which one to add to. Nothing was changed.")
        if not fallback or not _DEV.match(fallback):
            raise we.WriteError("No port is known for the Trusted Network, so there is nowhere to add the VLANs. "
                                "Nothing was changed.")
        return fallback

    def kea_on(self) -> bool:
        """Kea hands out the addresses here: its settings page answers and it is switched on."""
        try:
            _w, form = self._form(KEA + "/get")
        except we.WriteError:
            return False
        general = form.get("general") if isinstance(form, dict) else None
        return isinstance(general, dict) and str(_flat(general.get("enabled"))) in ("1", "true", "True")

    # ------------------------------------------------------------------ the plan (reads only)
    def port_form_ready(self) -> bool | None:
        """Can this firewall's own port form switch a port on and give it an address? True / False, or None when the
        form could not be read (the step itself then says what it finds). Reads only."""
        try:
            _wrapper, form = self._form(f"{AS}/get_item")
        except we.WriteError:
            return None
        return all(k in form for k in PORT_FORM_FIELDS)

    # -- BUILD 518 (the maintainer, live disc, 12 Nov 2026): rules part 1 said "IPv6 is off for the whole firewall" and the next
    # page still warned that IPv6 was on for the WAN; he set IPv6 Configuration Type to None by hand. That was the
    # plugin's job, and beta 1 has no plugin, so it is done here through the firewall's own port form.
    @staticmethod
    def ipv6_type_field(form: dict) -> tuple[str, str] | None:
        """(field, the key of its None choice) for the port form's IPv6 Configuration Type, found by what the firewall
        itself calls its choices (one of them is DHCPv6, one is None), not by a name taken on trust. None when this
        form has no such list."""
        for name, node in form.items():
            labels = we._option_labels(node)
            if not labels or not any(_V6_CHOICE.match(str(v).strip()) for v in labels.values()):
                continue
            none = next((k for k, v in labels.items() if str(k).lower() == "none" or str(v).strip().lower() == "none"), None)
            if none is not None:
                return str(name), str(none)
        return None

    def _ipv6_type_is_none(self, ident: str) -> bool | None:
        try:
            _w, form = self._form(f"{AS}/get_item/{ident}")
        except we.WriteError:
            return None
        found = self.ipv6_type_field(form)
        return None if found is None else we._selected_keys(form[found[0]]) == [found[1]]

    def ipv6_types_none(self, idents: Sequence[str] = ("wan", "lan"), polls: int = 5, apply_anyway: bool = False) -> dict:
        """Set IPv6 Configuration Type to None on these ports and Apply. {"changed", "already", "cannot"}: lists of the
        ports' names. A port whose form has no such list, or that the firewall would not save, is left as it was and
        named in "cannot". The change is judged by reading the form back, since Apply can lose its own answer while
        the ports are set up again."""
        out: dict = {"changed": [], "already": [], "cannot": []}
        backs: list[Callable[[], None]] = []
        for ident in idents:
            try:
                wrapper, form = self._form(f"{AS}/get_item/{ident}")
                found = self.ipv6_type_field(form)
                if found is None:
                    out["cannot"].append(ident)
                    continue
                field, none = found
                if we._selected_keys(form[field]) == [none]:
                    out["already"].append(ident)
                    continue
                _res, before = self._post_form(f"{AS}/set_item/{ident}", wrapper, form, {field: none},
                                               f"the {ident.upper()} port")
            except we.WriteError:
                out["cannot"].append(ident)
                continue

            def back(ident=ident, wrapper=wrapper, before=before) -> None:
                self._call("post", f"{AS}/set_item/{ident}", json={wrapper: before})
            backs.append(back)
            out["changed"].append(ident)
        if not out["changed"]:
            if apply_anyway and out["already"] and not out["cannot"]:
                # BUILD 535 (the maintainer, 13 Nov 2026, 26.7.9): saved as None by the plugin, whose own apply failed. Apply here.
                self._reconfigure(AS + "/reconfigure")
                out["applied"] = list(out["already"])
            return out
        self._reconfigure(AS + "/reconfigure")
        for _ in range(max(1, polls)):
            if all(self._ipv6_type_is_none(i) for i in out["changed"]):
                return out
            self.sleep(3)
        for b in reversed(backs):                    # not None when read back: put the ports' forms back as they were
            self._try_back(b)
        self._reconfigure(AS + "/reconfigure")
        out["cannot"] += out["changed"]
        out["changed"] = []
        return out

    def plan(self, zones: Sequence[str], trusted_device: str, ports: dict | None = None,
             in_use: Sequence[str] = (), wifi: dict | None = None, dhcp: str | None = None) -> Plan:  # type: ignore[override]
        """`zones` get a VLAN each; `ports` ({zone: device}) get that spare port, given a place on the firewall; `wifi`
        ({zone: {"card", "ssid", "passphrase"}}) get a Wi-Fi network of their own on that card, then a port for it.
        `dhcp` (BUILD 499, the maintainer: "ask each time", "guide them to the kea though"): on a firewall where dnsmasq hands
        out the addresses, "dnsmasq" keeps it and adds the new ranges there; anything else moves the handout to Kea."""
        ports = {z: d for z, d in (ports or {}).items() if z in PORT_ZONES and isinstance(d, str) and _DEV.match(d)}
        wifi = {z: w for z, w in (wifi or {}).items() if z in WIFI_ZONES and z not in ports and isinstance(w, dict)}
        for z, w in wifi.items():
            if not can_host(w.get("card")):
                raise we.WriteError(f"{w.get('card')} is not a Wi-Fi card this firewall can host a network on. Nothing was "
                                    "changed.")
            why = ssid_problem(w.get("ssid"))
            from pazuzu_core.ap_openwrt import passphrase_problem
            why = why or passphrase_problem(w.get("passphrase"))
            if why:
                raise we.WriteError(f"{WORDS[z]}: {why} Nothing was changed.")
        if len({w["card"] for w in wifi.values()}) != len(wifi):
            raise we.WriteError("The same Wi-Fi card was picked for two zones; each card hosts one network. Nothing was "
                                "changed.")
        want = [z for z in OFFERED if z in set(zones) and z not in ports and z not in wifi]
        if not want and not ports and not wifi:
            raise we.WriteError("Pick at least one zone to give a network of its own.")
        if len(set(ports.values())) != len(ports):
            raise we.WriteError("The same port was picked for two zones. Nothing was changed.")
        if wifi:
            clones = self._rows(WL + "/search_item")
            busy = {str(r.get("if") or "") for r in clones}
            for z, w in wifi.items():
                if w["card"] in busy:
                    raise we.WriteError(f"{w['card']} already has a Wi-Fi network on the firewall (Interfaces, Wireless), "
                                        "and it hosts only one. Nothing was changed.")
            ports.update({z: "" for z in wifi})            # given a port like a spare one, once the network exists
        if self.port_form_ready() is False:        # BUILD 515: said before anything is changed, not after three changes
            raise we.WriteError(OLD_PORT_FORM)
        existing = self.vlans()
        parent = self.parent(existing, trusted_device) if want else ""
        tags = pick_tags(len(want), [v["tag"] for v in existing], self.rng) if want else []
        order = [z for z in PORT_ZONES if z in ports] + want
        addrs = plan_addresses(order, avoid=self.networks() + [n for n, _u in self.kea_subnets()], rng=self.rng).by_zone()
        rows = self._ports()
        kea = self.kea_on()
        move = (self.kea_takeover(rows) if not kea and dhcp != "dnsmasq" and self.dnsmasq_on() and self.kea_readable()
                else None)
        if move is not None:
            kea = True
        server = "Kea" if kea else ("dnsmasq" if self.dnsmasq_on() else "")
        waiting = self._pending()
        made: list[dict] = []
        steps: list[Step] = []
        lines = ["Give " + ("these zones" if len(order) > 1 else "this zone") + " a network of its own"]
        if waiting:
            lines.append("Apply the interface changes that are already waiting on the firewall (Interfaces, Assignments)")
            steps.append(Step("tidy", lambda: self._do_tidy()))
        if move is not None:
            lines += move[0]
            steps += move[1]
        for zone in order:                          # what an earlier, unfinished try of Pazuzu's own left behind
            for left in self._leftovers(LABELS[zone], rows, existing, in_use):
                lines.append(f"Remove what an earlier try left for {WORDS[zone]}: " + left["what"])
                steps.append(Step("leftover", lambda x=left: self._drop_leftovers(x)))

        def pool_of(zone, a):
            if a.dhcp_start:
                return f"{a.dhcp_start}-{a.dhcp_end}"
            base = int(ipaddress.ip_network(a.network).network_address)
            return f"{ipaddress.ip_address(base + MGMT_POOL[0])}-{ipaddress.ip_address(base + MGMT_POOL[1])}"

        for zone in order:
            a = addrs[zone]
            facts = {"zone": zone, "tag": None, "parent": "", "label": LABELS[zone], "network": a.network,
                     "ip": a.firewall_ip, "pool": pool_of(zone, a), "device": "", "identifier": "", "uuid": ""}
            if zone in wifi:
                w = wifi[zone]
                ch = CHANNELS[sorted(wifi).index(zone) % len(CHANNELS)]
                facts.update(card=w["card"], ssid=w["ssid"], passphrase=w["passphrase"], channel=ch, wifi=True)
                lines.append(f"{WORDS[zone]}: its own Wi-Fi network \u201c{w['ssid']}\u201d on the card {w['card']} (2.4 GHz, "
                             f"WPA2, channel {ch}), called {facts['label']}, the firewall at {a.firewall_ip} on {a.network}"
                             + (f", addresses {facts['pool'].replace('-', ' to ')} handed out by {server}" if server else ""))
                steps.append(Step("wifi-ap", lambda f=facts: self._do_ap(f)))
                steps.append(Step("assign", lambda f=facts: self._do_port(f)))
            elif zone in ports:
                dev = ports[zone]
                row = next((r for r in rows if str(r.get("device")) == dev), None)
                if row is None and dev not in self._offered_ports():
                    raise we.WriteError(f"The firewall does not show the port {dev}. Plug it in, wait ten seconds and check "
                                        "again. Nothing was changed.")
                ident = str((row or {}).get("identifier") or "")
                if ident.lower() in ("wan", "lan"):
                    raise we.WriteError(f"{dev} is the firewall's {ident.upper()} port, so it was left alone. Nothing was changed.")
                if ident and str((row or {}).get("addr4") or "").strip():
                    raise we.WriteError(f"{dev} ({ident}) already has an address on the firewall, so it was left alone. Pick "
                                        "it on the ports page instead. Nothing was changed.")
                facts.update(device=dev, identifier=ident)
                lines.append(f"{WORDS[zone]}: the port {dev}" + (f" ({ident})" if ident else ", given a place on the firewall")
                             + f", called {facts['label']}, the firewall at {a.firewall_ip} on {a.network}"
                             + (f", addresses {facts['pool'].replace('-', ' to ')} handed out by {server}" if server else ""))
                steps.append(Step("assign", lambda f=facts: self._do_port(f)))
            else:
                tag = tags[want.index(zone)]
                facts.update(tag=tag, parent=parent)
                lines.append(f"{WORDS[zone]}: VLAN {tag} on {parent}, called {facts['label']}, the firewall at {a.firewall_ip} "
                             f"on {a.network}" + (f", addresses {facts['pool'].replace('-', ' to ')} handed out by {server}" if server else ""))
                steps.append(Step("vlan", lambda f=facts: self._do_vlan(f)))
                steps.append(Step("assign", lambda f=facts: self._do_port(f)))
            made.append(facts)
            if kea:
                steps.append(Step("dhcp", lambda f=facts: self._do_kea(f)))
            elif server:
                steps.append(Step("dhcp", lambda f=facts: self._do_range(f)))
        if not server:
            lines.append("The firewall hands out addresses with neither Kea nor dnsmasq, so no address handout is set up "
                         "for these: switch one on under Services, or give devices fixed addresses")
        if wifi:
            lines.append("Each Wi-Fi network uses the password you typed; it goes to the firewall and is kept nowhere else")
        if want:
            lines.append("The VLANs already there are not changed")
            lines.append("Your switch or access point needs the same VLAN numbers to carry these networks")
        lines.append("It uses the installer account, which can open every page")
        digest = plan_digest("zone-vlans", {"parent": parent, "zones": [(f["zone"], f["tag"], (f.get("card") or f["device"])
                                                                          if f["tag"] is None else "", f["network"],
                                                                          f.get("ssid") or "") for f in made],
                                            "kea": kea, "tidy": waiting})
        return Plan(steps, lines, digest, "", {"made": made, "parent": parent, "kea": kea})

    def apply(self, plan: Plan, gate: Callable[[str, Sequence[str]], bool]) -> list[Any]:
        if not gate(plan.digest, plan.lines):
            raise we.WriteError("Not approved with a passkey. Nothing was changed.")
        self.said = []
        return self._run(plan.steps)

    # ------------------------------------------------------------------ the steps
    def _do_vlan(self, f: dict) -> Callable[[], None]:
        wrapper, form = self._form(VL + "/get_item")
        res, _before = self._post_form(VL + "/add_item", wrapper, form,
                                       {"if": f["parent"], "tag": str(f["tag"]), "descr": f["label"]}, "the VLAN")
        uuid = str(res.get("uuid", ""))
        if not we._UUID.match(uuid):
            raise we.WriteError("The firewall saved the VLAN but did not say which row it is. Look at Interfaces, Devices, VLAN.")
        f["uuid"] = uuid

        def back() -> None:
            self._drop_vlan(uuid)
        if not self._reconfigure(VL + "/reconfigure"):
            self._try_back(back)
            raise we.WriteError("The firewall saved the VLAN but would not apply it. It was taken back.")
        _w, mine = self._form(f"{VL}/get_item/{uuid}")
        dev = str(_flat(mine.get("vlanif")) or "")
        if not _DEV.match(dev):
            dev = next((v["device"] for v in self.vlans() if v["uuid"] == uuid and _DEV.match(v["device"])), "")
        if not dev:
            self._try_back(back)
            raise we.WriteError("The firewall made the VLAN but did not say its device name, so it was taken back.")
        f["device"] = dev
        self.said.append(f"Made VLAN {f['tag']} on {f['parent']} ({dev}) for {WORDS[f['zone']]}.")
        return back

    def _leftovers(self, label: str, rows: list, vlans: list, in_use: Sequence[str] = ()) -> list:
        """An earlier try's own port and VLAN (both called `label`) that never got to the end. A port with that name on
        anything else is someone's own and is refused, plainly. One a zone is using is never a leftover: that zone
        already has its network, and nothing is changed."""
        out = []
        ours = {v["device"]: v for v in vlans if v["descr"] == label and v["device"]}
        busy = [d for d in ours if d in set(in_use)]
        if busy:
            raise we.WriteError(f"That zone already has its network ({', '.join(busy)}, called {label}), so nothing was "
                                "changed. Pick it on the ports page.")
        for r in rows:
            if str(r.get("description") or "") != label:
                continue
            dev, ident = str(r.get("device") or ""), str(r.get("identifier") or "")
            if dev not in ours:
                raise we.WriteError(f"A port called {label} is already on the firewall ({ident or dev}) and it is not one "
                                    "Pazuzu made, so it was left alone. Rename or remove it under Interfaces, Assignments. "
                                    "Nothing was changed.")
            out.append({"ident": ident, "device": dev, "uuid": ours.pop(dev)["uuid"],
                        "what": f"the port {ident} and VLAN {dev}"})
        for dev, v in ours.items():                 # a VLAN of ours with no port on it
            out.append({"ident": "", "device": dev, "uuid": v["uuid"], "what": f"VLAN {dev}"})
        return out

    def _drop_leftovers(self, x: dict) -> None:
        if x["ident"]:
            self._drop_port(x["ident"], x["device"])
        self._drop_vlan(x["uuid"])
        self.said.append(f"Removed {x['what']} left by an earlier try.")
        return None

    def _offered_ports(self) -> set:
        try:
            _w, form = self._form(f"{AS}/get_item")
        except we.WriteError:
            return set()
        return set(we._option_labels(form.get("if")) or {})

    def _do_ap(self, f: dict) -> Callable[[], None]:
        """The Wi-Fi network itself (Interfaces, Wireless): an access point on the card, WPA2 with the person's password,
        on its own channel. The firewall names the device (run0_wlan1); the port step then uses that name."""
        wrapper, form = self._form(f"{WL}/get_item")
        changes = {"if": f["card"], "mode": "hostap", "descr": f["label"], "ssid": f["ssid"], "use_common": "1",
                   "channel": str(f["channel"]), "wpa.enable": "1", "wpa.wpa_mode": "2", "wpa.wpa_key_mgmt": "WPA-PSK",
                   "wpa.wpa_pairwise": "CCMP", "wpa.passphrase": f["passphrase"]}
        res, _b = self._post_form(f"{WL}/add_item", wrapper, form, changes, "the Wi-Fi network",
                                  optional=("use_common", "channel", "wpa.wpa_pairwise"), free=("if", "channel"))
        uuid = str(res.get("uuid", ""))
        if not we._UUID.match(uuid):
            raise we.WriteError("The firewall saved the Wi-Fi network but did not say which one it is. Look at Interfaces, "
                                "Wireless.")

        def back() -> None:
            got = self._call("post", f"{WL}/del_item/{uuid}", json={})
            if not (isinstance(got, dict) and str(got.get("result")) == "deleted"):
                raise we.WriteError("The firewall would not remove the Wi-Fi network. Look at Interfaces, Wireless.")
            self._reconfigure(WL + "/reconfigure")
        row = next((r for r in self._rows(WL + "/search_item") if str(r.get("uuid")) == uuid), None)
        dev = str((row or {}).get("cloneif") or "")
        if not re.match(r"^[a-z]+\d{1,3}_wlan\d{1,3}$", dev):
            self._try_back(back)
            raise we.WriteError("The firewall made the Wi-Fi network but did not show its device name. It was taken back.")
        if not self._reconfigure(WL + "/reconfigure"):
            self._try_back(back)
            raise we.WriteError("The firewall saved the Wi-Fi network but would not apply it. It was taken back.")
        f["device"] = dev
        self.said.append(f"Made the Wi-Fi network \u201c{f['ssid']}\u201d on {f['card']} ({dev}).")
        return back

    def _do_port(self, f: dict) -> Callable[[], None]:
        if f.get("identifier"):                     # already has a place on the firewall, with no address: set it up there
            ident = f["identifier"]
            self._known(ident)
            put_back = self._change(f"{AS}/get_item/{ident}", f"{AS}/set_item/{ident}",
                                    {"descr": f["label"], "enable": "1", "type4": "staticv4", "ipaddr": f["ip"] + "/24"},
                                    "the port")

            def undo() -> None:
                put_back()
                self._reconfigure(AS + "/reconfigure")
            if not self._reconfigure(AS + "/reconfigure"):
                self._try_back(undo)
                raise we.WriteError("The firewall saved the port but would not apply it. It was put back.")
            self.said.append(f"Set up the port {f['device']} ({ident}, {f['label']}) with the firewall at {f['ip']}.")
            return undo
        wrapper, form = self._form(f"{AS}/get_item")
        self._post_form(f"{AS}/add_item", wrapper, form,
                        {"if": f["device"], "descr": f["label"], "enable": "1", "type4": "staticv4",
                         "ipaddr": f["ip"] + "/24"}, "the port")
        # The firewall's port form (26.7) has one address field and no separate mask: seen in its own form, which has
        # ipaddr but no subnet. The address is given with its mask, the way the form's other address fields take one.
        row = self._port(self._ports(), f["device"])
        if row is None or not re.match(r"^[a-z]+\d*$", str(row.get("identifier") or "")):
            raise we.WriteError("The firewall saved the port but did not show which one it is. Look at Interfaces, Assignments.")
        ident = f["identifier"] = str(row["identifier"])

        def back() -> None:
            self._drop_port(ident, f["device"])
        if not self._reconfigure(AS + "/reconfigure"):
            self._try_back(back)
            raise we.WriteError("The firewall saved the port but would not apply it. It was taken back.")
        self.said.append(f"Gave it a port ({ident}, {f['label']}) with the firewall at {f['ip']}.")
        return back

    def _drop_port(self, ident: str, device: str) -> None:
        """Take a port back off the firewall and apply that. Judged by what the firewall shows afterwards (the port gone
        from its list), not only by the word it answers with; when it is still there, its answer is said."""
        try:
            got = self._call("post", f"{AS}/del_item/{ident}", json={})
        except we.WriteError as exc:
            if "lock" not in str(exc).lower():
                raise
            # The firewall keeps a new port "locked" against removal by default: unlock it (its own form), then remove it.
            self._change(f"{AS}/get_item/{ident}", f"{AS}/set_item/{ident}", {"lock": "0"}, "the port")
            got = self._call("post", f"{AS}/del_item/{ident}", json={})
        self._reconfigure(AS + "/reconfigure")
        if self._port(self._ports(), device) is not None:
            raise we.WriteError(f"the firewall kept the port {ident} (it answered {str(got)[:120]})")

    def _drop_vlan(self, uuid: str) -> None:
        got = self._call("post", f"{VL}/del_item/{uuid}", json={})
        self._reconfigure(VL + "/reconfigure")
        if any(v["uuid"] == uuid for v in self.vlans()):
            raise we.WriteError(f"the firewall kept the VLAN (it answered {str(got)[:120]})")

    def _do_kea(self, f: dict) -> Callable[[], None]:
        wrapper, form = self._form(KEA + "/get_subnet")
        res, _b = self._post_form(KEA + "/add_subnet", wrapper, form,
                                  {"subnet": f["network"], "pools": f["pool"], "option_data.routers": f["ip"],
                                   "option_data.domain_name_servers": f["ip"], "description": f["label"],
                                   "option_data_autocollect": "0"},
                                  "the address handout", optional=("description", "option_data.domain_name_servers",
                                                                   "option_data_autocollect"),
                                  free=("option_data.routers", "option_data.domain_name_servers", "pools"))
        uuid = str(res.get("uuid", ""))
        if not we._UUID.match(uuid):
            raise we.WriteError("Kea saved the subnet but did not say which row it is. Look at Services, Kea DHCP, Subnets.")
        f["subnet_uuid"] = uuid
        undo_listen = self._kea_listen(f["identifier"])

        def back() -> None:
            if undo_listen is not None:
                undo_listen()
            got = self._call("post", f"{KEA}/del_subnet/{uuid}", json={})
            if not (isinstance(got, dict) and str(got.get("result")) == "deleted"):
                raise we.WriteError("Kea would not remove the subnet. Look at Services, Kea DHCP, Subnets.")
            self._reconfigure(KEA_APPLY)
        if not self._reconfigure(KEA_APPLY):
            self._try_back(back)
            raise we.WriteError("Kea saved the subnet but would not apply it. It was taken back.")
        self.said.append(f"Kea hands out {' and '.join(p.replace('-', ' to ') for p in f['pool'].splitlines())} there.")
        return back

    def kea_subnets(self) -> list[tuple[str, str]]:
        """Kea's own subnets, [(network, uuid)], read whether Kea is on or not. BUILD 498 (lab, 10 Nov 2026): Kea was off
        but still held a subnet for the LAN, so moving dnsmasq's LAN range over was refused ("Subnet must be unique")."""
        try:
            rows = self._rows(KEA + "/search_subnet")
        except we.WriteError:
            return []
        out = []
        for r in rows:
            try:
                out.append((str(ipaddress.ip_network(str(r.get("subnet") or "").strip(), strict=False)),
                            str(r.get("uuid") or "")))
            except ValueError:
                continue
        return out

    def kea_reserved(self) -> tuple[set, set]:
        """The addresses and hardware addresses Kea already has fixed: ({ip}, {hw})."""
        try:
            rows = self._rows(KEA + "/search_reservation")
        except we.WriteError:
            return set(), set()
        return ({str(r.get("ip_address") or "").strip() for r in rows} - {""},
                {str(r.get("hw_address") or "").strip().lower() for r in rows} - {""})

    def _use_kea(self, f: dict) -> Callable[[], None]:
        """Kea already has a subnet on this network: use it as it is, and only have Kea listen on the port."""
        f["subnet_uuid"] = f["existing_uuid"]
        undo_listen = self._kea_listen(f["identifier"])

        def back() -> None:
            if undo_listen is not None:
                undo_listen()
                self._reconfigure(KEA_APPLY)
        self.said.append(f"Kea already had a subnet for {f['network']}; it is used as it is.")
        return back

    def kea_readable(self) -> bool:
        try:
            self._form(KEA + "/get")
            return True
        except we.WriteError:
            return False

    def kea_takeover(self, rows: Sequence[dict]) -> tuple[list[str], list[Step], list[str]]:
        """Move the address handout from dnsmasq to Kea: (lines, steps, networks moved). Each dnsmasq range becomes a Kea
        subnet on the same network with the same pool (the firewall as router and name server); fixed addresses with a
        hardware address come along as Kea reservations; then dnsmasq's ranges are taken off (dnsmasq itself stays, for
        anything else it does) and Kea is switched on. Devices keep the address they have. Undo puts dnsmasq back."""
        ranges = self._rows(DNSMASQ + "/search_range")
        by_ident = {str(r.get("identifier") or ""): r for r in rows if isinstance(r, dict)}
        moves, lines, notes = [], [], []
        by_net: dict[str, dict] = {}
        for r in ranges:
            ident = str(r.get("interface") or "")
            got = _network_of(by_ident.get(ident) or {})
            start, end = str(r.get("start_addr") or ""), str(r.get("end_addr") or "")
            if not ident or got is None or not start or not end:
                notes.append(f"dnsmasq's range {start} to {end} ({ident or 'any port'}) is left with dnsmasq: it is not on "
                             "one port with its own network")
                continue
            # BUILD 506 (lab, factory 26.7, 11 Nov 2026: "Subnet must be unique" for 192.168.1.0/24 again): a factory
            # dnsmasq has two ranges on the LAN, its IPv4 one and an IPv6 one (::1000 to ::2000). Each became a Kea
            # subnet on the same network, and Kea refused the second. An IPv6 range is not Kea DHCPv4's: it stays with
            # dnsmasq. Two IPv4 ranges on one network become one subnet with both pools.
            try:
                v4 = ipaddress.ip_address(start).version == 4 and ipaddress.ip_address(end).version == 4
            except ValueError:
                v4 = False
            if not v4:
                notes.append(f"dnsmasq's IPv6 range on {ident.upper()} stays with dnsmasq")
                continue
            if got[0] in by_net:
                by_net[got[0]]["uuids"].append(str(r.get("uuid") or ""))
                by_net[got[0]]["pools"].append(f"{start}-{end}")
                continue
            x = {"uuid": str(r.get("uuid") or ""), "uuids": [str(r.get("uuid") or "")], "pools": [f"{start}-{end}"],
                 "identifier": ident, "network": got[0], "ip": got[1],
                 "label": f"{ident.upper()} (moved from dnsmasq by Pazuzu)", "zone": ident}
            by_net[got[0]] = x
            moves.append(x)
        for x in moves:
            x["pool"] = "\n".join(x["pools"])                    # Kea takes one pool per line
        if not moves:
            return (["dnsmasq hands out no addresses on a port of its own, so nothing is moved to Kea"] + notes, [], [])
        have = dict(self.kea_subnets())
        for x in moves:
            if have.get(x["network"]):
                x["existing_uuid"] = have[x["network"]]
        known_ip, known_hw = self.kea_reserved()
        try:
            hosts = self._rows(DNSMASQ + "/search_host")
        except we.WriteError:
            hosts = []
        keep = []
        for h in hosts:
            ip, hw = str(h.get("ip") or "").strip(), str(h.get("hwaddr") or "").strip().lower()
            m = next((x for x in moves if ip and ipaddress.ip_address(ip) in ipaddress.ip_network(x["network"])), None) \
                if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip or "") else None
            if m and (ip in known_ip or hw in known_hw):
                notes.append(f"The fixed address {ip} is already in Kea, so it is left as Kea has it")
            elif m and re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", hw):
                keep.append({"ip": ip, "hw": hw, "name": _host_label(h.get("host")), "move": m,
                             "descr": str(h.get("descr") or "")[:200]})
            elif ip:
                notes.append(f"The fixed address {ip} stays with dnsmasq (it has no hardware address to carry over)")
        lines.append("Move the address handout from dnsmasq to Kea, OPNsense's newer DHCP server. Devices keep the address "
                     "they have")
        for x in moves:
            if x.get("existing_uuid"):
                lines.append(f"{x['identifier'].upper()} ({x['network']}): Kea already has a subnet for it, so that one is "
                             "used as it is (Services, Kea DHCP, Subnets)")
                continue
            lines.append(f"{x['identifier'].upper()} ({x['network']}): Kea hands out "
                         f"{' and '.join(p.replace('-', ' to ') for p in x['pools'])}, as "
                         f"dnsmasq did, with the firewall ({x['ip']}) as router and name server")
        if keep:
            lines.append(f"{len(keep)} fixed address(es) come along to Kea")
        lines += notes
        steps = [Step("dnsmasq-ranges-off", lambda: self._ranges_off([u for x in moves for u in x["uuids"]]))]
        steps += [Step("dhcp", lambda f=x: (self._use_kea(f) if f.get("existing_uuid") else self._do_kea(f))) for x in moves]
        if keep:
            steps.append(Step("kea-reservations", lambda: self._do_reservations(keep)))
        steps.append(Step("kea-on", self._kea_on))
        return lines, steps, [x["network"] for x in moves]

    def _ranges_off(self, uuids: Sequence[str]) -> Callable[[], None]:
        """dnsmasq's ranges that Kea takes over are taken off (read first, so Undo adds them back exactly)."""
        kept = []
        for u in uuids:
            if not we._UUID.match(u):
                continue
            wrapper, form = self._form(f"{DNSMASQ}/get_range/{u}")
            kept.append((wrapper, {k: _flat(v) for k, v in form.items()}))
            got = self._call("post", f"{DNSMASQ}/del_range/{u}", json={})
            if not (isinstance(got, dict) and str(got.get("result")) == "deleted"):
                raise we.WriteError("dnsmasq would not let go of its range. Nothing more was changed.")

        def back() -> None:
            for wrapper, body in kept:
                res = self._call("post", f"{DNSMASQ}/add_range", json={wrapper: body})
                if not (isinstance(res, dict) and str(res.get("result")) == "saved"):
                    raise we.WriteError("dnsmasq would not take its range back. Look at Services, Dnsmasq DNS & DHCP.")
            self._reconfigure(DNSMASQ_APPLY)
        if not self._reconfigure(DNSMASQ_APPLY):
            self._try_back(back)
            raise we.WriteError("dnsmasq would not apply the change. It was put back.")
        self.said.append("dnsmasq no longer hands out addresses on those ports; Kea does.")
        return back

    def _do_reservations(self, keep: Sequence[dict]) -> Callable[[], None]:
        made = []
        for k in keep:
            sub = k["move"].get("subnet_uuid") or ""
            wrapper, form = self._form(KEA + "/get_reservation")
            res, _b = self._post_form(KEA + "/add_reservation", wrapper, form,
                                      {"subnet": sub, "ip_address": k["ip"], "hw_address": k["hw"], "hostname": k["name"],
                                       "description": k["descr"] or "moved from dnsmasq by Pazuzu"},
                                      "a fixed address", optional=("hostname", "description"),
                                      free=("subnet",))
            uuid = str(res.get("uuid", ""))
            if we._UUID.match(uuid):
                made.append(uuid)

        def back() -> None:
            for u in made:
                self._call("post", f"{KEA}/del_reservation/{u}", json={})
            self._reconfigure(KEA_APPLY)
        self.said.append(f"{len(made)} fixed address(es) moved to Kea.")
        return back

    def _kea_on(self) -> Callable[[], None]:
        wrapper, form = self._form(KEA + "/get")
        general = form.get("general") if isinstance(form, dict) else {}
        was = str(_flat((general or {}).get("enabled")) or "0")
        res = self._call("post", KEA + "/set", json={wrapper: {"general": {"enabled": "1"}}})
        self._saved(res, "Kea's on switch")

        def back() -> None:
            got = self._call("post", KEA + "/set", json={wrapper: {"general": {"enabled": was}}})
            self._saved(got, "Kea's on switch")
            self._reconfigure(KEA_APPLY)
        if not self._reconfigure(KEA_APPLY) or not self.kea_on():
            self._try_back(back)
            raise we.WriteError("Kea did not start. Everything was put back, so dnsmasq hands out addresses as before.")
        self.said.append("Kea is on and hands out the addresses.")
        return back

    def dnsmasq_on(self) -> bool:
        """dnsmasq hands out the addresses here (the stock server on a new firewall): its page answers and it is on."""
        try:
            _w, form = self._form(DNSMASQ + "/get")
        except we.WriteError:
            return False
        return str(_flat(form.get("enable") if isinstance(form, dict) else "")) in ("1", "true", "True")

    def _dnsmasq_listen(self, ident: str) -> Callable[[], None] | None:
        """dnsmasq set to answer on chosen ports only (a new firewall: LAN) is told to answer on this one too. Returns what
        puts the list back, or None when it answers everywhere already (nothing to change)."""
        wrapper, form = self._form(DNSMASQ + "/get")
        node = form.get("interface") if isinstance(form, dict) else None
        labels = we._option_labels(node)
        picked = [k for k, v in (node or {}).items() if isinstance(v, dict) and str(v.get("selected")) in ("1", "True", "true")] \
            if labels is not None else [x for x in str(_flat(node) or "").split(",") if x]
        if not picked or ident in picked:
            return None
        if labels is not None and ident not in labels:
            raise we.WriteError(f"dnsmasq does not offer {ident} to answer on. Look at Services, Dnsmasq DNS & DHCP.")
        return self._change(DNSMASQ + "/get", DNSMASQ + "/set", {"interface": ",".join(picked + [ident])},
                            "dnsmasq's ports", free=("interface",))

    def _do_range(self, f: dict) -> Callable[[], None]:
        """A dnsmasq range on the zone's port (the pool in the middle of its network), dnsmasq answering there."""
        start, end = f["pool"].split("-")
        undo_listen = self._dnsmasq_listen(f["identifier"])
        wrapper, form = self._form(DNSMASQ + "/get_range")
        try:
            res, _b = self._post_form(DNSMASQ + "/add_range", wrapper, form,
                                      {"interface": f["identifier"], "start_addr": start, "end_addr": end,
                                       "description": "Pazuzu: " + WORDS.get(f["zone"], f["zone"])},
                                      "the address handout", optional=("description",), free=("start_addr", "end_addr"))
        except we.WriteError:
            if undo_listen is not None:
                self._try_back(undo_listen)
            raise
        uuid = str(res.get("uuid", ""))
        if not we._UUID.match(uuid):
            raise we.WriteError("dnsmasq saved the range but did not say which row it is. Look at Services, Dnsmasq.")

        def back() -> None:
            self._call("post", f"{DNSMASQ}/del_range/{uuid}", json={})
            if undo_listen is not None:
                undo_listen()
            self._reconfigure(DNSMASQ_APPLY)
        if not self._reconfigure(DNSMASQ_APPLY):
            self._try_back(back)
            raise we.WriteError("dnsmasq saved the range but would not apply it. It was taken back.")
        self.said.append(f"{WORDS.get(f['zone'], f['zone'])}: dnsmasq hands out {start} to {end}.")
        return back

    def _kea_listen(self, ident: str) -> Callable[[], None] | None:
        """Add the port to the ones Kea listens on (its own pick-list). Returns what puts the list back."""
        wrapper, form = self._form(KEA + "/get")
        general = form.get("general") if isinstance(form, dict) else None
        node = general.get("interfaces") if isinstance(general, dict) else None
        labels = we._option_labels(node)
        if labels is None or ident not in labels:
            raise we.WriteError(f"Kea does not offer {ident} to listen on. Look at Services, Kea DHCP, Settings.")
        was = [k for k, v in node.items() if isinstance(v, dict) and str(v.get("selected")) in ("1", "True", "true")]
        if ident in was:
            return None
        res = self._call("post", KEA + "/set", json={wrapper: {"general": {"interfaces": ",".join(was + [ident])}}})
        self._saved(res, "the ports Kea listens on")

        def back() -> None:
            got = self._call("post", KEA + "/set", json={wrapper: {"general": {"interfaces": ",".join(was)}}})
            self._saved(got, "the ports Kea listens on")
        return back
