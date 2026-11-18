"""Every zone's network hands out addresses: a DHCP range for each port or VLAN a zone is on.

What the firewall already has is read first: Kea's subnets (when Kea hands out addresses), else dnsmasq's DHCP ranges.
A zone network that already has one is left exactly as it is. One that has none gets one, from the firewall's own
empty form: Kea a subnet (the firewall's address as router and name server, a pool, and Kea told to listen there),
dnsmasq a range on that port. The pool is the middle of the network (.100 to .199 on a /24), leaving room for fixed
addresses below and above. The internet side and the VPN never get one. Each step can be taken back.

Kea's own subnets (described "PZ_...") are also kept whole: one that hands out no router or no name server gets the
firewall's own address there for both (with Kea's "auto collect" switched off for it, so the values it was given are
the ones it hands out), and one whose network is on none of the firewall's ports any more (left over from an earlier
try) is removed. Subnets of the person's own are never changed.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Callable, Sequence

from pazuzu_core import write_engine as we
from pazuzu_core.passkey_gate import plan_digest
from pazuzu_core.wifi_backup import Plan, Step
from pazuzu_core.zone_vlans import DNSMASQ, DNSMASQ_APPLY, KEA, KEA_APPLY, LABELS, ZoneVlans  # noqa: F401

SKIP = ("wan", "wireguard_admin")
WORDS = {"management": "Management", "trusted": "Trusted Network", "iot": "Smart devices", "guest": "Guests", "kids": "KidsNet",
         "dmz": "Public servers", "quarantine": "Quarantine"}


def network_of(row: dict) -> tuple[str, str] | None:
    """(network, firewall address) of a port, from the firewall's interface overview row; None without an IPv4 one."""
    vals = row.get("addr4") if isinstance(row.get("addr4"), list) else [row.get("addr4")]
    for c in vals:
        try:
            iface = ipaddress.ip_interface(str(c))
        except ValueError:
            continue
        if iface.version == 4:
            return str(iface.network), str(iface.ip)
    return None


def pool_for(network: str) -> str | None:
    """The handout range: .100 to .199 of a /24 (or bigger, its first /24's); the middle half of a smaller one."""
    net = ipaddress.ip_network(network)
    if net.prefixlen > 29:
        return None                                       # too small to hand anything out
    base = int(net.network_address)
    if net.prefixlen <= 24:
        return f"{ipaddress.ip_address(base + 100)}-{ipaddress.ip_address(base + 199)}"
    size = net.num_addresses
    return f"{ipaddress.ip_address(base + size // 4)}-{ipaddress.ip_address(base + (3 * size) // 4 - 1)}"


def _plain(v: Any) -> str:
    if isinstance(v, dict):
        picked = [k for k, x in v.items() if isinstance(x, dict) and str(x.get("selected")) in ("1", "True", "true")]
        return ",".join(picked) if picked else ""
    if isinstance(v, list):
        return ",".join(str(x) for x in v)
    return "" if v is None else str(v)


def kea_details(getter: Callable[[str], Any]) -> list[dict] | None:
    """[{"uuid", "subnet", "label", "routers", "dns", "auto"}] for each Kea subnet, from its own form. None when it
    could not be read."""
    try:
        rows = (getter(KEA + "/search_subnet?rowCount=-1&searchPhrase=") or {}).get("rows")
    except Exception:
        return None
    if not isinstance(rows, list):
        return None
    out = []
    for r in rows[:48]:
        uuid = str(r.get("uuid") or "") if isinstance(r, dict) else ""
        if not we._UUID.match(uuid):
            continue
        try:
            body = getter(KEA + "/get_subnet/" + uuid)
        except Exception:
            return None
        form = next(iter(body.values()), None) if isinstance(body, dict) and len(body) == 1 else None
        if not isinstance(form, dict):
            return None
        od = form.get("option_data") if isinstance(form.get("option_data"), dict) else {}
        out.append({"uuid": uuid, "subnet": _plain(form.get("subnet")), "label": _plain(form.get("description")),
                    "routers": _plain(od.get("routers")), "dns": _plain(od.get("domain_name_servers")),
                    "auto": _plain(form.get("option_data_autocollect")) in ("1", "true", "True")})
    return out


def _networks(ports: Sequence[dict]) -> list[tuple[Any, str]]:
    out = []
    for r in ports:
        if isinstance(r, dict):
            got = network_of(r)
            if got:
                out.append((ipaddress.ip_network(got[0]), got[1]))
    return out


def _net(text: str):
    try:
        return ipaddress.ip_network(str(text), strict=False)
    except ValueError:
        return None


def incomplete(details: Sequence[dict], ports: Sequence[dict]) -> list[dict]:
    """Pazuzu's own subnets (PZ_...) on a firewall port that hand out no router or no name server:
    [{"uuid", "subnet", "label", "ip"}] (ip: the firewall's address there)."""
    nets = _networks(ports)
    out = []
    for d in details:
        if not str(d.get("label") or "").startswith("PZ_") or (d.get("routers") and d.get("dns")):
            continue
        n = _net(d.get("subnet"))
        ip = next((a for net, a in nets if n is not None and net == n), "")
        if ip:
            out.append({"uuid": d["uuid"], "subnet": d["subnet"], "label": d["label"], "ip": ip})
    return out


def strays(details: Sequence[dict], ports: Sequence[dict]) -> list[dict]:
    """Pazuzu's own subnets (PZ_...) whose network is on none of the firewall's ports: [{"uuid", "subnet", "label"}]."""
    nets = [net for net, _a in _networks(ports)]
    out = []
    for d in details:
        n = _net(d.get("subnet"))
        if str(d.get("label") or "").startswith("PZ_") and n is not None and not any(n.overlaps(x) for x in nets):
            out.append({"uuid": d["uuid"], "subnet": d["subnet"], "label": d["label"]})
    return out


def missing(zones: dict, ports: Sequence[dict], kea_subnets: Sequence[str] | None, ranges: Sequence[str] | None) -> list[dict]:
    """The zone networks with no handout: [{"zone", "device", "identifier", "network", "ip"}]. `zones` is {zone: device};
    `kea_subnets` the networks Kea serves (None when Kea is not the one handing out), `ranges` the ports dnsmasq serves."""
    out = []
    by_dev = {str(r.get("device")): r for r in ports if isinstance(r, dict)}
    served = []
    for s in kea_subnets or []:
        try:
            served.append(ipaddress.ip_network(str(s), strict=False))
        except ValueError:
            pass
    for zone, dev in zones.items():
        if zone in SKIP or not dev:
            continue
        row = by_dev.get(str(dev))
        if not row or not str(row.get("identifier") or ""):
            continue
        got = network_of(row)
        if got is None:
            continue
        net = ipaddress.ip_network(got[0])
        has = any(net.overlaps(s) for s in served) if kea_subnets is not None else str(row["identifier"]) in set(ranges or [])
        if not has:
            out.append({"zone": zone, "device": str(dev), "identifier": str(row["identifier"]),
                        "network": got[0], "ip": got[1]})
    return out


def _flat_keep(node: Any) -> Any:
    from pazuzu_core.wifi_backup import _flat
    return _flat(node)


class ZoneDhcp(ZoneVlans):
    def _kea_subnets(self) -> list[str]:
        return [str(r.get("subnet") or "") for r in self._rows(KEA + "/search_subnet")]

    def _dnsmasq_ranges(self) -> list[str] | None:
        try:
            return [str(r.get("interface") or "") for r in self._rows(DNSMASQ + "/search_range")]
        except we.WriteError:
            return None

    def plan(self, zones: dict) -> Plan:  # type: ignore[override]
        kea = self.kea_on()
        move = None
        if not kea and self.dnsmasq_on() and self.kea_readable():      # Kea is the one Pazuzu uses: move to it first
            move = self.kea_takeover(self._ports())
            if move[1]:
                kea = True
            else:
                move = None
        ranges = None if kea else self._dnsmasq_ranges()
        if not kea and ranges is None:
            raise we.WriteError("The firewall hands out addresses with neither Kea nor dnsmasq, so there is nothing to add "
                                "the ranges to. Switch one on under Services, then try again. Nothing was changed.")
        ports = self._ports()
        details = (kea_details(lambda p: self._call("get", p)) or []) if kea else []
        fill = incomplete(details, ports) if kea else []
        drop = strays(details, ports) if kea else []
        live = [d["subnet"] for d in details if d["uuid"] not in {x["uuid"] for x in drop}] + (move[2] if move else [])
        todo = missing(zones, ports, live if kea else None, ranges)
        if not (todo or fill or drop or move):
            raise we.WriteError("Every zone's network already hands out addresses, with the firewall as router and name "
                                "server. Nothing was changed.")
        steps: list[Step] = list(move[1]) if move else []
        lines = ["Hand out addresses on every zone's network (" + ("Kea" if kea else "dnsmasq") + ")"] + (move[0] if move else [])
        for t in todo:
            pool = pool_for(t["network"])
            if pool is None:
                lines.append(f"{WORDS.get(t['zone'], t['zone'])}: {t['network']} is too small to hand out addresses; left alone")
                continue
            f = dict(t, pool=pool, label=LABELS.get(t["zone"], "PZ_" + t["zone"].title()))
            lines.append(f"{WORDS.get(t['zone'], t['zone'])} ({t['device']}, {t['network']}): addresses "
                         f"{pool.replace('-', ' to ')}, the firewall ({t['ip']}) as router and name server")
            steps.append(Step("dhcp", lambda x=f: self._do_kea(x)) if kea else Step("dhcp", lambda x=f: self._do_range(x)))
        for x in fill:
            lines.append(f"{x['label']} ({x['subnet']}): hand out the firewall ({x['ip']}) as router and name server")
            steps.append(Step("dhcp-fill", lambda y=x: self._do_fill(y)))
        for x in drop:
            lines.append(f"{x['label']} ({x['subnet']}): left over from an earlier try, on none of the firewall's ports; "
                         "remove it")
            steps.append(Step("dhcp-drop", lambda y=x: self._do_drop(y)))
        if not steps:
            raise we.WriteError("No zone network is big enough to hand out addresses. Nothing was changed.")
        lines.append("Networks of your own are not changed")
        lines.append("It uses the installer account, which can open every page")
        return Plan(steps, lines, plan_digest("zone-dhcp", {"kea": kea, "move": move[2] if move else [],
                                                            "todo": [(t["zone"], t["network"]) for t in todo],
                                                            "fill": [x["uuid"] for x in fill],
                                                            "drop": [x["uuid"] for x in drop]}),
                    "", {"todo": todo, "kea": kea, "fill": fill, "drop": drop})

    def _subnet_form(self, uuid: str) -> tuple[str, dict]:
        return self._form(f"{KEA}/get_subnet/{uuid}")

    def _do_fill(self, x: dict) -> Callable[[], None]:
        """The firewall's address as router and name server on one of Pazuzu's subnets, read back."""
        wrapper, form = self._subnet_form(x["uuid"])
        od = form.get("option_data") if isinstance(form.get("option_data"), dict) else {}
        was = {"routers": _plain(od.get("routers")), "domain_name_servers": _plain(od.get("domain_name_servers"))}
        body: dict = {"option_data": {"routers": x["ip"], "domain_name_servers": x["ip"]}}
        undo: dict = {"option_data": dict(was)}
        if "option_data_autocollect" in form:
            undo["option_data_autocollect"] = "1" if _plain(form.get("option_data_autocollect")) in ("1", "true", "True") else "0"
            body["option_data_autocollect"] = "0"
        res = self._call("post", f"{KEA}/set_subnet/{x['uuid']}", json={wrapper: body})
        if not (isinstance(res, dict) and str(res.get("result")) == "saved"):
            raise we.WriteError(f"Kea did not save the router for {x['subnet']}. Nothing more was changed.")

        def back() -> None:
            got = self._call("post", f"{KEA}/set_subnet/{x['uuid']}", json={wrapper: undo})
            if not (isinstance(got, dict) and str(got.get("result")) == "saved"):
                raise we.WriteError(f"Kea would not put {x['subnet']} back. Look at Services, Kea DHCP, Subnets.")
            self._reconfigure(KEA_APPLY)
        _w, now = self._subnet_form(x["uuid"])
        nod = now.get("option_data") if isinstance(now.get("option_data"), dict) else {}
        if _plain(nod.get("routers")) != x["ip"] or _plain(nod.get("domain_name_servers")) != x["ip"]:
            self._try_back(back)
            raise we.WriteError(f"Kea saved {x['subnet']} but read back without the router or name server, so it was put "
                                "back. Look at Services, Kea DHCP, Subnets.")
        if not self._reconfigure(KEA_APPLY):
            self._try_back(back)
            raise we.WriteError("Kea saved the router but would not apply it. It was taken back.")
        self.said.append(f"{x['label']}: Kea now hands out the firewall ({x['ip']}) as router and name server.")
        return back

    def _do_drop(self, x: dict) -> Callable[[], None]:
        """Remove one of Pazuzu's own subnets that is on none of the firewall's ports. Undo adds it back as it was."""
        wrapper, form = self._subnet_form(x["uuid"])
        keep = {k: _flat_keep(v) for k, v in form.items()}
        got = self._call("post", f"{KEA}/del_subnet/{x['uuid']}", json={})
        if not (isinstance(got, dict) and str(got.get("result")) == "deleted"):
            raise we.WriteError(f"Kea would not remove {x['subnet']}. Nothing more was changed.")

        def back() -> None:
            res = self._call("post", f"{KEA}/add_subnet", json={wrapper: keep})
            if not (isinstance(res, dict) and str(res.get("result")) == "saved"):
                raise we.WriteError(f"Kea would not add {x['subnet']} back. Look at Services, Kea DHCP, Subnets.")
            self._reconfigure(KEA_APPLY)
        left = [d for d in (kea_details(lambda p: self._call("get", p)) or []) if d["uuid"] == x["uuid"]]
        if left:
            raise we.WriteError(f"Kea said {x['subnet']} was removed, but it is still listed. Look at Services, Kea DHCP.")
        if not self._reconfigure(KEA_APPLY):
            self._try_back(back)
            raise we.WriteError("Kea removed the leftover but would not apply it. It was put back.")
        self.said.append(f"{x['label']} ({x['subnet']}): the leftover subnet was removed.")
        return back
