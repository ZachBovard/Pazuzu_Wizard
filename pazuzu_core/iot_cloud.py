"""What smart devices on the IoT network need from the internet that the baseline's web-only rule does not give them,
given to them internet-only: never your home networks. Read and planned here; made by "Finish getting to Happy".

Found on a production firewall, 30 Oct 2026, from its own block log (each a device that had stopped working):
  - Govee lights and AWS IoT devices talk MQTT on TCP 8883; the Govee app on a phone on the home network does too
    (its "IoT Access Anomaly" banner)
  - Ring: TCP 9998 (events) and 8557 (video link); live video is UDP to a port that changes every session
  - ecobee: TCP 8190
  - a 3D printer's cloud (a Bouffalo Lab chip): TCP 8816
  - Tuya plugs and bulbs: TCP 8886 (their MQTT), four of them the afternoon the first list went in
So:
  1. a port list, IoT_cloud_ports, and one rule from the IoT network to anything that is not a home network on it
  2. the Govee app's MQTT (8883) from the home network, internet only
  3. doorbells and cameras recognised by the name they give DHCP (Ring calls itself "ring-" and the end of its hardware
     address), put on a hardware-address list, IoT_cameras, with one rule letting UDP out to the internet from it.
     Never a maker prefix: Ring's 34:15:13 is Texas Instruments, the maker of its Wi-Fi chip, used by other gadgets too.
A list or rule a person made by hand with the same name counts as there (prod's were made by hand first, the same day).
"""
from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

PORTS = (("8883", "MQTT: Govee, AWS IoT"), ("8886", "MQTT: Tuya plugs and bulbs"), ("9998", "Ring events"),
         ("8557", "Ring video link"), ("8190", "ecobee"), ("8816", "3D printer cloud"))
ALIAS = "IoT_cloud_ports"
CAM_ALIAS = "IoT_cameras"
SEQ = "21"                                   # ahead of the baseline's blocks, like the VPN's (22) and quarantine (2)
RULE_IOT = "Pazuzu: IoT cloud links (internet only)"
RULE_APP = "Pazuzu: Govee app MQTT (internet only)"
RULE_CAM = "Pazuzu: camera live video (internet only)"
SAME_AS = {RULE_CAM: ("Pazuzu: Ring live video (internet only)",)}      # the hand-made one counts
CAMERA_NAMES = (re.compile(r"^ring-[0-9a-f]{4,12}$", re.I),)             # Ring doorbells and cameras
_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def port_alias_values(ports: Iterable[str]) -> dict:
    return {"enabled": "1", "name": ALIAS, "type": "port", "content": "\n".join(ports),
            "description": "Pazuzu: IoT cloud ports (" + ", ".join(w for _p, w in PORTS) + ")"}


def cam_alias_values(macs: Iterable[str]) -> dict:
    return {"enabled": "1", "name": CAM_ALIAS, "type": "mac", "content": "\n".join(macs),
            "description": "Pazuzu: doorbells and cameras (recognised by name)"}


def rule_values(kind: str, iface: str, net: str = "") -> dict:
    """The three rules. `iface` is the firewall's short name for the port (opt2, lan); `net` the network (CIDR)."""
    base = {"enabled": "1", "sequence": SEQ, "action": "pass", "interface": iface, "direction": "in",
            "ipprotocol": "inet", "destination_net": "private_networks", "destination_not": "1", "log": "0"}
    if kind == "iot":
        return {**base, "protocol": "TCP", "source_net": net, "destination_port": ALIAS, "description": RULE_IOT}
    if kind == "app":
        return {**base, "protocol": "TCP", "source_net": net, "destination_port": "8883", "description": RULE_APP}
    return {**base, "protocol": "UDP", "source_net": CAM_ALIAS, "description": RULE_CAM}


def _list(content: Any) -> list[str]:
    """An alias's content as the firewall lists it ("8816,8883" or one per line), as clean strings."""
    if isinstance(content, (list, tuple)):
        parts = content
    else:
        parts = re.split(r"[,\n]", str(content or ""))
    return [str(p).strip().lower() for p in parts if str(p).strip()]


def cameras(clients: Any, names: Mapping[str, str] | None = None) -> list[str]:
    """The hardware addresses of the devices that call themselves a doorbell or camera, by their DHCP name or the
    firewall's lookup name, sorted."""
    names = names or {}
    out = set()
    for c in clients if isinstance(clients, list) else []:
        if not isinstance(c, Mapping):
            continue
        mac = str(c.get("mac") or "").lower()
        nm = str(c.get("name") or names.get(str(c.get("ip") or "")) or "").split(".")[0]
        if _MAC.match(mac) and any(p.match(nm) for p in CAMERA_NAMES):
            out.add(mac)
    return sorted(out)


def state(aliases: Any, rules: Any, cams: list[str], have_lan: bool) -> dict:
    """What is there and what is not, read only. `aliases` and `rules` are the firewall's search rows.
    {"ports_missing": [port], "alias": bool, "rules_missing": [kind], "cams": [mac], "cams_missing": [mac],
     "cam_alias": bool}"""
    by_name = {str(a.get("name")): a for a in aliases or [] if isinstance(a, Mapping)}
    have_rules = {str(r.get("description") or r.get("descr") or "") for r in rules or []
                  if isinstance(r, Mapping) and str(r.get("enabled", "1")) not in ("0", "false")}
    alias = by_name.get(ALIAS)
    in_alias = _list(alias.get("content")) if alias else []
    cam = by_name.get(CAM_ALIAS)
    in_cam = _list(cam.get("content")) if cam else []
    wanted_rules = [("iot", RULE_IOT)] + ([("app", RULE_APP)] if have_lan else []) + ([("cam", RULE_CAM)] if cams else [])
    missing_rules = [k for k, d in wanted_rules if d not in have_rules and not any(x in have_rules for x in SAME_AS.get(d, ()))]
    return {"ports_missing": [p for p, _w in PORTS if p not in in_alias], "alias": alias is not None,
            "alias_ports": in_alias, "rules_missing": missing_rules, "cams": cams,
            "cams_missing": [m for m in cams if m not in in_cam], "cam_alias": cam is not None, "cam_macs": in_cam}


def done(st: Mapping) -> bool:
    return not (st.get("ports_missing") or st.get("rules_missing") or st.get("cams_missing"))


def findings(st: Mapping) -> list[str]:
    out = []
    if st.get("ports_missing"):
        words = dict(PORTS)
        out.append("Not let out yet: " + ", ".join(f"{p} ({words[p]})" for p in st["ports_missing"]) + ". Devices that "
                   "need them stay offline in their apps")
    if "iot" in (st.get("rules_missing") or []):
        out.append("No rule lets the IoT network reach its devices' clouds on those ports")
    if "app" in (st.get("rules_missing") or []):
        out.append("The Govee app on your home network cannot reach its cloud (MQTT, 8883)")
    if st.get("cams_missing") or "cam" in (st.get("rules_missing") or []):
        out.append("A doorbell or camera cannot send live video (" + ", ".join(st.get("cams_missing") or st.get("cams") or [])
                   + ")")
    return [f + ". Finish getting to Happy (Normal) adds it, internet only, never your home networks" for f in out]


def lines(todo: Mapping) -> list[str]:
    """The passkey screen's words."""
    st = todo.get("iot_cloud") or {}
    out = []
    if st.get("ports_missing") or "iot" in (st.get("rules_missing") or []):
        out.append("Let smart devices reach their clouds, internet only: " + ", ".join(f"{p} ({w})" for p, w in PORTS))
    if "app" in (st.get("rules_missing") or []):
        out.append("Let the Govee app on your home network reach its cloud (MQTT 8883), internet only")
    if st.get("cams_missing") or "cam" in (st.get("rules_missing") or []):
        out.append("Let doorbells and cameras send live video (UDP), internet only: " + ", ".join(st.get("cams") or []))
    return out
