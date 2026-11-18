"""Where each device belongs, and the devices that should be cut off now. Read and planned here; the moves are the
person's (a device is moved by joining it to the right network), the quarantine goes through the existing quarantine
list with the passkey. BUILD 431.

The box says what a device is (hanbi_box.device_kind, from Zenarmor's store, the maker and the name) and what it has
been doing (zen evidence). The manager knows where it sits (the zone of its address) and whether a port forward points
at it. From those:

  kind      -> zone it belongs in
  phone, computer      Trusted
  smart, hub, media,   IoT (a hub gets "home to it" allows there; a printer is argued about, IoT with an allow works)
  printer, camera
  server               DMZ (anything a forward points at is a server, whatever else it looks like)
  network              wherever it is (an access point or switch serves the zone it sits in)
  unknown              no recommendation, except on Trusted, where "who is this?" is asked

A device the person has named ("you said the Samsung is a phone") keeps that word: it is stored by hardware address
and wins over every guess.

Quarantine is never automatic (the person's own rule: a passkey for every change). It is offered at the top of the
board, red, with the evidence, when:
  - a device on an isolated network (IoT, Guest, DMZ) opened connections to many other inside addresses (probing),
  - any device reached malware-class app categories, or kept reaching blocked countries from inside,
  - a device nobody knows (no name, no maker, nothing from Zenarmor) turned up on the Trusted network.
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping

ZONE_FOR = {"phone": "trusted", "computer": "trusted", "smart": "iot", "hub": "iot", "media": "iot", "printer": "iot",
            "camera": "iot", "server": "dmz"}
ZONE_WORDS = {"trusted": "Trusted Network", "iot": "IoT network", "dmz": "DMZ", "guest": "Guest network",
              "quarantine": "Quarantine", "management": "Management"}
KIND_WORDS = {"phone": "a phone or tablet", "computer": "a computer", "server": "a server", "media": "a TV or media box",
              "smart": "a smart device", "camera": "a camera or doorbell", "hub": "a hub", "printer": "a printer",
              "network": "an access point or switch", "unknown": "not known yet"}
PROBE_TARGETS = 8                 # distinct inside addresses one device opened connections to: probing
BAD_APPS = ("malware", "botnet", "command and control", "c2", "crypto mining", "cryptomining", "mining", "phishing",
            "exploit", "tor")
COUNTRY_BLOCKS = 20               # connections to blocked countries, from inside, before it is worth a word


def kind_of(device: Mapping, said: Mapping[str, str] | None = None) -> tuple[str, str]:
    """The device's kind: what the person said, else what the box worked out."""
    mac = str(device.get("mac") or "").lower()
    if said and mac in said and said[mac]:
        return said[mac], "you said so"
    return str(device.get("kind") or "unknown"), str(device.get("kind_why") or "")


def recommend(kind: str, zone: str | None, forward: bool = False) -> dict:
    """{"zone": the zone it belongs in or "", "move": bool, "why"}. `zone` is where it sits now (a zone key, or None
    when the manager cannot place it)."""
    if forward:
        kind = "server"
    want = ZONE_FOR.get(kind, "")
    if kind == "network":
        return {"zone": "", "move": False, "why": "an access point or switch serves the network it sits in"}
    if kind == "unknown":
        if zone == "trusted":
            return {"zone": "", "move": False, "why": "nobody knows what this is, and it is on your Trusted Network: say what it is, or quarantine it"}
        return {"zone": "", "move": False, "why": ""}
    if not want:
        return {"zone": "", "move": False, "why": ""}
    if zone is None:
        return {"zone": want, "move": False, "why": f"belongs on the {ZONE_WORDS[want]}; where it sits now could not be told"}
    if zone == want or (zone == "quarantine"):
        return {"zone": want, "move": False, "why": ""}
    if want == "dmz" and forward:
        return {"zone": want, "move": True, "why": f"a port forward points at it from the internet, so it is a server and belongs on the {ZONE_WORDS[want]}, not your {ZONE_WORDS.get(zone, zone)}"}
    return {"zone": want, "move": True, "why": f"{KIND_WORDS.get(kind, kind)} belongs on the {ZONE_WORDS[want]}, and it is on your {ZONE_WORDS.get(zone, zone)}"}


def how_to_move(want: str, connection: str, port_words: str = "") -> str:
    """What the person does: the move is theirs. `connection` is "wired", "wifi" or "" (not known)."""
    where = ZONE_WORDS.get(want, want)
    if connection == "wifi":
        return f"Join it to the {where}'s Wi-Fi (the network's QR code is under Settings, Wi-Fi); it keeps everything else."
    if connection == "wired":
        return (f"Plug it into the {where}'s port" + (f" ({port_words})" if port_words else "")
                + ". Through a switch, the switch port has to carry that network instead.")
    return f"Join it to the {where}: its Wi-Fi (QR under Settings, Wi-Fi), or that network's port if it is wired."


def quarantine_offers(devices: Iterable[Mapping], zone_of, said: Mapping[str, str] | None = None,
                      held: Iterable[str] = ()) -> list[dict]:
    """[{mac, name, why, kind}] for the devices worth cutting off now, worst first. `zone_of(device)` gives the zone key
    or None; `held` the hardware addresses already on the quarantine list."""
    held = {str(h).lower() for h in held}
    out = []
    for d in devices:
        if not isinstance(d, Mapping):
            continue
        mac = str(d.get("mac") or "").lower()
        if not mac or mac in held or not d.get("here", True):
            continue
        zen = d.get("zen") if isinstance(d.get("zen"), Mapping) else {}
        zone = zone_of(d)
        kind, _why = kind_of(d, said)
        name = str(d.get("name") or zen.get("name") or d.get("vendor") or d.get("ip") or mac)
        score, why = 0, ""
        targets = int(zen.get("local_targets") or 0)
        if zone in ("iot", "guest", "dmz") and targets >= PROBE_TARGETS and kind not in ("network", "hub"):
            score, why = 3, f"opened connections to {targets} different devices inside your house from the {ZONE_WORDS[zone]}: that is probing, not a smart device at work"
        apps = [a for a, _n in (zen.get("apps") or []) if any(b in str(a).lower() for b in BAD_APPS)]
        if apps:
            score, why = max(score, 4), f"reached {', '.join(apps)} traffic, which Zenarmor classes as malicious"
        if int(zen.get("blocked") or 0) >= COUNTRY_BLOCKS and kind in ("unknown",) and zone in ("iot", "guest"):
            score, why = max(score, 2), f"kept being blocked ({zen.get('blocked')} times) and nobody knows what it is"
        if (kind == "unknown" and zone == "trusted" and not d.get("name") and not zen):
            score, why = max(score, 1), "turned up on your Trusted Network with no name and nothing known about it"
        if score:
            out.append({"mac": mac, "name": name, "kind": kind, "why": why, "score": score})
    return sorted(out, key=lambda o: (-o["score"], o["name"]))


def clean_kind(value: Any) -> str:
    v = str(value or "").strip().lower()
    if v in ("", "none", "clear", "forget"):
        return ""
    if v not in ZONE_FOR and v not in ("network", "unknown"):
        raise ValueError("That is not one of the kinds: phone, computer, server, media, smart, camera, hub, printer, network.")
    return v
