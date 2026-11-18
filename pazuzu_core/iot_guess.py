"""Devices on the Trusted Network that look like smart devices, so the person can move them to the IoT network.

Only a suggestion, from the maker of the device's network card (the first half of its hardware address, from the
makers' list the app already carries) and its name. Makers that sell mostly smart-home gear are listed below; a maker
that also sells phones and computers (Apple, Samsung, Google) is only suggested when the name says what it is. Nothing is
moved: the person joins the device to the IoT Wi-Fi (or plugs it into the IoT port) themselves.
"""
from __future__ import annotations

import re
from typing import Callable, Sequence

# Makers whose network cards are almost always in smart-home gear: plugs, bulbs, cameras, speakers, hubs, TVs.
MAKERS = ("espressif", "tuya", "shelly", "allterco", "belkin", "wemo", "philips lighting", "signify", "lifx",
          "sonos", "roku", "ring", "wyze", "ecobee", "nest labs", "irobot", "hikvision", "dahua", "amcrest", "reolink",
          "meross", "govee", "tp-link", "tplink", "kasa", "lutron", "chamberlain", "myq", "eufy", "anker", "arlo",
          "ezviz", "yeelight", "broadlink", "silicon labs", "hui zhou gaoshengda", "amazon technologies", "sengled",
          "leedarson", "midea", "vizio")
# Chip makers found in laptops and phones as well (Realtek, Intel, Murata, AzureWave...) are left out on purpose: they
# would flag ordinary computers. Those devices are suggested only when their name says what they are.
# Words in a device's own name that say what it is.
WORDS = re.compile(r"(?<![a-z])(plug|bulb|light|lamp|cam|camera|doorbell|ring|echo|alexa|nest|thermostat|tv|roku|chromecast|"
                   r"firetv|fire-tv|speaker|sonos|homepod|hub|bridge|hue|switch|sensor|vacuum|roomba|printer|esp|tasmota|"
                   r"shelly|wemo|kasa|tuya|smart|iot|garage|lock|radio|feeder|purifier|fan|appliance|washer|dryer|fridge)",
                   re.I)


def looks_smart(name: str, maker: str) -> str:
    """Why it looks like a smart device ("" when it does not)."""
    m = (maker or "").lower()
    if any(re.search(r"(^|[^a-z])" + re.escape(k) + r"($|[^a-z])", m) for k in MAKERS):
        return f"made by {maker}"
    w = WORDS.search(name or "")
    if w:
        return f"its name says {w.group(1).lower()}"
    return ""


def suggest(clients: Sequence[dict], trusted: Sequence[str], maker_of: Callable[[str], str]) -> list[dict]:
    """[{ip, mac, name, maker, why}] for the devices on the Trusted Network's port(s) that look like smart devices."""
    out = []
    for c in clients or []:
        if not isinstance(c, dict) or str(c.get("iface") or "") not in set(trusted):
            continue
        maker = maker_of(str(c.get("mac") or "")) or str(c.get("vendor") or "")
        why = looks_smart(str(c.get("name") or ""), maker)
        if why:
            out.append({"ip": str(c.get("ip") or ""), "mac": str(c.get("mac") or ""), "name": str(c.get("name") or ""),
                        "maker": maker, "why": why})
    return out
