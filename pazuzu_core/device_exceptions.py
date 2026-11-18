"""Letting the home network reach one smart device, one service at a time.

By default nothing on the home network (trusted) can reach the smart-device network (iot):
the baseline has no rule that allows it. This turns one person's choice, "my computers may
reach this device for printing", into a rule in the same shape as the baseline's own, so it
goes through the same translation, the same safety gate and the same guarded switch-on.

Pure: nothing here touches a firewall or a file.

What an exception is, deliberately small:
  * one device, by its address (a single IPv4 address on a private network, never a range);
  * one service from a short menu (never "everything", never a free-form port list);
  * the whole home network as the source. Narrowing it to one computer is a later change.

Discovery (finding a printer, casting to a TV) uses multicast, which does not cross between
networks. An exception lets a known device be reached; it does not make devices findable.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Iterable

SOURCE_ZONE = "trusted"
FIRST_PRIORITY = 520        # after the baseline's own trusted rules (500, 510), before the WAN rules (900)
LAST_PRIORITY = 599
MAX_EXCEPTIONS = LAST_PRIORITY - FIRST_PRIORITY + 1

# id -> (what the person sees, the services it opens)
SERVICES: dict[str, tuple[str, tuple[str, ...]]] = {
    "web": ("Its web page", ("tcp/80", "tcp/443")),
    "printing": ("Printing", ("tcp/631", "tcp/9100")),
    "ssh": ("Secure shell", ("tcp/22",)),
    "mqtt": ("Smart-home messages (MQTT)", ("tcp/1883", "tcp/8883")),
    "home_assistant": ("Home Assistant", ("tcp/8123",)),
}


@dataclass(frozen=True)
class DeviceException:
    device: str
    service: str
    note: str = ""


def validate(exc: DeviceException, existing: Iterable[DeviceException] = ()) -> list[str]:
    """Why this exception is not allowed. Empty means it is."""
    problems: list[str] = []
    if exc.service not in SERVICES:
        problems.append("Choose one of the listed services.")
    try:
        addr = ipaddress.ip_address(str(exc.device).strip())
    except ValueError:
        problems.append("Type the device's address as numbers, for example 192.168.20.14.")
        return problems
    if addr.version != 4:
        problems.append("Only IPv4 addresses are used here.")
    elif not addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast \
            or addr.is_unspecified or str(addr).endswith(".255") or str(addr).endswith(".0"):
        problems.append("That is not an address a device on your network would have.")
    if str(exc.device) != str(addr):
        problems.append("Type the address with no spaces, no range and no extra characters.")
    if len(exc.note) > 80:
        problems.append("Keep the note under 80 characters.")
    if any(c in exc.note for c in "\r\n\t<>\"'\\"):
        problems.append("The note may not contain quotes, angle brackets or line breaks.")
    for other in existing:
        if other.device == exc.device and other.service == exc.service:
            problems.append("That is already allowed.")
    if len(list(existing)) >= MAX_EXCEPTIONS:
        problems.append("That is the most exceptions there is room for.")
    return problems


def to_rule(index: int, exc: DeviceException) -> dict:
    """The exception as a manifest-shaped rule. `index` counts from 0."""
    problems = validate(exc)
    if problems:
        raise ValueError(" ".join(problems))
    if not 0 <= index < MAX_EXCEPTIONS:
        raise ValueError("No room for another exception.")
    title = SERVICES[exc.service][0]
    return {
        "action": "allow",
        "destination": [str(ipaddress.ip_address(exc.device))],
        "direction": "in",
        "enabled": True,
        "log": False,
        "name": f"Home network to {exc.device}: {title.lower()}" + (f" ({exc.note})" if exc.note else ""),
        "object_id": f"PZ-X-{index + 1:03d}",
        "object_type": "firewall_rule",
        "ownership": "pazuzu_managed",
        "priority": FIRST_PRIORITY + index,
        "schema_version": "0.4",
        "services": list(SERVICES[exc.service][1]),
        "source": [SOURCE_ZONE],
    }


def to_rules(exceptions: Iterable[DeviceException]) -> list[dict]:
    done: list[DeviceException] = []
    rules = []
    for exc in exceptions:
        problems = validate(exc, done)
        if problems:
            raise ValueError(" ".join(problems))
        rules.append(to_rule(len(done), exc))
        done.append(exc)
    return rules
