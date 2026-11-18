"""Who the firewall asks when a device looks up a name.

The firewall answers every lookup itself and asks one upstream resolver on the devices' behalf.
Three public ones are offered, and the person picks. The choice is only recorded here: pointing the
firewall's resolver at it is a change made later, by the manager, once the setting has been read back
and confirmed on the version in use. Nothing in this file touches a firewall.

The one-line descriptions say only what each provider says about itself.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

CHOICES_FILE = "choices.json"


@dataclass(frozen=True)
class Resolver:
    id: str
    name: str
    says: str
    servers: tuple[str, ...]


RESOLVERS: tuple[Resolver, ...] = (
    Resolver("quad9", "Quad9",
             "A non-profit. Blocks known-malicious sites. Says it does not store your address.",
             ("9.9.9.9", "149.112.112.112")),
    Resolver("opendns", "OpenDNS",
             "Run by Cisco. Widely used and fast, with its own filtering options.",
             ("208.67.222.222", "208.67.220.220")),
    Resolver("cloudflare", "Cloudflare",
             "Very fast. Publishes a privacy commitment. Its 1.1.1.1 address is also the one used for troubleshooting tests.",
             ("1.1.1.1", "1.0.0.1")),
)

BY_ID = {r.id: r for r in RESOLVERS}

CHECK_LINES = (
    "From a computer on your network: nslookup example.com <your firewall's address>",
    "It should answer. Then try nslookup example.com 8.8.8.8 (an outside server). That should fail: devices may only ask the firewall.",
)


def options() -> list[dict]:
    return [{"id": r.id, "name": r.name, "says": r.says, "servers": list(r.servers)} for r in RESOLVERS]


def load(key_dir) -> str | None:
    from pazuzu_core import choices_file
    choice = choices_file.read(key_dir).get("resolver")      # under the shared lock (10 Nov 2026)
    return choice if choice in BY_ID else None


def save(key_dir, choice: str) -> str:
    if choice not in BY_ID:
        raise ValueError("That is not one of the choices.")
    from pazuzu_core import choices_file
    choices_file.update(key_dir, lambda data: data.__setitem__("resolver", choice))
    return choice
