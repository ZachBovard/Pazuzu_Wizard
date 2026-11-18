"""Short tips, in plain words, shown where a person is most likely to wonder.

Each says one thing. A tip is advice about how the product behaves, never a promise about safety.
Draft wording: to be reviewed.
"""

from __future__ import annotations

TIPS: tuple[dict[str, str], ...] = (
    {"id": "blocklist_allow", "title": "Allowing something a list blocks",
     "text": "If you allow something a block list stopped, that choice is yours."},
    {"id": "passkey", "title": "Changes and your passkey",
     "text": "Every change asks for your passkey. Looking at things never does."},
    {"id": "pause", "title": "Testing with blocking paused",
     "text": "Pause blocking for 15 seconds to test. It switches back on by itself."},
    {"id": "no_admin_pw", "title": "Your main password",
     "text": "Pazuzu makes its own limited users, so it never needs your main password again."},
    {"id": "dns_test", "title": "If names stop working",
     "text": "To test name lookups, ask your firewall first. Outside servers are blocked on purpose; for a quick test use 1.1.1.1 or 1.0.0.1."},
    {"id": "upnp", "title": "Game console says strict NAT",
     "text": "UPnP and NAT-PMP are off on purpose. Devices can't open their own doors in your firewall."},
    {"id": "ports", "title": "Your two ports",
     "text": "Your firewall's page and secure shell use their own numbers. Write them down."},
    {"id": "iot", "title": "Smart devices and your computers",
     "text": "Smart devices can't be reached from your computers until you allow it, one device and one service at a time."},
    {"id": "discovery", "title": "Casting and printer discovery",
     "text": "Devices on different networks don't find each other on their own. You can allow a specific device, but searching for devices doesn't cross."},
    {"id": "ipv6", "title": "IPv6",
     "text": "IPv6 is off everywhere. If it is turned back on, the status goes to Not Happy and stays there."},
    {"id": "new_network", "title": "On another network",
     "text": "If your firewall isn't where it used to be, press Find my firewall."},
)
