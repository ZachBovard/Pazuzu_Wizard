"""Keep the plugin reachable when the stock allow-all rules are switched off.

The plugin on the firewall listens on one of the firewall's own addresses, for the computer that runs the manager.
Until the stock "allow everything" rules go, that works with no rule of its own. After they go, the network the
plugin listens on needs one: this adds a single pass rule on that network's port, from that network to the
firewall itself, for the plugin's one port. No other network gets it, and it is not a management rule: it only
lets the manager's computer talk to the plugin, and the plugin still needs its token.
Nothing in this file touches a firewall; the write engine does.
"""
from __future__ import annotations

DESCRIPTION = "Pazuzu: let this network reach the Pazuzu plugin"
SEQUENCE = "9"


def rule_values(interface: str, port: int) -> dict[str, str]:
    """In the firewall's own words: its API names a whole network by the interface name alone ("lan" is the LAN
    network, "lanip" its address). The form "lannet" is the packet filter's own macro and the API refuses it."""
    return {"enabled": "1", "sequence": SEQUENCE, "action": "pass", "interface": interface, "direction": "in",
            "ipprotocol": "inet", "protocol": "TCP", "source_net": interface, "destination_net": "(self)",
            "destination_port": str(port), "log": "0", "description": DESCRIPTION}


def build_plans(engine, address: str, port: int) -> list:
    """The one plan, or [] when the rule is already there or the address is on none of the firewall's networks.
    `address` is where the plugin listens."""
    interface = engine.interface_for(address)
    if not interface:
        return []
    if getattr(engine, "exists", lambda *a: False)("fw_rule", DESCRIPTION):
        return []
    return [engine.build("fw_rule", rule_values(interface, port))]


def manual_fields(interface: str | None, port: int) -> list[list[str]]:
    """The same rule as the firewall's own form shows it, for a person who would rather add it by hand
    (Firewall > Rules > the network's tab > Add). Pairs of [label, value]."""
    where = interface or "the network the plugin's address is on"
    return [["Action", "Pass"], ["Interface", where], ["Direction", "in"], ["TCP/IP version", "IPv4"],
            ["Protocol", "TCP"], ["Source", f"{interface} net" if interface else "that network's net"],
            ["Destination", "This Firewall"], ["Destination port range", f"{port} to {port}"],
            ["Description", DESCRIPTION]]
