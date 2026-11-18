"""Last safety check on concrete rules, just before they are created.

The manifest validator is the first line of defence; this is the second.
It looks at what the translator actually produced, so a gap in the
validator, or in the translator, cannot put a forbidden rule on the
firewall. Pure function, no I/O.

Refused:
    * a rule whose description is not a managed ("PAZUZU:") description;
    * a rule created enabled (the smoke deployment creates disabled rules);
    * an allow rule on the WAN interface (inbound WAN allow), except the one
      exact shape of the VPN's tunnel-port rule, created disabled (see
      is_tunnel_port_rule);
    * an allow rule from anywhere to anywhere on any protocol.

Exposing a service from the DMZ will one day need an explicit, approved
path. That path will be a separate, named parameter, not a loosening of
these checks.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

MANAGED_PREFIX = "PAZUZU:"
TUNNEL_PORT_PREFIX = "PAZUZU:PZ-WG-002:"


def _flag(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes"}


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip().lower()


def is_tunnel_port_rule(rule: Mapping[str, Any]) -> bool:
    """The only allow rule that may sit on the WAN: one UDP port, to the firewall itself, off.

    It is the VPN's own port. Everything has to match: the managed id PZ-WG-002, a pass rule,
    UDP, one numeric port, the firewall itself as destination, and created disabled. Any
    difference and it is an ordinary inbound WAN allow, which is refused.
    """
    port = _text(rule.get("destination_port"))
    return (
        str(rule.get("description") or "").startswith(TUNNEL_PORT_PREFIX)
        and _text(rule.get("action")) == "pass"
        and _text(rule.get("protocol")) == "udp"
        and port.isdigit() and 1 <= int(port) <= 65535
        and _text(rule.get("destination_net")) == "(self)"
        and _text(rule.get("destination_not")) in {"", "0", "false"}
        and not _flag(rule.get("enabled"))
    )


def check_concrete_rules(
    rules: Iterable[Mapping[str, Any]],
    *,
    wan_interface: str | None,
    allow_enabled: bool = False,
) -> tuple[str, ...]:
    wan_names = {"wan"}
    if wan_interface:
        wan_names.add(_text(wan_interface))

    problems: list[str] = []

    for rule in rules:
        description = str(rule.get("description") or "")
        label = description or "(rule without a description)"
        action = _text(rule.get("action"))

        if not description.startswith(MANAGED_PREFIX):
            problems.append(f"{label}: description is not a managed description")

        if not allow_enabled and _flag(rule.get("enabled")):
            problems.append(f"{label}: would be created enabled")

        if (action == "pass" and _text(rule.get("interface")) in wan_names
                and not is_tunnel_port_rule(rule)):
            problems.append(f"{label}: allow rule on the WAN interface")

        if (
            action == "pass"
            and _text(rule.get("source_net")) in {"", "any", "*"}
            and _text(rule.get("destination_net")) in {"", "any", "*"}
            and _text(rule.get("protocol")) in {"", "any"}
            and _text(rule.get("destination_port")) in {"", "any"}
        ):
            problems.append(f"{label}: allow rule from anywhere to anywhere")

    return tuple(problems)
