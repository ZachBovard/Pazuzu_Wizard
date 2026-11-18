"""Pick random management ports. Pure functions: nothing here touches the firewall.

Each install gets its own web GUI port and its own SSH port, so neither sits
on the usual scan lists (443, 22, 8443, ...). The plan is intent only. Applying
it means changing the firewall's listen settings, the management rules in the
manifest, the API base URL and the printed page together; `describe_changes`
lists exactly what has to move so nothing is changed halfway.

Ports are drawn from the registered range below the operating system's
ephemeral range, so they never collide with outgoing connections.
"""

from __future__ import annotations

import secrets
from urllib.parse import urlsplit
from dataclasses import dataclass
from typing import Callable, Iterable

LOW = 10240
HIGH = 49151          # FreeBSD's ephemeral range starts at 49152
MAX_TRIES = 500

# Ports that are the first thing a scanner or a tired admin tries.
AVOID = frozenset({
    22, 80, 443, 2222, 2200, 3000, 3128, 4443, 5000, 5900, 8000, 8008, 8080,
    8081, 8088, 8443, 8444, 8888, 9000, 9090, 9443, 10000, 12345, 22222,
    31337, 41641, 4242,
})


@dataclass(frozen=True)
class PortPlan:
    gui: int
    ssh: int


def _default_rng(low: int, high: int) -> int:
    return low + secrets.randbelow(high - low + 1)


def _usable(port: int, reserved: frozenset[int]) -> bool:
    return (
        LOW <= port <= HIGH
        and port not in AVOID
        and port not in reserved
        and port % 100 != 0        # round numbers are guessed first
    )


def plan_management_ports(
    *,
    reserved: Iterable[int] = (),
    rng: Callable[[int, int], int] | None = None,
) -> PortPlan:
    """Two different ports, neither avoided nor already in use.

    `reserved` is every port already in use on the box (listeners, aliases,
    forwards). `rng(low, high)` is injectable for tests; the default is the
    operating system's secure random source.
    """
    draw = rng or _default_rng
    taken = frozenset(int(p) for p in reserved)
    picked: list[int] = []
    for _ in range(MAX_TRIES):
        port = draw(LOW, HIGH)
        if _usable(port, taken) and port not in picked:
            picked.append(port)
            if len(picked) == 2:
                return PortPlan(gui=picked[0], ssh=picked[1])
    raise ValueError("could not find two free management ports")


def validate_port_plan(plan: PortPlan, reserved: Iterable[int] = ()) -> list[str]:
    taken = frozenset(int(p) for p in reserved)
    errors = []
    for name, port in (("gui", plan.gui), ("ssh", plan.ssh)):
        if not isinstance(port, int) or isinstance(port, bool):
            errors.append(f"{name} port must be a whole number")
        elif not _usable(port, taken):
            errors.append(f"{name} port {port} is outside the range, avoided or in use")
    if plan.gui == plan.ssh:
        errors.append("gui and ssh ports must differ")
    return errors


def describe_changes(plan: PortPlan) -> list[dict[str, str]]:
    """Everything that must change together when the plan is applied."""
    errors = validate_port_plan(plan)
    if errors:
        raise ValueError("; ".join(errors))
    return [
        {"target": "firewall web GUI listen port", "change": f"443 to {plan.gui}"},
        {"target": "firewall SSH listen port", "change": f"22 to {plan.ssh}"},
        {"target": "manifest rule PZ-MGMT-010 (block other management access)",
         "change": f"destination port 443 to {plan.gui}"},
        {"target": "lifeline rules (floating, to the firewall)",
         "change": f"https 443 to {plan.gui}, ssh 22 to {plan.ssh}"},
        {"target": "API base URL used by the tools and the plugin",
         "change": f"add port {plan.gui}"},
        {"target": "final informational page and the printed copy",
         "change": "show both ports"},
    ]


def printed_page_lines(plan: PortPlan, host: str) -> list[str]:
    """What the wizard's closing page shows about management access."""
    errors = validate_port_plan(plan)
    if errors:
        raise ValueError("; ".join(errors))
    if not host or any(c.isspace() or c in "/\\'\"<>" for c in host):
        raise ValueError("host must be a plain address or name")
    return [
        f"Manage your firewall at https://{host}:{plan.gui}",
        f"Secure shell, if you turn it on, uses port {plan.ssh}",
    ]


def gui_port_from_base_url(base_url: str | None) -> int | None:
    """The web GUI port the firewall is actually reached on, from the address in use.

    None unless the address is https to a real host with an explicit port other than 443. A
    loopback address (an SSH tunnel or a local test server) says nothing about the port the
    firewall itself listens on, and plain http is never a firewall. A port that is not a plain
    number in range is ignored.
    """
    try:
        parts = urlsplit(str(base_url or ""))
        port = parts.port
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or not host or host == "localhost" or host.startswith("127.") or host == "::1":
        return None
    if port is None or port == 443 or not 1 <= port <= 65535:
        return None
    return port


def with_gui_port(groups: dict[str, list[str]], port: int | None) -> dict[str, list[str]]:
    """A copy of the service groups whose management group follows the port in use.

    The management rules (PZ-MGMT-001, -002, -010) are written for tcp/443. When the firewall's
    web GUI answers on another port, the rules must name that port, or the lifeline would not
    cover the page the person actually uses. Nothing else in the groups changes.
    """
    out = {name: list(members) for name, members in groups.items()}
    if port is not None and "firewall_management" in out:
        out["firewall_management"] = [f"tcp/{port}"]
    return out


PLAN_FILE = "ports.json"


def load_or_create_plan(key_dir, reserved: Iterable[int] = (),
                        rng: Callable[[int, int], int] | None = None) -> PortPlan:
    """The install's two planned ports, drawn once and kept in the key folder.

    Drawing is random but the answer is stable: the same install always shows the same ports,
    so the page, the printed copy and a later apply all agree. Planning changes nothing on the
    firewall. A saved file that no longer validates (hand-edited, or a port since taken) is
    replaced by a fresh draw.
    """
    import json
    from pathlib import Path

    path = Path(key_dir) / PLAN_FILE
    try:
        saved = json.loads(path.read_text(encoding="utf-8"))
        plan = PortPlan(gui=saved["gui"], ssh=saved["ssh"])
        if not validate_port_plan(plan, reserved):
            return plan
    except (OSError, ValueError, KeyError, TypeError):
        pass
    plan = plan_management_ports(reserved=reserved, rng=rng)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"gui": plan.gui, "ssh": plan.ssh, "state": "planned"}), encoding="utf-8")
    return plan
