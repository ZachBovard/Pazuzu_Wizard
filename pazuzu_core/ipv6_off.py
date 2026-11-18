"""Switch IPv6 off for the whole firewall, as the first thing the finish page does.

Why first: on the firewalls this was flown against, a firewall that picked up an IPv6 address stopped answering the
person, and the console's "assign interfaces" (used after a USB adapter moves) turns DHCPv6 back on for the WAN
without saying so. So the run starts by ticking the firewall-wide "Turn off IPv6" box (disableipv6 = 1),
reads it back, and only then carries on with the rules.

It is the same one setting the older console tool (ipv6_execution) changes, written the same way: read all the
settings, change that one value, save, apply, read back; if any step fails the saved settings are put back.
Nothing here touches a rule or an address. The whole run is already approved as one plan, so this does not ask again.
"""
from __future__ import annotations

from pazuzu_core import ipv6_execution as ix
from pazuzu_core.egress_drift import ipv6_allowance
from pazuzu_core.write_engine import WriteError

BASE = "/api/interfaces/settings"

LINE = "Turn IPv6 off for the whole firewall (Interfaces, Settings, the Turn off IPv6 box). This goes first."
IFACES_LINE = "Set the IPv6 Configuration Type to None on the WAN and the LAN (Interfaces, the WAN or LAN, then Save and Apply)."
BY_HAND = ("Do it on the firewall: Interfaces, Settings, tick Turn off IPv6, then Save and Apply. "
           "(After you re-assign ports at the console, also set the WAN's IPv6 Configuration Type to None.)")


class _Client:
    """The three calls ipv6_execution makes, over the write engine's own request method."""

    def __init__(self, engine):
        self.e = engine

    def _call(self, name, method, path, **kw):
        try:
            return self.e._req(method, BASE + path, **kw)
        except WriteError as exc:
            raise WriteError(f"{name}: {exc}") from exc

    def get_settings(self):
        return self._call("read", "get", "/get")

    def set_settings(self, body):
        return self._call("save", "post", "/set", json=body)

    def reconfigure(self, body):
        return self._call("apply", "post", "/reconfigure", json=body)


def state(engine) -> str | None:
    """"on" (IPv6 is allowed), "off", or None when the setting could not be read."""
    try:
        off = ipv6_allowance(_Client(engine).get_settings())
    except WriteError:
        return None
    return None if off is None else ("off" if off else "on")


def turn_off(engine) -> dict:
    """Switch it off and read it back. Returns ipv6_execution's answer; raises ExecutionFailed with a plain reason."""
    try:
        return ix.execute_disable_ipv6(_Client(engine), approved=True)
    except ix.ExecutionFailed:
        raise
    except WriteError as exc:
        raise ix.ExecutionFailed(str(exc)) from exc
