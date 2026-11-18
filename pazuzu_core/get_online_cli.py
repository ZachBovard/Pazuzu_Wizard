"""Run the get-online check against the live firewall (read only).

Asks the one question first: "what connects you to the internet?" from the
provider list, then checks the WAN for that kind of connection. Skip the
question with --profile <id> (for example generic_dhcp). --region sets the
country list (default US).
"""

from __future__ import annotations

import argparse
import sys

from pazuzu_core.get_online import check_wan
from pazuzu_core.isp_profile import NOT_LISTED, PROFILES, wan_choices


def pick(region: str, ask=input, say=print):
    """Returns (profile or None, connection type)."""
    choices = wan_choices(region)
    say("What connects you to the internet?")
    for i, c in enumerate(choices, 1):
        say(f"  {i}. {c.label}" + ("" if c.verified or c.profile_id == NOT_LISTED
                                   else "  (not yet tested)"))
    while True:
        raw = ask("Type a number: ").strip()
        if raw.isdigit() and 1 <= int(raw) <= len(choices):
            chosen = choices[int(raw) - 1]
            break
        say("Please type one of the numbers above.")
    if chosen.profile_id == NOT_LISTED:
        say("Assuming automatic setup (DHCP), the most common kind.")
        return None, "dhcp"
    profile = PROFILES[chosen.profile_id]
    return profile, profile.connection_types[0]


def report(verdict, profile, say=print) -> int:
    say(("OK: " if verdict.ok else "NOT YET: ") + verdict.say)
    for i, step in enumerate(verdict.next, 1):
        say(f"  {i}. {step}")
    if not verdict.ok and profile is not None:
        for tip in profile.troubleshooting:
            say(f"  Tip: {tip}")
    return 0 if verdict.ok else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", choices=sorted(PROFILES))
    ap.add_argument("--region", default="US")
    args = ap.parse_args(argv)

    if args.profile:
        profile = PROFILES[args.profile]
        kind = profile.connection_types[0]
    else:
        profile, kind = pick(args.region)

    from pazuzu_core.firewall_rule_audit_cli import _quiet_lab_tls_warnings
    from pazuzu_core.opnsense_client import discover_interfaces

    _quiet_lab_tls_warnings()
    return report(check_wan(discover_interfaces(), kind), profile)


if __name__ == "__main__":
    raise SystemExit(main())
