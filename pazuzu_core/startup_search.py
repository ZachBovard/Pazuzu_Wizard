"""Start the way a person would on a brand-new install: look at what is there first.

Before the wizard opens, this searches the networks this device is on for firewalls, reads the certificate
fingerprint each one shows, prints what it found, and picks the firewall to talk to:

  * a firewall named with --firewall is the one, whatever else is there;
  * a key folder that already belongs to a firewall goes back to that one, and never to a different one;
  * exactly one firewall found is the one;
  * several found, and nothing says which: the person is asked (or told to name one), never guessed for.

It is read-only: it only connects and reads the front page and the certificate of private addresses (the same
quick search the "Find my firewall" button does). No password or key is sent. Every outside call is injected, so
the tests run without a network.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

# OPNsense's own factory address, from its documentation. Used for one thing only: to recognise a firewall that was
# reset or installed again (it comes back at this address). It is never searched for: the search looks only at the
# networks this device is on, and at an address a person typed.
FACTORY = ("192.168.1.1", 443)


class StartupError(Exception):
    """The start cannot go on without the person deciding something. The message says what."""


class KeysElsewhere(StartupError):
    """The keys in this folder belong to a firewall that did not answer, and others did. A person decides, and the
    wizard's own page is where: it carries what was seen so the page can list it."""
    def __init__(self, message: str, outcome: "Outcome"):
        super().__init__(message)
        self.outcome = outcome


@dataclass
class Sighting:
    host: str
    port: int
    via: str
    fingerprint: str = ""          # 64 hex characters, or "" when the certificate could not be read
    cert_name: str = ""            # the certificate's own name, for telling several firewalls apart (display only)
    says_opnsense: bool = True     # False: it answered on TLS at a named address, but its page did not say OPNsense

    @property
    def where(self) -> str:
        return self.host + ("" if self.port == 443 else f":{self.port}")

    def start_of_fingerprint(self) -> str:
        fp = (self.fingerprint or "").upper()
        if len(fp) < 16:
            return "(certificate not readable)"
        return " ".join(fp[i:i + 2] for i in range(0, 16, 2)) + " ..."

    def as_dict(self) -> dict:
        return {"host": self.host, "port": self.port, "via": self.via, "fingerprint_start": self.start_of_fingerprint(),
                "cert_name": self.cert_name, "says_opnsense": self.says_opnsense}


@dataclass
class Outcome:
    sightings: list[Sighting] = field(default_factory=list)
    chosen: Sighting | None = None
    why: str = ""                  # one sentence: why this one

    @property
    def others(self) -> list[Sighting]:
        return [s for s in self.sightings if self.chosen is None or (s.host, s.port) != (self.chosen.host, self.chosen.port)]

    def as_dict(self) -> dict:
        return {"found": [s.as_dict() for s in self.sightings],
                "chosen": self.chosen.where if self.chosen else "",
                "why": self.why,
                "others": [s.where for s in self.others]}


def _read_fp(fetch_fp: Callable[[str, int], str], host: str, port: int) -> str:
    try:
        return str(fetch_fp(host, port) or "")
    except Exception:
        return ""


def _read_name(fetch_name: Callable[[str, int], str], host: str, port: int) -> str:
    try:
        return str(fetch_name(host, port) or "")
    except Exception:
        return ""


def _ask_which(sightings: list[Sighting], ask: Callable[[str], str] | None, say: Callable[[str], None]) -> Sighting:
    names = ", ".join(s.where for s in sightings)
    if ask is None:
        raise StartupError(f"More than one firewall answered ({names}), and nothing says which is yours. "
                           f"Start again with --firewall and the address of the one you want.")
    say("More than one firewall answered. Which one is yours?")
    for i, s in enumerate(sightings, 1):
        name = f"   named {s.cert_name}" if s.cert_name else ""
        say(f"  {i}. {s.where:<18} certificate starts {s.start_of_fingerprint()}{name}   (found via {s.via})")
    for _ in range(3):
        reply = (ask("Type its number (or press Enter to stop): ") or "").strip()
        if not reply:
            break
        if reply.isdigit() and 1 <= int(reply) <= len(sightings):
            return sightings[int(reply) - 1]
        say("That is not one of the numbers above.")
    raise StartupError("No firewall was picked, so nothing was started. Start again with --firewall and its address.")


def _installed_again(stamp, sightings: list[Sighting], pin: str | None) -> bool:
    """The keys' own firewall is silent, and the only one that answered sits at OPNsense's factory address with a
    certificate that is not the one the keys were made on: a firewall that was reset or installed again. With
    anything less (several answering, another address, no saved certificate to compare) a person decides."""
    if len(sightings) != 1 or not pin:
        return False
    only = sightings[0]
    fp = (only.fingerprint or "").lower()
    return (only.host, only.port) == FACTORY and (only.host, only.port) != tuple(stamp) \
        and bool(fp) and fp != pin.lower()


def look_around(named: tuple[str, int] | None = None, stamp: tuple[str, int] | None = None, *,
                pin: str | None = None, finder: Callable | None = None, fetch_fp: Callable[[str, int], str] | None = None,
                ask: Callable[[str], str] | None = None, say: Callable[[str], None] = print,
                fetch_name: Callable[[str, int], str] | None = None) -> Outcome:
    """Search, say what is there, and choose. Raises StartupError when the person has to decide first."""
    from pazuzu_core import find_firewall as ff
    from pazuzu_core.enroll_safety import fetch_cert_name, fetch_fingerprint
    real = finder is None
    finder = finder or ff.find_firewall
    fetch_fp = fetch_fp or fetch_fingerprint
    # A finder handed in is a test's: it gets no look at the network for names unless one is handed in too.
    fetch_name = fetch_name or ((lambda h, p: fetch_cert_name(h, p, 4)) if real else (lambda h, p: ""))
    say("Searching the networks this device is on for firewalls...")
    typed, ports = [], []
    for want in (named, stamp):
        if want and want[0] not in typed:
            typed.append(want[0])
            ports.append(want[1])
    report = None
    try:
        report = finder(typed=typed, launch=[], extra_ports=ports, wifi=False)
    except Exception as exc:
        say(f"The search could not run ({str(exc).splitlines()[0][:120] if str(exc) else type(exc).__name__}).")
    sightings = [Sighting(f.host, f.port, f.via, _read_fp(fetch_fp, f.host, f.port), _read_name(fetch_name, f.host, f.port))
                 for f in (getattr(report, "found", None) or [])]

    if named and not any(s.host == named[0] for s in sightings):
        # A named firewall may sit on a port or a network the quick search does not cover: ask it directly.
        fp = _read_fp(fetch_fp, named[0], named[1])
        if fp:
            sightings.append(Sighting(named[0], named[1], "the address you gave", fp, says_opnsense=False))
        else:
            say(f"Nothing answered at {named[0]}" + ("" if named[1] == 443 else f":{named[1]}")
                + ". It may be off, still starting, or on another cable.")

    if sightings:
        say(f"What's there ({len(sightings)}):")
        for s in sightings:
            note = "" if s.says_opnsense else "   (answered, but its page did not say OPNsense)"
            name = f"   named {s.cert_name}" if s.cert_name else ""
            say(f"  {s.where:<18} certificate starts {s.start_of_fingerprint()}{name}{note}")
    else:
        note = getattr(report, "note", "") if report is not None else ""
        say("No firewall answered." + (f" {note}" if note else ""))

    out = Outcome(sightings=sightings)
    by_host = {s.host: s for s in sightings}
    if named:
        out.chosen = by_host.get(named[0])
        out.why = f"You named {named[0]}." if out.chosen else ""
    elif stamp and stamp[0] in by_host:
        out.chosen = by_host[stamp[0]]
        out.why = f"The keys in this folder belong to {stamp[0]}, and it answered."
    elif stamp and _installed_again(stamp, sightings, pin):
        out.chosen = sightings[0]
        out.why = (f"The firewall these keys were made on ({stamp[0]}) did not answer. The one at {FACTORY[0]} is at the "
                   "factory address and shows a different certificate than the keys were made on, so it was installed "
                   "again. The old keys are set aside (not deleted) and this starts fresh, as on a new install.")
    elif stamp:
        if sightings:
            raise KeysElsewhere(
                f"The keys in this key folder belong to the firewall at {stamp[0]}, which did not answer. "
                f"These did: {', '.join(s.where for s in sightings)}. Keys only work on the firewall that made them, "
                f"so to use one of those start with --firewall and its address, and a new folder name after --dir.", out)
        out.why = ""
        say(f"The keys in this key folder belong to the firewall at {stamp[0]}, and nothing answered on the networks this "
            "computer is on. The wizard will open and say so, and let you look again or pick another firewall.")
    elif len(sightings) == 1:
        out.chosen = sightings[0]
        out.why = f"It is the only firewall that answered: {sightings[0].where}."
    elif len(sightings) > 1:
        out.chosen = _ask_which(sightings, ask, say)
        out.why = f"You picked {out.chosen.where}."
    return out
