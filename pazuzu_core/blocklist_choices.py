"""Which block lists the person wants the firewall's name lookups to use.

One main list is required: HaGeZi, at a level the person picks (each level includes the one below it).
Other lists are optional add-ons. The choice is only recorded here. Turning a list on is a later change
made by the manager, once the firewall's own list setting has been read back on the version in use, and
the list address has been confirmed against the author's page. No list address is stored in this file,
because none has been checked on this firewall version: a guessed address would be a silent failure.

Sizes are rounded and are what each author published when this was written. They change.
Nothing in this file touches a firewall.
"""

from __future__ import annotations

import json
from pathlib import Path

CHOICES_FILE = "choices.json"
KEY = "blocklists"

AUTHOR = "HaGeZi"
AUTHOR_PAGE = "github.com/hagezi/dns-blocklists"

# The main list: exactly one level.
LEVELS: tuple[dict, ...] = (
    {"id": "light", "name": "Light", "size": "about 85,000 names",
     "says": "Ads and trackers, with the fewest side effects. Least likely to break a site or an app."},
    {"id": "normal", "name": "Normal", "size": "about 260,000 names",
     "says": "A balanced everyday list. Ads, trackers, scams and malware."},
    {"id": "pro", "name": "Pro", "size": "about 340,000 names",
     "says": "More thorough. Blocks more trackers and more sites that are known to be bad. A few sites may need an exception."},
    {"id": "proplus", "name": "Pro++", "size": "about 390,000 names",
     "says": "Stricter again. Expect to allow a few things now and then."},
    {"id": "ultimate", "name": "Ultimate", "size": "about 480,000 names",
     "says": "The strictest level. Most likely to block something you wanted, so it suits people happy to fix that."},
)
LEVEL_IDS = tuple(x["id"] for x in LEVELS)
RECOMMENDED = "pro"          # the author's own pick for most people

TIF_SIZES: tuple[dict, ...] = (
    {"id": "full", "name": "Full", "size": "about 620,000 names"},
    {"id": "medium", "name": "Medium", "size": "about 270,000 names"},
    {"id": "mini", "name": "Mini", "size": "about 120,000 names"},
)
TIF_IDS = tuple(x["id"] for x in TIF_SIZES)

# Optional add-ons. `overlaps` is a plain warning, never a block.
EXTRAS: tuple[dict, ...] = (
    {"id": "tif", "name": "HaGeZi Threat Intelligence Feeds", "kind": "sizes",
     "says": "Names tied to malware, phishing, scams and attacks. Pick a size.",
     "page": "github.com/hagezi/dns-blocklists", "overlaps": "Partly included in Pro++ and Ultimate."},
    {"id": "popupads", "name": "HaGeZi Pop-Up Ads", "kind": "plain",
     "says": "Names used by pop-up and pop-under adverts.",
     "page": "github.com/hagezi/dns-blocklists", "overlaps": ""},
    {"id": "stevenblack", "name": "StevenBlack hosts", "kind": "plain",
     "says": "A long-running combined list of ad, tracker and malware names.",
     "page": "github.com/StevenBlack/hosts", "overlaps": "Overlaps a lot with the HaGeZi level you pick."},
    {"id": "oisd", "name": "OISD (big)", "kind": "plain",
     "says": "A well-known combined list, kept free of names that break common sites.",
     "page": "oisd.nl", "overlaps": "Overlaps a lot with the HaGeZi level you pick."},
    {"id": "r0xd4n3t", "name": "r0xd4n3t Pi-hole lists", "kind": "list_of_lists",
     "says": "This is a list of many lists, not one list. Turning it on can pull in dozens of lists at once.",
     "page": "github.com/r0xd4n3t/pihole-adlists",
     "overlaps": "Many overlaps, and a large memory cost. Best left off unless you know why you want it."},
)
EXTRA_IDS = tuple(x["id"] for x in EXTRAS)

WARNINGS = (
    "More lists use more of the firewall's memory and make name lookups a little slower to start. Overlapping lists add cost and no extra protection.",
    "If you allow something a list blocks, that is your decision and your risk.",
    "The address of each list is confirmed against its author's page when it is switched on. It has not been checked on this firewall version yet.",
)


def state(key_dir) -> dict:
    saved = load(key_dir)
    return {"choice": saved, "levels": [dict(x) for x in LEVELS], "recommended": RECOMMENDED,
            "tif_sizes": [dict(x) for x in TIF_SIZES], "extras": [dict(x) for x in EXTRAS],
            "author": AUTHOR, "author_page": AUTHOR_PAGE, "warnings": list(WARNINGS)}


def load(key_dir) -> dict | None:
    from pazuzu_core import choices_file
    data = choices_file.read(key_dir)          # under the shared lock: never a half-written file (10 Nov 2026)
    if not data:
        return None
    saved = data.get(KEY)
    try:
        return clean(saved)
    except ValueError:
        return None


def clean(raw) -> dict:
    """The choice, checked. A main level is required."""
    if not isinstance(raw, dict):
        raise ValueError("Pick one main list.")
    main = raw.get("main")
    if main not in LEVEL_IDS:
        raise ValueError("Pick one main list.")
    extras = raw.get("extras", [])
    if not isinstance(extras, list) or any(not isinstance(x, str) for x in extras):
        raise ValueError("That is not one of the choices.")
    if any(x not in EXTRA_IDS for x in extras):
        raise ValueError("That is not one of the choices.")
    ordered = [x for x in EXTRA_IDS if x in extras]
    out = {"main": main, "extras": ordered}
    if "tif" in ordered:
        size = raw.get("tif_size", "full")
        if size not in TIF_IDS:
            raise ValueError("That is not one of the choices.")
        out["tif_size"] = size
    return out


def save(key_dir, raw) -> dict:
    from pazuzu_core import choices_file
    choice = clean(raw)
    choices_file.update(key_dir, lambda data: data.__setitem__(KEY, choice))
    return choice
