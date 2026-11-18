"""The five protection levels, for the three shields the firewall itself runs.

Critical, Warning, Caution, Secure, Normal. The firewall-only DNS rules are Warning and up (the rule stages
already do that). From there each step up turns one more shield on:

    Warning   rules only
    Caution   + packet inspection (IPS)
    Secure    + DNS block lists
    Normal    + DNS ad lists

This module only reads and decides; the write goes through the write engine (read page answered first,
the firewall's own form checked, a passkey for the plan, read back, old values kept for the undo).
The firewall names its lists itself; Pazuzu sorts them into "ad lists" and "block lists" by their names
and shows the sorting, so it can be seen and corrected rather than trusted blindly.
"""
from __future__ import annotations

import re
from typing import Any, Mapping

LEVELS = ("critical", "warning", "caution", "secure", "normal")
SETTABLE = (1, 2, 3, 4)                 # Critical is the timed all-off, which has its own switch

_ADS = re.compile(r"(^|[^a-z])ads?([^a-z]|$)|adaway|adguard|yoyo|admiral|easylist|advert|tracker|tracking", re.I)
_BLOCK_DEFAULT = re.compile(r"malware|phish|stevenblack|hagezi|threat|ransom|abuse|scam", re.I)
_AD_DEFAULT = re.compile(r"adaway|adguard|yoyo|easylist", re.I)


class LevelsError(Exception):
    pass


def _options(node: Any) -> dict[str, tuple[str, bool]]:
    """{key: (label, selected)} for one of the firewall's pick-lists, else {}."""
    if isinstance(node, dict) and node and all(isinstance(x, dict) and "value" in x for x in node.values()):
        return {str(k): (str(x.get("value")), str(x.get("selected")) in ("1", "True", "true")) for k, x in node.items()}
    return {}


def ips_is_on(ids_form: Any) -> bool:
    """Packet inspection that blocks. Older forms have an IPS tick; 26.7's has a capture mode instead, and only
    divert or netmap block (the live-capture mode only alerts)."""
    if str(_dig(ids_form, "general.enabled")) != "1":
        return False
    gen = _dig(ids_form, "general")
    if isinstance(gen, dict) and "ips" in gen:
        return str(gen["ips"]) == "1"
    chosen = [(k + " " + lab).lower() for k, (lab, sel) in _options(_dig(ids_form, "general.mode")).items() if sel]
    return any("divert" in c or "netmap" in c for c in chosen)


def divert_choice(mode_node: Any) -> tuple[str | None, str | None]:
    """The firewall's own keys for 'divert' and for the alerts-only live mode, found by name: (divert, alerts_only)."""
    opts = _options(mode_node)
    on = [k for k, (lab, _s) in opts.items() if "divert" in (k + " " + lab).lower()]
    off = [k for k, (lab, _s) in opts.items() if "pcap" in (k + " " + lab).lower() or "live" in lab.lower()]
    return (on[0] if len(on) == 1 else None), (off[0] if len(off) == 1 else None)


def _dig(form: Any, path: str) -> Any:
    node = form
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def split_lists(options: Mapping[str, tuple[str, bool]]) -> tuple[list[str], list[str]]:
    """The keys of the ad lists and of the block lists, by the firewall's own names for them."""
    ads, block = [], []
    for key, (label, _sel) in options.items():
        (ads if _ADS.search(label) else block).append(key)
    return ads, block


def read_flags(ids_form: Any, unbound_form: Any) -> dict:
    """What is on now, from the two forms (the part of each answer inside its single outer key)."""
    opts = _options(_dig(unbound_form, "dnsbl.type"))
    ads_keys, block_keys = split_lists(opts)
    chosen = {k for k, (_l, sel) in opts.items() if sel}
    dns_on = str(_dig(unbound_form, "dnsbl.enabled")) == "1"
    ips = ips_is_on(ids_form)
    return {"ips": ips, "block": dns_on and bool(chosen & set(block_keys)), "ads": dns_on and bool(chosen & set(ads_keys)),
            "chosen": sorted(chosen), "ads_keys": ads_keys, "block_keys": block_keys,
            "labels": {k: lab for k, (lab, _s) in opts.items()}}


def level_index(flags: Mapping) -> int | None:
    """1..4 when the three shields match a level exactly; None when they are in some mixed state."""
    ips, block, ads = bool(flags["ips"]), bool(flags["block"]), bool(flags["ads"])
    table = {(False, False, False): 1, (True, False, False): 2, (True, True, False): 3, (True, True, True): 4}
    return table.get((ips, block, ads))


def wanted(idx: int) -> dict:
    if idx not in SETTABLE:
        raise LevelsError("Only Warning, Caution, Secure and Normal can be set here.")
    return {"ips": idx >= 2, "block": idx >= 3, "ads": idx >= 4}


def types_for(idx: int, flags: Mapping, remembered: Mapping | None = None) -> list[str]:
    """The list keys to have selected at this level. Lists the person already chose stay chosen; a shield that
    was never on gets a sensible default from the firewall's own names, or the switch says what to pick."""
    want = wanted(idx)
    labels = flags["labels"]
    keep: list[str] = []
    for shield, keys, default in (("block", flags["block_keys"], _BLOCK_DEFAULT), ("ads", flags["ads_keys"], _AD_DEFAULT)):
        if not want[shield]:
            continue
        have = [k for k in flags["chosen"] if k in keys]
        if not have and remembered:
            have = [k for k in (remembered.get(shield) or []) if k in keys]
        if not have:
            have = [k for k in keys if default.search(labels.get(k, ""))][:1]
        if not have:
            name = "block lists" if shield == "block" else "ad lists"
            raise LevelsError(f"The firewall's DNS page has no {name} Pazuzu can tell apart. Choose one there "
                              "once (Services, Unbound DNS, Blocklist) and this switch will keep your choice.")
        keep += have
    return keep


def describe(flags: Mapping) -> dict:
    labels = flags["labels"]
    return {"ads": [labels[k] for k in flags["ads_keys"]], "block": [labels[k] for k in flags["block_keys"]]}


def _types_in_row(row: Mapping, opts: Mapping[str, tuple[str, bool]]) -> set[str]:
    """Which of the firewall's list keys one grid row uses. The grid may show a list by key or by name, and one
    row may use several (comma separated), so both the whole text and each piece are matched."""
    text = str(row.get("type") or "").strip()
    pieces = [text] + [p.strip() for p in text.split(",")]
    found = set()
    for key, (label, _sel) in opts.items():
        names = {key.lower(), label.lower()}
        if any(p and p.lower() in names for p in pieces):
            found.add(key)
    return found


def read_flags_grid(ids_form: Any, type_node: Any, rows: list) -> dict:
    """Like read_flags, for the firewall that keeps its block lists as a grid of entries (one row per entry,
    each with its own on/off). `type_node` is the pick-list of the empty entry form."""
    opts = _options(type_node)
    ads_keys, block_keys = split_lists(opts)
    chosen: set[str] = set()
    for row in rows:
        if isinstance(row, dict) and str(row.get("enabled", "1")) in ("1", "True", "true"):
            chosen |= _types_in_row(row, opts)
    ips = ips_is_on(ids_form)
    return {"ips": ips, "block": bool(chosen & set(block_keys)), "ads": bool(chosen & set(ads_keys)),
            "chosen": sorted(chosen), "ads_keys": ads_keys, "block_keys": block_keys,
            "labels": {k: lab for k, (lab, _s) in opts.items()}}


def entries_to_add(idx: int, flags: Mapping, remembered: Mapping | None = None) -> list[tuple[str, list[str]]]:
    """For the grid: the new entries to make, as (shield, list keys). Pazuzu only adds entries; it does not switch
    an entry off, so going to a level that needs a list off is said plainly, never half done."""
    types = types_for(idx, flags, remembered)
    labels = flags["labels"]
    off = [k for k in flags["chosen"] if k not in types]
    if off:
        names = ", ".join(labels.get(k, k) for k in off)
        raise LevelsError(f"Pazuzu adds block lists but does not switch one off yet. Turn off {names} on the firewall's own "
                          "page (Services, Unbound DNS, Blocklists), then try again.")
    out = []
    for shield, keys in (("block", flags["block_keys"]), ("ads", flags["ads_keys"])):
        missing = [k for k in types if k in keys and k not in flags["chosen"]]
        if missing:
            out.append((shield, missing))
    return out
