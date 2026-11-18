"""Will the firewall's hardware be happy running Zenarmor? Judged from the facts the plugin reads (hanbi_box/hardware.py).

Every threshold here is one that Zenarmor or OPNsense publishes, and each row says which. Nothing is made up:
  - Zenarmor, "Hardware Requirements": 64-bit Intel-compatible only; at least a dual-core processor (its smallest tier
    lists a single-core PassMark score of 200, which this cannot measure, so Zenarmor's own check at setup stays the judge);
    memory of at least 1 GB (the installer will not go on with less) and 8 GB for a good reporting experience with its
    full reporting database (Elasticsearch); an SSD recommended; at least 5 MB per hour for every 1 Mbps of traffic on
    disk; network cards that work with netmap, with Intel cards (em, igb) named as the ones that perform well and Realtek
    not mentioned at all; virtual machines fine, but not advised above 500 devices and 500 Mbps.
  - Zenarmor, "Managing the reporting database": SQLite "supports up to 100 devices and requires minimal system resources".
  - OPNsense, "Hardware sizing & setup": a 40 GB SSD is its "reasonable" disk; the smallest tier (an SD or CF card) cannot run
    features that write to disk.
The levels: "ok", "note" (not a blocker; something Zenarmor or OPNsense advises otherwise) and "stop" (Zenarmor will not
install, by its own words). A verdict is a help to the person; Zenarmor runs its own check when it is set up.
"""
from __future__ import annotations

import re

GIB = 1024 ** 3
INTEL = {"em", "igb", "igc", "ix", "ixl", "ixv", "ixgbe", "lem"}
REALTEK = {"re", "rl", "rge"}
VIRTUAL = {"vtnet", "vmx", "hn", "xn", "xnb"}
# Memory the machine reports is a little under what is fitted (the kernel keeps some), so each size is met a little below it.
AT_LEAST_1 = 0.9 * GIB
AT_LEAST_4 = 3.5 * GIB
AT_LEAST_8 = 7.0 * GIB


def _gb(n: float) -> str:
    gib = n / GIB
    return "%.1f GB" % gib if gib < 1.5 else "%d GB" % round(gib)


def _size(n) -> str:
    if not isinstance(n, int) or n <= 0:
        return ""
    gb = n / 1e9
    return ("%d GB" % round(gb)) if gb < 1000 else ("%.1f TB" % (gb / 1000))


def _row(what: str, level: str, says: str, help: str) -> dict:
    return {"what": what, "level": level, "says": says, "help": help}


def _processor(f: dict) -> dict:
    arch, cpu, cores = f.get("arch") or "", f.get("cpu") or "", f.get("cores")
    says = ", ".join(x for x in (cpu, ("%d cores" % cores) if cores else "") if x) or "could not be read"
    if arch and arch not in ("amd64", "x86_64"):
        return _row("Processor", "stop", says + " (" + arch + ")",
                    "Zenarmor is only available for 64-bit Intel-compatible hardware (x86-64).")
    if cores is not None and cores < 2:
        return _row("Processor", "note", says, "Zenarmor recommends at least two cores.")
    return _row("Processor", "ok", says,
                "Zenarmor asks for two or more cores and a fast single core. It also checks the processor itself when you set it up, "
                "and tells you then if it is too weak.")


def _memory(f: dict) -> dict:
    ram = f.get("ram_bytes")
    if not isinstance(ram, int) or ram <= 0:
        return _row("Memory", "note", "could not be read", "Zenarmor needs at least 1 GB, and recommends 8 GB for its full reporting database.")
    says = _gb(ram)
    if ram < AT_LEAST_1:
        return _row("Memory", "stop", says, "Zenarmor will not install with less than 1 GB.")
    if ram < AT_LEAST_4:
        return _row("Memory", "note", says,
                    "Enough to run Zenarmor on a small network (its table: up to 50 devices at 300 Mbps with 1 GB). Its full reporting "
                    "database (Elasticsearch) wants 8 GB, so choose the light one (SQLite) when it asks.")
    if ram < AT_LEAST_8:
        return _row("Memory", "note", says,
                    "Zenarmor's table suits up to 100 devices at 500 Mbps with 4 GB. Its full reporting database (Elasticsearch) wants "
                    "8 GB, so choose the light one (SQLite) when it asks.")
    return _row("Memory", "ok", says, "8 GB is what Zenarmor recommends for a good reporting experience with its full reporting database.")


def _main_disk(f: dict):
    disks = [d for d in (f.get("disks") or []) if isinstance(d, dict)]
    root = f.get("root") or {}
    dev = str(root.get("device") or "")
    for d in disks:                                   # the disk the root lives on, when the file system is named after it
        if dev.startswith("/dev/") and d.get("name") and re.match(re.escape(str(d["name"])) + r"(?!\d)", dev[5:]):
            return d
    return max(disks, key=lambda d: d.get("bytes") or 0) if disks else None


def _on_live_cd(f: dict) -> bool:
    dev = str((f.get("root") or {}).get("device") or "")
    return dev.startswith(("/dev/md", "/dev/iso", "/dev/cd", "tmpfs", "unionfs", "/dev/ufs/cdboot"))


def _disk(f: dict) -> dict:
    d, root = _main_disk(f), f.get("root") or {}
    if _on_live_cd(f):
        return _row("Disk", "ok", "running from the live CD",
                    "The disk can only be judged once the firewall is installed on it. Zenarmor recommends an SSD, and its reports need "
                    "at least 5 MB per hour for every 1 Mbps of traffic.")
    if d is None and not root:
        return _row("Disk", "note", "could not be read", "Zenarmor recommends an SSD.")
    kind = (d or {}).get("kind") or "unknown"
    words = {"nvme": "SSD (NVMe)", "ssd": "SSD", "hdd": "spinning disk", "flash": "flash card", "unknown": "type not reported"}[kind]
    says = ", ".join(x for x in (_size((d or {}).get("bytes")) or _size(root.get("size")), words, ("%s free" % _size(root.get("avail"))) if _size(root.get("avail")) else "") if x)
    estimate = ("Its reports need at least 5 MB per hour for every 1 Mbps of traffic: a 100 Mbps link used 12 hours a day is about "
                "6 GB a day.")
    if kind == "hdd":
        return _row("Disk", "note", says, "Zenarmor recommends an SSD for better performance, especially with its full reporting database. " + estimate)
    if kind == "flash":
        return _row("Disk", "note", says,
                    "Zenarmor recommends an SSD. OPNsense's own documentation says its smallest tier, an SD or CF card, cannot run features "
                    "that write to disk all the time. " + estimate)
    size = (d or {}).get("bytes") or root.get("size")
    if isinstance(size, int) and size < 40e9:
        return _row("Disk", "note", says, "OPNsense's documentation suggests at least a 40 GB SSD for a reasonable setup. " + estimate)
    return _row("Disk", "ok", says, "Zenarmor recommends an SSD. " + estimate)


def _cards(f: dict):
    nics = [n for n in (f.get("nics") or []) if isinstance(n, dict) and n.get("driver")]
    if not nics:
        return None
    names = ", ".join(n.get("name", "") for n in nics)
    drivers = {n["driver"] for n in nics}
    intel, real, virt = drivers & INTEL, drivers & REALTEK, drivers & VIRTUAL
    if real:
        label = ("Realtek" if not (drivers - REALTEK) else "Realtek and others") + " (" + names + ")"
        return _row("Network cards", "note", label,
                    "Zenarmor asks you to check that your cards work with netmap, the way it reads the traffic. It names only Intel cards "
                    "(em, igb) as performing well and does not mention Realtek, so there is no promise either way. If the firewall ever "
                    "hangs or drops the network under heavy traffic, these ports are the first suspect; some OPNsense users report "
                    "trouble with Realtek cards.")
    if virt and not (drivers - VIRTUAL):
        return _row("Network cards", "ok", "virtual (" + names + ")", "Virtual network cards, as in a virtual machine.")
    if intel and not (drivers - INTEL):
        return _row("Network cards", "ok", "Intel (" + names + ")",
                    "Zenarmor and OPNsense both point to Intel cards as the dependable choice.")
    return _row("Network cards", "ok", names,
                "Zenarmor's page does not list these cards either way. Its own check at setup will say.")


def _machine(f: dict):
    v = f.get("virtual")
    if not v:
        return None
    return _row("Virtual machine", "ok", "yes (" + str(v) + ")",
                "Zenarmor says it runs on virtual machines such as Proxmox, VirtualBox and KVM. It advises against it only for large "
                "networks: more than 500 devices and more than 500 Mbps.")


def judge(f: dict) -> dict:
    """{"level", "headline", "rows", "database"}. `database`: which reporting database the hardware suits: "elasticsearch"
    when it has the 8 GB and four cores Zenarmor names for it, otherwise "sqlite"; None when the memory or the cores could
    not be read, so nothing is said either way."""
    rows = [r for r in (_processor(f), _memory(f), _disk(f), _cards(f), _machine(f)) if r]
    order = {"ok": 0, "note": 1, "stop": 2}
    worst = max((r["level"] for r in rows), key=lambda x: order[x])
    stops = [r for r in rows if r["level"] == "stop"]
    notes = [r["what"].lower() for r in rows if r["level"] == "note"]
    if worst == "stop":
        head = "Zenarmor will not install on this hardware: " + "; ".join(r["what"].lower() + " (" + r["says"] + ")" for r in stops) + "."
    elif worst == "note":
        head = "Nothing stops Zenarmor here. Worth knowing: " + ", ".join(notes) + "."
    else:
        head = "This hardware meets what Zenarmor publishes."
    ram, cores = f.get("ram_bytes"), f.get("cores")
    if not (isinstance(ram, int) and ram > 0 and isinstance(cores, int) and cores > 0):
        database = None
    else:
        database = "elasticsearch" if ram >= AT_LEAST_8 and cores >= 4 else "sqlite"
    return {"level": worst, "headline": head, "rows": rows, "database": database}
