"""A built-in audit of the firewall's own rules: read the filter (and NAT) export, flag likely problems.

Read-only. It parses the semicolon export OPNsense gives from Firewall: Rules (and the port-forward export),
normalises each rule, and runs a set of checks. Every check returns plain-words findings with a severity, the
rule it is about, and what to do — the same shape as shield_levels / stock_rules, so the manager can show them.

It never changes anything and it resolves no aliases against the firewall: it reasons from the export alone, so a
few checks are deliberately conservative ("verify") rather than certain. What it is sure of (a disabled leftover,
an IPv4 rule pointing at a v6 list, a sequence clash) it says plainly; what depends on an alias's contents (a
pass that may shadow a later block) it flags to be confirmed.
"""
from __future__ import annotations

import csv
import io
import re
from typing import Any, Iterable

SEVERITIES = ("critical", "high", "medium", "low")
MANAGED_PREFIX = "PAZUZU:"
_PZ_ROLE = re.compile(r"PAZUZU:(PZ-[A-Z]+-\d+)")
_RFC1918 = re.compile(r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)")
_IFACE_NET = re.compile(r"^(lan|wan|opt\d+)$", re.I)
_V6_HINT = re.compile(r"v6|ipv6", re.I)   # a name that says v6 — not merely ending in 6 (a /16 CIDR is not IPv6)
_VPN_HINT = re.compile(r"\b(vpn|wireguard|wg)\b", re.I)


def _b(value: Any) -> bool:
    return str(value).strip() in ("1", "true", "True", "yes", "on")


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _norm(row: dict) -> dict:
    """One export row -> the fields the checks use. Unknown/blank fields become ''."""
    g = lambda *names: next((str(row[n]).strip() for n in names if n in row and str(row[n]).strip()), "")
    desc = g("description", "descr")
    role = _PZ_ROLE.search(desc)
    seq = _int(g("sequence") or g("sort_order"))         # the CSV export calls it sequence; the API row, sort_order
    return {
        "uuid": g("uuid", "@uuid"),
        "enabled": _b(row.get("enabled", "1")) and not _b(row.get("disabled")),
        "seq": seq,
        # OPNsense's own automatic/internal rules (anti-lockout, bogons, default deny): the live API returns them,
        # the CSV export does not. They carry is_automatic/legacy, and sit at sequence 0. They are not the user's
        # to fix, so the structure checks skip them (the admin-path check still sees them — anti-lockout is a path).
        "auto": _b(row.get("is_automatic")) or _b(row.get("legacy")) or seq == 0,
        "action": g("action").lower(),
        "quick": _b(row.get("quick", "1")),
        "interface": g("interface").lower(),
        "ipprotocol": g("ipprotocol").lower(),
        "protocol": g("protocol").lower(),
        "src": g("source_net", "source.network"),
        "src_not": _b(row.get("source_not") or row.get("source.not")),
        "dst": g("destination_net", "destination.network"),
        "dst_not": _b(row.get("destination_not") or row.get("destination.not")),
        "dport": g("destination_port", "destination.port"),
        "descr": desc,
        "managed": desc.startswith(MANAGED_PREFIX),
        "role": role.group(1) if role else "",
    }


def parse_rules(text: str) -> list[dict]:
    """Normalised rules from the filter export (the first line is the header)."""
    reader = csv.DictReader(io.StringIO(text.strip()), delimiter=";")
    reader.fieldnames = [f.lstrip("@").strip() for f in (reader.fieldnames or [])]
    return [_norm(r) for r in reader if any((v or "").strip() for v in r.values())]


def from_rows(rows: Iterable[dict]) -> list[dict]:
    """Normalise rule rows that came from the firewall API (firewall/filter/search_rule) instead of the CSV
    export. The API returns the same flat field names, so every check runs unchanged."""
    return [_norm(r) for r in rows if isinstance(r, dict)]


def parse_nat(text: str) -> list[dict]:
    """Normalised port-forwards from the NAT export. `pass_mode` is 'rule' (associated rule) or 'pass' (rdr-pass)."""
    reader = csv.DictReader(io.StringIO(text.strip()), delimiter=";")
    reader.fieldnames = [f.lstrip("@").strip() for f in (reader.fieldnames or [])]
    out = []
    for r in reader:
        if not any((v or "").strip() for v in r.values()):
            continue
        g = lambda n: str(r.get(n, "")).strip()
        out.append({"uuid": g("uuid"), "seq": _int(g("sequence")), "enabled": not _b(g("disabled")),
                    "interface": g("interface").lower(), "protocol": g("protocol").lower(),
                    "src": g("source.network"), "dst": g("destination.network"), "dport": g("destination.port"),
                    "target": g("target"), "local_port": g("local-port"), "pass_mode": g("pass").lower(),
                    "log": _b(g("log")), "descr": g("descr")})
    return out


# ------------------------------------------------------------------ helpers the checks share

def _tokens(s: str) -> list[str]:
    return [t for t in re.split(r"[,\s]+", s.strip().lower()) if t]


def _is_private_dst(token: str) -> bool:
    """Any single token denoting a local / RFC1918 address: an interface net (lan/optN/wan), (self), an RFC1918
    literal, or an alias whose name says private/rfc1918/local."""
    for part in _tokens(token):
        if (part in ("(self)", "self") or _IFACE_NET.match(part) or _RFC1918.match(part)
                or "private" in part or "rfc1918" in part or "local" in part):
            return True
    return False


def _is_broad_private(token: str) -> bool:
    """Only the broad set that covers *all* RFC1918 (an alias named private/rfc1918) — NOT a single interface net
    or (self). This asymmetry is what keeps the shadow check honest: private_networks covers opt1, but opt1 does
    not cover lan, and (self) does not cover opt2."""
    return any("private" in p or "rfc1918" in p for p in _tokens(token))


def _covers_tok(outer: str, inner: str) -> bool:
    if outer in ("", "any"):
        return True
    if outer == inner:
        return True
    return _is_broad_private(outer) and _is_private_dst(inner)


def _covers(outer: str, inner: str) -> bool:
    """Does `outer` cover `inner`? Either may be a comma-list; every inner token must be covered by some outer
    token. Conservative — it never claims coverage across two user aliases it cannot read."""
    outers = _tokens(outer) or [""]
    inners = _tokens(inner) or [""]
    return all(any(_covers_tok(o, i) for o in outers) for i in inners)


def _overlap(a: str, b: str) -> bool:
    return _covers(a, b) or _covers(b, a)


def _port_overlap(a: str, b: str) -> bool:
    a, b = a.strip().lower(), b.strip().lower()
    return a in ("", "any") or b in ("", "any") or a == b


def _same_scope(a: dict, b: dict) -> bool:
    """Two rules can act on the same traffic path: same interface (or one is floating), same IP family."""
    if a["interface"] and b["interface"] and a["interface"] != b["interface"]:
        return False
    fam_a, fam_b = a["ipprotocol"], b["ipprotocol"]
    if fam_a and fam_b and fam_a != fam_b and "inet46" not in (fam_a, fam_b):
        return False
    return True


def _f(sev: str, check: str, rule: dict, title: str, fix: str) -> dict:
    return {"severity": sev, "check": check, "uuid": rule.get("uuid", ""), "seq": rule.get("seq"),
            "role": rule.get("role", ""), "title": title, "fix": fix}


# ------------------------------------------------------------------ the checks

def check_shadowing(rules: list[dict]) -> list[dict]:
    """A pass that defeats a later protective block (a broad pass that fires first and opens what the block would
    close), and a pass a block already above it makes dead. Only non-negated rules are reasoned about, and only
    where source, destination and port genuinely overlap — so this stays quiet unless the overlap is real. Still
    'verify', since alias *contents* are not read."""
    out = []
    live = [r for r in rules if r["enabled"] and r["quick"] and not r["src_not"] and not r["dst_not"]]
    passes = [r for r in live if r["action"] == "pass"]
    blocks = [r for r in live if r["action"] in ("block", "reject")]
    seen: set = set()
    for p in passes:
        for b in blocks:
            # same interface only (a floating rule's source already constrains which traffic it sees, so
            # comparing a floating pass against another interface's block is spurious)
            if p["uuid"] == b["uuid"] or p["interface"] != b["interface"] or not _same_scope(p, b):
                continue
            if not _overlap(p["src"], b["src"]) or not _port_overlap(p["dport"], b["dport"]):
                continue
            # a broad pass (all ports) to a private destination, above a block that covers that destination
            if (p["seq"] < b["seq"] and p["dport"] in ("", "any")
                    and _is_private_dst(p["dst"]) and _covers(b["dst"], p["dst"])
                    and ("defeat", p["uuid"], b["uuid"]) not in seen):
                seen.add(("defeat", p["uuid"], b["uuid"]))
                out.append(_f("high", "shadow-defeats-block", p,
                              f"broad pass (seq {p['seq']}) {p['descr'][:30] or p['src']+'->'+p['dst']!r} sits above "
                              f"block (seq {b['seq']}) {b['role'] or b['descr'][:28]} on {p['interface'] or 'floating'} "
                              "and opens a private destination that block is meant to close",
                              "narrow the pass to the one host+port it needs, or move it below the block"))
            # a block above already covers this pass's whole source+destination: the pass never fires
            if (p["seq"] > b["seq"] and _covers(b["src"], p["src"]) and _covers(b["dst"], p["dst"])
                    and ("dead", p["uuid"], b["uuid"]) not in seen):
                seen.add(("dead", p["uuid"], b["uuid"]))
                out.append(_f("medium", "dead-pass", p,
                              f"pass (seq {p['seq']}) {p['descr'][:30] or p['src']+'->'+p['dst']!r} never fires: block "
                              f"(seq {b['seq']}) {b['role'] or b['descr'][:28]} above it already covers it",
                              "delete the pass, or move it above the block if it is really meant to win"))
    return out


def check_proto_alias_mismatch(rules: list[dict]) -> list[dict]:
    """An IPv4 rule pointing at a v6-named alias (or vice versa): it matches nothing useful."""
    out = []
    for r in rules:
        fam = r["ipprotocol"]
        for side, tok in (("source", r["src"]), ("destination", r["dst"])):
            if not tok or _IFACE_NET.match(tok) or tok.lower() in ("any", "(self)"):
                continue
            hit = bool(_V6_HINT.search(tok))
            if fam == "inet" and hit:
                out.append(_f("high", "proto-alias-mismatch", r,
                              f"rule (seq {r['seq']}) is IPv4 (inet) but its {side} alias {tok!r} looks IPv6",
                              "set the rule to inet6, or point it at the matching IPv4 alias; merge the pair into one inet46 rule"))
            if fam == "inet6" and not hit and ("v4" in tok.lower() or "ipv4" in tok.lower()):
                out.append(_f("high", "proto-alias-mismatch", r,
                              f"rule (seq {r['seq']}) is IPv6 (inet6) but its {side} alias {tok!r} looks IPv4",
                              "set the rule to inet, or point it at the matching IPv6 alias"))
    return out


def check_vpn_passthrough_port(rules: list[dict]) -> list[dict]:
    """A 'let the VPN through' style pass whose port does not match the managed WireGuard port."""
    out = []
    wg_ports = {r["dport"] for r in rules if r["role"].startswith("PZ-WG") and r["dport"]}
    if not wg_ports:
        return out
    for r in rules:
        if r["role"].startswith("PZ-WG") or not r["dport"]:
            continue
        if _VPN_HINT.search(r["descr"]) and r["dport"] not in wg_ports and r["dport"].isdigit():
            out.append(_f("high", "vpn-port-mismatch", r,
                          f"'{r['descr'][:40]}' (seq {r['seq']}) opens port {r['dport']}, but the managed WireGuard "
                          f"port is {', '.join(sorted(wg_ports))}",
                          f"align it to {', '.join(sorted(wg_ports))}, or delete it until the VPN is set up"))
    return out


_SERVICE_PORTS = {"53", "67", "123", "ntp", "domain", "domain-s", "pz_udp_53_67_123", "pz_tcp_53_853"}


def check_admin_path(rules: list[dict], stock_allow_live: bool, mgmt_zone: str = "lan") -> list[dict]:
    """Once the stock allow-all is off, admin access to the firewall should rest on an explicit rule, not on the
    allow-all being toggled back on. Flags when the user rules hold no management allow to (self) from the mgmt
    zone. Medium, not high: OPNsense's automatic anti-lockout rule (not in this export) usually covers the LAN —
    so this is a 'confirm', and matters most for a non-LAN management zone."""
    if stock_allow_live:
        return []
    allows_self = [r for r in rules if r["enabled"] and r["action"] == "pass"
                   and r["dst"].lower() in ("(self)", "self") and r["interface"] == mgmt_zone]
    mgmt_allows = [r for r in allows_self
                   if r["dport"] and r["dport"].lower() not in _SERVICE_PORTS
                   and not (r["role"].startswith("PZ-WG") or r["role"].startswith("PZ-CORE"))
                   and "8787" not in r["dport"]]
    if not mgmt_allows:
        return [_f("medium", "admin-path", {"uuid": "", "seq": None, "role": ""},
                   f"the stock allow-all is off and no user rule allows a management port to the firewall from {mgmt_zone!r} "
                   "(only DNS/DHCP/NTP, WireGuard and the plugin). OPNsense's automatic anti-lockout may be covering the LAN",
                   f"confirm anti-lockout is on, or add an explicit allow for your admin port from {mgmt_zone} — then the stock allow-all can be deleted for good")]
    return []


def check_zone_parity(rules: list[dict]) -> list[dict]:
    """Every internal zone that has any PZ rule should have the same core families. Flag a zone missing one."""
    out = []
    families = ("PZ-CORE", "PZ-DNS-010")
    zones: dict[str, set[str]] = {}
    for r in rules:
        if not r["role"] or not r["interface"]:
            continue
        fam = next((f for f in families if r["role"].startswith(f)), None)
        if fam:
            zones.setdefault(r["interface"], set()).add(fam)
    internal = {z for z, fams in zones.items() if fams}
    for z in sorted(internal):
        missing = [f for f in families if f not in zones[z]]
        for f in missing:
            out.append(_f("medium", "zone-parity", {"uuid": "", "seq": None, "role": f},
                          f"zone {z!r} has PZ rules but is missing {f} (other internal zones have it)",
                          f"extend {f} to {z}, or confirm {z} is meant to be an exception"))
    return out


def check_dead_rules(rules: list[dict]) -> list[dict]:
    """Disabled, unmanaged rules are deletion candidates; two rules on one sequence clash."""
    out = []
    for r in rules:
        if not r["enabled"] and not r["managed"]:
            shown = (r["descr"][:40] or "no description")
            out.append(_f("low", "dead-rule", r,
                          f"disabled leftover (seq {r['seq']}): {shown!r}",
                          "delete it if it is no longer needed"))
    by_seq: dict[int, list[dict]] = {}
    for r in rules:
        by_seq.setdefault(r["seq"], []).append(r)
    for seq, group in sorted(by_seq.items()):
        if len(group) > 1 and any(r["enabled"] for r in group) and len({r["interface"] for r in group}) < len(group):
            ids = ", ".join(r["uuid"][:8] for r in group)
            out.append(_f("low", "seq-collision", group[0],
                          f"sequence {seq} is shared by {len(group)} rules on the same scope ({ids})",
                          "give them distinct sequences so the order is unambiguous"))
    return out


def check_descriptions(rules: list[dict]) -> list[dict]:
    """An enabled, unmanaged rule with no description is a future mystery."""
    return [_f("low", "missing-description", r,
               f"enabled rule (seq {r['seq']}) has no description", "add one so it is not deleted on sight later")
            for r in rules if r["enabled"] and not r["descr"]]


def audit(rules: list[dict], nat: list[dict] | None = None, *, mgmt_zone: str = "lan") -> list[dict]:
    """Run every check and return findings, most severe first. `rules` from parse_rules; `nat` optional."""
    user = [r for r in rules if not r.get("auto")]        # the user's own rules; OPNsense's automatic ones are skipped
    stock_allow_live = any(r["enabled"] and r["action"] == "pass" and "default allow" in r["descr"].lower()
                           for r in user)
    findings: list[dict] = []
    findings += check_shadowing(user)
    findings += check_proto_alias_mismatch(user)
    findings += check_vpn_passthrough_port(user)
    findings += check_admin_path(rules, stock_allow_live, mgmt_zone)   # all rules: an automatic anti-lockout is a valid path
    findings += check_zone_parity(user)
    findings += check_dead_rules(user)
    findings += check_descriptions(user)
    if nat is not None:
        findings += check_nat(nat)
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: (order.get(f["severity"], 9), f.get("seq") or 0))
    return findings


def check_nat(nat: list[dict]) -> list[dict]:
    """Port-forwards: a forward that skips the filter (rdr-pass), one with no source limit, one without logging."""
    out = []
    for n in nat:
        if not n["enabled"]:
            continue
        if n["pass_mode"] == "pass":
            out.append(_f("high", "nat-rdr-pass", n,
                          f"forward (seq {n['seq']}) {n['descr'][:30]!r} uses rdr-pass, which skips the filter rules entirely",
                          "switch it to an associated filter rule so the DROP/geo blocks still apply"))
        if n["src"].lower() in ("", "any"):
            out.append(_f("medium", "nat-open-source", n,
                          f"forward (seq {n['seq']}) {n['descr'][:30]!r} accepts from any source",
                          "set the source to your geo/US alias unless it must be world-open"))
        if not n["log"]:
            out.append(_f("low", "nat-no-log", n,
                          f"forward (seq {n['seq']}) {n['descr'][:30]!r} has logging off", "turn logging on for inbound forwards"))
    return out


def report(findings: list[dict]) -> str:
    """A plain-text report, grouped by severity — what the manager would show."""
    if not findings:
        return "No problems found."
    lines = []
    for sev in SEVERITIES:
        group = [f for f in findings if f["severity"] == sev]
        if not group:
            continue
        lines.append(f"\n{sev.upper()} ({len(group)})")
        for f in group:
            where = f"seq {f['seq']}" if f.get("seq") else (f.get("role") or "")
            lines.append(f"  [{f['check']}] {where}: {f['title']}")
            lines.append(f"      fix: {f['fix']}")
    return "\n".join(lines).strip()


def saved_credentials(key_dir=None) -> dict:
    """The read key and firewall the wizard already saved, from its key folder (~/.pazuzu by default): the
    pazuzu-read key file and the firewall.json stamp. So --live can use the same firewall the wizard owns,
    with no environment variables to set by hand."""
    import json
    import os
    from pathlib import Path
    folder = Path(key_dir or os.environ.get("PAZUZU_KEY_DIR") or (Path.home() / ".pazuzu"))
    out: dict = {}
    key_file = folder / "OPNsense.internal_pazuzu-read_apikey.txt"
    try:
        for line in key_file.read_text(encoding="utf-8", errors="replace").splitlines():
            name, _, value = line.partition("=")
            if name.strip() == "key":
                out["key"] = value.strip()
            elif name.strip() == "secret":
                out["secret"] = value.strip()
    except OSError:
        pass
    try:
        stamp = json.loads((folder / "firewall.json").read_text(encoding="utf-8", errors="replace"))
        host, port = stamp.get("host"), int(stamp.get("port") or 443)
        if host:
            out["base_url"] = f"https://{host}" + ("" if port == 443 else f":{port}")
    except (OSError, ValueError, TypeError):
        pass
    return out


def _fill_env_from_saved() -> None:
    """Fill the read-key env vars from the saved key folder when they are not already set (set ones win)."""
    import os
    saved = saved_credentials()
    if saved.get("key"):
        os.environ.setdefault("OPNSENSE_API_KEY", saved["key"])
    if saved.get("secret"):
        os.environ.setdefault("OPNSENSE_API_SECRET", saved["secret"])
    if saved.get("base_url") and not os.environ.get("OPNSENSE_BASE_URL"):
        os.environ["OPNSENSE_BASE_URL"] = saved["base_url"]
    os.environ.setdefault("OPNSENSE_TLS_VERIFY", "false")


def audit_live() -> list[dict]:
    """Read the live filter rules straight from the firewall and audit them. Uses the read key the wizard saved
    (~/.pazuzu) unless OPNSENSE_API_KEY / OPNSENSE_API_SECRET / OPNSENSE_BASE_URL are set in the environment."""
    _fill_env_from_saved()
    from pazuzu_core.opnsense_client import discover_firewall_rules
    got = discover_firewall_rules()
    rows = got.get("rows", []) if isinstance(got, dict) else []
    return audit(from_rows(rows))


def main(argv: list[str] | None = None) -> int:
    """python -m pazuzu_core.rule_audit (--live | <filter_export.csv> [nat_export.csv])

    --live reads the rules straight from the firewall over its read-only API (load your read key first). Otherwise
    it reads the semicolon exports OPNsense gives (Firewall: Rules, and Firewall: NAT: Port Forward). It prints the
    findings grouped by severity and exits non-zero when anything critical or high is found."""
    import sys
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        print(main.__doc__.strip().splitlines()[0])
        return 2
    if args[0] == "--live":
        import os
        _fill_env_from_saved()
        where = os.environ.get("OPNSENSE_BASE_URL", "")
        if not where:
            print("No firewall to read: set OPNSENSE_BASE_URL, or run the wizard so it saves the firewall and key.")
            return 2
        try:
            from pazuzu_core.opnsense_client import discover_firewall_rules
            rows = discover_firewall_rules().get("rows", [])
        except Exception as exc:  # noqa: BLE001
            print(f"Could not read {where} ({type(exc).__name__}: {exc}).")
            print("If the key is for a different firewall, run the wizard against this one and sign in (it saves the "
                  "read key and stamps the firewall), or set OPNSENSE_API_KEY / OPNSENSE_API_SECRET / OPNSENSE_BASE_URL by hand.")
            return 2
        rules, nat = from_rows(rows), None
        print(f"(read live from {where})")
    else:
        rules = parse_rules(open(args[0], encoding="utf-8", errors="replace").read())
        nat = parse_nat(open(args[1], encoding="utf-8", errors="replace").read()) if len(args) > 1 else None
    findings = audit(rules, nat)
    print(f"{len(rules)} rules read; {len(findings)} findings.\n")
    print(report(findings))
    return 1 if any(f["severity"] in ("critical", "high") for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
