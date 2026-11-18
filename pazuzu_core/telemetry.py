"""What may leave the box, captured on the manager (this PC), shown before it is sent (docs/architecture/telemetry.md).

Four rules, in code:
  1. Off by default, asked once: a kind whose switch is off is never captured, not merely never sent.
  2. Shown before it leaves: each capture is one JSON file in the outbox; the Reports page lists them byte for byte with
     Send and Discard. Nothing is sent from here by itself.
  3. Small, and about the product, never the home: the scrubber is the only way a payload reaches a file, and it refuses
     the whole file (never trims it) when any value looks like an address, a hardware address, a name of the home's own,
     or key material. A refusal is counted, so a leak is a visible bug.
  4. Counted on the box screen: the counts here are what the box's "Sent to Pazuzu" line shows.

The box plugin never sends anything and nothing is added to it for this.
"""
from __future__ import annotations

import json
import re
import secrets
import time
from pathlib import Path
from typing import Any, Iterable, Mapping

KINDS = {"versions": "versions", "checks": "checks", "problems": "problem", "devices": "device-needs"}
SWITCHES = tuple(KINDS)                              # the first screen's switches: all off until a person turns one on
OUTBOX = "outbox"
SENT = "sent"
ID_FILE = "install_id"
COUNTS_FILE = "telemetry_counts.json"
ADDRESS = "https://reports.hanbi.net/v1/report"      # step 4: where Send posts, over TLS, from this PC
WEEK = 7 * 24 * 3600

# What the scrubber refuses. Each is a thing that must never leave, matched anywhere inside a string.
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6 = re.compile(r"(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{1,4}(?![0-9a-fA-F:])")
_MAC = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}(?![0-9a-fA-F])|(?<![0-9a-fA-F])[0-9a-fA-F]{12}(?![0-9a-fA-F])")
_HOME_NAME = re.compile(r"\.(arpa|local|lan|home|internal)\b|\.duckdns\.org\b", re.I)
_KEY = re.compile(r"-----BEGIN|(?:key|secret|password|passkey|token)\s*[=:]", re.I)
_LONG_SECRET = re.compile(r"[A-Za-z0-9+/=_-]{32,}")     # an API key, a WireGuard key, a base64 blob

ALLOWED_KEYS = {
    "versions": {"manager_build", "plugin_version", "firewall_version", "hardware", "platform"},
    "checks": {"controls", "posture", "shield", "days_since_setup", "manager_build"},
    "problem": {"job", "step", "category", "manager_build", "plugin_version"},
    "device-needs": {"allows", "promotes", "stopped"},
}


class Refused(ValueError):
    """The payload held something that must never leave. The whole capture is dropped, and counted."""


def scrub(payload: Any, home_words: Iterable[str] = ()) -> Any:
    """The same payload, once every value has been checked; raises Refused on the first thing that must not leave.
    `home_words`: this home's own names (the firewall's host name, its zones' names), refused wherever they appear."""
    words = [w.lower() for w in home_words if w and len(str(w)) >= 3]

    def look(v, path):
        if isinstance(v, Mapping):
            for k, x in v.items():
                if not isinstance(k, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,40}", k):
                    raise Refused(f"{path}: a key that is not a plain field name")
                look(x, f"{path}.{k}")
        elif isinstance(v, (list, tuple)):
            for i, x in enumerate(v):
                look(x, f"{path}[{i}]")
        elif isinstance(v, str):
            s = v
            if len(s) > 200:
                raise Refused(f"{path}: a value longer than 200 characters")
            if _MAC.search(s):
                raise Refused(f"{path}: a hardware address")
            if _IPV4.search(s):
                raise Refused(f"{path}: an address")
            if _IPV6.search(s) and ("::" in s or s.count(":") >= 5):
                raise Refused(f"{path}: an address")
            if _HOME_NAME.search(s):
                raise Refused(f"{path}: a name of the home's own")
            if _KEY.search(s) or _LONG_SECRET.search(s):
                raise Refused(f"{path}: looks like a key or a secret")
            low = s.lower()
            for w in words:
                if w in low:
                    raise Refused(f"{path}: a name of the home's own")
        elif v is None or isinstance(v, (bool, int, float)):
            return
        else:
            raise Refused(f"{path}: a value of a kind that is not sent ({type(v).__name__})")

    look(payload, "report")
    return payload


def _now() -> float:
    return time.time()


class Telemetry:
    """The outbox on this PC. `consent` is the first screen's switches ({"versions": bool, ...})."""

    def __init__(self, key_dir: Path, consent: Mapping[str, bool] | None, home_words: Iterable[str] = (),
                 now=None):
        self.key_dir = Path(key_dir)
        self.consent = {k: bool((consent or {}).get(k)) for k in SWITCHES}
        self.home_words = list(home_words)
        self._now = now or _now

    # -- the id this install's reports share, and nothing else
    def install_id(self) -> str:
        p = self.key_dir / ID_FILE
        try:
            got = p.read_text(encoding="utf-8").strip()
            if re.fullmatch(r"[a-f0-9]{32}", got):
                return got
        except OSError:
            pass
        return self.new_id()

    def new_id(self) -> str:
        self.key_dir.mkdir(parents=True, exist_ok=True)
        got = secrets.token_hex(16)
        (self.key_dir / ID_FILE).write_text(got, encoding="utf-8")
        return got

    # -- counts: refused, written, sent (what the box's line shows)
    def counts(self) -> dict:
        try:
            data = json.loads((self.key_dir / COUNTS_FILE).read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return {"refused": int(data.get("refused") or 0), "written": int(data.get("written") or 0),
                        "sent": int(data.get("sent") or 0), "last_sent": data.get("last_sent"),
                        "last_refusal": str(data.get("last_refusal") or "")}
        except (OSError, ValueError, TypeError):
            pass
        return {"refused": 0, "written": 0, "sent": 0, "last_sent": None, "last_refusal": ""}

    def _bump(self, key: str, **extra) -> None:
        c = self.counts()
        c[key] = c.get(key, 0) + 1
        c.update(extra)
        self.key_dir.mkdir(parents=True, exist_ok=True)
        (self.key_dir / COUNTS_FILE).write_text(json.dumps(c), encoding="utf-8")

    # -- capture
    def capture(self, switch: str, payload: Mapping[str, Any]) -> Path | None:
        """One report into the outbox, or None: the switch is off (never captured), or the scrubber refused it (counted).
        The file is exactly what would be sent."""
        kind = KINDS.get(switch)
        if kind is None or not self.consent.get(switch):
            return None
        body = {k: v for k, v in dict(payload).items() if k in ALLOWED_KEYS[kind]}
        report = {"v": 1, "kind": kind, "install": self.install_id(), "at": int(self._now()), "report": body}
        try:
            scrub(report["report"], self.home_words)
        except Refused as exc:
            self._bump("refused", last_refusal=str(exc))
            return None
        out = self.key_dir / OUTBOX
        out.mkdir(parents=True, exist_ok=True)
        path = out / f"{kind}-{int(self._now())}-{secrets.token_hex(3)}.json"
        path.write_text(json.dumps(report, indent=1, sort_keys=True), encoding="utf-8")
        self._bump("written")
        return path

    def due(self, switch: str) -> bool:
        """Is a weekly kind due: no report of it written or sent in the last week."""
        kind = KINDS.get(switch)
        if kind is None or not self.consent.get(switch):
            return False
        latest = 0
        for folder in (self.key_dir / OUTBOX, self.key_dir / OUTBOX / SENT):
            for p in folder.glob(f"{kind}-*.json") if folder.exists() else []:
                try:
                    latest = max(latest, int(p.name.split("-")[1]))
                except (IndexError, ValueError):
                    continue
        return self._now() - latest >= WEEK

    # -- the Reports page
    def waiting(self) -> list[dict]:
        return self._list(self.key_dir / OUTBOX)

    def sent(self) -> list[dict]:
        return self._list(self.key_dir / OUTBOX / SENT)

    def _list(self, folder: Path) -> list[dict]:
        out = []
        for p in sorted(folder.glob("*.json")) if folder.exists() else []:
            try:
                text = p.read_text(encoding="utf-8")
                data = json.loads(text)
            except (OSError, ValueError):
                continue
            out.append({"name": p.name, "kind": data.get("kind"), "at": data.get("at"), "text": text,
                        "bytes": len(text.encode("utf-8"))})
        return out

    def discard(self, name: str) -> bool:
        p = self._named(name)
        if p is None:
            return False
        p.unlink()
        return True

    def discard_all(self) -> int:
        n = 0
        for r in self.waiting():
            n += 1 if self.discard(r["name"]) else 0
        return n

    def _named(self, name: str) -> Path | None:
        if not re.fullmatch(r"[a-z-]+-\d+-[a-f0-9]{6}\.json", str(name or "")):
            return None
        p = self.key_dir / OUTBOX / name
        return p if p.exists() else None

    def send(self, name: str, address: str | None = None, opener=None, timeout: float = 15) -> dict:
        """POST one waiting report to the reports address, exactly as the file holds it, over HTTPS with the system's
        own certificate check (Let's Encrypt on reports.hanbi.net). A 2xx moves it to sent/; anything else leaves it
        where it is with the reason. Through this PC's own connection, never the box, never the VPN."""
        p = self._named(name)
        if p is None:
            return {"ok": False, "why": "That report is not waiting any more."}
        url = address or ADDRESS
        if not url.startswith("https://"):
            return {"ok": False, "why": "The reports address must be https."}
        body = p.read_bytes()
        try:
            if opener is not None:
                code, answer = opener(url, body)
            else:
                import urllib.request
                req = urllib.request.Request(url, data=body, method="POST",
                                             headers={"Content-Type": "application/json", "User-Agent": "pazuzu-manager"})
                with urllib.request.urlopen(req, timeout=timeout) as r:      # verifies the certificate against the system's roots
                    code, answer = r.status, r.read()[:200].decode("utf-8", "replace")
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "why": "Could not reach the reports address: " + type(exc).__name__}
        if not 200 <= int(code) < 300:
            return {"ok": False, "why": f"The reports address answered {code}."}
        self.mark_sent(name)
        return {"ok": True}

    def mark_sent(self, name: str) -> bool:
        """After a 2xx from the reports address (step 4): the file moves to sent/ and is counted."""
        p = self._named(name)
        if p is None:
            return False
        dest = self.key_dir / OUTBOX / SENT
        dest.mkdir(parents=True, exist_ok=True)
        p.replace(dest / p.name)
        self._bump("sent", last_sent=int(self._now()))
        return True

    def view(self) -> dict:
        """Everything the Reports page shows."""
        c = self.counts()
        return {"switches": dict(self.consent), "install_id": self.install_id(), "address": ADDRESS,
                "waiting": self.waiting(), "sent": self.sent()[-20:], "counts": c,
                "box_line": (f"Sent to Pazuzu: {c['sent']} report{'s' if c['sent'] != 1 else ''}, last on "
                             + time.strftime("%d %b", time.localtime(c["last_sent"])))
                if c.get("sent") and c.get("last_sent") else "Nothing is sent to Pazuzu"}


# -- the payloads, built from what the manager already has (each a pure function, so it is testable)
def versions_payload(manager_build: int, plugin_version: str | None, firewall_version: str | None,
                     hardware: Mapping | None, platform: str) -> dict:
    hw = hardware if isinstance(hardware, Mapping) else {}
    ram = hw.get("ram_bytes")
    return {"manager_build": int(manager_build), "plugin_version": str(plugin_version or ""),
            "firewall_version": str(firewall_version or ""), "platform": "hanbi" if platform == "hanbi" else "pazuzu",
            "hardware": {"cores": int(hw.get("cores") or 0), "ram_gb": int(round(ram / 2 ** 30)) if ram else 0,
                         "ports": len(hw.get("nics") or []), "wifi": bool(hw.get("wifi")),
                         "bluetooth": bool(hw.get("bluetooth")), "virtual": bool(hw.get("virtual"))}}


def checks_payload(controls: Iterable[Mapping], posture: str, shield: Any, days_since_setup: int | None,
                   manager_build: int) -> dict:
    return {"controls": {str(c.get("id")): str(c.get("status")) for c in controls if isinstance(c, Mapping) and c.get("id")},
            "posture": str(posture or ""), "shield": str(shield if shield is not None else ""),
            "days_since_setup": int(days_since_setup) if days_since_setup is not None else -1,
            "manager_build": int(manager_build)}


def problem_category(error: str) -> str:
    """The error's plain category, never its text."""
    e = str(error or "").lower()
    if "passkey" in e or "not approved" in e:
        return "not-approved"
    if "401" in e or "403" in e or "not allowed" in e or "refused" in e:
        return "refused"
    if "timed out" in e or "timeout" in e or "did not answer" in e:
        return "timeout"
    if "certificate" in e or "tls" in e:
        return "tls"
    if "not understood" in e or "usual shape" in e:
        return "not-understood"
    if "nothing was changed" in e or "nothing more was changed" in e:
        return "stopped-safe"
    return "other"


def problem_payload(job_kind: str, step: str, error: str, manager_build: int, plugin_version: str | None) -> dict:
    return {"job": re.sub(r"[^a-z0-9-]", "", str(job_kind or "").lower())[:40],
            "step": re.sub(r"[^a-z0-9 -]", "", str(step or "").lower())[:60],
            "category": problem_category(error), "manager_build": int(manager_build),
            "plugin_version": str(plugin_version or "")}


def device_needs_payload(allows: Iterable[Mapping], promotes: Iterable[str], stopped: Iterable[Mapping],
                         maker_of) -> dict:
    """`allows`: [{"mac", "kind", "proto", "dport"}] from the Always rules on the firewall; `stopped`: the box's needs
    rows with count > 200; `maker_of(mac)` the maker word. The hardware address never enters the payload."""
    def word(mac):
        return re.sub(r"[^A-Za-z0-9 .&-]", "", str(maker_of(mac) or ""))[:40] or "unknown"
    return {"allows": [{"maker": word(a.get("mac")), "kind": str(a.get("kind") or "out"), "proto": str(a.get("proto") or "").lower(),
                        "port": int(a.get("dport") or 0)} for a in allows],
            "promotes": [int(p) for p in promotes if str(p).isdigit()],
            "stopped": [{"maker": word(s.get("mac")), "proto": str(s.get("proto") or "").lower(), "port": int(s.get("dport") or 0),
                         "where": str(s.get("where") or "out"), "count": int(s.get("count") or 0)}
                        for s in stopped if int(s.get("count") or 0) > 200]}
