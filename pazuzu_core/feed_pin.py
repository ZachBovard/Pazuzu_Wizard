"""The PC's side of the plugin feed over HTTPS (HTTPS step 2).

From plugin 0.7.18 the feed answers HTTPS on its own port as well as plain HTTP, with a key made on the firewall and
signed by nobody. What proves it is the same box is the key's pin: the SHA-256 of its public key (SubjectPublicKeyInfo),
in URL-safe base64 without padding, 43 characters. The plugin shows it in its codes (`k=`); this computes it the same
way from the certificate the feed presents.

The rules, the same as the apps':

1. **Never go back.** Once this computer holds a pin for a box (host and port), it speaks only HTTPS to it, and a
   different key stops the request with words. It never falls back to plain HTTP.
2. **Learning a pin.** From the root-password install (the plugin's own line prints it, over Secure Shell, whose key
   was checked), or, for a box with no pin yet, on first use: `/phone/state` says `https_port`, and the key that
   answers there is kept. A new install from this computer may replace the pin (the box was reset, it has a new key).
3. **A box without HTTPS** (a plugin older than 0.7.18) is spoken to as before, in plain HTTP, until it has a pin.

Pins are kept in `feed_pins.json` in the key folder (`~/.pazuzu`, or `PAZUZU_FEED_PINS`), not secret: a pin is a public
key's fingerprint. Standard library only.
"""
from __future__ import annotations

import base64
import functools
import hashlib
import http.client
import json
import os
import socket
import ssl
import threading
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse, urlunparse

FILE = "feed_pins.json"
PIN_LEN = 43
PROBE_S = 3.0


class PinError(urllib.error.URLError):
    """A pinned box answered with another key, or would not answer HTTPS at all. Never falls back to plain HTTP."""


# -- the pin -------------------------------------------------------------------------------------------------------

def _der_item(buf: bytes, at: int) -> tuple[int, int, int]:
    if at + 2 > len(buf):
        raise ValueError("certificate")
    tag, first = buf[at], buf[at + 1]
    at += 2
    if first < 0x80:
        size = first
    else:
        n = first & 0x7F
        if n == 0 or n > 4 or at + n > len(buf):
            raise ValueError("certificate")
        size = int.from_bytes(buf[at:at + n], "big")
        at += n
    if at + size > len(buf):
        raise ValueError("certificate")
    return tag, at, at + size


def spki(cert_der: bytes) -> bytes:
    """The certificate's SubjectPublicKeyInfo, whole, as DER (hanbi_box/feed_tls.py does the same on the box)."""
    tag, start, _ = _der_item(cert_der, 0)
    if tag != 0x30:
        raise ValueError("certificate")
    tag, at, end = _der_item(cert_der, start)
    if tag != 0x30:
        raise ValueError("certificate")
    tag, _, nxt = _der_item(cert_der, at)
    if tag == 0xA0:
        at = nxt
    for _ in range(5):
        _, _, at = _der_item(cert_der, at)
    tag, _, stop = _der_item(cert_der, at)
    if tag != 0x30 or stop > end:
        raise ValueError("certificate")
    return cert_der[at:stop]


def pin_of_der(cert_der: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(spki(cert_der)).digest()).decode("ascii").rstrip("=")


def valid_pin(pin) -> bool:
    return isinstance(pin, str) and len(pin) == PIN_LEN and all(c.isalnum() or c in "-_" for c in pin)


def _context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE           # nobody signed it: the pin, checked after the handshake, is the proof
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def probe(host: str, port: int, timeout: float = PROBE_S) -> str | None:
    """The pin of the key that answers HTTPS at host:port, or None when nothing does."""
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as raw:
            with _context().wrap_socket(raw, server_hostname=None) as tls:
                der = tls.getpeercert(binary_form=True)
        return pin_of_der(der) if der else None
    except (OSError, ValueError, ssl.SSLError):
        return None


# -- where pins are kept ---------------------------------------------------------------------------------------------

def _key_dir(key_dir=None) -> Path:
    return Path(key_dir or os.environ.get("PAZUZU_FEED_PINS") or os.environ.get("PAZUZU_KEY_DIR")
                or (Path.home() / ".pazuzu"))


_LOCK = threading.Lock()


def _where(url: str) -> str | None:
    p = urlparse(str(url or ""))
    if not p.hostname or p.scheme not in ("http", "https"):
        return None
    return "%s:%d" % (p.hostname, p.port or (443 if p.scheme == "https" else 80))


def pins(key_dir=None) -> dict:
    """{"host:port": {"pin", "https_port"}} for every box this computer knows by its key."""
    try:
        with open(_key_dir(key_dir) / FILE, "r", encoding="utf-8") as fh:
            data = json.loads(fh.read(256 * 1024))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: {"pin": v["pin"], "https_port": int(v.get("https_port") or 0)} for k, v in data.items()
            if isinstance(k, str) and isinstance(v, dict) and valid_pin(v.get("pin"))}


def pin_for(url: str, key_dir=None) -> str | None:
    where = _where(url)
    got = pins(key_dir).get(where) if where else None
    return got["pin"] if got else None


def https_port_for(url: str, key_dir=None) -> int | None:
    where = _where(url)
    got = pins(key_dir).get(where) if where else None
    return (got["https_port"] or None) if got else None


def keep(url: str, pin: str, key_dir=None, https_port: int | None = None) -> bool:
    """Keep (or replace) the pin for the box at this URL's host and port, and the port its HTTPS answers on."""
    where = _where(url)
    if not where or not valid_pin(pin):
        return False
    with _LOCK:
        have = pins(key_dir)
        have[where] = {"pin": pin, "https_port": int(https_port or urlparse(url).port or 0)}
        folder = _key_dir(key_dir)
        folder.mkdir(parents=True, exist_ok=True)
        tmp = folder / (FILE + ".tmp")
        tmp.write_text(json.dumps(have, indent=1, sort_keys=True), encoding="utf-8")
        os.replace(tmp, folder / FILE)
    return True


def pin_from_lines(lines) -> str | None:
    """The plugin's install line ends with `HANBI_FEED_PIN=<pin>` (plugin 0.7.21 on), over Secure Shell."""
    for ln in reversed([str(x) for x in (lines or [])]):
        ln = ln.strip()
        if ln.startswith("HANBI_FEED_PIN="):
            pin = ln.split("=", 1)[1].strip()
            return pin if valid_pin(pin) else None
    return None


def learn(url: str, key_dir=None, replace: bool = False, timeout: float = PROBE_S) -> str | None:
    """First use: ask the box which port answers HTTPS (`/phone/state`, plain, no secret in it), take the key that
    answers there and keep its pin. Kept only when there is none yet, unless `replace` (a new install from here)."""
    have = pin_for(url, key_dir)
    if have and not replace:
        return have
    p = urlparse(str(url or ""))
    if not p.hostname:
        return None
    port = p.port or 8787
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        base = urlunparse(("http", "%s:%d" % (p.hostname, port), "", "", "", ""))
        with opener.open(base + "/phone/state", timeout=timeout) as r:
            state = json.loads(r.read(65536))
        https_port = int(state.get("https_port") or 0)
    except Exception:  # noqa: BLE001 - an older plugin, or no answer: stay as it was
        return have
    if not https_port:
        return have
    pin = probe(p.hostname, https_port, timeout)
    if pin and keep(url, pin, key_dir, https_port):
        return pin
    return have


def learn_soon(url: str, key_dir=None, replace: bool = False, tries: int = 1, every: float = 3.0) -> None:
    """learn() in the background, so a slow or silent box never holds anything up. A plugin just put on makes its key
    as it starts, so `replace` tries for a minute: the old pin (a reset firewall) gives way to the new key."""
    import time

    def go():
        for i in range(max(1, tries if not replace else 20)):
            before = pin_for(url, key_dir)
            got = learn(url, key_dir, replace, PROBE_S)
            if got and (not replace or got != before or i > 0):
                return
            time.sleep(every)
    threading.Thread(target=go, daemon=True).start()


# -- opening -------------------------------------------------------------------------------------------------------

class _PinnedConnection(http.client.HTTPSConnection):
    def __init__(self, *a, pin: str = "", **kw):
        kw["context"] = _context()
        super().__init__(*a, **kw)
        self._pin = pin

    def connect(self):
        super().connect()
        der = self.sock.getpeercert(binary_form=True)
        try:
            got = pin_of_der(der) if der else ""
        except ValueError:
            got = ""
        if got != self._pin:
            self.sock.close()
            raise PinError("The plugin on %s answered with a different key than this computer knows. If the "
                           "firewall was reset or the plugin put on again, put it on again from the setup here; "
                           "otherwise something else may be answering at that address." % self.host)


class _PinnedHandler(urllib.request.HTTPSHandler):
    def __init__(self, pin: str):
        super().__init__(context=_context())
        self._pin = pin

    def https_open(self, req):
        return self.do_open(functools.partial(_PinnedConnection, pin=self._pin), req)


def secure(url: str, port: int | None = None) -> str:
    p = urlparse(url)
    if p.scheme != "http":
        return url
    netloc = p.netloc if not port else "%s:%d" % (("[%s]" % p.hostname) if ":" in (p.hostname or "") else p.hostname, port)
    return urlunparse(("https", netloc) + tuple(p[2:]))


def urlopen(req, timeout: float = 5, key_dir=None, plain=None):
    """urllib.request.urlopen for the plugin's feed: HTTPS with its pin when this computer holds one (never plain
    again, never through a proxy), and when it does not, `plain` (the caller's own way, urllib.request.urlopen by
    default) as before."""
    if isinstance(req, str):
        req = urllib.request.Request(req)
    pin = pin_for(req.full_url, key_dir)
    if not pin:
        return (plain or urllib.request.urlopen)(req, timeout=timeout)  # noqa: S310 (the box's own private address)
    req.full_url = secure(req.full_url, https_port_for(req.full_url, key_dir))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _PinnedHandler(pin))
    try:
        return opener.open(req, timeout=timeout)
    except PinError:
        raise
    except urllib.error.HTTPError:
        raise
    except (urllib.error.URLError, OSError, ssl.SSLError) as exc:
        reason = getattr(exc, "reason", exc)
        if isinstance(reason, PinError):
            raise reason
        raise
