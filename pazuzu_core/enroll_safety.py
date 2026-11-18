"""Safety helpers for first-run enrollment (the only place a root password
is sent): refuse non-private addresses, pin the firewall's certificate, and
save key files readable only by their owner. Standard library plus requests.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import socket
import ssl
import subprocess
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from requests.adapters import HTTPAdapter

PIN_FILE = "firewall_cert_sha256.txt"


def host_is_private(host: str) -> bool:
    """True only for loopback, link-local and private addresses.

    A name is looked up and every address it gives must be private, so a typo
    or a public name can never receive the root password. A name that does not
    resolve is refused.
    """

    host = (host or "").strip().strip("[]")
    if not host:
        return False
    try:
        ips = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            ips = [ipaddress.ip_address(i[4][0].split("%")[0])
                   for i in socket.getaddrinfo(host, None)]
        except (OSError, ValueError):
            return False
    return bool(ips) and all(
        ip.is_private or ip.is_loopback or ip.is_link_local for ip in ips
    )


def base_host_port(base_url: str) -> tuple[str, int]:
    parts = urlsplit(base_url)
    return parts.hostname or "", parts.port or (443 if parts.scheme == "https" else 80)


def fetch_fingerprint(host: str, port: int, timeout: float = 10) -> str:
    """SHA-256 of the certificate the server shows, as 64 hex characters."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock) as tls:
            der = tls.getpeercert(binary_form=True)
    return hashlib.sha256(der).hexdigest()


def fetch_cert_name(host: str, port: int, timeout: float = 10) -> str:
    """The certificate's common name (or first DNS name), or "" if it can't be read.
    Best effort and for display only; the fingerprint is what is trusted."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock) as tls:
                der = tls.getpeercert(binary_form=True)
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        cert = x509.load_der_x509_certificate(der)
        names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if names:
            return str(names[0].value)[:80]
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns = san.value.get_values_for_type(x509.DNSName)
        return str(dns[0])[:80] if dns else ""
    except Exception:
        return ""


def show_fingerprint(fp: str) -> str:
    fp = fp.upper()
    return ":".join(fp[i:i + 2] for i in range(0, len(fp), 2))


class PinnedAdapter(HTTPAdapter):
    """Accepts one certificate only, by fingerprint. Hostname does not matter."""

    def __init__(self, fingerprint: str, **kwargs):
        self._fingerprint = fingerprint
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["assert_fingerprint"] = self._fingerprint
        super().init_poolmanager(*args, **kwargs)


def make_session(verify, pin: str | None = None):
    """A session that ignores proxy settings, with the pin applied if given."""
    import requests

    s = requests.Session()
    s.trust_env = False
    s.verify = False if pin else verify
    if pin:
        s.mount("https://", PinnedAdapter(pin))
    s.headers["Connection"] = "close"
    from pazuzu_core import activity
    return activity.watch(s)


def load_pin(key_dir: Path) -> str | None:
    try:
        text = (key_dir / PIN_FILE).read_text(encoding="utf-8").strip().lower()
    except OSError:
        return None
    return text if len(text) == 64 and all(c in "0123456789abcdef" for c in text) else None


def save_pin(key_dir: Path, fp: str) -> str:
    path = key_dir / PIN_FILE
    if path.exists():
        path.unlink()
    return write_private(path, fp + "\n")


def refresh_pin(key_dir: Path, host: str, port: int, name: str, fetch=None, verify=None) -> bool:
    """BUILD 471: the admin page uses a Let's Encrypt certificate for `name`, renewed every 60 days, so the pinned
    fingerprint goes stale. When the page shows a different certificate, it is trusted again only if it is valid for
    `name` by the public CAs (checked on this very address); then that is the new pin. True when the pin was updated."""
    import ssl as _ssl
    if not name:
        return False
    try:
        now = (fetch or fetch_fingerprint)(host, port)
    except Exception:  # noqa: BLE001
        return False
    if not now or now == load_pin(key_dir):
        return False

    def _verified() -> bool:
        try:
            ctx = _ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=name) as tls:
                    der = tls.getpeercert(binary_form=True)
            return hashlib.sha256(der).hexdigest() == now
        except Exception:  # noqa: BLE001
            return False
    if not (verify or _verified)():
        return False
    save_pin(key_dir, now)
    return True


def trust_flow(base_url: str, key_dir: Path, ask: Callable[[str], str] = input,
               say: Callable[[str], None] = print) -> str | None:
    """Show the certificate and ask before trusting it. None means: stop."""
    host, port = base_host_port(base_url)
    fp = fetch_fingerprint(host, port)
    saved = load_pin(key_dir)
    if saved == fp:
        say("The firewall's certificate matches the one you trusted earlier.")
        return fp
    say("The firewall shows this certificate fingerprint (SHA-256):")
    say("  " + show_fingerprint(fp))
    if saved:
        say("WARNING: this is DIFFERENT from the certificate you trusted before.")
    say("Compare it with the fingerprint the firewall itself shows for its web")
    say("certificate (I have not confirmed where on 26.7). If you cannot compare")
    say("it, only continue on a network you trust.")
    if ask("Type yes to trust this certificate: ").strip().lower() != "yes":
        return None
    return fp


def write_private(path: Path, text: str) -> str:
    """Create a new file only the current user can read. Never overwrites."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    if os.name != "nt":
        return "limited to your user"
    try:  # Windows: drop inherited access, keep full control for this user
        who = os.environ.get("USERNAME", "")
        done = bool(who) and subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{who}:F"],
            capture_output=True, timeout=15).returncode == 0
    except (OSError, subprocess.SubprocessError):
        done = False
    return "limited to your user" if done else "could NOT be limited; restrict it by hand"
