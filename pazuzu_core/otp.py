"""A one-time-password seed made on this device, shown once, and never kept.

The seed is made here, drawn as a QR code for an authenticator app, and typed or pasted into the
firewall's user form by the person. Nothing is written to a file or sent anywhere. The same seed can be
checked against the code the phone shows, so a bad scan is found before the root account is shut.

Standard time-based codes: SHA-1, 6 digits, 30 seconds, a 160-bit seed in base32.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import struct
import time
from urllib.parse import quote

from pazuzu_core import qr

STEP = 30
DIGITS = 6
_SEED = re.compile(r"^[A-Z2-7]{32}$")
_ACCOUNT = re.compile(r"[^A-Za-z0-9._-]")


class OtpError(ValueError):
    pass


def new_seed() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")


def account_name(raw) -> str:
    name = _ACCOUNT.sub("", str(raw or ""))[:32]
    return name or "admin"


def uri(seed: str, account: str, issuer: str = "Pazuzu firewall") -> str:
    if not _SEED.match(seed or ""):
        raise OtpError("That is not a seed this app made.")
    acct = account_name(account)
    return (f"otpauth://totp/{quote(issuer)}:{quote(acct)}?secret={seed}"
            f"&issuer={quote(issuer)}&algorithm=SHA1&digits={DIGITS}&period={STEP}")


def code_at(seed: str, when: float) -> str:
    if not _SEED.match(seed or ""):
        raise OtpError("That is not a seed this app made.")
    key = base64.b32decode(seed)
    digest = hmac.new(key, struct.pack(">Q", int(when // STEP)), hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    value = (struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** DIGITS)
    return f"{value:0{DIGITS}d}"


def check(seed: str, code, now: float | None = None, window: int = 1) -> bool:
    """True when the code matches now, or one step either side (clocks drift a little)."""
    text = re.sub(r"\s", "", str(code or ""))
    if not re.fullmatch(r"\d{6}", text):
        return False
    at = time.time() if now is None else now
    return any(hmac.compare_digest(code_at(seed, at + i * STEP), text) for i in range(-window, window + 1))


def make(account: str) -> dict:
    """A fresh seed, with the address an authenticator app reads and the picture of it."""
    seed = new_seed()
    link = uri(seed, account)
    return {"seed": seed, "uri": link, "svg": qr.svg(qr.encode(link, "M"), label="One-time password QR code"),
            "account": account_name(account)}
