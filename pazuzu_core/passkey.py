"""Passkey check for approving firewall changes. No network, no web page.

Every change to the firewall needs a passkey touch on the exact plan being
approved. This module is the checking part only: it makes a challenge that is
tied to the plan's digest, registers a passkey (keeping only its public part),
and verifies a signed approval.

Deliberately narrow, so it is small enough to read in one sitting:

* one key type: ES256 (ECDSA, P-256, SHA-256), the type every platform
  authenticator offers;
* one attestation format: "none" (we do not ask who made the authenticator);
* the user must have been checked locally (face, fingerprint or PIN), not
  just a touch;
* the signature maths is done by the `cryptography` package, not by us.

If the passkey is lost there is no back door: the owner resets and enrolls
again. Nothing secret is stored: the file holds public keys only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import tempfile
import time
from dataclasses import dataclass, replace
from pathlib import Path

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    HAVE_CRYPTO = True
except ImportError:  # the passkey path needs it; the rest of the project does not
    HAVE_CRYPTO = False

CHALLENGE_PREFIX = b"hanbi-approve-v1:"
CHALLENGE_SECONDS = 120
CREDENTIALS_FILE = "passkeys.json"

FLAG_UP = 0x01   # the user was present
FLAG_UV = 0x04   # the user was checked locally
FLAG_AT = 0x40   # attested credential data follows

COSE_KTY_EC2 = 2
COSE_ALG_ES256 = -7
COSE_CRV_P256 = 1


class PasskeyError(Exception):
    """Something about the passkey step is wrong; the message says what."""


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64url(text: str) -> bytes:
    if not isinstance(text, str):
        raise PasskeyError("expected text in a passkey field")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError) as exc:
        raise PasskeyError("a passkey field is not valid base64") from exc


def _need_crypto() -> None:
    if not HAVE_CRYPTO:
        raise PasskeyError(
            "passkeys need the 'cryptography' package: pip install cryptography")


# --- a very small CBOR reader (what a passkey registration contains) ---------

def cbor_decode(data: bytes):
    """Decode one CBOR value. Supports ints, bytes, text, arrays and maps.

    Refuses everything else (tags, floats, indefinite lengths) and refuses
    trailing bytes, so odd input fails loudly instead of being half-read.
    """

    value, end = _cbor_item(data, 0, 0)
    if end != len(data):
        raise PasskeyError("unexpected extra data after the passkey record")
    return value


def _cbor_item(data: bytes, pos: int, depth: int):
    if depth > 8:
        raise PasskeyError("passkey record is nested too deeply")
    if pos >= len(data):
        raise PasskeyError("passkey record ended early")
    head = data[pos]
    major, info = head >> 5, head & 0x1F
    pos += 1
    if info < 24:
        arg = info
    elif info in (24, 25, 26, 27):
        size = 1 << (info - 24)
        if pos + size > len(data):
            raise PasskeyError("passkey record ended early")
        arg = int.from_bytes(data[pos:pos + size], "big")
        pos += size
    else:
        raise PasskeyError("passkey record uses a form we do not accept")

    if major == 0:
        return arg, pos
    if major == 1:
        return -1 - arg, pos
    if major in (2, 3):
        if arg > len(data) - pos:
            raise PasskeyError("passkey record ended early")
        chunk = data[pos:pos + arg]
        pos += arg
        if major == 2:
            return bytes(chunk), pos
        try:
            return chunk.decode("utf-8"), pos
        except UnicodeDecodeError as exc:
            raise PasskeyError("passkey record has bad text") from exc
    if major == 4:
        if arg > len(data) - pos:
            raise PasskeyError("passkey record ended early")
        items = []
        for _ in range(arg):
            item, pos = _cbor_item(data, pos, depth + 1)
            items.append(item)
        return items, pos
    if major == 5:
        if arg > len(data) - pos:
            raise PasskeyError("passkey record ended early")
        out = {}
        for _ in range(arg):
            key, pos = _cbor_item(data, pos, depth + 1)
            val, pos = _cbor_item(data, pos, depth + 1)
            if isinstance(key, (list, dict)):
                raise PasskeyError("passkey record has an odd key")
            if key in out:
                raise PasskeyError("passkey record repeats a key")
            out[key] = val
        return out, pos
    raise PasskeyError("passkey record uses a form we do not accept")


# --- the stored public record -------------------------------------------------

@dataclass(frozen=True)
class Credential:
    credential_id: str        # base64url
    x: str                    # base64url, 32 bytes
    y: str                    # base64url, 32 bytes
    sign_count: int
    rp_id: str
    label: str = ""

    def public_key(self):
        _need_crypto()
        try:
            return ec.EllipticCurvePublicNumbers(
                int.from_bytes(unb64url(self.x), "big"),
                int.from_bytes(unb64url(self.y), "big"),
                ec.SECP256R1()).public_key()
        except ValueError as exc:
            raise PasskeyError("the stored passkey key is not valid") from exc


def load_credentials(path: Path) -> tuple[Credential, ...]:
    path = Path(path)
    if not path.exists():
        return ()
    try:
        raw = json.loads(_patiently(lambda: path.read_text(encoding="utf-8")))
        return tuple(Credential(**row) for row in raw["credentials"])
    except (ValueError, KeyError, TypeError) as exc:
        raise PasskeyError(
            f"the passkey file {path.name} could not be read: {exc}") from exc


def _patiently(action):
    """Windows briefly refuses to open or replace a file another thread is using
    (or a scanner is looking at). Try again for about two seconds before giving up."""

    for attempt in range(40):
        try:
            return action()
        except PermissionError:
            if attempt == 39:
                raise
            time.sleep(0.05)


def save_credentials(path: Path, credentials) -> None:
    """Write the public records, replacing the file in one step."""

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(
        {"credentials": [c.__dict__ for c in credentials]},
        indent=2, sort_keys=True) + "\n"
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".passkeys-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(body)
        _patiently(lambda: os.replace(tmp, path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# --- challenges: tied to the plan digest, single use, short lived ------------

@dataclass(frozen=True)
class Challenge:
    value: str          # base64url, what the browser signs
    digest: str         # the plan digest this approval is for
    expires: float


class Issuer:
    """Hands out challenges and takes each one back at most once."""

    def __init__(self, clock=time.time, seconds: int = CHALLENGE_SECONDS):
        self._clock = clock
        self._seconds = seconds
        self._open: dict[str, Challenge] = {}

    def issue(self, digest: str) -> Challenge:
        if not digest or not isinstance(digest, str):
            raise PasskeyError("there is no plan digest to approve")
        nonce = os.urandom(16)
        raw = hashlib.sha256(
            CHALLENGE_PREFIX + nonce + digest.encode("utf-8")).digest()
        now = self._clock()
        self._open = {k: v for k, v in self._open.items() if v.expires > now}
        challenge = Challenge(b64url(raw), digest, now + self._seconds)
        self._open[challenge.value] = challenge
        return challenge

    def take(self, value: str) -> Challenge:
        challenge = self._open.pop(value, None)
        if challenge is None:
            raise PasskeyError(
                "that approval was not asked for, or was already used")
        if challenge.expires <= self._clock():
            raise PasskeyError("that approval took too long; ask again")
        return challenge


# --- shared checks -------------------------------------------------------------

def _client_data(client_data_json: bytes, kind: str, challenge: str,
                 origin) -> None:
    """`origin` is one allowed page address, or several (an approval may come from the setup page
    or from the manager, both on this device). Anything else is refused."""
    allowed = (origin,) if isinstance(origin, str) else tuple(origin)
    try:
        data = json.loads(client_data_json.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise PasskeyError("the browser's record could not be read") from exc
    if not isinstance(data, dict):
        raise PasskeyError("the browser's record could not be read")
    if data.get("type") != kind:
        raise PasskeyError("this is the wrong kind of passkey message")
    if data.get("challenge") != challenge:
        raise PasskeyError("the passkey was not signed for this plan")
    if data.get("origin") not in allowed:
        raise PasskeyError("the passkey was made for a different site")
    if data.get("crossOrigin") is True:
        raise PasskeyError("the passkey was used from inside another page")


def _auth_data(auth: bytes, rp_id: str) -> tuple[int, int]:
    if len(auth) < 37:
        raise PasskeyError("the authenticator data is too short")
    if auth[:32] != hashlib.sha256(rp_id.encode("utf-8")).digest():
        raise PasskeyError("the passkey was made for a different site")
    flags = auth[32]
    if not flags & FLAG_UP:
        raise PasskeyError("the passkey was not touched")
    if not flags & FLAG_UV:
        raise PasskeyError(
            "the passkey did not check you (face, fingerprint or PIN)")
    return flags, struct.unpack(">I", auth[33:37])[0]


# --- registration --------------------------------------------------------------

def register(*, attestation_object: bytes, client_data_json: bytes,
             challenge: str, rp_id: str, origin: str, label: str = "") -> Credential:
    """Check a new passkey and return its public record."""

    _need_crypto()
    _client_data(client_data_json, "webauthn.create", challenge, origin)
    obj = cbor_decode(attestation_object)
    if not isinstance(obj, dict) or obj.get("fmt") != "none":
        raise PasskeyError("only passkeys without attestation are accepted")
    auth = obj.get("authData")
    if not isinstance(auth, bytes):
        raise PasskeyError("the new passkey has no authenticator data")
    flags, count = _auth_data(auth, rp_id)
    if not flags & FLAG_AT:
        raise PasskeyError("the new passkey carries no key")

    rest = auth[37:]
    if len(rest) < 18:
        raise PasskeyError("the new passkey record is too short")
    id_len = struct.unpack(">H", rest[16:18])[0]
    if id_len == 0 or id_len > 1023 or len(rest) < 18 + id_len:
        raise PasskeyError("the new passkey id is the wrong size")
    credential_id = rest[18:18 + id_len]
    cose = cbor_decode_prefix(rest[18 + id_len:])
    if (not isinstance(cose, dict) or cose.get(1) != COSE_KTY_EC2
            or cose.get(3) != COSE_ALG_ES256 or cose.get(-1) != COSE_CRV_P256):
        raise PasskeyError("only ES256 passkeys are accepted")
    x, y = cose.get(-2), cose.get(-3)
    if not (isinstance(x, bytes) and isinstance(y, bytes)
            and len(x) == 32 and len(y) == 32):
        raise PasskeyError("the new passkey key is the wrong size")
    cred = Credential(b64url(credential_id), b64url(x), b64url(y),
                      count, rp_id, label)
    cred.public_key()           # refuses a point that is not on the curve
    return cred


def cbor_decode_prefix(data: bytes):
    """Decode the first CBOR value; the key is followed by nothing we use."""

    value, _end = _cbor_item(data, 0, 0)
    return value


# --- approval ------------------------------------------------------------------

def verify_assertion(cred: Credential, *, challenge: str,
                     client_data_json: bytes, authenticator_data: bytes,
                     signature: bytes, rp_id: str, origin: str) -> Credential:
    """Check a signed approval. Returns the record with its counter moved on."""

    _need_crypto()
    if cred.rp_id != rp_id:
        raise PasskeyError("the passkey was made for a different site")
    _client_data(client_data_json, "webauthn.get", challenge, origin)
    _flags, count = _auth_data(authenticator_data, rp_id)
    if (count or cred.sign_count) and count <= cred.sign_count:
        raise PasskeyError(
            "the passkey's counter did not move forward: it may be a copy")
    signed = authenticator_data + hashlib.sha256(client_data_json).digest()
    try:
        cred.public_key().verify(signature, signed, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise PasskeyError("the passkey's signature does not match") from exc
    return replace(cred, sign_count=max(count, cred.sign_count))


def verify_approval(issuer: Issuer, credentials, *, expected_digest: str,
                    credential_id: str, client_data_json: bytes,
                    authenticator_data: bytes, signature: bytes,
                    rp_id: str, origin: str) -> tuple[Credential, ...]:
    """The whole check the executor will ask for.

    Passes only when the signed challenge was issued for `expected_digest`,
    has not been used or expired, and the signature is from a registered
    passkey. Returns the credential list with that passkey's counter updated;
    the caller saves it.
    """

    try:
        client = json.loads(client_data_json.decode("utf-8"))
        value = client["challenge"]
    except (ValueError, KeyError, TypeError, UnicodeDecodeError) as exc:
        raise PasskeyError("the browser's record could not be read") from exc
    challenge = issuer.take(value)
    if challenge.digest != expected_digest:
        raise PasskeyError("the passkey was signed for a different plan")
    match = next((c for c in credentials if c.credential_id == credential_id), None)
    if match is None:
        raise PasskeyError("that passkey is not registered")
    updated = verify_assertion(
        match, challenge=challenge.value, client_data_json=client_data_json,
        authenticator_data=authenticator_data, signature=signature,
        rp_id=rp_id, origin=origin)
    return tuple(updated if c is match else c for c in credentials)
