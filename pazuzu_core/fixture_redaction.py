"""Scrub recorded firewall responses so they can be committed as fixtures.

Pure functions. Real responses contain addresses, hardware addresses,
identifiers and sometimes secrets. Before a response is saved as a test
fixture it goes through a Redactor, which keeps the shape (keys, types,
list lengths) and replaces the content:

    IPv4 / IPv6 addresses   documentation ranges (192.0.2.0/24, 198.51.100.0/24,
                            203.0.113.0/24, 2001:db8::/32), prefix lengths kept
    hardware addresses      locally administered 02:00:00:00:xx:xx
    UUIDs                   00000000-0000-4000-8000-xxxxxxxxxxxx
    long key-like strings   <redacted-secret>
    values under sensitive  <redacted>   (password, secret, token, ssid,
    key names                             hostname, serial, duid, ...)
    literals you name       <redacted-literal>

The same original always maps to the same replacement within one Redactor,
so relationships between rows survive. Values under version-like keys and
network masks, 0.0.0.0, 127.0.0.1 and ::1 are left alone, because tests
need them intact.

verify() then checks that no original value is still present, and
find_unredacted() scans any text for things that look like unredacted data,
so a stray fixture cannot be committed by accident.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Iterable

_IPV4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(/\d{1,2})?(?![\w.])")
_IPV6 = re.compile(r"(?<![\w:])([0-9A-Fa-f:]{2,39})(%[\w.]+)?(/\d{1,3})?(?![\w:])")
_MAC = re.compile(r"(?<![\w:])((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})(?![\w:])")
_UUID = re.compile(
    r"(?<![\w-])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![\w-])"
)
_SECRET = re.compile(r"(?<![\w+/-])[A-Za-z0-9+/_-]{40,}={0,2}(?![\w+/=-])")

_SENSITIVE_KEYS = (
    "password", "passwd", "secret", "token", "apikey", "api_key", "passphrase",
    "psk", "private", "privkey", "authorized", "serial", "hostid", "duid",
    "ssid", "hostname", "fqdn", "domain", "username", "email", "certificate",
    "pubkey",
)
_PRESERVED_KEYS = ("version", "abi", "product_name", "product_id", "series")

_DOC_V4 = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)
_FAKE_UUID = re.compile(r"^00000000-0000-4000-8000-\d{12}$")


def _is_netmask(text: str) -> bool:
    try:
        ipaddress.IPv4Network(f"0.0.0.0/{text}")
        return True
    except ValueError:
        return False


class Redactor:
    def __init__(self, extra_literals: Iterable[str] = ()) -> None:
        self._literals = [s for s in extra_literals if s]
        self._v4: dict[str, str] = {}
        self._v6: dict[str, str] = {}
        self._mac: dict[str, str] = {}
        self._uuid: dict[str, str] = {}
        self._originals: set[str] = set()
        self._kinds: dict[str, str] = {}

    def _remember(self, original: str, kind: str) -> None:
        self._originals.add(original)
        self._kinds.setdefault(original, kind)

    # -- replacement helpers -------------------------------------------------

    def _v4_for(self, address: str) -> str:
        if address in {"0.0.0.0", "255.255.255.255", "127.0.0.1"} or _is_netmask(address):
            return address
        if address not in self._v4:
            index = len(self._v4)
            net, offset = divmod(index, 254)
            self._v4[address] = (
                str(_DOC_V4[net][offset + 1]) if net < len(_DOC_V4)
                else f"<ipv4-redacted-{index}>"
            )
            self._remember(address, "ipv4 address")
        return self._v4[address]

    def _v6_for(self, address: str) -> str:
        if address in {"::", "::1"}:
            return address
        if address not in self._v6:
            self._v6[address] = f"2001:db8::{len(self._v6) + 1:x}"
            self._remember(address, "ipv6 address")
        return self._v6[address]

    def _mac_for(self, address: str) -> str:
        if address.lower() in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}:
            return address
        if address not in self._mac:
            n = len(self._mac) + 1
            self._mac[address] = f"02:00:00:00:{n >> 8 & 255:02x}:{n & 255:02x}"
            self._remember(address, "hardware address")
        return self._mac[address]

    def _uuid_for(self, value: str) -> str:
        if value not in self._uuid:
            self._uuid[value] = f"00000000-0000-4000-8000-{len(self._uuid) + 1:012d}"
            self._remember(value, "uuid")
        return self._uuid[value]

    # -- text and structure --------------------------------------------------

    def scrub_text(self, text: str) -> str:
        for literal in self._literals:
            if literal in text:
                self._remember(literal, "named literal")
                text = text.replace(literal, "<redacted-literal>")

        text = _UUID.sub(lambda m: self._uuid_for(m.group(0)), text)
        text = _MAC.sub(lambda m: self._mac_for(m.group(1)), text)

        def v4(match: re.Match[str]) -> str:
            try:
                ipaddress.IPv4Address(match.group(1))
            except ValueError:
                return match.group(0)
            return self._v4_for(match.group(1)) + (match.group(2) or "")

        text = _IPV4.sub(v4, text)

        def v6(match: re.Match[str]) -> str:
            candidate = match.group(1)
            if candidate.count(":") < 2:
                return match.group(0)
            try:
                ipaddress.IPv6Address(candidate)
            except ValueError:
                return match.group(0)
            return self._v6_for(candidate) + (match.group(3) or "")

        text = _IPV6.sub(v6, text)

        def secret(match: re.Match[str]) -> str:
            self._remember(match.group(0), "key-like string")
            return "<redacted-secret>"

        return _SECRET.sub(secret, text)

    def scrub(self, value: Any, key: str = "") -> Any:
        lowered = key.lower()

        if any(p in lowered for p in _PRESERVED_KEYS):
            return value

        if any(s in lowered for s in _SENSITIVE_KEYS):
            self._remember_sensitive(value)
            return "<redacted>" if value not in (None, "", [], {}) else value

        if isinstance(value, dict):
            return {k: self.scrub(v, str(k)) for k, v in value.items()}
        if isinstance(value, list):
            return [self.scrub(v, key) for v in value]
        if isinstance(value, str):
            return self.scrub_text(value)
        return value

    def _remember_sensitive(self, value: Any) -> None:
        if isinstance(value, str) and len(value) >= 6 and not value.isdigit():
            self._remember(value, "value of a sensitive field")
        elif isinstance(value, (dict, list)):
            for item in (value.values() if isinstance(value, dict) else value):
                self._remember_sensitive(item)

    # -- checks ---------------------------------------------------------------

    def verify(self, scrubbed: Any) -> list[str]:
        """Originals that still appear in the scrubbed data (should be empty)."""

        text = json.dumps(scrubbed, sort_keys=True)
        placeholders = (
            set(self._v4.values()) | set(self._v6.values())
            | set(self._mac.values()) | set(self._uuid.values())
        )
        leaks = []
        for original in sorted(self._originals - placeholders):
            pattern = rf"(?<![\w.:-]){re.escape(original)}(?![\w.:-])"
            if re.search(pattern, text):
                leaks.append(original)
        return leaks

    def leaks(self, scrubbed: Any) -> list[tuple[str, str]]:
        """(kind, location) for every original still present, never the value.

        Values under version-like keys are skipped on purpose: they are kept
        intact because tests need them. Locations are key paths such as
        rows[3].name.
        """

        placeholders = (
            set(self._v4.values()) | set(self._v6.values())
            | set(self._mac.values()) | set(self._uuid.values())
        )
        suspects = {
            original: re.compile(rf"(?<![\w.:-]){re.escape(original)}(?![\w.:-])")
            for original in self._originals - placeholders
        }
        found: list[tuple[str, str]] = []

        def check(text: str, path: str) -> None:
            for original, pattern in suspects.items():
                if pattern.search(text):
                    found.append((self._kinds.get(original, "value"), path))

        def walk(value: Any, path: str, key: str = "") -> None:
            if any(p in key.lower() for p in _PRESERVED_KEYS):
                return
            if isinstance(value, dict):
                for child_key, child in value.items():
                    child_path = f"{path}.{child_key}" if path else str(child_key)
                    check(str(child_key), f"{child_path} (key)")
                    walk(child, child_path, str(child_key))
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    walk(child, f"{path}[{index}]", key)
            elif isinstance(value, str):
                check(value, path or "(root)")

        walk(scrubbed, "")
        return found

    def finalize(self, scrubbed: Any) -> Any:
        """Replace every remembered original wherever it still appears.

        A value found under a sensitive key (an address, a name) can also sit
        in a field the key rules did not cover. Once an original is known to
        be sensitive it is removed everywhere, so a value is never kept just
        because it appeared twice. Values under version-like keys are kept.
        """

        placeholders = (
            set(self._v4.values()) | set(self._v6.values())
            | set(self._mac.values()) | set(self._uuid.values())
        )
        suspects = [
            re.compile(rf"(?<![\w.:-]){re.escape(original)}(?![\w.:-])")
            for original in sorted(self._originals - placeholders)
        ]

        def clean(text: str) -> str:
            for pattern in suspects:
                text = pattern.sub("<redacted>", text)
            return text

        def walk(value: Any, key: str = "") -> Any:
            if any(p in key.lower() for p in _PRESERVED_KEYS):
                return value
            if isinstance(value, dict):
                result: dict[str, Any] = {}
                for child_key, child in value.items():
                    new_key = clean(str(child_key))
                    while new_key in result:
                        new_key += "_"
                    result[new_key] = walk(child, str(child_key))
                return result
            if isinstance(value, list):
                return [walk(child, key) for child in value]
            if isinstance(value, str):
                return clean(value)
            return value

        return walk(scrubbed)

    def counts(self) -> dict[str, int]:
        return {
            "ipv4": len(self._v4), "ipv6": len(self._v6),
            "mac": len(self._mac), "uuid": len(self._uuid),
        }


def find_unredacted(text: str) -> list[str]:
    """Things in text that look like unredacted data (kinds only, not values)."""

    problems: list[str] = []

    for match in _IPV4.finditer(text):
        address = match.group(1)
        try:
            ip = ipaddress.IPv4Address(address)
        except ValueError:
            continue
        if (address in {"0.0.0.0", "255.255.255.255", "127.0.0.1"}
                or _is_netmask(address)
                or any(ip in net for net in _DOC_V4)):
            continue
        problems.append("ipv4 address outside the documentation ranges")

    for match in _MAC.finditer(text):
        address = match.group(1).lower()
        if not address.startswith("02:00:00:00:") and address not in {
                "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}:
            problems.append("hardware address")

    for match in _UUID.finditer(text):
        if not _FAKE_UUID.match(match.group(0)):
            problems.append("uuid")

    for match in _IPV6.finditer(text):
        candidate = match.group(1)
        if candidate.count(":") >= 2:
            try:
                ip6 = ipaddress.IPv6Address(candidate)
            except ValueError:
                continue
            if candidate in {"::", "::1"} or ip6 in ipaddress.ip_network("2001:db8::/32"):
                continue
            problems.append("ipv6 address outside the documentation range")

    if _SECRET.search(text):
        problems.append("long key-like string")

    return problems
