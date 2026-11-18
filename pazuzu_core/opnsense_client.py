from __future__ import annotations

import ipaddress
import os
from typing import Any
from urllib.parse import urlsplit

import requests

from pazuzu_core.operations import OperationId, get_operation


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Required environment variable is missing: {name}")
    return value


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _base_url() -> str:
    """The firewall address, checked before any credential is sent to it.

    Only scheme, host and an optional port are accepted. Plain http is
    allowed to a loopback address (a local mock server) or when
    OPNSENSE_ALLOW_INSECURE_HTTP is set, because the API key and secret
    would otherwise cross the network unencrypted.
    """

    raw = _required_env("OPNSENSE_BASE_URL").strip().rstrip("/")
    parts = urlsplit(raw)

    try:
        parts.port
    except ValueError:
        raise RuntimeError("OPNSENSE_BASE_URL has an invalid port") from None

    if parts.scheme not in {"https", "http"} or not parts.hostname:
        raise RuntimeError("OPNSENSE_BASE_URL must look like https://host[:port]")
    if parts.username or parts.password or parts.path or parts.query or parts.fragment:
        raise RuntimeError(
            "OPNSENSE_BASE_URL must contain only the scheme, host and optional "
            "port (no credentials, path, query or fragment)"
        )
    if parts.scheme == "http" and not (
        _is_loopback(parts.hostname)
        or os.getenv("OPNSENSE_ALLOW_INSECURE_HTTP", "").strip().lower()
        in {"true", "1", "yes", "on"}
    ):
        raise RuntimeError(
            "OPNSENSE_BASE_URL must use https. Plain http is allowed only to "
            "localhost, or in a lab with OPNSENSE_ALLOW_INSECURE_HTTP=true"
        )

    return raw


def _tls_setting() -> bool | str:
    ca_bundle = os.getenv("OPNSENSE_CA_BUNDLE")
    if ca_bundle:
        return ca_bundle

    value = os.getenv("OPNSENSE_TLS_VERIFY", "true").strip().lower()
    if value in {"true", "1", "yes", "on"}:
        return True
    if value in {"false", "0", "no", "off"}:
        return False
    raise RuntimeError("OPNSENSE_TLS_VERIFY must be true or false")


class ReadOnlyOPNsenseClient:
    """Executes only explicitly allowlisted, read-only operations."""

    def __init__(self) -> None:
        self.base_url = _base_url()
        self.timeout = float(os.getenv("OPNSENSE_TIMEOUT", "10"))

        self.session = requests.Session()
        from pazuzu_core import activity
        activity.watch(self.session)
        self.session.max_redirects = 0
        self.session.auth = (
            _required_env("OPNSENSE_API_KEY"),
            _required_env("OPNSENSE_API_SECRET"),
        )
        self.session.verify = _tls_setting()
        # Ignore proxy and CA-bundle environment variables: left on, an
        # exported REQUESTS_CA_BUNDLE or CURL_CA_BUNDLE overrides the
        # session's own verify setting (and a proxy variable could carry
        # the API credentials somewhere else). Use OPNSENSE_CA_BUNDLE.
        self.session.trust_env = False

    def execute(self, operation_id: OperationId | str) -> Any:
        operation = get_operation(operation_id)

        response = self.session.get(
            f"{self.base_url}{operation.path}",
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def close(self) -> None:
        self.session.close()


def preflight() -> dict[str, Any]:
    client = ReadOnlyOPNsenseClient()
    try:
        result = client.execute(OperationId.SYSTEM_FIRMWARE)
        return {
            "connected": True,
            "http_status": 200,
            "result": result,
        }
    finally:
        client.close()


def discover_interfaces() -> Any:
    client = ReadOnlyOPNsenseClient()
    try:
        return client.execute(OperationId.INTERFACES_OVERVIEW)
    finally:
        client.close()


def discover_interface_settings() -> Any:
    """The firewall-wide interface settings, which include the IPv6 allowance (read only)."""
    client = ReadOnlyOPNsenseClient()
    try:
        return client.execute(OperationId.INTERFACES_SETTINGS)
    finally:
        client.close()


def discover_firewall_aliases() -> Any:
    client = ReadOnlyOPNsenseClient()
    try:
        return client.execute(OperationId.FIREWALL_ALIASES)
    finally:
        client.close()


def discover_firewall_rules() -> Any:
    client = ReadOnlyOPNsenseClient()
    try:
        return client.execute(OperationId.FIREWALL_RULES)
    finally:
        client.close()
